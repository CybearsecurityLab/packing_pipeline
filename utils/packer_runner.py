import argparse
import os
import shutil
import subprocess
import sys
import yaml
import concurrent.futures
import threading
import time
from multiprocessing import cpu_count
from tqdm import tqdm
import hashlib
import re

try:
    from .sha_gate import ShaGate
except ImportError:  # direct-script launch (e.g. `python utils/packer_runner.py`)
    from sha_gate import ShaGate

# Inputs include non-ASCII filenames (e.g. CJK installer names). When stdout is
# redirected to a file on Windows it defaults to cp1252, so printing a failure
# line for such a file raises UnicodeEncodeError -- and because that fires inside
# the failure-reporting path, it aborts the whole batch. Force UTF-8 with a
# replacement fallback so no log line can ever kill the run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# Set when Ctrl+C is pressed; workers check this and bail out immediately.
_cancel_event = threading.Event()


class MemoryGate:
    """Admission control by estimated RAM, for packers whose per-job memory
    scales with input size (e.g. PEzor: donut embeds the whole input PE as a
    C++ string literal, so clang's peak RSS grows ~linearly with input size).

    A fixed worker count can't model this: 8 tiny inputs fit easily, but two
    large inputs can exhaust the WSL VM and crash it (host-level
    Wsl/Service/E_UNEXPECTED). Instead, each job estimates its peak RSS from the
    input size and reserves that from a shared budget; jobs block until their
    reservation fits. Small jobs run many-wide, large jobs self-serialize, and a
    job whose estimate alone exceeds the budget is skipped as unpackable here.
    """

    def __init__(self, budget_mb, floor_mb, per_input_mb):
        self.budget_mb = float(budget_mb)
        self.floor_mb = float(floor_mb)
        self.per_input_mb = float(per_input_mb)
        self._available = float(budget_mb)
        self._cv = threading.Condition()

    def estimate_mb(self, size_bytes):
        return self.floor_mb + self.per_input_mb * (size_bytes / 1048576.0)

    def fits(self, est_mb):
        """True if a job this large can ever run (estimate <= whole budget)."""
        return est_mb <= self.budget_mb

    def acquire(self, est_mb):
        # A single job may reserve up to the entire budget (runs alone).
        est_mb = min(est_mb, self.budget_mb)
        with self._cv:
            # Wait until enough budget frees up. A job needing the whole budget
            # waits for everything else to finish; this never deadlocks because
            # every acquired reservation is always released.
            while self._available < est_mb:
                self._cv.wait()
            self._available -= est_mb
        return est_mb

    def release(self, est_mb):
        with self._cv:
            self._available += est_mb
            self._cv.notify_all()


# Set per-packer in run_packing (None for packers without memory-scaled jobs).
_mem_gate = None

# --- DIALOG KILLER (Windows only) ---
if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32

    _EnumWindows = user32.EnumWindows
    _GetWindowTextW = user32.GetWindowTextW
    _GetClassNameW = user32.GetClassNameW
    _PostMessageW = user32.PostMessageW
    _IsWindowVisible = user32.IsWindowVisible
    _GetWindowThreadProcessId = user32.GetWindowThreadProcessId

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _WM_CLOSE = 0x0010

    # --- Process-tree introspection (used to scope the dialog killer) ---
    kernel32 = ctypes.windll.kernel32
    _CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    _Process32First = kernel32.Process32First
    _Process32Next = kernel32.Process32Next
    _CloseHandle = kernel32.CloseHandle
    _TH32CS_SNAPPROCESS = 0x00000002
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    def _build_parent_map():
        """Snapshot all processes and return a {pid: parent_pid} map."""
        parents = {}
        snap = _CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snap == _INVALID_HANDLE_VALUE:
            return parents
        try:
            entry = _PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)
            ok = _Process32First(snap, ctypes.byref(entry))
            while ok:
                parents[entry.th32ProcessID] = entry.th32ParentProcessID
                ok = _Process32Next(snap, ctypes.byref(entry))
        finally:
            _CloseHandle(snap)
        return parents

    def _window_owned_by_tree(hwnd, parents, root_pid):
        """True if hwnd's owning process is root_pid or one of its descendants."""
        pid = wintypes.DWORD(0)
        _GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        cur = pid.value
        if not cur:
            return False
        seen = set()
        while cur and cur not in seen:
            if cur == root_pid:
                return True
            seen.add(cur)
            cur = parents.get(cur, 0)
        return False

# Packer-specific settings
PACKER_SETTINGS = {
    "exe32pack": {
        "use_dialog_killer": True,
        "timeout": 30,
    },
    "upx": {
        "use_dialog_killer": False,
        "timeout": 1000,
    },
    "eronona": {
        "use_dialog_killer": False,
        "timeout": 60,
    },
    "fsg_v1.3": {
        "use_dialog_killer": False,
        # FSG v1.33 packs on the CLI (`FSG.EXE <input>`) but pops a
        # "compression ratio" dialog at the end and never exits on its
        # own -- the process hangs forever. The runner's subprocess
        # times out (exit code 0xFFFFFFFF) and reports failure even
        # though the file IS packed. success_by_hash tells the runner
        # to detect success by comparing the staged-input SHA-256
        # before vs after: if it changed, the pack succeeded and the
        # timeout was just the dialog refusing to dismiss itself.
        "timeout": 30,
        "success_by_hash": True,
    },
    "pezor": {
        "use_dialog_killer": False,
        "timeout": 600,
        # PEzor shells into WSL2 and compiles C++ per job; donut embeds the whole
        # input PE as a string literal, so clang's peak RSS scales ~linearly with
        # input size (measured ~60 + 57*input_MB; 100 MB input -> ~5.8 GB). A flat
        # worker count can't model this -- two large inputs at once exhaust the
        # WSL VM and crash it (host-level Wsl/Service/E_UNEXPECTED). Gate jobs by
        # estimated RAM instead. Budget stays under the VM's ~9.3 GB usable so the
        # VM never OOMs. max_workers is just an upper ceiling on wsl.exe launches;
        # the memory gate is the real throttle. wsl_workers is the default
        # concurrent wsl.exe count; --workers on the CLI overrides it (capped at
        # max_workers) and the runner logs the effective value at start-up.
        "max_workers": 8,
        "wsl_workers": 4,
        "mem_budget_mb": 7500,
        "mem_floor_mb": 250,
        "mem_per_input_mb": 60,
    },
    # Default for unknown packers
    "_default": {
        "use_dialog_killer": False,
        "timeout": 60,
    },
}


# Global verbosity flag. When False (default) we only show progress bars,
# failures, the active packer, and its test cases. When True we print everything.
VERBOSE = False


def vlog(msg):
    """Print only when --verbose is set (uses tqdm.write so bars stay intact)."""
    if VERBOSE:
        tqdm.write(msg)


def get_packer_settings(packer_name):
    return PACKER_SETTINGS.get(packer_name.lower(), PACKER_SETTINGS["_default"])


def _silent_remove(path):
    """Best-effort file removal that never raises."""
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _maybe_success_by_hash(
    packer_settings,
    packer_bin,
    pre_hash,
    staging_path,
    dst_path,
    output_behavior,
):
    """Fallback success detector for packers that never exit cleanly.

    FSG v1.33 packs the input in place but hangs on a "compression
    ratio" dialog and never returns; the runner's subprocess times out
    with exit code 0xFFFFFFFF even though the file was packed. When
    PACKER_SETTINGS[packer]["success_by_hash"] is True, compare the
    staged input's SHA-256 before vs after: a change means packing
    succeeded -- return True and promote staging_path to dst_path.

    Also opportunistically terminates any lingering packer process
    (FSG.EXE never exits; the next job would otherwise collide on the
    file lock).
    """
    if not packer_settings or not packer_settings.get("success_by_hash"):
        return False
    if output_behavior != "in_place" or not pre_hash:
        return False
    try:
        if not os.path.exists(staging_path):
            return False
        with open(staging_path, "rb") as f:
            post_hash = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return False
    if post_hash == pre_hash:
        return False
    try:
        shutil.copyfile(staging_path, dst_path)
    except OSError:
        return False
    _kill_packer_process_by_name(packer_bin)
    return True


def _kill_packer_process_by_name(packer_bin):
    """Kill any process whose executable basename matches the packer binary.

    Some packers (notably FSG v1.33) never exit cleanly -- they pop a
    "compression ratio" dialog and the runner's subprocess times out.
    Even after the timeout, the child process is still alive and would
    hold the staged file open for the next job. Best-effort: find any
    running process with a matching image name and terminate it.
    """
    if os.name != "nt" or not packer_bin:
        return
    try:
        target = os.path.basename(packer_bin).lower()
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        kernel32 = ctypes.windll.kernel32
        CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
        Process32FirstW = kernel32.Process32FirstW
        Process32NextW = kernel32.Process32NextW
        CloseHandle = kernel32.CloseHandle

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == ctypes.c_void_p(-1).value:
            return
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                if entry.szExeFile.lower() == target:
                    handle = kernel32.OpenProcess(0x0001, False, entry.th32ProcessID)
                    if handle:
                        kernel32.TerminateProcess(handle, 1)
                        kernel32.CloseHandle(handle)
                ok = Process32NextW(snap, ctypes.byref(entry))
        finally:
            CloseHandle(snap)
    except Exception:
        # Best-effort -- never let cleanup kill the runner.
        pass


def _move_into_place(produced, dst_path):
    """Move a produced artifact onto dst_path, atomically when on the same volume.

    Using os.replace keeps dst_path from ever holding a half-written file: it
    only appears once a complete, packed artifact exists.
    """
    _silent_remove(dst_path)
    try:
        os.replace(produced, dst_path)
    except OSError:
        # Cross-volume (e.g. packer dropped output on a different drive).
        shutil.move(produced, dst_path)


def _apply_sha_gate(sha_gate, *, input_path, output_path, packer_dir, app):
    """Verify one packed artifact against the shared SHA gate.

    Returns ``(True, None)`` when the gate is disabled or accepts the
    artifact. Returns ``(False, message)`` and best-effort deletes
    ``output_path`` when the gate rejects it (defense in depth -- callers
    should also delete on rejection to keep their accounting honest).
    """
    if sha_gate is None:
        return True, None
    result = sha_gate.verify_pack(
        input_path=input_path,
        output_path=output_path,
        packer_dir=packer_dir,
        app=app,
    )
    if result.accepted:
        return True, None
    _silent_remove(output_path)
    return False, result.message


def sanitize_filename(filename):
    """
    Convert filename to ASCII-safe version, replacing spaces with underscores.
    """
    # 1. Replace spaces with underscores immediately
    filename = filename.replace(" ", "_")

    try:
        filename.encode("ascii")
        return filename  # Already ASCII-safe
    except UnicodeEncodeError:
        pass

    name, ext = os.path.splitext(filename)

    # Extract ASCII portions
    ascii_parts = re.findall(r"[\x00-\x7F]+", name)
    # Join and strip bad chars
    ascii_portion = "".join(ascii_parts).strip("_-")

    # Create short hash of original name for uniqueness
    name_hash = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]

    if ascii_portion:
        safe_name = f"{ascii_portion}_{name_hash}"
    else:
        safe_name = f"packed_{name_hash}"

    return safe_name + ext


def dialog_killer(stop_event, scope_to_tree=True, target_keywords=None):
    """Background thread that auto-closes packer error/nag dialog boxes.

    By default it only closes dialogs owned by this process or one of its
    descendants (the packer subprocesses), so it never touches unrelated
    dialogs belonging to the user's other applications. If process-tree
    scoping is disabled it falls back to matching dialog-title keywords.
    """
    if os.name != "nt":
        return

    # Keywords to match in dialog titles (case-insensitive) — legacy fallback.
    target_keywords = target_keywords or [
        "error",
        "exe32pack",
        "evaluation",
        "trial",
        "limit",
        "warning",
        "notice",
    ]

    closed_count = [0]
    root_pid = os.getpid()
    parents_holder = {"map": {}}

    def enum_callback(hwnd, _):
        if not _IsWindowVisible(hwnd):
            return True

        class_name = ctypes.create_unicode_buffer(256)
        _GetClassNameW(hwnd, class_name, 256)

        # #32770 is the Windows dialog box class
        if class_name.value != "#32770":
            return True

        if scope_to_tree:
            # Only close dialogs spawned by our own packer process tree.
            if _window_owned_by_tree(hwnd, parents_holder["map"], root_pid):
                _PostMessageW(hwnd, _WM_CLOSE, 0, 0)
                closed_count[0] += 1
            return True

        title = ctypes.create_unicode_buffer(256)
        _GetWindowTextW(hwnd, title, 256)
        title_lower = title.value.lower()
        if any(kw in title_lower for kw in target_keywords):
            _PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            closed_count[0] += 1
        return True

    callback = _WNDENUMPROC(enum_callback)

    while not stop_event.is_set():
        # Refresh the PID->parent snapshot once per sweep (not per window).
        if scope_to_tree:
            parents_holder["map"] = _build_parent_map()
        _EnumWindows(callback, 0)
        time.sleep(0.05)  # Check every 50ms

    if closed_count[0] > 0:
        vlog(f"[*] Dialog killer closed {closed_count[0]} popup(s)")


# --- CONFIGURATION ---
# Anchor all paths to the project root (parent of this script's dir) so the
# runner works regardless of the current working directory it is launched from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
BENIGN_SOURCE_DIR = os.path.join(PROJECT_ROOT, "benign_sources")
PACKED_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "packed_sources")
YAML_CONFIG_FILE = os.path.join(PROJECT_ROOT, "manifest", "packer_corpus.yaml")

# UPDATED: Enforce strict x86 mapping
ARCH_MAP = {
    "PE32": ["x86"],
    "PE32+": [],  # Disabled x64
    "PE64": [],  # Disabled x64
    "BOTH": ["x86"],  # Only take the x86 portion
}


def load_yaml(path):
    if not os.path.exists(path):
        print(f"[!] Error: Configuration file '{path}' not found.")
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_targets(supported_arch):
    if isinstance(supported_arch, list):
        requested_archs = supported_arch
    else:
        requested_archs = [supported_arch]

    target_folders = set()
    for arch in requested_archs:
        folders = ARCH_MAP.get(arch, [])
        if folders:
            target_folders.update(folders)

    targets = []
    for folder in target_folders:
        search_path = os.path.join(BENIGN_SOURCE_DIR, folder)
        if os.path.exists(search_path):
            for f in os.listdir(search_path):
                full_path = os.path.join(search_path, f)
                # Skip already-packed files
                if ".packed" in f.lower():
                    continue
                if os.path.isfile(full_path) and f.lower().endswith(".exe"):
                    targets.append(full_path)
    return targets


# --- SHORT PATH FOR UNICODE FILENAMES ---
if os.name == "nt":
    _GetShortPathNameW = ctypes.windll.kernel32.GetShortPathNameW
    _GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _GetShortPathNameW.restype = wintypes.DWORD


def get_short_path(path):
    """Convert a path to its Windows 8.3 short form (ASCII-safe)."""
    if os.name != "nt":
        return path

    try:
        path.encode("ascii")
        return path
    except UnicodeEncodeError:
        pass

    # Must exist for GetShortPathName to work
    if not os.path.exists(path):
        return path

    buf_size = _GetShortPathNameW(path, None, 0)
    if buf_size == 0:
        return path

    buf = ctypes.create_unicode_buffer(buf_size)
    _GetShortPathNameW(path, buf, buf_size)
    return buf.value


def to_wsl_path(win_path):
    """Convert a Windows path to WSL path format."""
    # Normalize to absolute path
    abs_path = os.path.abspath(win_path)
    # Convert C:\Users\... to /mnt/c/Users/...
    if len(abs_path) >= 2 and abs_path[1] == ":":
        drive = abs_path[0].lower()
        rest = abs_path[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return abs_path.replace("\\", "/")


def pack_single_file(args):
    """Worker function to pack a single file."""
    if _cancel_event.is_set():
        return False, "Cancelled"

    # Unpack defensively. The first 11 fields are required; sha_gate and
    # packer_dir_name are optional trailing fields so external callers that
    # build a shorter tuple (e.g. wrapper/upx_scrambler.py's internal UPX
    # pre-pack) degrade to "no gate" instead of raising ValueError.
    (
        src_path,
        output_dir,
        packer_bin,
        cmd_template,
        max_size_kb,
        timeout,
        output_behavior,
        dependencies,
        config,
        project_file,
        packer_name,
        *rest,
    ) = args
    sha_gate = rest[0] if len(rest) > 0 else None
    packer_dir_name = rest[1] if len(rest) > 1 else os.path.basename(
        os.path.normpath(output_dir)
    )

    filename = os.path.basename(src_path)
    safe_filename = sanitize_filename(filename)
    dst_path = os.path.join(output_dir, safe_filename)

    # Per-packer settings (timeout, success_by_hash, etc.). The
    # hash-based success fallback for hang-on-dialog packers (FSG) is
    # gated on this lookup.
    pk_settings = get_packer_settings(packer_name)

    if max_size_kb > 0:
        file_size_kb = os.path.getsize(src_path) / 1024
        if file_size_kb > max_size_kb:
            return False, f"Skipped (Too large: {file_size_kb:.1f} KB)"

    if os.path.exists(dst_path):
        return False, "Skipped (Exists)"

    # Estimate this job's peak RAM (for packers with a memory gate). Inputs whose
    # estimate alone exceeds the whole budget can't run on this VM -> skip them.
    gate = _mem_gate
    est_mb = 0.0
    if gate is not None:
        est_mb = gate.estimate_mb(os.path.getsize(src_path))
        if not gate.fits(est_mb):
            size_mb = os.path.getsize(src_path) / 1048576.0
            return (
                False,
                f"Skipped (Too large for memory budget: {size_mb:.0f} MB input "
                f"-> ~{est_mb:.0f} MB RAM > {gate.budget_mb:.0f} MB budget)",
            )

    current_input = src_path
    temp_files_to_clean = []

    if dependencies:
        for dep_name in dependencies:
            dep_def = next(
                (
                    p
                    for p in config.get("definitions", [])
                    if p["packer_name"].lower() == dep_name.lower()
                ),
                None,
            )
            dep_test_cases = [
                t
                for t in config.get("test_cases", [])
                if t["packer_name"].lower() == dep_name.lower()
            ]

            if not dep_def or not dep_test_cases:
                return False, f"Dependency or test case not found for: {dep_name}"

            dep_case = next(
                (t for t in dep_test_cases if "DEFAULT" in t["id"]), dep_test_cases[0]
            )

            # --- FIX: Use a safe local path for the dependency stage ---
            # This prevents the "FileNotFound" error by avoiding long absolute paths with spaces
            dep_stage_path = os.path.abspath(
                os.path.join(output_dir, f"stage_{dep_name}_{safe_filename}")
            )

            # Create a local temporary copy of the current_input to the output_dir
            # so the packer is working on a local file, not a deep-pathed source file.
            # Key the name on safe_filename so parallel workers never share this path.
            temp_local_input = os.path.abspath(
                os.path.join(
                    output_dir,
                    f"tmp_input_{dep_name}_{os.path.splitext(safe_filename)[0]}.exe",
                )
            )
            shutil.copy2(current_input, temp_local_input)
            temp_files_to_clean.append(temp_local_input)

            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, ".."))
            raw_dep_bin = dep_case["binary_path"]
            if raw_dep_bin.startswith("./"):
                raw_dep_bin = raw_dep_bin[2:]
            dep_bin = os.path.abspath(os.path.join(project_root, raw_dep_bin))

            # Build command using the local temp input
            dep_raw_template = dep_case["cli_template"]
            dep_cmd_parts = dep_raw_template.split()
            dep_command = []

            for part in dep_cmd_parts:
                # We use get_short_path to further protect against path issues
                new_part = (
                    part.replace("{bin}", get_short_path(dep_bin))
                    .replace("{in}", get_short_path(temp_local_input))
                    .replace("{out}", get_short_path(dep_stage_path))
                    .replace("{python}", sys.executable)
                )
                dep_command.append(new_part)

            try:
                # Handle in_place for dependencies
                if dep_def.get("output_behavior") == "in_place":
                    shutil.copy2(temp_local_input, dep_stage_path)
                    dep_command = [
                        p.replace(
                            get_short_path(temp_local_input),
                            get_short_path(dep_stage_path),
                        )
                        for p in dep_command
                    ]

                subprocess.run(
                    dep_command,
                    check=True,
                    capture_output=True,
                    timeout=timeout,
                    cwd=os.path.dirname(dep_bin),
                )

                current_input = dep_stage_path
                temp_files_to_clean.append(dep_stage_path)
            except subprocess.CalledProcessError as e:
                return False, f"Dependency {dep_name} failed: {e.stderr.decode()}"
            except Exception as e:
                return False, f"Stage failed ({dep_name}): {str(e)}"

    # --- Create local temp for intermediate files and Safe Input Copy ---
    # Each job gets its OWN subdir so parallel workers never collide on shared
    # temp names. A clobbered/removed input is what produced the "Permission
    # denied" failures under --workers > 1.
    # Short, ASCII-safe, per-job-unique stem. Short names keep legacy packers
    # happy; the unique suffix means a packer that drops output into its own CWD
    # writes a unique name there instead of a shared "in.packed.exe" that
    # parallel workers would otherwise fight over.
    stem = "i" + hashlib.md5(safe_filename.encode("utf-8")).hexdigest()[:7]

    # Use the stem (not the human filename) for the _temp_build subdir too, so the
    # ENTIRE staged path is [a-z0-9_]-safe. PEzor passes this path through
    # wsl.exe -> bash, where shell metacharacters in the name corrupt it:
    # "Batch File Split & Join" backgrounds the command at '&' (exit 127);
    # "Rocks'n'Diamonds" has its quotes eaten by bash -> "RocksnDiamonds", a path
    # that doesn't exist -> broken symlink / donut "File not found".
    local_temp = os.path.join(output_dir, "_temp_build", stem)
    os.makedirs(local_temp, exist_ok=True)

    safe_input_name = stem + ".exe"
    safe_input_path = os.path.join(local_temp, safe_input_name)

    _silent_remove(safe_input_path)

    # Copy from current_input, not src_path: when this packer has dependencies
    # (e.g. hackupx depends on upx), current_input points at the last stage's
    # output. Using src_path here would silently discard the dependency chain
    # and feed the packer the original unpacked file.
    try:
        shutil.copyfile(current_input, safe_input_path)
    except OSError as e:
        return False, f"Failed to create temp input copy: {e}"

    # Everything is produced inside local_temp and only moved to dst_path on a
    # verified success, so a crash mid-pack can never leave a partial dst_path
    # that a later run would wrongly skip as "Exists".
    staging_out = os.path.join(local_temp, "out_" + stem + ".exe")
    temp_amber_output = os.path.join(local_temp, f"{stem}_packed.exe")  # Amber style
    temp_suffix_output = os.path.join(local_temp, f"{stem}.packed.exe")  # Eronona style
    cwd_suffix_output = os.path.join(
        os.path.dirname(packer_bin), f"{stem}.packed.exe"
    )

    pack_env = os.environ.copy()
    pack_env["TEMP"] = os.path.abspath(local_temp)
    pack_env["TMP"] = os.path.abspath(local_temp)

    # amber v2.0 shells out to `go build` to compile a runtime stub. The prebuilt
    # amber.exe is from the GOPATH era (no go.mod); Go 1.21+ defaults to module
    # mode outside GOPATH and refuses the build. GO111MODULE=off restores the
    # legacy behavior so v2.0's stub compiles. The Go toolchain must also be on
    # PATH -- prefer Scoop's shim, then fall back to other common installs.
    if packer_name.lower() == "amber_v2.0":
        pack_env["GO111MODULE"] = "off"
        go_path_candidates = [
            r"C:\Users\Towshi\scoop\shims",
            r"C:\Program Files\Go\bin",
            r"C:\Go\bin",
        ]
        existing = pack_env.get("PATH", "")
        prepend = []
        for p in go_path_candidates:
            if os.path.isdir(p) and any(f.lower() == "go.exe" for f in os.listdir(p)):
                prepend.append(p)
        pack_env["PATH"] = ";".join(prepend + [existing]) if prepend else existing

    # In-place packers modify a single file (named via {in} or {out}). Stage that
    # file inside local_temp so dst_path stays untouched until success.
    staged_pre_hash = None
    if output_behavior == "in_place":
        try:
            shutil.copyfile(safe_input_path, staging_out)
        except OSError as e:
            return False, f"Failed to setup in-place file: {e}"
        # Capture the SHA-256 of the staged input BEFORE invoking the packer
        # so the post-failure check can detect that in-place packing actually
        # happened even when the subprocess times out (FSG v1.33 hangs on a
        # "compression ratio" dialog and never exits cleanly).
        try:
            with open(staging_out, "rb") as _f:
                staged_pre_hash = hashlib.sha256(_f.read()).hexdigest()
        except OSError:
            staged_pre_hash = None

    # --- Robust Command Construction ---
    raw_parts = cmd_template.split()
    command_list = []
    is_wsl_command = raw_parts[0].lower() == "wsl" if raw_parts else False

    # Shell scripts invoked by WSL (e.g. PEzor's pezor_wrap.sh) can't tolerate
    # Windows-style CRLF line endings -- bash on Linux reads the \r as part of
    # the token, silently corrupting keywords like `if`/`fi`/`then` and failing
    # with "unexpected end of file from 'if' command". Strip CRs at the source
    # path before WSL sees the file. No-op for non-shell-script packers.
    if is_wsl_command and packer_bin.lower().endswith((".sh", ".bash")):
        try:
            with open(packer_bin, "rb") as f:
                content = f.read()
            if b"\r\n" in content:
                with open(packer_bin, "wb") as f:
                    f.write(content.replace(b"\r\n", b"\n"))
        except OSError as e:
            return False, f"Failed to normalize shell script line endings: {e}"

    # Prepare values for substitution
    # Use short paths for Windows binaries to avoid space issues
    val_bin = packer_bin
    if is_wsl_command:
        val_bin = to_wsl_path(packer_bin)

    # In-place packers operate on the staged file, so {in} points at it too;
    # otherwise {in} is the (read-only) input copy.
    in_source = staging_out if output_behavior == "in_place" else safe_input_path
    val_in = get_short_path(os.path.abspath(in_source))
    if is_wsl_command:
        val_in = to_wsl_path(val_in)

    # Direct-output packers ({out}) write to the staging path, never dst_path.
    val_out = os.path.abspath(staging_out)
    if output_behavior != "explicit_absolute":
        val_out = get_short_path(val_out)
    if is_wsl_command:
        val_out = to_wsl_path(val_out)

    val_python = sys.executable
    val_project = get_short_path(os.path.abspath(project_file)) if project_file else ""

    for part in raw_parts:
        # Use simple substitution to preserve flags attached to placeholders
        # e.g., "-f{in}" -> "-fC:\path\to\in.exe"
        new_part = part
        if "{python}" in new_part:
            new_part = new_part.replace("{python}", val_python)

        if "{bin}" in new_part:
            new_part = new_part.replace("{bin}", val_bin)

        if "{project}" in new_part:
            new_part = new_part.replace("{project}", val_project)

        if "{in}" in new_part:
            new_part = new_part.replace("{in}", val_in)

        if "{out}" in new_part:
            new_part = new_part.replace("{out}", val_out)

        command_list.append(new_part)

    # Reserve this job's estimated RAM before launching the heavy subprocess so
    # concurrent jobs never collectively exceed the budget (released in finally).
    gate_held = 0.0
    if gate is not None:
        if _cancel_event.is_set():
            return False, "Cancelled"
        gate_held = gate.acquire(est_mb)

    try:
        # cwd = packer binary's directory. Hyperion (v1.2 and v2.3.1) shells out
        # to Fasm\FASM.EXE with relative paths under Src\FasmContainer32\, so it
        # MUST run from its own dir or it fails with "Could not open output file
        # Src\FasmContainer32\infile.asm". Don't change this without re-testing
        # hyperion on at least one small sample.
        cwd = os.path.dirname(packer_bin)

        # DEBUG: Uncomment the next line to see exactly what runs
        # print(f"DEBUG EXECUTING: {command_list}")

        result = subprocess.run(
            command_list,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            encoding="mbcs" if os.name == "nt" else "utf-8",
            errors="replace",
            timeout=timeout,
            env=pack_env,
            cwd=cwd,
            input="\n\n",
        )

        # --- POST-PROCESSING ---
        # Locate the produced artifact (depends on the packer's output style) and
        # move it into place only now that packing has succeeded. Checking
        # staging_out first covers explicit/in-place packers; the suffix names
        # cover Amber/Eronona; the CWD path is the legacy fallback.
        produced = next(
            (
                p
                for p in (
                    staging_out,
                    temp_amber_output,
                    temp_suffix_output,
                    cwd_suffix_output,
                )
                if os.path.exists(p)
            ),
            None,
        )

        if produced:
            _move_into_place(produced, dst_path)

        if os.path.exists(dst_path):
            accepted, gate_msg = _apply_sha_gate(
                sha_gate,
                input_path=safe_input_path,
                output_path=dst_path,
                packer_dir=packer_dir_name,
                app=safe_filename,
            )
            if not accepted:
                return False, gate_msg
            return True, "Packed"

        combined_output = (
            f"STDOUT: {result.stdout.strip()} | STDERR: {result.stderr.strip()}"
        )
        return (
            False,
            f"Failed (No Output) - Behavior: {output_behavior} | {combined_output}",
        )

    except subprocess.TimeoutExpired:
        # FSG v1.33 hangs forever on its "compression ratio" dialog and
        # never exits; the runner's subprocess times out and reports
        # failure even though the file was already packed in place.
        # success_by_hash in PACKER_SETTINGS tells us to fall back to a
        # staged-input hash comparison.
        if _maybe_success_by_hash(
            pk_settings, packer_bin, staged_pre_hash, staging_out, dst_path,
            output_behavior,
        ):
            accepted, gate_msg = _apply_sha_gate(
                sha_gate,
                input_path=safe_input_path,
                output_path=dst_path,
                packer_dir=packer_dir_name,
                app=safe_filename,
            )
            if not accepted:
                return False, gate_msg
            return True, "Packed (detected via hash change after timeout)"
        return False, "Timeout (possible stuck dialog)"

    except subprocess.CalledProcessError as e:
        out = e.stdout.strip() if e.stdout else ""
        err = e.stderr.strip() if e.stderr else ""
        if _maybe_success_by_hash(
            pk_settings, packer_bin, staged_pre_hash, staging_out, dst_path,
            output_behavior,
        ):
            accepted, gate_msg = _apply_sha_gate(
                sha_gate,
                input_path=safe_input_path,
                output_path=dst_path,
                packer_dir=packer_dir_name,
                app=safe_filename,
            )
            if not accepted:
                return False, gate_msg
            return True, "Packed (detected via hash change after non-zero exit)"
        return False, f"Exit Code {e.returncode} - STDOUT: {out} | STDERR: {err}"

    except Exception as e:
        if _maybe_success_by_hash(
            pk_settings, packer_bin, staged_pre_hash, staging_out, dst_path,
            output_behavior,
        ):
            accepted, gate_msg = _apply_sha_gate(
                sha_gate,
                input_path=safe_input_path,
                output_path=dst_path,
                packer_dir=packer_dir_name,
                app=safe_filename,
            )
            if not accepted:
                return False, gate_msg
            return True, "Packed (detected via hash change after exception)"
        return False, f"Exception: {str(e)}"

    finally:
        if gate is not None and gate_held:
            gate.release(gate_held)
        # Clean artifacts that live OUTSIDE local_temp (which the caller wipes
        # per test case): the CWD fallback drop and dependency staging files.
        _silent_remove(cwd_suffix_output)
        for leftover in temp_files_to_clean:
            _silent_remove(leftover)


def run_packing(
    packer_name_input,
    max_size_kb=0,
    config=None,
    workers=1,
    wsl_workers=None,
    sha_gate=None,
):
    _cancel_event.clear()
    if config is None:
        config = load_yaml(YAML_CONFIG_FILE)

    definitions = config.get("definitions", [])
    packer_def = next(
        (
            p
            for p in definitions
            if p["packer_name"].lower() == packer_name_input.lower()
        ),
        None,
    )

    if not packer_def:
        print(f"[!] Packer definition not found for: {packer_name_input}")
        return []

    pk_settings = get_packer_settings(packer_name_input)

    # Some packers (e.g. PEzor) can't tolerate the global worker count because
    # each job spawns a heavy WSL/compile subprocess. Honor a per-packer cap.
    # wsl_workers_override (None unless the user passed --wsl-workers) takes
    # precedence over the packer's wsl_workers default; falls back to that
    # default if neither the override nor --workers exceeds the floor.
    wsl_workers_default = pk_settings.get("wsl_workers")
    if wsl_workers is not None:
        workers = wsl_workers
        print(
            f"[*] {packer_name_input} wsl_workers override: {workers} "
            f"(packer cap={pk_settings.get('max_workers')})"
        )
    elif wsl_workers_default is not None and workers < wsl_workers_default:
        print(
            f"[*] {packer_name_input} defaulting to wsl_workers={wsl_workers_default} "
            f"(use --wsl-workers N to override; cap={pk_settings.get('max_workers')})"
        )
        workers = wsl_workers_default
    max_workers_cap = pk_settings.get("max_workers")
    if max_workers_cap and workers > max_workers_cap:
        print(
            f"[*] Capping workers for '{packer_name_input}': "
            f"{workers} -> {max_workers_cap} (packer is resource-heavy)"
        )
        workers = max_workers_cap

    # If the packer's per-job memory scales with input size, install a memory
    # gate so concurrency is throttled by estimated RAM rather than thread count.
    global _mem_gate
    if pk_settings.get("mem_budget_mb"):
        _mem_gate = MemoryGate(
            budget_mb=pk_settings["mem_budget_mb"],
            floor_mb=pk_settings.get("mem_floor_mb", 0),
            per_input_mb=pk_settings.get("mem_per_input_mb", 0),
        )
        cap_mb = _mem_gate.budget_mb - _mem_gate.floor_mb
        cap_in = cap_mb / _mem_gate.per_input_mb if _mem_gate.per_input_mb else 0
        print(
            f"[*] Memory gate for '{packer_name_input}': budget "
            f"{_mem_gate.budget_mb:.0f} MB, est ~{_mem_gate.floor_mb:.0f}"
            f"+{_mem_gate.per_input_mb:.0f}*input_MB; inputs over "
            f"~{cap_in:.0f} MB are skipped (need more RAM than the VM has)"
        )
    else:
        _mem_gate = None

    # Check if 'CLI' is in the tags
    tags = packer_def.get("tags", [])
    if "CLI" not in tags:
        print(f"[*] Skipping '{packer_name_input}' - Not a CLI tool (Tags: {tags})")
        return []
    # ----------------------------------

    selected_tests = []
    for case in config.get("test_cases", []):
        if case.get("packer_name", "").lower() == packer_name_input.lower():
            selected_tests.append(case)

    if not selected_tests:
        print(f"[!] No test cases found for packer: '{packer_name_input}'")
        return []

    # Per-test-case stats collected for the final report (used in 'all' mode).
    report_rows = []

    tqdm.write(f"[*] Found {len(selected_tests)} test cases for '{packer_name_input}'")

    # Get packer-specific settings
    settings = get_packer_settings(packer_name_input)

    # Only start dialog killer if needed
    stop_event = None
    killer_thread = None
    if settings["use_dialog_killer"]:
        stop_event = threading.Event()
        killer_thread = threading.Thread(
            target=dialog_killer, args=(stop_event,), daemon=True
        )
        killer_thread.start()

    try:
        case_bar = tqdm(
            selected_tests,
            total=len(selected_tests),
            unit="case",
            desc=f"[{packer_name_input}] Test cases",
            position=1,
            leave=False,
        )
        for test_case in case_bar:
            test_id = test_case["id"]
            case_bar.set_postfix_str(test_id)

            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, ".."))
            raw_bin_path = test_case["binary_path"]
            if raw_bin_path.startswith("./"):
                raw_bin_path = raw_bin_path[2:]
            packer_bin = os.path.join(project_root, raw_bin_path)

            if not os.path.exists(packer_bin):
                tqdm.write(f"    [!] Error: Packer binary not found at: {packer_bin}")
                report_rows.append(
                    {
                        "packer": packer_name_input,
                        "test_id": test_id,
                        "packed": 0,
                        "skipped": 0,
                        "failed": 0,
                        "total": 0,
                        "note": "packer binary not found",
                    }
                )
                continue

            # Include version in directory name (e.g., upx_5.1.0/TEST_ID)
            version = packer_def.get("version", "unknown")
            # Sanitize version for filesystem (replace spaces, parens, etc.)
            safe_version = re.sub(r'[^\w\.\-]', '_', version).strip('_')
            packer_dir_name = f"{packer_name_input}_{safe_version}"
            output_dir = os.path.join(PACKED_OUTPUT_DIR, packer_dir_name, test_id)
            os.makedirs(output_dir, exist_ok=True)

            targets = get_targets(test_case.get("supported_input_arch", "PE32"))
            if not targets:
                tqdm.write(
                    f"    [!] No targets found for case {test_id} (Checking x86 only)"
                )
                report_rows.append(
                    {
                        "packer": packer_name_input,
                        "test_id": test_id,
                        "packed": 0,
                        "skipped": 0,
                        "failed": 0,
                        "total": 0,
                        "note": "no x86 targets",
                    }
                )
                continue

            # Prime the SHA gate with the input batch BEFORE submitting any
            # jobs so an output cannot equal an input that hasn't been
            # packed yet. Repeated calls are no-ops on duplicates.
            if sha_gate is not None:
                sha_gate.prime_inputs(targets)

            # Get the behavior from the definition (defaults to explicit)
            output_behavior = packer_def.get("output_behavior", "explicit")
            dependencies = packer_def.get("dependencies", [])

            # Resolve project_file if present. Prefer the test case's own
            # project_file (lets different test cases drive different project
            # profiles, e.g. Obsidium short vs long .opf), falling back to the
            # packer definition's default.
            raw_project = test_case.get("project_file") or packer_def.get("project_file", "")
            if raw_project:
                if raw_project.startswith("./"):
                    raw_project = raw_project[2:]
                project_file_path = os.path.join(project_root, raw_project)
            else:
                project_file_path = ""

            vlog(f"\n--- Case: {test_id} (Workers: {workers}) ---")

            jobs = []
            for src in targets:
                jobs.append(
                    (
                        src,
                        output_dir,
                        packer_bin,
                        test_case["cli_template"],
                        max_size_kb,
                        settings["timeout"],
                        output_behavior,
                        dependencies,
                        config,
                        project_file_path,
                        packer_name_input,
                        sha_gate,
                        packer_dir_name,
                    )
                )

            success_count = 0
            skipped_count = 0
            failed_count = 0

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    future_to_file = {
                        executor.submit(pack_single_file, job): job[0] for job in jobs
                    }

                    with tqdm(
                        total=len(jobs),
                        unit="file",
                        desc=f"  └─ Packing [{test_id}]",
                        position=2,
                        leave=False,
                    ) as pbar:
                        for future in concurrent.futures.as_completed(future_to_file):
                            fname = os.path.basename(future_to_file[future])
                            try:
                                success, msg = future.result()
                                if success:
                                    success_count += 1
                                elif msg.startswith("Skipped") or msg == "Cancelled":
                                    skipped_count += 1
                                    vlog(f"[~] {fname}: {msg}")
                                else:
                                    failed_count += 1
                                    tqdm.write(f"[-] {fname}: {msg}")
                            except Exception as exc:
                                failed_count += 1
                                tqdm.write(f"[x] Exception processing {fname}: {exc}")

                            pbar.update(1)
            except KeyboardInterrupt:
                _cancel_event.set()
                tqdm.write("\n[!] Interrupted — cancelling remaining jobs...")
                raise

            tqdm.write(f"    Result: {success_count}/{len(targets)} packed.")

            report_rows.append(
                {
                    "packer": packer_name_input,
                    "test_id": test_id,
                    "packed": success_count,
                    "skipped": skipped_count,
                    "failed": failed_count,
                    "total": len(targets),
                    "note": "",
                }
            )

            # Clean up _temp_build directory
            temp_build_dir = os.path.join(output_dir, "_temp_build")
            if os.path.exists(temp_build_dir):
                try:
                    shutil.rmtree(temp_build_dir)
                except Exception as e:
                    tqdm.write(f"    [!] Warning: Could not remove temp dir: {e}")

        case_bar.close()

    finally:
        if stop_event:
            stop_event.set()

        if killer_thread:
            killer_thread.join(timeout=1)

    return report_rows


def print_final_report(rows):
    """Print an aggregated summary after an 'all' run and write it to a file.

    The report is written to packed_sources/packing_report.txt and overwritten
    on every run.
    """
    executed = [r for r in rows if not r.get("note")]
    not_run = [r for r in rows if r.get("note")]

    lines = []
    lines.append("=" * 72)
    lines.append("FINAL PACKING REPORT")
    lines.append("=" * 72)

    if not executed and not not_run:
        lines.append("No CLI packing was performed (no matching test cases ran).")
        lines.append("=" * 72)
    else:
        if executed:
            name_w = max(max(len(r["packer"]) for r in executed), len("Packer"))
            case_w = max(max(len(r["test_id"]) for r in executed), len("Test Case"))

            header = (
                f"{'Packer':<{name_w}}  {'Test Case':<{case_w}}  "
                f"{'Packed':>6}  {'Skipped':>7}  {'Failed':>6}  {'Total':>6}"
            )
            lines.append(header)
            lines.append("-" * len(header))

            tot_packed = tot_skipped = tot_failed = tot_total = 0
            for r in executed:
                lines.append(
                    f"{r['packer']:<{name_w}}  {r['test_id']:<{case_w}}  "
                    f"{r['packed']:>6}  {r['skipped']:>7}  {r['failed']:>6}  {r['total']:>6}"
                )
                tot_packed += r["packed"]
                tot_skipped += r["skipped"]
                tot_failed += r["failed"]
                tot_total += r["total"]

            lines.append("-" * len(header))
            lines.append(
                f"{'TOTALS':<{name_w}}  {'':<{case_w}}  "
                f"{tot_packed:>6}  {tot_skipped:>7}  {tot_failed:>6}  {tot_total:>6}"
            )

            # Surface packers/cases that produced nothing new but had failures.
            problem_cases = [r for r in executed if r["failed"] > 0 and r["packed"] == 0]
            if problem_cases:
                lines.append("")
                lines.append("[!] Test cases that packed 0 files and had failures:")
                for r in problem_cases:
                    lines.append(
                        f"    - {r['packer']} / {r['test_id']}: "
                        f"{r['failed']} failed of {r['total']}"
                    )
        else:
            lines.append("No test cases produced output.")

        # Cases that never ran (missing binary, no x86 targets, etc.).
        if not_run:
            lines.append("")
            lines.append(f"[i] Cases not run ({len(not_run)}):")
            for r in not_run:
                lines.append(
                    f"    - {r['packer']} / {r['test_id']}: {r['note']}"
                )

        lines.append("=" * 72)

    report_text = "\n".join(lines)
    print("\n" + report_text)

    # Persist to packed_sources, overwriting any previous report.
    try:
        os.makedirs(PACKED_OUTPUT_DIR, exist_ok=True)
        report_path = os.path.join(PACKED_OUTPUT_DIR, "packing_report.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text + "\n")
        print(f"\n[*] Report written to: {os.path.abspath(report_path)}")
    except Exception as e:
        print(f"[!] Warning: could not write report file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded packer runner.")
    parser.add_argument(
        "packer_names",
        nargs="*",
        default=["all"],
        metavar="PACKER",
        help="One or more packer names (e.g. 'upx_v5.1.0 amber_v3.0 hxor_packer'), "
        "or 'all'. Defaults to 'all' when omitted.",
    )
    parser.add_argument(
        "--max-size-kb", type=int, default=0, help="Skip files larger than KB."
    )
    # Use ~80% of available cores by default so packing parallelizes while
    # leaving headroom for the OS and the dialog-killer thread.
    default_workers = max(int(cpu_count() * 0.8), 1)
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of parallel threads (default: {default_workers})",
    )
    parser.add_argument(
        "--wsl-workers",
        type=int,
        default=None,
        help="Override the per-packer WSL worker count (e.g. PEzor; default 4). "
        "Caps at the per-packer max_workers ceiling. Has no effect on packers "
        "that don't define a wsl_workers setting.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run pack verification after packing to delete unverified samples.",
    )
    parser.add_argument(
        "--verify-dry-run",
        action="store_true",
        help="Run pack verification in dry-run mode (report only, no deletes).",
    )
    parser.add_argument(
        "--sha-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reject SHA pass-throughs and cross-packer duplicate outputs "
             "(default: enabled; use --no-sha-gate for legacy/debug runs).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print everything. Without it: only progress bars, failures, "
        "the active packer, and its test cases.",
    )

    args = parser.parse_args()
    VERBOSE = args.verbose
    main_config = load_yaml(YAML_CONFIG_FILE)

    all_defs = main_config.get("definitions", [])

    # Resolve the requested packer name(s) into a concrete run list. 'all'
    # (alone or mixed in) expands to every defined packer; otherwise we take the
    # names as given, de-duplicating while preserving order and dropping any that
    # don't exist in the manifest (with a warning).
    requested = args.packer_names
    if any(p.lower() == "all" for p in requested):
        packers = sorted({d["packer_name"] for d in all_defs})
        print(f"=== RUNNING ALL PACKERS: {', '.join(packers)} ===")
    else:
        known = {d["packer_name"].lower(): d["packer_name"] for d in all_defs}
        packers = []
        seen = set()
        for p in requested:
            key = p.lower()
            if key in seen:
                continue
            seen.add(key)
            if key not in known:
                print(f"[!] Unknown packer '{p}' - skipping (not in manifest).")
                continue
            packers.append(known[key])
        if not packers:
            print("[!] No valid packers to run. Use 'all' or a name from the manifest.")
            sys.exit(1)
        print(f"=== RUNNING PACKERS: {', '.join(packers)} ===")

    packer_bar = tqdm(
        packers,
        total=len(packers),
        unit="packer",
        desc="Packers completed",
        position=0,
        leave=True,
    )
    # Instantiate the SHA gate once per top-level process so state (input
    # SHAs, published output SHAs) is shared across every packer in an
    # 'all' run. The constructor reconciles the on-disk cache so re-runs
    # do not re-hash the existing ~30k corpus.
    sha_gate = (
        ShaGate(PACKED_OUTPUT_DIR, pipeline="cli", hash_workers=args.workers)
        if args.sha_gate
        else None
    )
    if sha_gate is not None:
        print("[*] SHA gate: ENABLED  (use --no-sha-gate to disable)")
    else:
        print("[!] SHA gate: DISABLED  (pass-throughs and cross-packer "
              "duplicates will be accepted)")

    all_results = []
    for p in packer_bar:
        packer_bar.set_postfix_str(p)
        rows = run_packing(
            p,
            args.max_size_kb,
            main_config,
            args.workers,
            wsl_workers=args.wsl_workers,
            sha_gate=sha_gate,
        )
        all_results.extend(rows or [])
        tqdm.write("=" * 40)
    packer_bar.close()
    print_final_report(all_results)

    # Post-packing verification
    if args.verify or args.verify_dry_run:
        print("\n" + "=" * 50)
        print("POST-PACKING VERIFICATION")
        print("=" * 50)
        from pack_verifier import verify_directory
        packed_dir = os.path.abspath(PACKED_OUTPUT_DIR)
        if os.path.exists(packed_dir):
            verify_directory(packed_dir, dry_run=args.verify_dry_run)
        else:
            print(f"[!] No packed output directory found at: {packed_dir}")
