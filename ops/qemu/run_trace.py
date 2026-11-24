#!/usr/bin/env python3
"""Run one disposable two-vCPU QEMU trace and write auditable metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm_profiles  # noqa: E402


def final_summary(trace: Path) -> dict | None:
    if not trace.exists():
        return None
    result = None
    with trace.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "summary":
                result = event
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# The paper stops recording after two minutes with no newly executed code (the
# unpacking layers have settled / the payload is idle or blocked).  The launcher
# normally emits that boundary itself, but under heavy TCG instrumentation the
# guest's timer interrupts starve and every GUEST clock (GetTickCount64 etc.)
# nearly freezes once execution goes idle — so the guest can neither time out nor
# detect its own idleness.  We therefore ALSO observe the identical rule in HOST
# real time: strictly zero new exec AND write events for a full two minutes after
# sample_start.  Zero activity (not merely slow) distinguishes a settled sample
# from one still crawling through unpacking, so this cannot truncate an unpack.
HOST_IDLE_SECONDS = 120

# Guest vCPU count.  Pinned in the backend identity: icount requires
# thread=single, so this changes how guest threads interleave and therefore what
# a packer's timing and synchronisation observe.
GUEST_SMP = "2"

# Sentinel distinguishing "the stamp does not carry this key" from "the stamp
# carries it with value None".  A stamp predating the tracing-parameter pin has
# no icount_shift at all, and must not be treated as attesting to one.
_UNSET = object()
NO_START_SECONDS = 600
_ACTIVITY_MARKERS = (b'"event":"exec"', b'"event":"write"')
_READ_OVERLAP = 64
_SCAN_BUFFER = bytearray(8 * 1024 * 1024)


def _activity_and_started(trace: Path, offset: int) -> tuple[int, int, int, bool, bool]:
    """Return (any_new_activity, any_new_writes, new_offset, saw_sample_start, saw_stop).

    Reads from _READ_OVERLAP bytes before `offset` so a marker split across two
    polls by a partial stdio flush is still matched; counts are taken only in the
    strictly-new bytes to avoid double counting the overlap region.  new_writes is
    counted separately so a continuous VM that has finished unpacking (still
    executing, no longer writing) can be recognised as settled.
    """
    if not trace.exists():
        return 0, 0, offset, False, False
    seek_to = max(0, offset - _READ_OVERLAP)
    activity = writes = 0
    started = stopped = False
    view = memoryview(_SCAN_BUFFER)
    with trace.open("rb", buffering=0) as handle:
        handle.seek(seek_to)
        position = seek_to
        carry = b""
        while True:
            count = handle.readinto(_SCAN_BUFFER)
            if not count:
                break
            chunk = carry + bytes(view[:count])
            chunk_start = position - len(carry)
            position += count
            fresh = chunk[max(0, offset - chunk_start):]
            if not activity and any(marker in fresh for marker in _ACTIVITY_MARKERS):
                activity = 1
            if not writes and b'"event":"write"' in fresh:
                writes = 1
            if not started and b'"event":"sample_start"' in chunk:
                started = True
            if not stopped and b'"action":3' in chunk:
                stopped = True
            carry = chunk[-_READ_OVERLAP:]
        new_offset = position
    return activity, writes, new_offset, started, stopped


def _graceful_quit(monitor: Path | None, runas: str | None) -> bool:
    """Ask QEMU to exit via its monitor so the plugin FLUSHES ITS SUMMARY.

    process.terminate() signals the OUTERMOST process, which under --runas is `sudo`
    (and then bwrap). The signal does not reliably reach QEMU through that chain, so
    the plugin never writes its summary block: meta.summary comes back all-None and
    the run is scored UNRESOLVED_TRACE_LOSS even though the sample ran to a clean
    idle boundary. The packer corpus never hit this because it ran without --runas,
    where terminate() reached QEMU directly (565/609 of those runs were eligible).

    An HMP `quit` shuts QEMU down through its normal exit path, which runs the
    plugin's atexit flush. Falls back to signals if the monitor is unreachable.
    """
    if monitor is None or not monitor.exists():
        return False
    script = (
        "import socket, sys, time\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.settimeout(5)\n"
        "s.connect(sys.argv[1])\n"
        "time.sleep(0.5)\n"
        "try:\n"
        "    s.recv(65536)\n"
        "except Exception:\n"
        "    pass\n"
        "s.sendall(b'quit\\n')\n"
        "time.sleep(1)\n"
    )
    argv = ["python3", "-c", script, str(monitor.resolve())]
    if runas:
        argv = ["sudo", "-n", "-u", runas] + argv
    try:
        return subprocess.run(argv, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30).returncode == 0
    except Exception:
        return False


def wait_or_host_idle(
    process, trace: Path, host_timeout: int, host_idle_seconds: int = HOST_IDLE_SECONDS,
    no_start_seconds: int = NO_START_SECONDS, write_settled_seconds: int = 0,
    monitor_path: Path | None = None, runas_user: str | None = None,
    stop_grace_seconds: int = 180, guest_completion: bool = False,
) -> tuple[int | None, bool, bool, bool, bool]:
    """Wait for qemu, terminating early on the host-observed idle boundary.

    Returns (return_code, host_timed_out, host_observed_idle, never_started,
    write_settled).  host_observed_idle is set only when sample_start was seen AND
    activity strictly ceased for host_idle_seconds — the paper's completion boundary
    measured in host time.  never_started is set when sample_start was NEVER seen
    within no_start_seconds.  write_settled is set when writes (but not necessarily
    execution) ceased for write_settled_seconds after sample_start — a continuous VM
    interpreter that has finished unpacking keeps executing forever yet stops
    writing, so it never trips host_observed_idle and would otherwise burn the full
    host timeout with a runaway trace.  write_settled_seconds <= 0 DISABLES this
    boundary (the default), preserving the exact prior completion semantics.

    host_idle_seconds <= 0 DISABLES the host-idle, no-start, and write-settled
    boundaries: the run then ends only on the guest's own clean completion (the
    certification fixture's ExitProcess -> launcher stop marker) or the host
    timeout.  Use that for the fixture cert.
    """
    started_at = time.monotonic()
    offset = 0
    sample_started = False
    last_activity_at = started_at
    last_write_at = started_at
    stop_seen_at: float | None = None
    poll = 1.0
    while True:
        try:
            return_code = process.wait(timeout=poll)
            return return_code, False, False, False, False  # guest ended on its own
        except subprocess.TimeoutExpired:
            pass
        now = time.monotonic()
        activity, writes, offset, saw_start, saw_stop = _activity_and_started(
            trace, offset)
        if saw_start:
            sample_started = True
        if saw_stop and stop_seen_at is None:
            stop_seen_at = now
        if activity > 0:
            last_activity_at = now
        if writes > 0:
            last_write_at = now
        # The guest emitted the launcher's stop marker: the trace is COMPLETE.
        # Windows' own shutdown never finishes under this instrumentation, so
        # waiting for the power-off burns the whole host timeout (1.5-2.5 h per
        # certification) for no additional evidence.  Quit once the marker has been
        # seen and the trace has been quiet for the grace window.
        if (
            stop_grace_seconds > 0
            and stop_seen_at is not None
            and now - stop_seen_at >= stop_grace_seconds
            and now - last_activity_at >= stop_grace_seconds
        ):
            _graceful_quit(monitor_path, runas_user)
            process.terminate()
            try:
                return process.wait(timeout=60), False, False, False, False
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(), False, False, False, False
        if now - started_at >= host_timeout:
            _graceful_quit(monitor_path, runas_user)
            process.terminate()
            try:
                return process.wait(timeout=60), True, False, False, False
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(), True, False, False, False
        if (
            (host_idle_seconds > 0 or guest_completion)
            and not sample_started
            and no_start_seconds > 0
            and now - started_at >= no_start_seconds
        ):
            _graceful_quit(monitor_path, runas_user)
            process.terminate()
            try:
                return process.wait(timeout=60), False, False, True, False
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(), False, False, True, False
        if (
            host_idle_seconds > 0
            and not guest_completion
            and sample_started
            and now - last_activity_at >= host_idle_seconds
        ):
            _graceful_quit(monitor_path, runas_user)
            process.terminate()
            try:
                return process.wait(timeout=60), False, True, False, False
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(), False, True, False, False
        if (
            host_idle_seconds > 0
            and not guest_completion
            and write_settled_seconds > 0
            and sample_started
            and now - last_write_at >= write_settled_seconds
        ):
            _graceful_quit(monitor_path, runas_user)
            process.terminate()
            try:
                return process.wait(timeout=60), False, False, False, True
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(), False, False, False, True



def identity_mismatches(current: dict, stamped: dict, profile: str) -> list[str]:
    mismatches = [key for key, value in current.items()
                  if stamped.get(key, _UNSET) != value]
    if stamped.get("profile", vm_profiles.CERTIFIED) != profile and "profile" not in mismatches:
        mismatches.append("profile")
    return mismatches


def _monitor_command(monitor: Path, commands: list[str], runas: str | None,
                     connect_timeout: float = 60.0,
                     process: subprocess.Popen | None = None) -> int:
    """Send HMP commands to a running QEMU, as the account that owns the socket.

    Needed for the resume path. `-incoming` restores the guest but leaves it PAUSED,
    and the delivery medium must be swapped in AFTER resume: a `-drive ...media=cdrom`
    given at startup is overridden when migration restores the drive's saved state,
    which still references whatever medium was present at capture time (measured:
    ide1-cd0 with zero read operations). Changing the medium via the monitor after
    resume IS honoured, so the order is: wait for socket -> change -> cont.
    """
    script = (
        "import socket, sys, time\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "for attempt in range(100):\n"
        "    try:\n"
        "        s.connect(sys.argv[1])\n"
        "        break\n"
        "    except OSError:\n"
        "        time.sleep(0.1)\n"
        "else:\n"
        "    sys.exit(4)\n"
        "s.settimeout(5)\n"
        "def prompt():\n"
        "    out = b''\n"
        "    try:\n"
        "        while b'(qemu)' not in out:\n"
        "            chunk = s.recv(65536)\n"
        "            if not chunk:\n"
        "                break\n"
        "            out += chunk\n"
        "    except Exception:\n"
        "        pass\n"
        "    return out.decode(errors='replace')\n"
        "prompt()\n"
        "def ask(cmd):\n"
        "    s.sendall((cmd + '\\n').encode())\n"
        "    return prompt()\n"
        "end = time.monotonic() + 900\n"
        "def settled():\n"
        "    st = ask('info status')\n"
        "    return 'VM status:' in st and 'inmigrate' not in st\n"
        "while not settled():\n"
        "    if time.monotonic() > end:\n"
        "        sys.exit(2)\n"
        "    time.sleep(0.5)\n"
        "def done(cmd):\n"
        "    if cmd.startswith('change '):\n"
        "        path = cmd.split('\"filename\":\"')[-1].split('\"')[0] if 'json:' in cmd else cmd.split()[-1]\n"
        "        return path.rsplit('/', 1)[-1] in ask('info block ide1-cd0')\n"
        "    if cmd == 'cont':\n"
        "        return 'VM status: running' in ask('info status')\n"
        "    return None\n"
        "for cmd in sys.argv[2:]:\n"
        "    for attempt in range(30):\n"
        "        if attempt and done(cmd):\n"
        "            break\n"
        "        ask(cmd)\n"
        "        if done(cmd) is not False:\n"
        "            break\n"
        "        time.sleep(2)\n"
        "    else:\n"
        "        sys.exit(3)\n"
    )
    deadline = time.monotonic() + connect_timeout
    while not monitor.exists():
        if process is not None and process.poll() is not None:
            return 5
        if time.monotonic() > deadline:
            return 1
        time.sleep(0.2)
    argv = ["python3", "-c", script, str(monitor.resolve()), *commands]
    if runas:
        argv = ["sudo", "-n", "-u", runas] + argv
    return subprocess.run(argv, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode


def _backing_chain(base: Path) -> list[Path]:
    out = [base.resolve()]
    try:
        info = subprocess.run(
            ["/usr/bin/qemu-img", "info", "--backing-chain", "--output=json",
             str(base.resolve())],
            capture_output=True, text=True, check=True,
        )
        for node in json.loads(info.stdout):
            fn = node.get("filename")
            if fn:
                out.append(Path(fn).resolve())
    except Exception:
        pass
    seen, chain = set(), []
    for p in out:
        if str(p) not in seen:
            seen.add(str(p))
            chain.append(p)
    return chain


def _bwrap_prefix(qemu: Path, plugin: Path, base: Path, rw_dirs) -> list[str]:
    prefix = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        # QEMU's snapshot=on writes its throwaway overlay under /var/tmp; without
        # this the sandbox has no such directory and the drive fails to open.
        "--tmpfs", "/var/tmp",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind-try", "/etc/localtime", "/etc/localtime",
        "--ro-bind", str(qemu.resolve().parent), str(qemu.resolve().parent),
        "--ro-bind", str(plugin.resolve()), str(plugin.resolve()),
    ]
    # QEMU's firmware (bios-256k.bin, vgabios, ...) lives in the build tree under
    # qemu-bundle/usr/local/share/qemu, but those entries are SYMLINKS into
    # qemu-src/pc-bios. Binding only the build dir therefore exposes dangling links
    # and QEMU dies with "could not load PC BIOS 'bios-256k.bin'". Bind the resolved
    # targets too. (This is why --confine had never actually worked: it was wired to
    # nothing, so the breakage was never exercised.)
    firmware = qemu.resolve().parent / "qemu-bundle/usr/local/share/qemu"
    bound_targets: set[str] = set()
    if firmware.is_dir():
        prefix += ["--ro-bind", str(firmware), str(firmware)]
        for entry in firmware.iterdir():
            try:
                target_dir = str(entry.resolve().parent)
            except OSError:
                continue
            if target_dir not in bound_targets:
                bound_targets.add(target_dir)
                prefix += ["--ro-bind-try", target_dir, target_dir]
    for f in _backing_chain(base):
        prefix += ["--ro-bind", str(f), str(f)]
    seen = set()
    for d in rw_dirs:
        rd = str(Path(d).resolve())
        if rd in seen:
            continue
        seen.add(rd)
        prefix += ["--bind", rd, rd]
    prefix.append("--")
    return prefix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("work", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--meta", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--monitor", type=Path)
    parser.add_argument("--host-timeout", type=int, default=3600)
    parser.add_argument(
        "--host-idle-seconds",
        type=int,
        default=HOST_IDLE_SECONDS,
        help="host-observed idle boundary (paper's 2-min no-execution rule). "
        "<=0 disables it; use 0 for the fixture cert, whose completion is the "
        "guest stop marker, not idle.",
    )
    parser.add_argument(
        "--no-start-seconds",
        type=int,
        default=NO_START_SECONDS,
        help="fast-fail boundary: if sample_start is never observed within this "
        "many host seconds, the sample loaded but never executed -- terminate "
        "instead of burning the full host timeout. <=0 disables it; ignored "
        "entirely when --host-idle-seconds<=0 (fixture cert).",
    )
    parser.add_argument(
        "--transparent", action="store_true",
        help="anti-VM transparency: use a realistic CPU model with -hypervisor to "
        "hide QEMU's CPUID hypervisor bit/vendor leaf and brand string, so anti-VM "
        "packers (telock/yoda/armadillo) do not bail to an evasion path. Off by "
        "default; the certified 91 labels used the default qemu64.",
    )
    parser.add_argument(
        "--cpu-model", dest="cpu_model", default="qemu64",
        help="QEMU -cpu model (default qemu64 = certified). With --transparent a "
        "realistic model like Nehalem/Haswell hides the QEMU brand string.",
    )
    parser.add_argument(
        "--guest-completion",
        action="store_true",
        help="end only on the guest's own boundary (launcher stop marker or the "
        "plugin's instruction budget); host idle and write-settled cut-offs are "
        "off, the no-start check stays, and the host timeout is a safety net.",
    )
    parser.add_argument(
        "--insn-budget",
        type=int,
        default=0,
        help="stop recording once the monitored processes retire this many "
        "instructions (deterministic observation bound). 0 disables it.",
    )
    parser.add_argument(
        "--guest-insn-budget",
        type=int,
        default=0,
        help="stop recording once the whole guest retires this many instructions "
        "after the sample starts (deterministic wall-time bound). 0 disables it.",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="exact-reproducibility mode for a QEMU built with -icount det=on and "
        "the blkdet filter: forces sleep=off, gates virtual timers to the vCPU "
        "thread, drops the realtime deadline from the icount budget, and delivers "
        "every disk and CD completion at a fixed virtual delay after submission.",
    )
    parser.add_argument(
        "--write-settled-seconds",
        type=int,
        default=0,
        help="opt-in completion boundary for continuous VM interpreters: if no "
        "WRITE events occur for this many host seconds after sample_start (even "
        "while execution continues), unpacking has settled -- terminate instead of "
        "burning the full host timeout on a runaway trace. <=0 disables it "
        "(default), preserving the exact prior completion semantics.",
    )
    parser.add_argument(
        "--icount-shift",
        type=int,
        default=2,
        help="TCG icount shift (1 insn = 2^shift virtual ns).  A FIXED LOW shift "
        "decouples guest virtual time from the plugin-slowed host clock so the "
        "guest scheduler tick fires every ~2^-shift*10^9 instructions instead of "
        "every ~1-30k, ending the boot-lottery thread starvation.  shift=2 gives "
        "~250k instructions per 1ms tick.  Do NOT use shift=auto (it reconverges "
        "to real time and reproduces the starvation).  <0 disables icount.",
    )
    parser.add_argument(
        "--icount-sleep",
        choices=("on", "off"),
        default="on",
        help="icount sleep policy.  With sleep=on (the certified default) virtual "
        "time advances at REAL speed while every vCPU is idle, so a guest Sleep(500) "
        "takes as long as the loaded host needs to service the wakeup.  Packers that "
        "time a fixed sleep (hxor's runtimeDelay allows 550ms for a 500ms Sleep) then "
        "detect analysis whenever the host is busy.  sleep=off warps virtual time "
        "straight to the next timer deadline, so a guest sleep costs its nominal "
        "virtual duration regardless of host load.  sleep=off is a DIFFERENT backend "
        "identity and must not be mixed with certified sleep=on results.",
    )
    parser.add_argument(
        "--guest-memory",
        default="3G",
        help="fixed guest RAM allocation, e.g. 2G/2560M/3G (default 3G). On this "
        "3.8 GiB host, 3G risks boot-time swap thrash and 2G has shown a "
        "kernel-discovery boot quirk; 2560M is the reliable middle ground.",
    )
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument(
        "--delivery-disk", type=Path, default=None,
        help="attach this raw image as a second drive. Used with --loadvm: a savevm "
        "snapshot has a DIRTY NTFS volume that the host cannot mount read-write, so "
        "the sample cannot be written into the snapshot. A separate clean FAT16 disk "
        "sidesteps that -- nothing in the snapshot is modified.",
    )
    parser.add_argument(
        "--incoming", type=Path, default=None, metavar="MIGSTATE",
        help="resume RAM state from this external QEMU migration file. Preferred "
        "over --loadvm: it works with the per-run overlay the harness relies on for "
        "isolation, whereas a qcow2 internal snapshot is only visible in the file "
        "that physically holds it. Must be resumed at the SAME -m size it was "
        "captured with.",
    )
    parser.add_argument(
        "--loadvm", default=None, metavar="NAME",
        help="resume from a named qcow2 VM snapshot instead of cold-booting. Windows "
        "boot is ~300 s solo and 400-900+ s under contention, and it is paid on EVERY "
        "trace -- it dominates a large campaign and starves itself at high "
        "concurrency. Resuming a pre-booted guest removes that cost entirely. The "
        "launcher reads a FIXED path (C:\\Panda\\sample.exe), so one snapshot "
        "serves every sample: swap the file, not the path. No guest_launcher rebuild, "
        "so the certified launcher_sha256 is unaffected.",
    )
    parser.add_argument(
        "--plugin-arg", dest="plugin_args", action="append", default=[],
        metavar="KEY=VALUE",
        help="extra option appended to the -plugin argument (repeatable), e.g. "
        "--plugin-arg pf_loop=on for paper_trace_pf.so's page-fault-loop events. "
        "The plugin rejects unknown options, so a typo fails loudly.",
    )
    parser.add_argument("--validation-stamp", type=Path)
    parser.add_argument(
        "--profile", choices=vm_profiles.PROFILES, default=vm_profiles.CERTIFIED,
        help="analysis profile (ops/qemu/vm_profiles.py). certified (default) is the "
        "certified lane's exact command line; vmarm is the anti-VM-hardened arm with "
        "its own machine identity, boot snapshot and validation stamp.",
    )
    parser.add_argument("--guest-smp", default=GUEST_SMP)
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="opt-in QEMU seccomp sandbox for untrusted (malware) samples: adds "
        "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,"
        "resourcecontrol=deny. Off by default; the benign sweep does not set it.",
    )
    parser.add_argument(
        "--runas",
        default=None,
        help="opt-in: run the QEMU process as this unprivileged user (-runas). Off "
        "by default. Use for malware runs so an escape does not run as the caller.",
    )
    parser.add_argument(
        "--confine",
        action="store_true",
        help="opt-in: wrap QEMU in a bubblewrap sandbox (FS + network + user "
        "namespace isolation) for untrusted (malware) samples. Exposes only the "
        "run dir, the base image, qemu, and the plugin; hides the repo/.env/home; "
        "no network. Off by default; does not touch the certified qemu binary.",
    )
    args = parser.parse_args()
    if args.profile != vm_profiles.CERTIFIED and (args.transparent
                                                  or args.cpu_model != "qemu64"):
        parser.error("--transparent/--cpu-model are certified-profile knobs; the "
                     f"{args.profile} profile fixes its own CPU")
    if args.deterministic:
        args.icount_sleep = "off"

    repo = Path(__file__).resolve().parents[2]
    qemu = args.qemu or (
        repo / "empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"
    )
    plugin = args.plugin or repo / "ops/qemu/paper_trace.so"
    validation_stamp = args.validation_stamp or vm_profiles.default_stamp(
        args.profile, repo)
    ntdll = repo / "empirical_results/qemu_runtime/ntdll.dll"
    qemu_img = Path("/usr/bin/qemu-img")
    meta = args.meta or args.trace.with_suffix(".meta.json")
    log = args.log or args.trace.with_suffix(".qemu.log")
    monitor = args.monitor or args.trace.with_suffix(".monitor.sock")
    for required in (args.base, qemu, plugin, qemu_img, ntdll):
        if not required.exists():
            parser.error(f"required path does not exist: {required}")
    if args.work.exists():
        parser.error(f"refusing to reuse analysis overlay: {args.work}")
    if monitor.exists():
        parser.error(f"refusing to reuse monitor socket: {monitor}")

    args.work.parent.mkdir(parents=True, exist_ok=True)
    args.trace.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(qemu_img), "check", str(args.base)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            str(qemu_img),
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(args.base.resolve()),
            str(args.work),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if args.runas:
        # The overlay, trace and log are created HERE (as the caller) but written by
        # QEMU running as args.runas. Without this the guest dies instantly with
        # "Could not open ...work.qcow2: Permission denied". Widen only these
        # per-run artifacts, never the base image, which stays read-only.
        try:
            args.work.chmod(0o666)
            # Only the files QEMU itself writes need pre-creating. meta.json is
            # written by THIS process at the end, so touching it here leaves a
            # zero-byte file for the whole run that readers mistake for "finished"
            # (it silently broke a completion poller). Leave it alone.
            for extra in (args.trace, args.log):
                if extra is not None:
                    extra.parent.mkdir(parents=True, exist_ok=True)
                    extra.touch(exist_ok=True)
                    extra.chmod(0o666)
        except OSError as exc:
            parser.error(f"--runas set but cannot make run artifacts writable: {exc}")

    hardening: list[str] = []
    if args.sandbox:
        hardening += [
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
    # NOTE: QEMU's own -runas is NOT used. This build rejects it outright
    # ("-runas: invalid option"), and -sandbox is likewise not compiled in. The drop
    # is therefore done on the HOST side by prefixing `sudo -n -u <user>` below, so
    # an exploited QEMU lands as an unprivileged service account instead of as the
    # operator. Rebuilding QEMU to regain -runas/-sandbox would change the pinned
    # backend identity and invalidate the existing labels.

    command = [
        str(qemu),
        "-name",
        "paper-trace",
        *hardening,
        "-machine",
        vm_profiles.machine_arg(args.profile),
        "-accel",
        "tcg,thread=single",
        "-cpu",
        # transparency: a realistic Intel model + -hypervisor clears the CPUID
        # hypervisor-present bit (leaf 1 ECX[31]) and the 0x40000000 vendor leaf, and
        # replaces the "QEMU Virtual CPU" brand string that anti-VM packers detect.
        # Default keeps the certified qemu64 so labeled results are unaffected.
        vm_profiles.cpu_arg(args.profile, args.cpu_model, args.transparent),
        "-m",
        args.guest_memory,
        "-smp",
        str(args.guest_smp),
        # icount: fixed-shift instruction-counted virtual clock so the guest
        # scheduler tick fires at a sane instructions-per-tick ratio despite the
        # plugin slowdown (ends the boot-lottery thread starvation).  Keeps
        # thread=single (icount forbids MTTCG); rr splits the budget across vCPUs.
        # clock=vm ties the CMOS/RTC to virtual time to match.
        *(
            ["-icount", f"shift={args.icount_shift},sleep={args.icount_sleep}"
             + (",det=on" if args.deterministic else "")]
            if args.icount_shift >= 0
            else []
        ),
        *vm_profiles.smbios_args(args.profile),
        "-rtc",
        vm_profiles.rtc_arg(args.profile, args.icount_shift >= 0),
        "-display",
        "none",
        "-monitor",
        f"unix:{monitor.resolve()},server=on,wait=off",
        "-serial",
        "none",
        "-parallel",
        "none",
        "-net",
        "none",
        "-no-reboot",
        *vm_profiles.disk_args(args.profile, args.work, args.deterministic),
        "-plugin",
        ",".join([f"{plugin.resolve()},out={args.trace.resolve()}",
                  *([f"insn_budget={args.insn_budget}"]
                    if args.insn_budget > 0 else []),
                  *([f"guest_insn_budget={args.guest_insn_budget}"]
                    if args.guest_insn_budget > 0 else []),
                  *vm_profiles.plugin_args(args.profile),
                  *args.plugin_args]),
    ]
    if args.profile != vm_profiles.CERTIFIED:
        command += vm_profiles.cdrom_args(
            args.profile,
            args.delivery_disk.resolve() if args.delivery_disk else None)
    elif args.delivery_disk:
        # Second IDE drive; the guest picks it up as the next available volume.
        # snapshot=on sends this device's writes to a throwaway temp overlay, so it
        # is writable from QEMU's point of view (loadvm needs that -- a plain
        # readonly=on drive fails with "Block node is read-only") while never
        # participating in the saved VM state and never modifying the host file.
        # Without it: "Device 'ide0-hd1' is writable but does not support snapshots".
        # index=2 puts this at ide1-cd0 -- master on the SECONDARY IDE channel, the
        # conventional CD position this Windows image enumerated at install time and
        # holds a drive letter for. Without it QEMU picks the next free slot on the
        # PRIMARY channel (measured: ide0-cd1), which Windows does not surface as a
        # lettered drive, while QEMU's own default EMPTY ide1-cd0 stays inserted --
        # so a monitor `change ide1-cd0` targets the empty default, not this ISO.
        # CD-ROM, not a hard disk. A guest resumed from saved RAM only has the
        # devices present at capture time, so a fixed IDE disk attached at resume is
        # invisible to Windows (measured: 0 read ops vs 7416 on the boot disk). A
        # media change on the already-enumerated CD drive IS honoured across resume
        # (measured: 23 read ops). readonly is implied by media=cdrom.
        command += vm_profiles.cdrom_args(args.profile, args.delivery_disk.resolve())
    if args.incoming:
        # RAM state comes from an EXTERNAL migration file, not a qcow2 internal
        # snapshot. Internal snapshots live only in the file that holds them and are
        # invisible through a backing chain, so `-loadvm` could never find one from
        # the fresh per-run overlay the harness boots ("Snapshot 'booted' does not
        # exist in one or more devices"). Splitting RAM state (shared, read-only
        # file) from disk state (cheap per-run overlay) satisfies both requirements:
        # every run resumes the same booted guest, and no run can touch the base.
        # The state was captured at -m 4G; resuming at any other size fails.
        command += ["-S", "-incoming", f"exec:cat {Path(args.incoming).resolve()}"]
    elif args.loadvm:
        command += ["-loadvm", args.loadvm]
    if args.confine:
        rw_dirs = [p.parent for p in (args.work, args.trace, args.meta, args.log,
                                      args.monitor, args.delivery_disk)
                   if p is not None]
        prefix = _bwrap_prefix(qemu, plugin, args.base, rw_dirs)
        if args.incoming:
            incoming = str(Path(args.incoming).resolve())
            prefix[1:1] = ["--ro-bind", incoming, incoming]
        command = prefix + command
    if args.runas:
        # Outermost wrapper: drop to the service account BEFORE bwrap, so the whole
        # confined subtree (bwrap included) runs unprivileged. Requires a sudoers
        # rule permitting this without a password; -n makes a missing rule fail
        # loudly rather than hang on a prompt.
        command = ["sudo", "-n", "-u", args.runas] + (
            ["env", f"DET_DEBUG_LOG={args.trace.parent.resolve() / 'detdebug.log'}"]
            if os.environ.get("DET_DEBUG") == "1" else []) + command
    started = time.monotonic()
    with log.open("wb") as log_handle:
        process = subprocess.Popen(command, stdout=log_handle, stderr=log_handle)
        if args.incoming:
            # Order matters: insert the medium BEFORE releasing the vCPUs, so the
            # launcher's very first poll after resume already sees the sample.
            post: list[str] = []
            if args.delivery_disk:
                if args.deterministic:
                    medium = json.dumps({
                        "driver": "blkdet",
                        "image": {"driver": "raw", "file": {
                            "driver": "file",
                            "filename": str(args.delivery_disk.resolve())}},
                    }, separators=(",", ":"))
                    post.append(f"change ide1-cd0 json:{medium}")
                else:
                    post.append(f"change ide1-cd0 {args.delivery_disk.resolve()}")
            post.append("cont")
            resume_rc = _monitor_command(monitor, post, args.runas,
                                         connect_timeout=300.0, process=process)
            if resume_rc != 0:
                exited_early = process.poll()
                _graceful_quit(monitor, args.runas)
                process.terminate()
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                meta.write_text(json.dumps({
                    "paper_termination_reason": "monitor_resume_failed",
                    "monitor_rc": resume_rc,
                    "monitor_socket_seen": monitor.exists(),
                    "qemu_exited_before_quit": exited_early,
                    "qemu_return_code": process.returncode,
                    "qemu_log_tail": log.read_bytes()[-4000:].decode(errors="replace"),
                    "elapsed_seconds": time.monotonic() - started,
                }))
                raise SystemExit(f"run_trace: monitor resume failed rc={resume_rc}")
        return_code, host_timed_out, host_observed_idle, never_started, write_settled = (
            wait_or_host_idle(
                process, args.trace, args.host_timeout, args.host_idle_seconds,
                args.no_start_seconds, args.write_settled_seconds,
                monitor_path=monitor, runas_user=args.runas,
                guest_completion=args.guest_completion,
                stop_grace_seconds=2 if args.deterministic else 180,
            )
        )
    elapsed = time.monotonic() - started
    summary = final_summary(args.trace)
    implemented_channels = {
        "basic_block_execution": True,
        "successful_memory_writes": True,
        "remote_process_writes": True,
        "shared_sections": True,
        "synchronous_disk_io": True,
        "asynchronous_disk_io": False,
        "memory_mapped_files": True,
        "unmap_and_free": True,
    }
    trace_integrity = {
        "root_marker": bool(summary and summary.get("root_pid")),
        "stop_marker": bool(summary and summary.get("saw_stop")),
        "executed_blocks": bool(summary and summary.get("exec_events", 0) > 0),
        "writes": bool(summary and summary.get("write_events", 0) > 0),
        "context": bool(summary and summary.get("context_failures") == 0),
        "block_context": bool(
            summary and summary.get("block_context_misses") == 0
        ),
        "process_snapshot": bool(
            summary and summary.get("process_snapshot_failures") == 0
        ),
        "virtual_memory_writes": bool(
            summary
            and summary.get("kernel_store_callbacks_registered") is False
            and summary.get("virtual_memory_write_failures") == 0
        ),
        "physical_mapping": bool(
            summary and summary.get("physical_mapping_failures") == 0
        ),
        "marker_registers": bool(
            summary
            and summary.get("marker_register_failures") == 0
            and summary.get("marker_query_failures") == 0
        ),
        "file_io": bool(
            summary
            and summary.get("file_io_failures") == 0
            and summary.get("asynchronous_file_io") == 0
        ),
        "mapped_files": bool(
            summary
            and summary.get("mapped_file_failures") == 0
            and summary.get("system_role_failures") == 0
        ),
        "unmap_and_free": bool(
            summary
            and summary.get("invalidation_failures") == 0
            and summary.get("unresolved_process_handles") == 0
        ),
    }
    backend_validation = None
    if validation_stamp.is_file():
        try:
            backend_validation = json.loads(
                validation_stamp.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, OSError):
            backend_validation = None
    # The identity pins the BINARIES and the TRACING PARAMETERS.  Binaries alone are
    # not enough: hxor_packer only unpacks at icount shift=0, because at shift=2 the
    # extra virtual-ns per instruction pushes its Sleep(500)/GetTickCount check past
    # its own 550ms allowance and it takes the evasion path.  A shift=0 result is
    # therefore a materially different measurement from the shift=2 results the rest
    # of the corpus was labelled under, and before this the stamp could not tell them
    # apart -- the shift was an environment variable invisible to certification.
    #
    # Parameters that change what the guest experiences are pinned.  Parameters that
    # only bound how long we watch (host timeout, host idle) are NOT: they can
    # truncate a recording, which the completion boundary already reports, but they
    # do not alter the guest's behaviour.
    current_identity = {
        "qemu_sha256": sha256(qemu),
        "plugin_sha256": sha256(plugin),
        "profile_header_sha256": sha256(repo / "ops/qemu/win10_profile.h"),
        "ntdll_sha256": sha256(ntdll),
        "icount_shift": args.icount_shift,
        "icount_sleep": args.icount_sleep if args.icount_shift >= 0 else None,
        "cpu_model": vm_profiles.cpu_arg(args.profile, args.cpu_model,
                                         args.transparent),
        "guest_smp": str(args.guest_smp),
        "deterministic": bool(args.deterministic),
        **vm_profiles.identity_fields(args.profile),
    }
    stamped_identity = (
        backend_validation.get("backend_identity", {})
        if isinstance(backend_validation, dict)
        else {}
    )
    # A stamp written before tracing parameters were pinned carries none of them.
    # Treat a missing key as "not attested" rather than as a match, so an old stamp
    # cannot silently vouch for a configuration it never saw.
    mismatches = identity_mismatches(current_identity, stamped_identity, args.profile)
    backend_validation_complete = bool(
        backend_validation
        and backend_validation.get("validated") is True
        and not mismatches
    )
    stop_detail = int(summary.get("stop_detail", 0)) if summary else 0
    saw_stop = bool(summary and summary.get("saw_stop"))
    guest_timed_out = bool(stop_detail & 0x80000000)
    guest_idle = bool(stop_detail & 0x40000000)
    guest_query_failed = bool(stop_detail & 0x20000000)
    guest_unrecovered_exception = bool(stop_detail & 0x10000000)
    instruction_budget_reached = bool(stop_detail & 0x08000000)
    guest_budget_reached = bool(
        instruction_budget_reached and args.guest_insn_budget > 0
        and int(summary.get("guest_instructions", 0)) >= args.guest_insn_budget
        and not (args.insn_budget > 0
                 and int(summary.get("sample_instructions", 0)) >= args.insn_budget)
    )
    # The host-observed idle boundary is the paper's two-minute no-execution rule
    # measured in host real time (see wait_or_host_idle).  It is a COMPLETE
    # recording of the unpacking — activity strictly ceased — so it is an eligible
    # completion, on equal footing with the guest-emitted stop/idle marker, and is
    # NOT a maximum-timeout truncation.  It only stands in when the guest could not
    # emit its own boundary (timer starvation during the post-unpack crawl).
    completion_observed = bool(
        (summary and summary.get("saw_stop")) or host_observed_idle or write_settled
    )
    metadata = {
        "schema_version": 1,
        "profile": args.profile,
        "backend": "upstream_qemu_tcg_plugin",
        "qemu_revision": "eca2c16212ef9dcb0871de39bb9d1c2efebe76be",
        "kernel_profile_guid_age": (
            summary.get("kernel_profile_guid_age") if summary else None
        ),
        "machine": "pc-i440fx-5.2",
        "guest_memory": args.guest_memory,
        "guest_vcpus": int(args.guest_smp),
        "tcg_threads": "single",
        "icount_shift": args.icount_shift if args.icount_shift >= 0 else None,
        "icount_sleep": args.icount_sleep if args.icount_shift >= 0 else None,
        "deterministic": args.deterministic,
        "global_event_order": True,
        "host_timeout_seconds": args.host_timeout,
        "monitor_socket": str(monitor.resolve()),
        "host_timed_out": host_timed_out,
        "guest_completion": args.guest_completion,
        "instruction_budget": args.insn_budget,
        "instruction_budget_reached": instruction_budget_reached,
        "guest_instruction_budget": args.guest_insn_budget,
        "guest_instruction_budget_reached": guest_budget_reached,
        "host_observed_idle": host_observed_idle,
        # The reason string below still says "two_minutes" because other code and
        # the generated documents key on it, but the boundary is configurable now.
        # Record what was ACTUALLY used so a run that idled for 900s is not read as
        # having idled for 120s.
        "host_idle_seconds": args.host_idle_seconds,
        "never_started": never_started,
        "write_settled": write_settled,
        "guest_timed_out": guest_timed_out,
        "guest_idle": guest_idle,
        "guest_query_failed": guest_query_failed,
        "guest_unrecovered_exception": guest_unrecovered_exception,
        "guest_exit_code": (
            None
            if not saw_stop
            or guest_timed_out
            or guest_idle
            or guest_query_failed
            or guest_unrecovered_exception
            or instruction_budget_reached
            else stop_detail
        ),
        "paper_termination_reason": (
            "no_execution_launch_failed" if never_started
            else "maximum_timeout_host" if host_timed_out
            else "backend_failure_no_summary" if not summary
            else "guest_instruction_budget" if guest_budget_reached
            else "instruction_budget" if instruction_budget_reached
            else "maximum_30_minute_timeout" if guest_timed_out
            else "unrecovered_exception_two_minutes"
            if guest_unrecovered_exception
            else "two_minutes_idle" if guest_idle
            else "two_minutes_idle_host_observed" if host_observed_idle
            else "unpacking_settled_write_idle" if write_settled
            else "status_query_failure" if guest_query_failed
            else "all_monitored_processes_exited"
        ),
        "elapsed_seconds": elapsed,
        "qemu_return_code": return_code,
        "trace_sha256": sha256(args.trace) if args.trace.exists() else None,
        "summary": summary,
        "implemented_channels": implemented_channels,
        "trace_integrity": trace_integrity,
        "backend_validation_complete": backend_validation_complete,
        # Tiers travel with the run so the classifier can grant cross-process
        # certification from the memory channels alone; without this it falls back
        # to the coarse certification_mode.
        "certified_tiers": (
            (backend_validation.get("evidence") or {}).get("certified_tiers")
            if isinstance(backend_validation, dict) and backend_validation_complete
            else None
        ),
        "certification_mode": (
            backend_validation.get("certification_mode")
            if isinstance(backend_validation, dict)
            else None
        ),
        "backend_validation_stamp": (
            str(validation_stamp.resolve()) if validation_stamp.exists() else None
        ),
        "backend_identity": current_identity,
        "backend_identity_mismatches": mismatches,
        "paper_label_eligible": (
            backend_validation_complete
            and completion_observed
            and not host_timed_out
            and not guest_timed_out
            and not guest_query_failed
            # every channel-quality gate except the stop marker, which is
            # replaced by completion_observed (guest stop OR host-observed idle).
            and all(v for k, v in trace_integrity.items() if k != "stop_marker")
        ),
        "ineligible_reason": (
            None if backend_validation_complete and completion_observed
            and not host_timed_out and not guest_timed_out
            and not guest_query_failed
            and all(v for k, v in trace_integrity.items() if k != "stop_marker")
            else "the exact current QEMU/plugin/profile identity has not passed "
            "the purpose-built Windows channel fixture"
            if not backend_validation_complete
            else "recording did not reach a completion boundary "
            "(no stop marker and no host-observed idle)"
            if not completion_observed
            else "recording hit the maximum host timeout while still active"
            if host_timed_out
            else "a required trace channel was not clean"
        ),
    }
    meta.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0 if metadata["paper_label_eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
