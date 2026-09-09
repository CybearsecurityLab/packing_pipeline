"""
Base GUI Wrapper - Abstract class for GUI automation

This abstract class provides common functionality for automating
GUI-based packer applications on Windows.
"""

import yaml
import time
import json
import hashlib
import threading
from pathlib import Path
from abc import ABC, abstractmethod
import subprocess
import pygetwindow as gw
import win32gui
import win32process
import shutil
import win32file
import pywintypes
from screeninfo import get_monitors
import win32con


# --- GLOBAL INPUT LOCK ---
# GUI automation is driven via pyautogui: real mouse clicks at absolute screen
# coordinates, real keystrokes, and window.activate() to bring a window to the
# foreground. A desktop has exactly one cursor, one keyboard focus, and one
# foreground window, so no two packers can *interact* at the same instant — one
# packer's clicks would land in another's window.
#
# This lock serializes the interaction phase (launch → fill fields → click)
# while leaving the long, no-input watch phase (file-lock polling) free to
# overlap across packers. Wrappers acquire it at launch and release it when they
# enter their watch loop. It is an RLock so a single worker re-acquiring is safe;
# it must only ever be released by the worker thread that holds it.
_INPUT_LOCK = threading.RLock()


# --- ACTIVE WRAPPER REGISTRY ---
# Every wrapper registers itself the moment it launches a packer process and
# deregisters when it closes. A run can therefore sweep this set on Ctrl+C and
# terminate any packer process/window still open, so an interrupted run never
# leaves orphaned packer GUIs littering the desktop.
_ACTIVE_WRAPPERS = set()
_ACTIVE_WRAPPERS_LOCK = threading.Lock()


# --- PASS-THROUGH GUARD ---
# Every GUI wrapper decides "packing finished" by watching the staged file
# until it stops being locked. An untouched file is trivially unlocked, so a
# packer that silently no-ops looks identical to one that succeeded, and the
# unmodified input gets published as a packed sample. Hashing the artifact at
# the single publish point and rejecting anything that still equals one of the
# benign inputs turns that silent no-op into a visible failure.
_BENIGN_SHAS = None
_BENIGN_SHAS_LOCK = threading.Lock()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _benign_shas(main_dir):
    """SHA-256 of every benign input, hashed once per process and cached on
    disk keyed by (size, mtime_ns) so a restart does not re-hash ~11 GB."""
    global _BENIGN_SHAS
    with _BENIGN_SHAS_LOCK:
        if _BENIGN_SHAS is not None:
            return _BENIGN_SHAS

        benign_dir = Path(main_dir) / "benign_sources" / "x86"
        cache_path = Path(main_dir) / "packed_sources" / "_audit" / "benign_shas.json"
        cached = {}
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
        except (OSError, ValueError):
            cached = {}

        shas = set()
        fresh = {}
        if benign_dir.is_dir():
            for entry in sorted(benign_dir.iterdir()):
                if not (entry.is_file() and entry.name.lower().endswith(".exe")):
                    continue
                try:
                    st = entry.stat()
                except OSError:
                    continue
                key = entry.name
                row = cached.get(key)
                if row and row.get("size") == st.st_size and row.get("mtime_ns") == st.st_mtime_ns:
                    sha = row["sha256"]
                else:
                    try:
                        sha = _sha256_file(entry)
                    except OSError:
                        continue
                fresh[key] = {"sha256": sha, "size": st.st_size, "mtime_ns": st.st_mtime_ns}
                shas.add(sha)

        if fresh != cached:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(fresh, f)
            except OSError:
                pass

        _BENIGN_SHAS = shas
        return _BENIGN_SHAS


# --- THREAD-LOCAL MOVE RESULT BRIDGE ---
# The SHA gate (utils/sha_gate.ShaGate) needs to know the *final* on-disk path
# of every produced GUI artifact so it can verify and, on rejection, delete
# it. Each wrapper's ``run()`` returns only ``bool`` and discards the path
# ``move_protected_file_to_output()`` returns. Thread-local storage lets the
# wrapper publish the path and ``GUIWrapperRunner.run_packer()`` consume it
# without touching ~28 individual wrapper classes.
_LAST_MOVED_OUTPUT = threading.local()


def clear_last_moved_output() -> None:
    """Drop any stale value from the current thread before a wrapper call."""
    _LAST_MOVED_OUTPUT.path = None


def consume_last_moved_output():
    """Return and clear the path the most recent wrapper published."""
    path = getattr(_LAST_MOVED_OUTPUT, "path", None)
    _LAST_MOVED_OUTPUT.path = None
    return path


def _publish_last_moved_output(path) -> None:
    """Called by ``move_protected_file_to_output`` after a successful move."""
    _LAST_MOVED_OUTPUT.path = str(path) if path is not None else None


def close_all_windows():
    """Terminate every packer process/window currently registered as active.

    Best-effort: each close is guarded so one failure can't stop the rest. Safe
    to call from a Ctrl+C handler — it iterates a snapshot, so close_application
    deregistering as it goes can't disturb the iteration.
    """
    with _ACTIVE_WRAPPERS_LOCK:
        active = list(_ACTIVE_WRAPPERS)
    if active:
        print(f"\n[INFO] Closing {len(active)} open packer window(s)...")
    for wrapper in active:
        try:
            wrapper.close_application()
        except Exception as e:
            print(f"[WARNING] Failed to close {wrapper.__class__.__name__}: {e}")


class BaseGUI(ABC):
    """
    Abstract base class for GUI automation wrappers.

    Provides common functionality for:
    - Window management (launch, find, close)
    - Coordinate-based clicking
    - File picker automation
    - File operations and monitoring
    - Configuration management

    Subclasses must implement packer-specific UI interactions.
    """

    # Common window patterns to exclude when finding the main window
    EXCLUDE_WINDOW_PATTERNS = [
        "visual studio code",
        "vscode",
        "explorer",
        "chrome",
        "firefox",
        "notepad++",
        "cmd",
        "powershell",
        "python",
    ]

    # Common file picker window title patterns
    FILE_PICKER_PATTERNS = [
        "Open file or project",
        "Open",
        "Browse",
        "Select File",
        "Choose File",
    ]

    ERROR_DIALOG_PATTERNS = [
        "access violation",
        "fatal",
        "internal error",
        "unhandled exception",
        "runtime error",
    ]

    SHORT_TIMEOUT = 5
    LONG_TIMEOUT = 10
    EXTRA_LONG_TIMEOUT = 500

    def __init__(self, yaml_path, main_dir):
        """
        Initialize the GUI wrapper.

        Args:
            yaml_path: Path to the packer configuration YAML
            main_dir: Main directory for the project
        """
        self.yaml_path = yaml_path
        self.main_dir = Path(main_dir)
        self.packer_info = None
        self.process = None
        self.window = None
        self.window_pid = None
        # Whether this instance currently holds the global input lock.
        self._holds_input = False

    # ========== INPUT SERIALIZATION ==========

    def acquire_input(self):
        """Acquire the global input lock for the interaction phase.

        Idempotent per instance: calling it again while already held is a no-op,
        so re-entrant interaction steps don't stack acquisitions.
        """
        if not self._holds_input:
            _INPUT_LOCK.acquire()
            self._holds_input = True

    def release_input(self):
        """Release the global input lock, allowing another packer to interact.

        Idempotent: safe to call even if the lock is not held (e.g. from the
        close/cleanup safety net after the watch method already released it).
        Must be called from the same worker thread that acquired the lock.
        """
        if self._holds_input:
            self._holds_input = False
            _INPUT_LOCK.release()

    # ========== ABSTRACT METHODS (must be implemented by subclasses) ==========

    @abstractmethod
    def get_packer_name(self) -> str:
        """
        Return the name of the packer (e.g., 'asm_guard', 'themida').

        Returns:
            str: Packer name as it appears in the YAML configuration
        """
        pass

    @abstractmethod
    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        """
        Main execution flow for the packer.

        This method should orchestrate the entire packing process:
        1. Load configuration
        2. Launch application
        3. Find window
        4. Interact with UI controls
        5. Process the file
        6. Wait for completion
        7. Cleanup

        Args:
            click_mode: Configuration mode (e.g., 'all', 'none', dict, list)
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        pass

    # ========== CONFIGURATION MANAGEMENT ==========

    def load_packer_info(self):
        """
        Load packer configuration from YAML.

        Returns:
            bool: True if packer found in YAML, False otherwise
        """
        packer_name = self.get_packer_name()
        print(f"[INFO] Loading packer configuration for '{packer_name}' from YAML...")

        with open(self.yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for packer in data.get("definitions", []):
            if packer.get("packer_name") == packer_name:
                self.packer_info = packer
                print(
                    f"[SUCCESS] Found {packer_name} v{packer.get('version', 'unknown')}"
                )
                print(f"[INFO] Binary path: {packer['binary_path']}")
                return True

        print(f"[ERROR] {packer_name} not found in YAML definitions")
        return False

    def get_exe_path(self):
        """
        Get the full path to the packer executable.

        Returns:
            Path: Full path to the executable

        Raises:
            ValueError: If packer info not loaded
            FileNotFoundError: If executable doesn't exist
        """
        if not self.packer_info:
            raise ValueError("Packer info not loaded")

        relative_path = self.packer_info["binary_path"].lstrip("./")
        exe_path = self.main_dir / relative_path

        if not exe_path.exists():
            raise FileNotFoundError(f"Executable not found at: {exe_path}")

        return exe_path

    # ========== FILE PATH UTILITIES ==========

    def extract_app_name(self, file_path):
        """
        Extract application name from file path.

        Args:
            file_path: Full path to file

        Returns:
            str: Filename only
        """
        return Path(file_path).name

    def get_output_path(self, input_file_path, output_suffix="_packed"):
        """
        Generate output path in main_dir/wrapper/.

        Args:
            input_file_path: Path to input file
            output_suffix: Suffix to add before extension (default: "_packed")

        Returns:
            Path: Output file path
        """
        app_name = self.extract_app_name(input_file_path)
        name_parts = Path(app_name)
        output_name = f"{name_parts.stem}{output_suffix}{name_parts.suffix}"
        return self.get_output_directory() / output_name

    def get_output_directory(self):
        """
        Get the wrapper output directory.

        Returns:
            Path: Output directory path (creates if doesn't exist)
        """
        output_dir = self.main_dir / "wrapper"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    # ========== WINDOW MANAGEMENT ==========

    def launch_application(self, shell=False):
        """
        Launch the packer GUI application.

        Args:
            shell (bool): Whether to use the shell as the executable program. Defaults to False.

        Returns:
            bool: True if launched successfully
        """
        # Acquire the global input lock before the window appears. This is the
        # universal first interaction step for every wrapper, so holding from
        # here covers launch + all subsequent clicks/keystrokes. The lock is
        # released later by the wrapper's watch method (or the close/cleanup
        # safety net below).
        self.acquire_input()

        exe_path = self.get_exe_path()
        print(f"\n[INFO] Launching application: {exe_path}")

        # Launch GUI application without capturing output
        # This prevents issues with Windows GUI apps
        self.process = subprocess.Popen(str(exe_path), cwd=exe_path.parent, shell=shell)

        # Register so a Ctrl+C sweep can find and close this window even if the
        # wrapper is aborted mid-interaction before it reaches close_application.
        with _ACTIVE_WRAPPERS_LOCK:
            _ACTIVE_WRAPPERS.add(self)

        print(f"[SUCCESS] Process started with PID: {self.process.pid}")
        print("[INFO] Waiting for GUI window to appear...")
        time.sleep(2)

        return True

    def center_window_on_monitor(self, monitor_number=0):
        """
        Move and center the window on a specific monitor.
        """
        try:
            if not self.window:
                print("[ERROR] No window available")
                return False

            hwnd = self.window._hWnd

            monitors = get_monitors()
            if monitor_number >= len(monitors):
                print(f"[WARNING] Monitor {monitor_number} not found, using primary")
                monitor_number = 0

            monitor = monitors[monitor_number]

            # Get window dimensions
            rect = win32gui.GetWindowRect(hwnd)
            window_width = rect[2] - rect[0]
            window_height = rect[3] - rect[1]

            # Calculate centered position
            new_x = monitor.x + (monitor.width - window_width) // 2
            new_y = monitor.y + (monitor.height - window_height) // 2

            # Move the window
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOP,
                new_x,
                new_y,
                window_width,
                window_height,
                win32con.SWP_SHOWWINDOW,
            )

            print(f"[SUCCESS] Window centered on monitor {monitor_number}")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to center window: {e}")
            return False

    def find_window(self, window_title=None, timeout=LONG_TIMEOUT):
        """
        Find the packer window by title or process ID.

        Args:
            window_title (str, optional): Specific title to search for.
                                        If None, searches by self.process.pid.
            timeout (int): Maximum seconds to wait for window.

        Returns:
            bool: True if window found
        """
        search_type = (
            f"title '{window_title}'" if window_title else f"PID {self.process.pid}"
        )
        print(f"\n[INFO] Searching for application window by {search_type}...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                windows = []

                def enum_windows_callback(hwnd, results):
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd)
                        if not title:
                            return True

                        # Logic branch: search by Title or PID
                        if window_title:
                            if window_title.lower() in title.lower():
                                results.append((hwnd, title))
                        elif self.process:
                            _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                            if window_pid == self.process.pid:
                                results.append((hwnd, title))
                    return True

                win32gui.EnumWindows(enum_windows_callback, windows)

                # Process found windows
                for hwnd, title in windows:
                    title_lower = title.lower()

                    # Check exclusions
                    if any(p in title_lower for p in self.EXCLUDE_WINDOW_PATTERNS):
                        print(
                            f"[DEBUG] Excluding window '{title}' (matches exclusion pattern)"
                        )
                        continue

                    print(f"[SUCCESS] Found window: '{title}' (HWND: {hwnd})")

                    # Using pygetwindow to wrap the found handle
                    self.window = gw.getWindowsWithTitle(title)[0]
                    self._record_window_pid(hwnd)
                    return True

            except Exception as e:
                print(f"[DEBUG] Error during window search: {e}")

            time.sleep(0.5)

        print(f"[ERROR] Window matching {search_type} not found within timeout")
        return False

    def close_application(self, SHORT_TIMEOUT=SHORT_TIMEOUT):
        """
        Close the packer application.
        """
        print("[INFO] Closing application...")

        # Deregister first: once we've decided to close, this wrapper should no
        # longer be a target for a concurrent close_all_windows sweep.
        with _ACTIVE_WRAPPERS_LOCK:
            _ACTIVE_WRAPPERS.discard(self)

        # Safety net: ensure the input lock is freed on every exit path, even if
        # the wrapper raised before reaching its watch method.
        self.release_input()

        try:
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=SHORT_TIMEOUT)
                print("[INFO] Application terminated gracefully")
        except Exception as e:
            print(f"[WARNING] Graceful termination failed: {e}")
            try:
                if self.process:
                    self.process.kill()
                    print("[INFO] Application force killed")
            except Exception as e2:
                print(f"[ERROR] Could not kill application: {e2}")

        self.process = None
        self.window = None
        self.window_pid = None

    # ========== ERROR / CRASH DIALOG HANDLING ==========

    def _record_window_pid(self, hwnd):
        """Record the PID that owns the located GUI window."""
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            self.window_pid = pid
        except Exception:
            self.window_pid = None

    def find_error_dialog(self, patterns=None, timeout=SHORT_TIMEOUT):
        """Return the hwnd of a fatal crash popup owned by this packer, or None.

        Polls up to `timeout` seconds; read-only, so safe under parallelism
        without the input lock.
        """
        patterns = [p.lower() for p in (patterns or self.ERROR_DIALOG_PATTERNS)]
        deadline = time.time() + max(0, timeout)
        while True:
            hwnd = self._scan_process_dialogs(patterns)
            if hwnd:
                return hwnd
            if time.time() >= deadline:
                return None
            time.sleep(0.3)

    def _scan_process_dialogs(self, patterns_lower):
        """One pass over owned #32770 dialogs; return the first matching hwnd."""
        acceptable = set()
        if self.process:
            acceptable.add(self.process.pid)
        if self.window_pid:
            acceptable.add(self.window_pid)

        matches = []

        def _collect(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                if win32gui.GetClassName(hwnd) != "#32770":
                    return True
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if acceptable and pid not in acceptable:
                    return True

                texts = [win32gui.GetWindowText(hwnd)]

                def _child(child_hwnd, _unused):
                    texts.append(win32gui.GetWindowText(child_hwnd))
                    return True

                win32gui.EnumChildWindows(hwnd, _child, None)
                blob = " ".join(t for t in texts if t).lower()
                if any(p in blob for p in patterns_lower):
                    matches.append(hwnd)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_collect, None)
        except Exception:
            pass
        return matches[0] if matches else None

    def dismiss_dialog(self, hwnd):
        """Best-effort close of a popup dialog via WM_CLOSE."""
        try:
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            time.sleep(0.3)
            return True
        except Exception as e:
            print(f"[WARNING] Could not dismiss error dialog: {e}")
            return False

    def _get_client_area_info(self, window_title):
        """
        Get client area information for a window.

        Args:
            window_title: Title of the window

        Returns:
            tuple: (client_width, client_height, client_point) or None on failure
        """
        try:
            hwnd = win32gui.FindWindow(None, window_title)
            client_rect = win32gui.GetClientRect(hwnd)
            _, _, client_width, client_height = client_rect
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))
            return client_width, client_height, client_point
        except Exception as e:
            print(f"[WARNING] Could not get client area details: {e}")
            return None

    def get_window_dimensions(self):
        """
        Get and print window dimensions.

        Returns:
            dict: Window dimension information or None
        """
        if not self.window:
            print("[ERROR] No window found")
            return None

        print("\n" + "=" * 60)
        print("WINDOW DIMENSIONS")
        print("=" * 60)

        print("\n[FULL WINDOW] (includes title bar and borders)")
        print(f"  Left:   {self.window.left}")
        print(f"  Top:    {self.window.top}")
        print(f"  Width:  {self.window.width}")
        print(f"  Height: {self.window.height}")
        print(f"  Right:  {self.window.left + self.window.width}")
        print(f"  Bottom: {self.window.top + self.window.height}")

        client_info = self._get_client_area_info(self.window.title)
        if client_info:
            client_width, client_height, client_point = client_info
            hwnd = win32gui.FindWindow(None, self.window.title)
            window_rect = win32gui.GetWindowRect(hwnd)
            win_left, win_top, _, _ = window_rect

            print("\n[CLIENT AREA] (actual usable space, excludes borders)")
            print(f"  Width:  {client_width}")
            print(f"  Height: {client_height}")
            print(f"  Screen Position: {client_point}")

            print("\n[CHROME SIZES]")
            print(f"  Title bar height: {client_point[1] - win_top}px")
            print(f"  Border width:     {client_point[0] - win_left}px")

        print("\n" + "=" * 60)

        return {
            "full_window": {
                "left": self.window.left,
                "top": self.window.top,
                "width": self.window.width,
                "height": self.window.height,
            }
        }

    # ========== COORDINATE-BASED CLICKING ==========

    def click_at_percent(self, x_percent, y_percent, description="", track_state=None):
        """
        Click at a position specified as percentage of window dimensions.

        This is the core method for GUI interaction. Uses percentage-based
        coordinates (0.0 to 1.0) for resolution independence.

        Args:
            x_percent: X position as percentage (0.0 to 1.0)
            y_percent: Y position as percentage (0.0 to 1.0)
            description: Description of what is being clicked
            track_state: Optional state variable name to toggle (for checkboxes)

        Returns:
            bool: True if click successful
        """
        if not self.window:
            print("[ERROR] No window found")
            return False

        try:
            import pyautogui

            self.window.activate()
            time.sleep(0.2)

            client_info = self._get_client_area_info(self.window.title)
            if not client_info:
                return False

            client_width, client_height, client_point = client_info
            abs_x = client_point[0] + int(client_width * x_percent)
            abs_y = client_point[1] + int(client_height * y_percent)

            if description:
                print(f"\n[ACTION] Clicking: {description}")
            print(f"  Position: {x_percent * 100:.1f}% x, {y_percent * 100:.1f}% y")
            print(f"  Client area: {client_width}x{client_height}")
            print(f"  Absolute coords: ({abs_x}, {abs_y})")

            # Handle state tracking if provided (useful for checkboxes)
            if track_state and hasattr(self, track_state):
                old_state = getattr(self, track_state)
                print(f"  Current state: {'☑ CHECKED' if old_state else '☐ UNCHECKED'}")

            pyautogui.click(abs_x, abs_y)
            time.sleep(0.1)

            # Toggle state if tracking
            if track_state and hasattr(self, track_state):
                setattr(self, track_state, not getattr(self, track_state))
                new_state = getattr(self, track_state)
                print(f"  New state: {'☑ CHECKED' if new_state else '☐ UNCHECKED'}")

            print("[+] Click successful")
            return True

        except Exception as e:
            print(f"[ERROR] Click failed: {e}")
            return False

    # ========== FILE PICKER AUTOMATION ==========

    def find_file_picker_window(self, timeout=SHORT_TIMEOUT):
        """
        Find the Windows Explorer/File Picker window.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            Window object or None
        """
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                for title in gw.getAllTitles():
                    if not title:
                        continue
                    if any(
                        p.lower() in title.lower() for p in self.FILE_PICKER_PATTERNS
                    ):
                        print(f"[SUCCESS] Found file picker: '{title}'")
                        return gw.getWindowsWithTitle(title)[0]
            except Exception as e:
                print(f"[DEBUG] Error during file picker search: {e}")

            time.sleep(0.2)

        print("[ERROR] File picker window not found within timeout")
        return None

    def paste_file_path_in_picker(self, file_path, app_name):
        """
        Navigate to directory and enter filename in file picker.

        Uses clipboard-based input to support Unicode/special characters.

        Args:
            file_path: Full path to the file
            app_name: Filename to enter in the picker

        Returns:
            bool: True if successful
        """
        try:
            import pyautogui
            import pyperclip

            time.sleep(0.5)

            picker_window = self.find_file_picker_window()
            if not picker_window:
                print("[ERROR] Could not find file picker window")
                return False

            print(f"\n[INFO] Activating file picker window: '{picker_window.title}'")
            picker_window.activate()
            time.sleep(0.3)

            # Enter the FULL absolute path directly into the File name field.
            # The Windows common Open dialog resolves a full path in one atomic
            # action: it navigates to the directory AND selects the file. This
            # avoids the timing race of a separate folder-navigation step, where
            # the filename could be entered before navigation finished.
            full_path = str(Path(file_path).resolve())
            print(f"[INFO] Focusing file name field...")
            pyautogui.hotkey("alt", "n")
            time.sleep(0.2)
            pyautogui.hotkey("ctrl", "a")
            time.sleep(0.1)

            # Paste full path using clipboard (supports Unicode/special chars)
            print(f"[INFO] Pasting full path: {full_path}")
            pyperclip.copy(full_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)

            # Submit with Enter (opens directly without needing the Open button)
            print("[INFO] Submitting path with Enter...")
            pyautogui.press("enter")
            time.sleep(0.5)

            print("[SUCCESS] Full file path entered and submitted")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to paste file path: {e}")
            return False

    # ========== FILE OPERATIONS ==========

    def is_file_locked(self, file_path):
        """
        Check if a file is locked (being read from OR written to by another process).

        Uses exclusive access check - fails if ANY process has ANY handle open.

        Args:
            file_path: Path to the file

        Returns:
            bool: True if locked (read OR write), False if completely available
        """
        try:
            # Try to open with EXCLUSIVE access (dwShareMode=0)
            # This fails if ANY other process has the file open for ANY reason
            handle = win32file.CreateFile(
                str(file_path),
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,  # <-- KEY: No sharing allowed (not even read)
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None,
            )
            win32file.CloseHandle(handle)
            return False  # Got exclusive access = file is FREE

        except pywintypes.error:
            # ERROR_SHARING_VIOLATION (32) or ERROR_LOCK_VIOLATION (33)
            return True  # File is LOCKED
        except Exception:
            return True  # Assume locked if check fails

    def move_protected_file_to_output(
        self, protected_file_path, output_dir=None, max_retries=5, retry_delay=2
    ):
        """
        Move the protected file to specified output directory.

        Args:
            protected_file_path: Path to the protected file
            output_dir: Destination directory (if None, file stays in place)

        Returns:
            str: Final file path or None on failure
        """
        if not protected_file_path:
            return None

        source = Path(protected_file_path)
        if not source.exists():
            print(f"[ERROR] Protected file not found: {source}")
            return None

        try:
            produced_sha = _sha256_file(source)
        except OSError as e:
            print(f"[ERROR] Could not hash produced file {source}: {e}")
            return None

        if produced_sha in _benign_shas(self.main_dir):
            print(
                f"[REJECTED] PASS-THROUGH: {source.name} is byte-identical to its "
                f"benign input (sha={produced_sha[:16]}). The packer did not modify "
                f"the file, so this is a failed pack, not a sample."
            )
            try:
                source.unlink()
            except OSError:
                pass
            return None

        # If no output directory specified, leave file in place
        if output_dir is None:
            print(f"\n[INFO] No output directory specified, file remains at: {source}")
            _publish_last_moved_output(source.resolve())
            return str(source)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / source.name

        print(f"\n[INFO] Moving protected file to output directory...")
        print(f"  From: {source}")
        print(f"  To:   {destination}")

        for attempt in range(max_retries):
            try:
                if self.is_file_locked(source):
                    print(
                        f"  [Attempt {attempt + 1}/{max_retries}] File still locked, waiting {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    continue
                shutil.move(str(source), str(destination))
                print(f"[SUCCESS] File moved to: {destination}")
                _publish_last_moved_output(destination.resolve())
                return str(destination)
            except PermissionError as e:
                print(
                    f"  [Attempt {attempt + 1}/{max_retries}] File in use, retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)

        print(f"[ERROR] Failed to move file after {max_retries} attempts")
        return None

    def cleanup_on_failure(self, input_file_path):
        """
        Clean up after a failed or timed out operation.

        Subclasses can override this to add packer-specific cleanup.

        Args:
            input_file_path: Path to the input file
        """
        print("\n[INFO] Cleaning up after failure...")
        # Free the input lock first in case close_application is overridden
        # without calling super().
        self.release_input()
        self.close_application()
