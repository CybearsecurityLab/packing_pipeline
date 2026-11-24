import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
QEMU = REPO / "ops/qemu"
PLUGIN_INCLUDE = Path(os.environ.get(
    "QEMU_PLUGIN_INCLUDE", "/data/determinism/qemu-det-src/include/plugins"))
QEMU_BUILD = Path(os.environ.get("QEMU_BUILD", "/data/determinism/qemu-det-build"))
GUEST_DLLS = Path("/data/determinism/vmarm/guestdlls/System32")

if importlib.util.find_spec("pefile") is None:
    build_syscall_table = None
else:
    _spec = importlib.util.spec_from_file_location(
        "build_syscall_table", QEMU / "build_syscall_table.py")
    build_syscall_table = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(build_syscall_table)


def _table_numbers():
    return [int(line.split(",")[0].strip(" {"), 16)
            for line in (QEMU / "win10_syscalls.h").read_text().splitlines()
            if line.startswith("    {0x")]


class SyscallHeaderTests(unittest.TestCase):
    def test_header_numbers_fit_the_plugin_lookup(self):
        numbers = _table_numbers()
        self.assertTrue(numbers)
        self.assertEqual(numbers, sorted(set(numbers)))
        self.assertLess(max(numbers), 0x2000)


@unittest.skipIf(build_syscall_table is None, "pefile is not installed")
class SyscallTableGeneratorTests(unittest.TestCase):
    def test_render_sorts_and_rejects_conflicts(self):
        text = build_syscall_table.render([
            ("ntdll", "aa", {0x12: "NtOpenKey", 0x2: "NtB"}),
            ("win32u", "bb", {0x1000: "NtUserX"}),
        ])
        self.assertIn('#define SYSCALL_TABLE_NTDLL_SHA256 "aa"', text)
        self.assertIn("#define SYSCALL_TABLE_WIN32U_COUNT 1", text)
        rows = [line.strip() for line in text.splitlines() if line.startswith("    {0x")]
        self.assertEqual(rows, ['{0x0002, "NtB"},', '{0x0012, "NtOpenKey"},',
                                '{0x1000, "NtUserX"},'])
        with self.assertRaises(ValueError):
            build_syscall_table.render([
                ("ntdll", "aa", {1: "NtA"}), ("win32u", "bb", {1: "NtB"})])

    @unittest.skipUnless((GUEST_DLLS / "ntdll.dll").is_file()
                         and (GUEST_DLLS / "win32u.dll").is_file(),
                         "guest DLLs are not available")
    def test_committed_header_matches_guest_dlls(self):
        text = build_syscall_table.build(
            [GUEST_DLLS / "ntdll.dll", GUEST_DLLS / "win32u.dll"])
        self.assertEqual(text, (QEMU / "win10_syscalls.h").read_text())
        for row in ('{0x0012, "NtOpenKey"}', '{0x0036, "NtQuerySystemInformation"}',
                    '{0x0017, "NtQueryValueKey"}', '{0x0034, "NtDelayExecution"}',
                    '{0x106c, "NtUserFindWindowEx"}'):
            self.assertIn(row, text)


def _pkg_config(flag):
    return subprocess.run(["pkg-config", flag, "glib-2.0"], check=True,
                          capture_output=True, text=True).stdout.split()


@unittest.skipUnless(shutil.which("cc") and shutil.which("pkg-config")
                     and (PLUGIN_INCLUDE / "qemu-plugin.h").is_file(),
                     "C compiler or QEMU plugin header unavailable")
class EvasionDecoderTests(unittest.TestCase):
    CASES = {
        "0fa2": ("cpuid", 4, 0, 0),
        "480fa2": ("cpuid", 4, 0, 0),
        "0f31": ("rdtsc", 4, 0, 0),
        "0f01f9": ("rdtscp", 4, 0, 0),
        "0f05": ("syscall", 4, 0, 0),
        "0f010d10203040": ("sidt", 4, 0, 0),
        "0f0100": ("sgdt", 4, 0, 0),
        "0f01e0": ("smsw", 4, 0, 0),
        "0f00c8": ("str", 4, 0, 0),
        "0f0000": ("sldt", 4, 0, 0),
        "0f01c1": ("vmcall", 4, 0, 0),
        "0f01d9": ("vmmcall", 4, 0, 0),
        "0f01d4": ("vmfunc", 4, 0, 0),
        "0f01d0": ("none", 4, 0, 0),
        "0f01f8": ("none", 4, 0, 0),
        "ed": ("in", 4, 0, 0),
        "66ed": ("in", 2, 0, 0),
        "ec": ("in", 1, 0, 0),
        "e471": ("in", 1, 0x71, 1),
        "e758": ("out", 4, 0x58, 1),
        "ee": ("out", 1, 0, 0),
        "f36c": ("ins", 1, 0, 0),
        "6f": ("outs", 4, 0, 0),
        "cd2d": ("int2d", 4, 0, 0),
        "cd2e": ("none", 4, 0, 0),
        "f1": ("icebp", 4, 0, 0),
        "cc": ("int3", 4, 0, 0),
        "0f0b": ("ud2", 4, 0, 0),
        "0f3f": ("0f3f", 4, 0, 0),
        "40": ("none", 4, 0, 0),
        "90": ("none", 4, 0, 0),
        "0f1f840000000000": ("none", 4, 0, 0),
        "e8a20f0000": ("none", 4, 0, 0),
    }

    @classmethod
    def setUpClass(cls):
        cls._directory = tempfile.TemporaryDirectory()
        work = Path(cls._directory.name)
        harness = work / "harness.o"
        subprocess.run([
            "cc", "-std=gnu11", "-O0", "-Wall", "-Wextra", "-Werror", "-c",
            *_pkg_config("--cflags"),
            f"-I{QEMU_BUILD}", f"-I{QEMU_BUILD / 'include'}", f"-I{PLUGIN_INCLUDE}",
            f"-I{QEMU}", str(REPO / "tests/evasion_decode_harness.c"),
            "-o", str(harness),
        ], check=True)
        undefined = subprocess.run(["nm", "-u", str(harness)], check=True,
                                   capture_output=True, text=True).stdout.split()
        stubs = work / "stubs.c"
        stubs.write_text("".join(f"void {name}(void) {{}}\n" for name in undefined
                                 if name.startswith("qemu_plugin_")))
        cls.binary = work / "harness"
        subprocess.run(["cc", str(harness), str(stubs), "-o", str(cls.binary),
                        *_pkg_config("--libs")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls._directory.cleanup()

    def run_harness(self, *arguments):
        return subprocess.run([str(self.binary), *arguments], check=True,
                              capture_output=True, text=True).stdout

    def test_translation_time_decoder(self):
        decoded = {}
        for line in self.run_harness(*self.CASES).splitlines():
            hexbytes, name, width, port, immediate = line.split()
            decoded[hexbytes] = (name, int(width), int(port), int(immediate))
        self.assertEqual(decoded, self.CASES)

    def test_emitted_records_are_valid_json(self):
        lines = [json.loads(line) for line in self.run_harness("--emit").splitlines()]
        syscall, int3 = lines[0], lines[1]
        self.assertEqual(syscall["event"], "evasion_check")
        self.assertEqual((syscall["seq"], int3["seq"]), (1, 2))
        self.assertEqual(syscall["pc"], "0x401000")
        self.assertEqual(syscall["kind"], "syscall")
        self.assertEqual(syscall["origin"], "sample")
        self.assertEqual(syscall["detail"], {
            "path": '\\Registry\\"VBOX"?', "caller": "0x7ff612340000",
            "caller_origin": "sample", "caller_module": 'pa"ck\\ed.exe',
            "module": 'pa"ck\\ed.exe'})
        self.assertEqual(int3["detail"], {})
        self.assertEqual(int3["origin"], "dynamic")
        self.assertEqual([line["allow"] for line in lines[2:8]],
                         [True] * 4 + [False] * 2)
        self.assertEqual(lines[8], {"match": "\\hardware\\description\\system"})
        self.assertEqual(lines[9], {"no_match": True})
        evasion = lines[10]["evasion"]
        self.assertEqual(evasion["syscall_counts"], {"NtOpenKey": 3})
        self.assertEqual(evasion["instructions"]["cpuid"], 5)
        self.assertEqual(evasion["suppressed"], 2)
        self.assertEqual(evasion["events"], 2)


if __name__ == "__main__":
    unittest.main()
