import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "ops/qemu"


def load(name, path=None, env=None):
    spec = importlib.util.spec_from_file_location(
        f"{name}_{id(env)}_{len(sys.modules)}", path or OPS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(OPS))
    try:
        with mock.patch.dict(os.environ, env or {}):
            spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


vm_profiles = load("vm_profiles")
evasion_analysis = load("evasion_analysis")
compare_arms = load("compare_arms")


def write_trace(path, events, tail=b""):
    with open(path, "wb") as fh:
        for e in events:
            fh.write(json.dumps(e, separators=(",", ":")).encode() + b"\n")
        fh.write(tail)
    return path


def exec_ev(n=1):
    return [{"event": "exec", "seq": 0, "vcpu": 0, "pid": 4, "tid": 8, "address": 4096,
             "size": 4, "basic_block_instructions": 1} for _ in range(n)]


def check(kind, origin="sample", **detail):
    return {"event": "evasion_check", "kind": kind, "origin": origin, "pid": 4,
            "pc": 4198400, "detail": detail}


EXITED = {"paper_termination_reason": "all_monitored_processes_exited", "guest_exit_code": 0}
BUDGET = {"paper_termination_reason": "guest_instruction_budget"}


class VmProfileTests(unittest.TestCase):
    def test_certified_matches_the_certified_command_line(self):
        self.assertEqual(vm_profiles.machine_arg("certified"), "pc-i440fx-5.2")
        self.assertEqual(vm_profiles.cpu_arg("certified"), "qemu64")
        self.assertEqual(vm_profiles.cpu_arg("certified", "Haswell", True), "Haswell,-hypervisor")
        self.assertEqual(vm_profiles.rtc_arg("certified", True), "base=localtime,clock=vm")
        self.assertEqual(vm_profiles.rtc_arg("certified", False), "base=localtime")
        self.assertEqual(vm_profiles.smbios_args("certified"), [])
        self.assertEqual(vm_profiles.plugin_args("certified"), [])
        self.assertEqual(vm_profiles.identity_fields("certified"), {})
        self.assertEqual(vm_profiles.disk_args("certified", "/w.qcow2", False),
                         ["-drive", "file=/w.qcow2,format=qcow2,if=ide,cache=writeback"])
        self.assertEqual(vm_profiles.disk_args("certified", "/w.qcow2", True),
                         ["-drive", "driver=blkdet,image.driver=qcow2,"
                                    "image.file.filename=/w.qcow2,if=ide,cache=writeback"])
        self.assertEqual(vm_profiles.cdrom_args("certified", None), [])
        self.assertEqual(vm_profiles.cdrom_args("certified", "/d.iso"),
                         ["-drive", "file=/d.iso,format=raw,if=ide,index=2,media=cdrom"])
        self.assertEqual(vm_profiles.default_stamp("certified", ROOT),
                         ROOT / "ops/qemu/backend_validation.json")

    def test_vmarm_hides_the_hypervisor_and_keeps_qemu64(self):
        cpu = vm_profiles.cpu_arg("vmarm")
        self.assertTrue(cpu.startswith("qemu64,"))
        for prop in ("hypervisor=off", "tcg-cpuid=off", "model-id=AMD Athlon"):
            self.assertIn(prop, cpu)
        machine = vm_profiles.machine_arg("vmarm")
        self.assertIn("x-oem-id=ALASKA", machine)
        self.assertIn("x-oem-table-id=", machine)
        self.assertNotIn("BOCHS", machine)
        smbios = vm_profiles.smbios_args("vmarm")
        types_ = [a.split(",")[0] for a in smbios[1::2]]
        self.assertEqual(types_, ["type=0", "type=1", "type=2", "type=3", "type=4", "type=17"])
        self.assertIn(f"uuid={vm_profiles.VMARM_UUID}", smbios[3])
        self.assertTrue(vm_profiles.rtc_arg("vmarm", True).startswith("base=2"))
        self.assertEqual(vm_profiles.plugin_args("vmarm"), ["evasion=on"])
        self.assertEqual(vm_profiles.default_stamp("vmarm", ROOT),
                         ROOT / "ops/qemu/backend_validation.vmarm.json")

    def test_vmarm_ide_devices_keep_blkdet_and_bus_positions(self):
        disk = vm_profiles.disk_args("vmarm", "/w.qcow2", True)
        self.assertTrue(disk[1].startswith("driver=blkdet,image.driver=qcow2,"
                                           "image.file.filename=/w.qcow2,if=none,id=ide0-hd0"))
        self.assertTrue(disk[3].startswith("ide-hd,drive=ide0-hd0,bus=ide.0,unit=0,model="))
        self.assertNotIn("QEMU", disk[3])
        empty = vm_profiles.cdrom_args("vmarm", None)
        self.assertEqual(empty[1], "if=none,id=ide1-cd0,media=cdrom")
        self.assertTrue(empty[3].startswith("ide-cd,drive=ide1-cd0,bus=ide.1,unit=0,model="))
        full = vm_profiles.cdrom_args("vmarm", "/d.iso")
        self.assertEqual(full[1], "file=/d.iso,format=raw,if=none,id=ide1-cd0,media=cdrom")

    def test_ide_strings_fit_the_identify_buffers(self):
        limits = {"model": 40, "serial": 20, "ver": 8}
        for key, value in vm_profiles.VMARM_DISK + vm_profiles.VMARM_CDROM:
            self.assertLessEqual(len(value), limits[key], key)
        self.assertLessEqual(len(vm_profiles.VMARM_MODEL_ID), 48)
        self.assertLessEqual(len(vm_profiles.VMARM_OEM_ID), 6)
        self.assertLessEqual(len(vm_profiles.VMARM_OEM_TABLE_ID), 8)

    def test_commas_in_values_are_escaped(self):
        self.assertEqual(vm_profiles._join((("a", "x,y"),)), "a=x,,y")

    def test_identity_changes_with_the_machine_config(self):
        fields = vm_profiles.identity_fields("vmarm")
        self.assertEqual(fields["profile"], "vmarm")
        before = fields["machine_config_sha256"]
        with mock.patch.object(vm_profiles, "VMARM_RTC_BASE", "2030-01-01T00:00:00"):
            self.assertNotEqual(vm_profiles.machine_config_sha256("vmarm"), before)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            vm_profiles.cpu_arg("stealth")

    def test_cli_args_survive_bash_mapfile(self):
        script = ('mapfile -t A < <(python3 "$1" qemu-args vmarm --disk /s.qcow2 '
                  '--cdrom /e.iso); printf "%s\\n" "${A[@]}"')
        out = subprocess.run(["bash", "-c", script, "_", str(OPS / "vm_profiles.py")],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(out, vm_profiles.machine_config("vmarm", disk="/s.qcow2",
                                                         cdrom="/e.iso"))


class RunTraceProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt = load("run_trace")

    def command(self, *argv):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ops/qemu").mkdir(parents=True)
        for name in ("run_trace.py", "vm_profiles.py"):
            shutil.copy(OPS / name, root / "ops/qemu" / name)
        (root / "empirical_results/qemu_runtime").mkdir(parents=True)
        (root / "empirical_results/qemu_runtime/ntdll.dll").write_bytes(b"x")
        (root / "ops/qemu/win10_profile.h").write_bytes(b"x")
        for name in ("base.qcow2", "qemu", "plugin.so", "d.iso"):
            (root / name).write_bytes(b"x")
        module = load("run_trace", root / "ops/qemu/run_trace.py")
        captured = {}

        class Captured(Exception):
            pass

        def popen(cmd, **_):
            captured["cmd"] = cmd
            raise Captured()

        module.subprocess = types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="[]"),
            Popen=popen, DEVNULL=None, TimeoutExpired=Exception)
        args = [str(a).replace("ROOT", str(root)) for a in argv]
        with mock.patch.object(sys, "argv", ["run_trace.py", f"{root}/base.qcow2",
                                             f"{root}/w/work.qcow2", f"{root}/t/trace.jsonl",
                                             "--qemu", f"{root}/qemu",
                                             "--plugin", f"{root}/plugin.so", *args]):
            try:
                module.main()
            except Captured:
                pass
        return [c.replace(str(root), "ROOT") for c in captured["cmd"]]

    def test_certified_default_command_is_unchanged(self):
        cmd = self.command("--deterministic")
        self.assertEqual(cmd[cmd.index("-machine") + 1], "pc-i440fx-5.2")
        self.assertEqual(cmd[cmd.index("-cpu") + 1], "qemu64")
        self.assertEqual(cmd[cmd.index("-rtc") + 1], "base=localtime,clock=vm")
        self.assertNotIn("-smbios", cmd)
        self.assertNotIn("-device", cmd)
        self.assertEqual(cmd[cmd.index("-drive") + 1],
                         "driver=blkdet,image.driver=qcow2,image.file.filename="
                         "ROOT/w/work.qcow2,if=ide,cache=writeback")
        self.assertEqual(cmd[cmd.index("-plugin") + 1],
                         "ROOT/plugin.so,out=ROOT/t/trace.jsonl")
        self.assertEqual(cmd.count("-drive"), 1)

    def test_certified_delivery_cd_is_unchanged(self):
        cmd = self.command("--delivery-disk", "ROOT/d.iso")
        self.assertEqual(cmd[-1], "file=ROOT/d.iso,format=raw,if=ide,index=2,media=cdrom")

    def test_vmarm_command(self):
        cmd = self.command("--profile", "vmarm", "--deterministic",
                           "--delivery-disk", "ROOT/d.iso")
        self.assertIn("hypervisor=off", cmd[cmd.index("-cpu") + 1])
        self.assertEqual(cmd.count("-smbios"), 6)
        self.assertTrue(cmd[cmd.index("-plugin") + 1].endswith(",evasion=on"))
        self.assertIn("ide-hd,drive=ide0-hd0,bus=ide.0,unit=0,model=WDC WD3200AAJS-60M0A1,"
                      "serial=WD-WCAV2A417923,ver=01.03E01", cmd)
        self.assertIn("file=ROOT/d.iso,format=raw,if=none,id=ide1-cd0,media=cdrom", cmd)

    def test_vmarm_rejects_certified_cpu_knobs(self):
        with self.assertRaises(SystemExit):
            self.command("--profile", "vmarm", "--transparent")

    def test_profiles_never_validate_against_each_other(self):
        certified = {"qemu_sha256": "q", "cpu_model": "qemu64"}
        vmarm = {**certified, "cpu_model": "x", **vm_profiles.identity_fields("vmarm")}
        mismatches = self.rt.identity_mismatches
        self.assertEqual(mismatches(certified, dict(certified), "certified"), [])
        self.assertEqual(mismatches(vmarm, dict(vmarm), "vmarm"), [])
        self.assertIn("profile", mismatches(vmarm, dict(certified), "vmarm"))
        self.assertEqual(mismatches(certified, {**certified, "profile": "vmarm"}, "certified"),
                         ["profile"])
        self.assertEqual(mismatches(certified, {}, "certified"), ["qemu_sha256", "cpu_model"])


class EvasionAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def analyse(self, events, meta=EXITED, windows=None, tail=b"", chunk=1 << 20):
        trace = write_trace(self.dir / "trace.jsonl", events, tail)
        return evasion_analysis.analyse(trace, meta, windows, chunk_bytes=chunk)

    def test_hypervisor_leaf_from_sample_flags_alone(self):
        r = self.analyse(exec_ev(5) + [check("cpuid", leaf="0x40000000")] + exec_ev(10**3),
                         meta=BUDGET)
        self.assertTrue(r["evasion_suspected"])
        self.assertEqual(r["evidence"][0]["signal"], "cpuid_hypervisor_leaf")
        self.assertFalse(r["outcome_anomaly"])

    def test_system_origin_checks_are_counted_not_flagged(self):
        r = self.analyse([check("cpuid", origin="system", leaf=0x40000000)] + exec_ev(3))
        self.assertFalse(r["evasion_suspected"])
        self.assertEqual(r["checks_by_kind_origin"], {"cpuid/system": 1})
        self.assertIsNone(r["first_red_check"])

    def test_high_tier_kinds(self):
        cases = [
            check("descriptor_table", insn="sidt"),
            check("io_port", port=0x5658),
            check("io_port", port=0x10, eax=0x564D5868),
            check("hypercall", insn="vmcall"),
            check("syscall", service="NtQuerySystemInformation", info_class=76),
            check("syscall", service="NtQuerySystemInformation", info_class=11,
                  provider="RSMB"),
            check("syscall", service="NtQuerySystemInformation", info_class=11,
                  provider=0x52534D42),
            check("syscall", service="NtOpenKeyEx",
                  key="\\Registry\\Machine\\SOFTWARE\\VMware, Inc.\\VMware Tools"),
            check("icebp", handler_origin="sample"),
        ]
        for event in cases:
            r = self.analyse([event] + exec_ev(10**3), meta=BUDGET)
            self.assertTrue(r["evasion_suspected"], event)
            self.assertEqual(r["evidence"][0]["tier"], "high", event)

    def test_medium_needs_an_outcome_anomaly(self):
        events = exec_ev(50) + [check("rdtsc_pair", delta=3000)]
        quiet = self.analyse(events + exec_ev(10), meta=BUDGET)
        self.assertFalse(quiet["evasion_suspected"])
        exited = self.analyse(events + exec_ev(10))
        self.assertTrue(exited["evasion_suspected"])
        self.assertTrue(exited["ended_shortly_after_check"])
        self.assertEqual([e["signal"] for e in exited["evidence"]],
                         ["rdtsc_pair_branch", "outcome_anomaly"])

    def test_activity_after_the_check_is_not_an_anomaly(self):
        events = [check("rdtsc_pair"), {"event": "file_write", "pid": 4}] + exec_ev(3)
        r = self.analyse(events)
        self.assertFalse(r["outcome_anomaly"])
        self.assertFalse(r["evasion_suspected"])

    def test_low_tier_needs_three_distinct_checks_and_an_anomaly(self):
        two = [check("cpuid", leaf=1), check("syscall", service="NtUserGetCursorPos")]
        self.assertFalse(self.analyse(two)["evasion_suspected"])
        three = two + [check("cpuid", leaf=0x80000002)]
        self.assertTrue(self.analyse(three)["evasion_suspected"])
        self.assertFalse(self.analyse(three, meta=BUDGET)["evasion_suspected"])

    def test_vm_window_title_flags(self):
        r = self.analyse(exec_ev(2), windows=["Untitled - Notepad",
                                              "This application cannot run in a virtual machine"])
        self.assertTrue(r["evasion_suspected"])
        self.assertEqual(r["vm_window_titles"],
                         ["This application cannot run in a virtual machine"])
        self.assertEqual(r["evidence"][0]["signal"], "vm_detection_window")

    def test_benign_windows_do_not_flag(self):
        r = self.analyse(exec_ev(2), windows=["Setup - Installer", "Program Manager"])
        self.assertFalse(r["evasion_suspected"])

    def test_activity_is_split_around_the_red_checks(self):
        events = (exec_ev(3) + [check("cpuid", leaf=1)] + exec_ev(4)
                  + [{"event": "write", "pid": 4}] + [check("cpuid", leaf=0)] + exec_ev(2))
        r = self.analyse(events)
        act = r["activity"]
        self.assertEqual(act["total"]["exec"], 9)
        self.assertEqual(act["before_first_red_check"]["exec"], 3)
        self.assertEqual(act["after_first_red_check"]["exec"], 6)
        self.assertEqual(act["after_last_red_check"], {
            "exec": 2, "write": 0, "file_write": 0, "process": 0})
        self.assertEqual(r["checks_total"], 2)
        self.assertEqual(len(r["first_checks"]), 2)

    def test_chunking_does_not_change_the_result(self):
        events = exec_ev(40) + [check("cpuid", leaf=0x40000001)] + exec_ev(40) + [
            check("syscall", service="NtDelayExecution", delay_ms=200_000),
            check("syscall", service="NtDelayExecution", interval=-600_000_000)] + exec_ev(7)
        events.append({"event": "summary", "exec_events": 87})
        whole = self.analyse(events)
        for chunk in (7, 64, 333):
            small = self.analyse(events, chunk=chunk)
            whole["trace_bytes"] = small["trace_bytes"]
            self.assertEqual(small, whole, chunk)
        self.assertEqual(whole["sleep_ms_total"], 260_000)
        self.assertIn("long_sleep", whole["signals"])
        self.assertEqual(whole["summary_exec_events"], 87)

    def test_truncated_final_line_is_tolerated(self):
        r = self.analyse(exec_ev(2) + [check("cpuid", leaf=1)],
                         tail=b'{"event":"evasion_check","kind":"cpu')
        self.assertEqual(r["checks_total"], 1)
        self.assertEqual(r["undecodable_checks"], 1)

    def test_termination_outcomes(self):
        term = evasion_analysis.termination
        self.assertEqual(term(EXITED, None)["outcome"], "exited")
        self.assertEqual(term(EXITED, 0xC0000005)["outcome"], "crashed")
        self.assertEqual(term({"paper_termination_reason": "all_monitored_processes_exited",
                               "guest_exit_code": 0xC0000409}, None)["outcome"], "crashed")
        self.assertEqual(term({"paper_termination_reason": "two_minutes_idle"}, None)["outcome"],
                         "idled")
        self.assertEqual(term(BUDGET, None)["outcome"], "budget")
        self.assertEqual(term(None, None)["outcome"], "unknown")

    def test_terminate_status_from_the_sample_marks_a_crash(self):
        r = self.analyse([check("rdtsc_pair"),
                          check("syscall", service="NtTerminateProcess", status="0xC0000005")])
        self.assertEqual(r["termination"]["outcome"], "crashed")
        self.assertTrue(r["evasion_suspected"])

    def test_registry_tiers(self):
        cls = evasion_analysis.classify_check
        self.assertEqual(cls(check("syscall", service="NtQueryValueKey",
                                   key="HARDWARE\\DESCRIPTION\\System",
                                   value_name="SystemBiosVersion")),
                         [("hardware_registry_query", "medium")])
        self.assertEqual(cls(check("syscall", service="NtOpenKey",
                                   key="SYSTEM\\ControlSet001\\Services\\VBoxGuest")),
                         [("vm_registry_key", "high")])
        self.assertEqual(cls(check("syscall", service="NtOpenKey", key="SOFTWARE\\Microsoft")),
                         [])
        self.assertEqual(cls(check("syscall", service="NtQueryInformationProcess",
                                   info_class=7)), [("debugger_query", "medium")])
        self.assertEqual(cls(check("int2d")), [("anti_debug_int2d", "medium")])
        self.assertEqual(cls(check("rdtsc_pair", feeds_branch=False)), [("rdtsc_pair", "low")])
        self.assertEqual(cls({"kind": "mystery"}), [])

    def test_read_windows_handles_utf16(self):
        path = self.dir / "windows.txt"
        path.write_bytes("A Title\r\nVirtualBox detected\r\n".encode("utf-16"))
        self.assertEqual(evasion_analysis.read_windows(path), ["A Title", "VirtualBox detected"])
        self.assertIsNone(evasion_analysis.read_windows(self.dir / "missing.txt"))

    def test_cli_writes_json(self):
        trace = write_trace(self.dir / "trace.jsonl", [check("hypercall")])
        meta = self.dir / "meta.json"
        meta.write_text(json.dumps(EXITED))
        out = self.dir / "evasion.json"
        evasion_analysis.main([str(trace), "--meta", str(meta), "--output", str(out)])
        data = json.loads(out.read_text())
        self.assertTrue(data["evasion_suspected"])
        compact = evasion_analysis.compact(data)
        self.assertEqual(compact["signals"], ["hypercall_probe"])
        self.assertNotIn("first", compact["evidence"][0])


def rep(label="UNRESOLVED_NO_UNPACKING_OBSERVED", layers=1,
        termination="all_monitored_processes_exited", exec_events=1000, evasion=None):
    return {"label": label, "layers": layers, "termination": termination,
            "exec_events": exec_events, "evasion": evasion}


def ev(suspected=False, red=0, before=None, after=None, evidence=()):
    return {"evasion_suspected": suspected, "red_checks_total": red,
            "exec_before_first_red_check": before, "exec_after_first_red_check": after,
            "evidence": list(evidence)}


class CompareArmsTests(unittest.TestCase):
    def test_type_only_in_vm_arm_confirms(self):
        r = compare_arms.compare([rep(), rep()], [rep("TYPE_III", 3), rep("TYPE_II", 2)])
        self.assertEqual(r["vm_arm_outcome"], "evasion_confirmed")
        self.assertEqual(r["vm_arm_type"], "TYPE_III")
        self.assertEqual(r["evidence"][0]["signal"], "type_only_in_vm_arm")

    def test_extra_layers_confirm(self):
        r = compare_arms.compare([rep(layers=1)], [rep(label="UNRESOLVED_X", layers=2)])
        self.assertEqual(r["vm_arm_outcome"], "evasion_confirmed")
        self.assertIsNone(r["vm_arm_type"])

    def test_termination_divergence_after_checks_confirms(self):
        r = compare_arms.compare(
            [rep(termination="all_monitored_processes_exited")],
            [rep(termination="guest_instruction_budget", evasion=ev(red=4))])
        self.assertEqual(r["vm_arm_outcome"], "evasion_confirmed")
        self.assertEqual(r["evidence"][0]["signal"], "termination_diverges")

    def test_post_check_exec_divergence_confirms(self):
        r = compare_arms.compare(
            [rep(exec_events=12_000)],
            [rep(exec_events=900_000, evasion=ev(red=1, before=10_000, after=890_000))])
        self.assertEqual(r["vm_arm_outcome"], "evasion_confirmed")
        self.assertEqual(r["evidence"][0]["certified_exec_after_check"], 2_000)
        self.assertTrue(r["evidence"][0]["certified_estimated_from_vm_prefix"])

    def test_exec_divergence_when_both_arms_hit_the_budget_is_not_evasion(self):
        both = dict(termination="instruction_budget")
        r = compare_arms.compare(
            [rep(exec_events=12_000, **both)],
            [rep(exec_events=900_000, evasion=ev(red=1, before=10_000, after=890_000), **both)])
        self.assertEqual(r["vm_arm_outcome"], "inconclusive")

    def test_divergence_without_checks_is_not_attributed(self):
        r = compare_arms.compare([rep(termination="all_monitored_processes_exited")],
                                 [rep(termination="guest_instruction_budget")])
        self.assertEqual(r["vm_arm_outcome"], "inconclusive")

    def test_virtualizer_running_to_budget(self):
        both = dict(termination="guest_instruction_budget")
        r = compare_arms.compare([rep(**both)], [rep(**both, evasion=ev())],
                                 protector="VMProtect v3.x")
        self.assertEqual(r["vm_arm_outcome"], "virtualization_suspected")
        r = compare_arms.compare([rep(**both)], [rep(**both, evasion=ev())], protector="UPX")
        self.assertEqual(r["vm_arm_outcome"], "inconclusive")

    def test_genuine_no_unpacking(self):
        r = compare_arms.compare([rep(), rep()], [rep(evasion=ev()), rep(evasion=ev())])
        self.assertEqual(r["vm_arm_outcome"], "genuine_no_unpacking")

    def test_suspected_without_divergence_is_inconclusive(self):
        high = {"signal": "cpuid_hypervisor_leaf", "tier": "high"}
        r = compare_arms.compare([rep()], [rep(evasion=ev(True, 1, 900, 100, [high]))])
        self.assertEqual(r["vm_arm_outcome"], "inconclusive")
        self.assertTrue(r["evasion_suspected"])
        self.assertIn(high, r["evidence"])

    def test_missing_arm(self):
        self.assertEqual(compare_arms.compare([], [rep()])["vm_arm_outcome"], "inconclusive")

    def test_reps_from_verdict_and_dirs(self):
        verdict = {"reps": ["TYPE_I", None],
                   "rep_diag": [{"termination": "two_minutes_idle", "exec_events": 5,
                                 "classifier": {"layers": 2}}, {}]}
        reps = compare_arms.reps_from_verdict(verdict)
        self.assertEqual(reps[0], {"label": "TYPE_I", "layers": 2,
                                   "termination": "two_minutes_idle", "exec_events": 5,
                                   "evasion": None})
        self.assertEqual(len(reps), 2)
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "classification.json").write_text(json.dumps({"complexity_type": "TYPE_II",
                                                           "layers": 2}))
        (d / "meta.json").write_text(json.dumps({**EXITED, "summary": {"exec_events": 7}}))
        trace = write_trace(d / "trace.jsonl", [check("hypercall")])
        (d / "evasion.json").write_text(json.dumps(evasion_analysis.analyse(trace, EXITED)))
        r = compare_arms.rep_from_dir(d)
        self.assertEqual((r["label"], r["layers"], r["exec_events"]), ("TYPE_II", 2, 7))
        self.assertTrue(r["evasion"]["evasion_suspected"])


class MalwareArmTests(unittest.TestCase):
    def test_certified_defaults_are_unchanged(self):
        lmt = load("label_malware_types", env={"MALWARE_ARM": ""})
        self.assertFalse(lmt.VMARM)
        self.assertEqual(lmt.VERDICTS, ROOT / "empirical_results/malware/verdicts")
        self.assertEqual(lmt.FAILURE_HISTORY.name, "failure_history.tsv")
        self.assertEqual(str(lmt.BOOTED_BASE), "/data/malware_runtime/booted.qcow2")

    def test_vmarm_paths_are_separate(self):
        lmt = load("label_malware_types", env={"MALWARE_ARM": "vmarm"})
        self.assertTrue(lmt.VMARM)
        self.assertEqual(lmt.VERDICTS, ROOT / "empirical_results/malware/verdicts_vmarm")
        self.assertEqual(lmt.FAILURE_HISTORY.name, "failure_history.vmarm.tsv")
        self.assertEqual(str(lmt.BOOTED_BASE), "/data/malware_runtime/booted.vmarm.qcow2")

    def test_bad_arm_is_rejected(self):
        with self.assertRaises(SystemExit):
            load("label_malware_types", env={"MALWARE_ARM": "stealth"})

    def test_untyped_worklist_selects_untyped_findings_only(self):
        lmt = load("label_malware_types", env={"MALWARE_ARM": "vmarm"})
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        base = {"zip_file": "z", "packer_label": "themida"}
        verdicts = {
            "a": {**base, "sample_file": "a.exe", "packer_type": "TYPE_I", "type_source": "dynamic",
                  "reps": ["TYPE_I"]},
            "b": {**base, "sample_file": "b.exe", "packer_type": None, "type_source": "unresolved",
                  "reps": ["UNRESOLVED_NO_UNPACKING_OBSERVED"], "rep_diag": [{}]},
            "c": {**base, "sample_file": "c.exe", "packer_type": None,
                  "type_source": "failed:never_started", "reps": [None]},
        }
        for k, v in verdicts.items():
            (d / f"{k}.json").write_text(json.dumps(v))
        rows, certified = lmt.untyped_worklist(d)
        self.assertEqual([r["sample_file"] for r in rows], ["b.exe"])
        self.assertEqual(rows[0], {"zip_file": "z", "packer_label": "themida",
                                   "sample_file": "b.exe"})
        self.assertIs(lmt.certified_verdict_for(rows[0], certified), certified["b.exe"])

    def test_vmarm_verdict_fields(self):
        lmt = load("label_malware_types", env={"MALWARE_ARM": "vmarm"})
        certified = {"sample_file": "b.exe", "packer_type": None, "type_source": "unresolved",
                     "reps": ["UNRESOLVED_NO_UNPACKING_OBSERVED"],
                     "rep_diag": [{"termination": "all_monitored_processes_exited",
                                   "classifier": {"layers": 1}}]}
        result = {"sample_file": "b.exe", "packer_label": "x", "packer_type": "TYPE_III",
                  "type_source": "dynamic", "reps": ["TYPE_III"],
                  "rep_diag": [{"termination": "guest_instruction_budget",
                                "classifier": {"layers": 3},
                                "evasion": ev(True, 2, 10, 10**6)}]}
        out = lmt.vmarm_verdict(result, certified)
        self.assertNotIn("packer_type", out)
        self.assertEqual(out["vm_arm_outcome"], "evasion_confirmed")
        self.assertEqual(out["vm_arm_type"], "TYPE_III")
        self.assertEqual(out["vm_arm_packer_type"], "TYPE_III")
        self.assertTrue(out["evasion_suspected"])
        self.assertIsInstance(out["evidence"], list)
        self.assertIsNone(out["certified"]["packer_type"])
        self.assertEqual(lmt.vmarm_verdict(result, None)["vm_arm_outcome"], "inconclusive")


class PackerArmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_certified_defaults_are_unchanged(self):
        la = load("label_all", env={"LABEL_ARM": ""})
        self.assertEqual(la.RUNS_ROOT, "empirical_results/qemu_runtime/all_runs")
        self.assertFalse(la.VMARM)

    def test_vmarm_selects_certified_unresolved_conditions(self):
        la = load("label_all", env={"LABEL_ARM": "vmarm", "LABEL_DONE_DIR": str(self.tmp)})
        self.assertEqual(la.RUNS_ROOT, "empirical_results/qemu_runtime/vmarm_runs")
        (self.tmp / "u.done").write_text(json.dumps({"label": "UNRESOLVED", "runs": {}}))
        (self.tmp / "t.done").write_text(json.dumps({"label": "TYPE_I", "runs": {}}))
        (self.tmp / "v.done").write_text(json.dumps({"label": "UNRESOLVED", "runs": {}}))
        (self.tmp / "v.vmarm.done").write_text("{}")
        self.assertTrue(la.vmarm_pending("u"))
        self.assertFalse(la.vmarm_pending("t"))
        self.assertFalse(la.vmarm_pending("v"))
        self.assertFalse(la.vmarm_pending("missing"))

    def test_annotate_manifest_keeps_the_certified_label(self):
        la = load("label_all", env={"LABEL_ARM": "vmarm"})
        la.REPO = self.tmp
        la.DONE_DIR = self.tmp / "full_matrix"
        tag = "zz_vmarm_test_condition"
        path = self.tmp / f"manifest/type/empirical_types_{tag}.yaml"
        path.parent.mkdir(parents=True)
        original = {"schema_version": 1, "conditions": [
            {"packer_family": "themida", "packer_version": "3", "label": None,
             "label_status": None}]}
        path.write_text(yaml.safe_dump(original, sort_keys=False))
        result = {"vm_arm_outcome": "evasion_confirmed", "vm_arm_type": "TYPE_III",
                  "vm_arm_type_rule": "max-observed", "label": "UNRESOLVED",
                  "evasion_suspected": True,
                  "evidence": [{"signal": "cpuid_hypervisor_leaf"}, {"signal": "x"},
                               {"signal": "x"}]}
        la.annotate_manifest(tag, result)
        cond = yaml.safe_load(path.read_text())["conditions"][0]
        self.assertIsNone(cond["label"])
        self.assertIsNone(cond["label_status"])
        self.assertEqual(cond["vm_arm"]["outcome"], "evasion_confirmed")
        self.assertEqual(cond["vm_arm"]["type"], "TYPE_III")
        self.assertEqual(cond["vm_arm"]["evidence"], ["cpuid_hypervisor_leaf", "x"])
        self.assertIsNone(la.annotate_manifest("no_such_condition_xyz", result))

    def test_vmarm_result_compares_run_dirs(self):
        la = load("label_all", env={"LABEL_ARM": "vmarm",
                                    "LABEL_CERTIFIED_RUNS_ROOT": "cert",
                                    "LABEL_RUNS_ROOT": "vm"})
        la.REPO = self.tmp
        for arm, label in (("cert", "UNRESOLVED_NO_UNPACKING_OBSERVED"), ("vm", "TYPE_II")):
            for rep_dir in ("tA_rep1", "tB_rep1"):
                d = self.tmp / arm / "t" / rep_dir
                d.mkdir(parents=True)
                (d / "classification.json").write_text(json.dumps(
                    {"complexity_type": label, "layers": 2 if label == "TYPE_II" else 1}))
                (d / "meta.json").write_text(json.dumps(EXITED))
        result = la.vmarm_result("t", "telock", "TYPE_II", {"tA_rep1": "TYPE_II"})
        self.assertEqual(result["vm_arm_outcome"], "evasion_confirmed")
        self.assertEqual(result["vm_arm_type"], "TYPE_II")
        self.assertEqual(result["vm_arm_type_rule"], "exact")

    def test_matrix_runner_rejects_cpu_knobs_in_vmarm(self):
        with mock.patch.object(sys, "argv", ["run_condition_matrix.py"]):
            with self.assertRaises(SystemExit):
                load("run_condition_matrix", env={"LABEL_ARM": "vmarm",
                                                  "LABEL_TRANSPARENT": "1"})
            matrix = load("run_condition_matrix", env={"LABEL_ARM": "vmarm"})
        self.assertTrue(matrix.VMARM)


class LabelDocumentTests(unittest.TestCase):
    def test_vm_arm_rows_only_for_unresolved_conditions(self):
        bld = load("build_label_document")
        corpus = {("themida", "3")}
        cond = {"packer_family": "themida", "packer_version": "3", "test_case_id": "tc",
                "label": None, "vm_arm": {"outcome": "evasion_confirmed", "type": "TYPE_III",
                                          "type_rule": "max-observed",
                                          "evasion_suspected": True,
                                          "evidence": ["cpuid_hypervisor_leaf"]}}
        row = bld.vm_arm_row(cond, corpus)
        self.assertEqual((row["certified"], row["outcome"], row["type"]),
                         ("UNRESOLVED", "evasion_confirmed", "TYPE_III"))
        exact = {**cond, "label": "TYPE_I", "label_status": "empirical_exact_trace_consensus"}
        self.assertIsNone(bld.vm_arm_row(exact, corpus))
        self.assertIsNone(bld.vm_arm_row({**cond, "vm_arm": None}, corpus))
        self.assertIsNone(bld.vm_arm_row(cond, set()))
        lines = bld.vm_arm_section({("themida", "3"): row})
        self.assertTrue(lines[0].startswith("## VM arm"))
        self.assertIn("| themida | 3 | tc | UNRESOLVED | evasion_confirmed | TYPE_III |", lines[-2])
        self.assertEqual(bld.vm_arm_section({}), [])


if __name__ == "__main__":
    unittest.main()
