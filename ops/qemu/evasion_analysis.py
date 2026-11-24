#!/usr/bin/env python3
"""Offline evasion analysis of one paper_trace run (VM arm).

Streams trace.jsonl in fixed-size chunks (O(1) memory): only lines carrying
`"event":"evasion_check"` or `"event":"summary"` are decoded, every other event is
counted with bytes.count between check positions. Combines the checks with the
run's termination (meta.json) and the launcher's window list (windows.txt) into a
tiered `evasion_suspected` flag with an evidence list.

    evasion_analysis.py trace.jsonl --meta meta.json [--windows windows.txt] [--output evasion.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import msgspec

    def _decode(line: bytes):
        try:
            return msgspec.json.decode(line)
        except msgspec.DecodeError:
            return None
except ImportError:
    def _decode(line: bytes):
        try:
            return json.loads(line)
        except ValueError:
            return None

SCHEMA_VERSION = 1
CHUNK_BYTES = 16 * 1024 * 1024
FIRST_CHECKS = 32
RED_ORIGINS = frozenset({"sample", "dynamic"})

HIGH, MEDIUM, LOW = "high", "medium", "low"
TIER_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}

CHECK_MARKER = b'"event":"evasion_check"'
SUMMARY_MARKER = b'"event":"summary"'
ACTIVITY_MARKERS = {
    "exec": b'"event":"exec"',
    "write": b'"event":"write"',
    "file_write": b'"event":"file_write"',
    "process": b'"event":"process"',
}

SHORT_EXEC_BLOCKS = 100_000
LONG_SLEEP_MS = 250_000

NATURAL_OUTCOMES = frozenset({"exited", "crashed", "idled"})
TERMINATION_OUTCOME = {
    "all_monitored_processes_exited": "exited",
    "unrecovered_exception_two_minutes": "crashed",
    "two_minutes_idle": "idled",
    "two_minutes_idle_host_observed": "idled",
    "unpacking_settled_write_idle": "idled",
    "instruction_budget": "budget",
    "guest_instruction_budget": "budget",
    "maximum_30_minute_timeout": "timeout",
    "maximum_timeout_host": "timeout",
    "no_execution_launch_failed": "failed",
    "backend_failure_no_summary": "failed",
    "status_query_failure": "failed",
    "monitor_resume_failed": "failed",
}

FIRMWARE_PROVIDERS = frozenset({"RSMB", "ACPI", "FIRM"})
SYSTEM_FIRMWARE_TABLE_INFORMATION = 76
SYSTEM_PROCESS_INFORMATION = 5
SYSTEM_BASIC_INFORMATION = 0
DEBUG_PROCESS_INFO_CLASSES = frozenset({7, 0x1E, 0x1F})
VMWARE_PORT = 0x5658
VMWARE_MAGIC = 0x564D5868

REGISTRY_SERVICES = frozenset({
    "ntopenkey", "ntopenkeyex", "ntcreatekey", "ntqueryvaluekey", "ntquerykey",
    "ntenumeratekey", "ntenumeratevaluekey", "ntquerymultiplevaluekey",
})
VM_REGISTRY_PATTERNS = (
    "vmware", "vbox", "virtualbox", "qemu", "bochs", "\\xen", "xenservice",
    "xenvdb", "virtio", "vmtools", "vmmouse", "vmhgfs", "vmci", "parallels",
    "sandboxie", "\\wine", "microsoft\\virtual machine\\guest",
    "hyper-v", "vmbus", "acpi\\dsdt\\vbox", "acpi\\fadt\\vbox", "acpi\\rsdt\\vbox",
)
HARDWARE_REGISTRY_PATTERNS = (
    "systembiosversion", "systembiosdate", "videobiosversion", "processornamestring",
    "enum\\ide", "enum\\scsi", "description\\system\\bios",
    "systemmanufacturer", "systemproductname", "baseboardmanufacturer",
    "scsi port 0\\scsi bus 0",
)
CURSOR_SERVICES = frozenset({"ntusergetcursorpos", "ntusergetcursorinfo",
                             "ntusergetlastinputinfo"})
WINDOW_SERVICES = frozenset({"ntuserbuildhwndlist", "ntuserfindwindowex",
                             "ntuserenumwindows"})
SIZE_SERVICES = frozenset({"ntqueryvolumeinformationfile", "ntqueryfullattributesfile",
                           "ntdeviceiocontrolfile", "ntglobalmemorystatus"})

VM_WINDOW_RE = re.compile(
    r"virtual\s*machine|virtual\s*environment|virtuali[sz]ed|vmware|virtualbox|vbox|"
    r"qemu|hypervisor|debugger|debugging|sandbox|emulat(?:or|ed|ion)|"
    r"can(?:not|'t|\s+not)\s+(?:be\s+)?run|unable\s+to\s+run|"
    r"monitoring\s+(?:tool|software)|analysis\s+(?:tool|environment)",
    re.IGNORECASE)


def _num(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _text(detail: dict, *keys: str) -> str:
    return " ".join(str(detail[k]) for k in keys if detail.get(k) is not None)


def _service(detail: dict) -> str:
    return str(detail.get("service") or detail.get("name")
               or detail.get("syscall") or "").strip().lower()


def _provider(detail: dict) -> str | None:
    raw = detail.get("provider")
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw.to_bytes(4, "big").decode("latin-1", errors="replace").upper()
    text = str(raw).strip()
    number = _num(text) if text.lower().startswith("0x") else None
    if number is not None:
        return number.to_bytes(4, "big").decode("latin-1", errors="replace").upper()
    return text.upper()


def _sleep_ms(detail: dict) -> int:
    for key in ("delay_ms", "interval_ms", "milliseconds"):
        value = _num(detail.get(key))
        if value is not None:
            return max(0, value)
    interval = _num(detail.get("interval"))
    if interval is not None:
        return abs(interval) // 10_000
    return 0


def classify_check(event: dict) -> list[tuple[str, str]]:
    """(signal_id, tier) pairs for one red-area evasion_check event."""
    kind = str(event.get("kind") or "")
    detail = event.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    if kind == "cpuid":
        leaf = _num(detail.get("leaf", detail.get("eax")))
        if leaf is not None and 0x40000000 <= leaf <= 0x400000FF:
            return [("cpuid_hypervisor_leaf", HIGH)]
        if leaf == 1:
            return [("cpuid_leaf1", LOW)]
        if leaf is not None and 0x80000002 <= leaf <= 0x80000004:
            return [("cpuid_brand_string", LOW)]
        if leaf == 0:
            return [("cpuid_vendor", LOW)]
        return [("cpuid_other", LOW)]
    if kind == "rdtsc_pair":
        if detail.get("feeds_branch") is False:
            return [("rdtsc_pair", LOW)]
        return [("rdtsc_pair_branch", MEDIUM)]
    if kind == "descriptor_table":
        return [("descriptor_table_probe", HIGH)]
    if kind == "io_port":
        port = _num(detail.get("port", detail.get("dx")))
        magic = _num(detail.get("eax", detail.get("magic")))
        if port == VMWARE_PORT or magic == VMWARE_MAGIC:
            return [("vmware_backdoor_port", HIGH)]
        return [("io_port_probe", MEDIUM)]
    if kind == "hypercall":
        return [("hypercall_probe", HIGH)]
    if kind in ("int2d", "icebp"):
        if detail.get("handler_origin") in RED_ORIGINS or detail.get("resumed") is True:
            return [(f"illegal_opcode_probe_{kind}", HIGH)]
        return [(f"anti_debug_{kind}", MEDIUM)]
    if kind == "syscall":
        return _classify_syscall(detail)
    return []


def _classify_syscall(detail: dict) -> list[tuple[str, str]]:
    service = _service(detail)
    if service in ("ntquerysysteminformation", "ntquerysysteminformationex"):
        info_class = _num(detail.get("info_class", detail.get("class")))
        if info_class == SYSTEM_FIRMWARE_TABLE_INFORMATION or (
                _provider(detail) in FIRMWARE_PROVIDERS):
            return [("firmware_table_query", HIGH)]
        if info_class == SYSTEM_PROCESS_INFORMATION:
            return [("process_enumeration", LOW)]
        if info_class == SYSTEM_BASIC_INFORMATION:
            return [("hardware_size_query", LOW)]
        return []
    if service in REGISTRY_SERVICES:
        path = _text(detail, "key", "path", "name", "value", "value_name").lower()
        if any(p in path for p in VM_REGISTRY_PATTERNS):
            return [("vm_registry_key", HIGH)]
        if any(p in path for p in HARDWARE_REGISTRY_PATTERNS):
            return [("hardware_registry_query", MEDIUM)]
        return []
    if service == "ntqueryinformationprocess":
        if _num(detail.get("info_class", detail.get("class"))) in DEBUG_PROCESS_INFO_CLASSES:
            return [("debugger_query", MEDIUM)]
        return []
    if service in CURSOR_SERVICES:
        return [("cursor_polling", LOW)]
    if service in WINDOW_SERVICES:
        return [("window_enumeration", LOW)]
    if service in SIZE_SERVICES:
        return [("hardware_size_query", LOW)]
    return []


def _brief(event: dict) -> dict:
    return {k: event.get(k) for k in ("seq", "kind", "origin", "pid", "pc", "detail")
            if event.get(k) is not None}


class _Scan:
    def __init__(self) -> None:
        self.totals = Counter()
        self.first_red_totals: Counter | None = None
        self.last_red_totals: Counter | None = None
        self.checks = 0
        self.by_kind: Counter = Counter()
        self.by_origin: Counter = Counter()
        self.by_kind_origin: Counter = Counter()
        self.first_checks: list[dict] = []
        self.first_red: dict | None = None
        self.signals: dict[str, dict] = {}
        self.sleep_ms = 0
        self.terminate_status: int | None = None
        self.undecodable_checks = 0
        self.summary: dict | None = None
        self.bytes = 0

    def count(self, data: bytes, start: int, end: int) -> None:
        if end <= start:
            return
        for name, marker in ACTIVITY_MARKERS.items():
            n = data.count(marker, start, end)
            if n:
                self.totals[name] += n

    def check(self, line: bytes) -> None:
        event = _decode(line)
        if not isinstance(event, dict):
            self.undecodable_checks += 1
            return
        self.checks += 1
        kind = str(event.get("kind") or "?")
        origin = str(event.get("origin") or "?")
        self.by_kind[kind] += 1
        self.by_origin[origin] += 1
        self.by_kind_origin[f"{kind}/{origin}"] += 1
        if len(self.first_checks) < FIRST_CHECKS:
            self.first_checks.append(_brief(event))
        if origin not in RED_ORIGINS:
            return
        if self.first_red is None:
            self.first_red = _brief(event)
            self.first_red_totals = Counter(self.totals)
        self.last_red_totals = Counter(self.totals)
        detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
        if kind == "syscall":
            service = _service(detail)
            if service == "ntdelayexecution":
                self.sleep_ms += _sleep_ms(detail)
            elif service == "ntterminateprocess":
                status = _num(detail.get("status", detail.get("exit_status")))
                if status is not None:
                    self.terminate_status = status
        for signal, tier in classify_check(event):
            self._signal(signal, tier, _brief(event))

    def _signal(self, signal: str, tier: str, first: dict) -> None:
        entry = self.signals.get(signal)
        if entry is None:
            self.signals[signal] = {"tier": tier, "count": 1, "first": first}
        else:
            entry["count"] += 1

    def summary_line(self, data, at: int, limit: int) -> None:
        start = data.rfind(b"\n", 0, at) + 1
        end = data.find(b"\n", at, limit)
        event = _decode(bytes(data[start:end if end >= 0 else limit]))
        if isinstance(event, dict):
            self.summary = event


def _process(scan: _Scan, data, size: int) -> None:
    position = 0
    while True:
        hit = data.find(CHECK_MARKER, position, size)
        if hit < 0:
            scan.count(data, position, size)
            break
        start = data.rfind(b"\n", 0, hit) + 1
        end = data.find(b"\n", hit, size)
        end = size if end < 0 else end + 1
        scan.count(data, position, start)
        scan.check(bytes(data[start:end]))
        position = end
    hit = data.rfind(SUMMARY_MARKER, 0, size)
    if hit >= 0:
        scan.summary_line(data, hit, size)


def scan_trace(path: Path, chunk_bytes: int = CHUNK_BYTES) -> _Scan:
    scan = _Scan()
    buf = bytearray(chunk_bytes)
    filled = 0
    with Path(path).open("rb", buffering=0) as handle:
        while True:
            if filled == len(buf):
                buf.extend(bytes(len(buf)))
            with memoryview(buf) as view:
                count = handle.readinto(view[filled:])
            scan.bytes += count
            if not count:
                if filled:
                    _process(scan, buf, filled)
                break
            filled += count
            cut = buf.rfind(b"\n", 0, filled)
            if cut < 0:
                continue
            _process(scan, buf, cut + 1)
            tail = filled - cut - 1
            buf[:tail] = buf[cut + 1:filled]
            filled = tail
    return scan


def read_windows(path: Path | None) -> list[str] | None:
    if path is None or not Path(path).is_file():
        return None
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def vm_window_titles(titles: list[str] | None) -> list[str]:
    return [t for t in (titles or []) if VM_WINDOW_RE.search(t)]


def termination(meta: dict | None, terminate_status: int | None) -> dict:
    meta = meta or {}
    reason = meta.get("paper_termination_reason")
    outcome = TERMINATION_OUTCOME.get(reason, "unknown") if reason else "unknown"
    exit_code = meta.get("guest_exit_code")
    codes = [c for c in (exit_code, terminate_status) if isinstance(c, int)]
    if outcome == "exited" and any(c >= 0xC0000000 for c in codes):
        outcome = "crashed"
    if meta.get("guest_unrecovered_exception"):
        outcome = "crashed"
    return {"reason": reason, "outcome": outcome, "guest_exit_code": exit_code,
            "terminate_status": terminate_status}


def _delta(after: Counter, before: Counter | None) -> dict | None:
    if before is None:
        return None
    return {name: after[name] - before[name] for name in ACTIVITY_MARKERS}


def decide(signals: dict[str, dict], term: dict, after_last: dict | None,
           vm_windows: list[str]) -> tuple[bool, bool, bool, list[dict]]:
    """Return (evasion_suspected, outcome_anomaly, ended_shortly_after_check, evidence)."""
    shortly = bool(after_last is not None
                   and term["outcome"] in NATURAL_OUTCOMES
                   and after_last["exec"] <= SHORT_EXEC_BLOCKS
                   and after_last["file_write"] == 0
                   and after_last["process"] == 0)
    anomaly = shortly or bool(vm_windows and term["outcome"] in NATURAL_OUTCOMES)
    evidence: list[dict] = []
    for title in vm_windows:
        evidence.append({"signal": "vm_detection_window", "tier": HIGH, "title": title})
    ordered = sorted(signals.items(), key=lambda kv: (TIER_RANK[kv[1]["tier"]], kv[0]))
    highs = [(s, e) for s, e in ordered if e["tier"] == HIGH]
    mediums = [(s, e) for s, e in ordered if e["tier"] == MEDIUM]
    lows = [(s, e) for s, e in ordered if e["tier"] == LOW]
    suspected = bool(highs or vm_windows)
    contributing = list(highs)
    if anomaly and mediums:
        suspected = True
        contributing += mediums
    if anomaly and len(mediums) + len(lows) >= 3:
        suspected = True
        contributing += [x for x in mediums if x not in contributing] + lows
    for signal, entry in contributing:
        evidence.append({"signal": signal, "tier": entry["tier"], "count": entry["count"],
                         "first": entry["first"]})
    if suspected and anomaly:
        evidence.append({"signal": "outcome_anomaly", "tier": "outcome",
                         "outcome": term["outcome"], "reason": term["reason"],
                         "after_last_check": after_last})
    return suspected, anomaly, shortly, evidence


def analyse(trace: Path, meta: dict | None = None, windows: list[str] | None = None,
            chunk_bytes: int = CHUNK_BYTES) -> dict:
    scan = scan_trace(trace, chunk_bytes)
    signals = dict(scan.signals)
    if scan.sleep_ms >= LONG_SLEEP_MS:
        signals["long_sleep"] = {"tier": MEDIUM, "count": 1,
                                 "first": {"sleep_ms_total": scan.sleep_ms}}
    term = termination(meta, scan.terminate_status)
    after_first = _delta(scan.totals, scan.first_red_totals)
    after_last = _delta(scan.totals, scan.last_red_totals)
    vm_windows = vm_window_titles(windows)
    suspected, anomaly, shortly, evidence = decide(signals, term, after_last, vm_windows)
    return {
        "schema_version": SCHEMA_VERSION,
        "trace": str(trace),
        "trace_bytes": scan.bytes,
        "checks_total": scan.checks,
        "red_checks_total": sum(n for k, n in scan.by_origin.items() if k in RED_ORIGINS),
        "undecodable_checks": scan.undecodable_checks,
        "checks_by_kind": dict(scan.by_kind),
        "checks_by_origin": dict(scan.by_origin),
        "checks_by_kind_origin": dict(scan.by_kind_origin),
        "first_checks": scan.first_checks,
        "first_red_check": scan.first_red,
        "activity": {
            "total": {name: scan.totals[name] for name in ACTIVITY_MARKERS},
            "before_first_red_check": (
                {name: scan.first_red_totals[name] for name in ACTIVITY_MARKERS}
                if scan.first_red_totals is not None else None),
            "after_first_red_check": after_first,
            "after_last_red_check": after_last,
        },
        "summary_exec_events": (scan.summary or {}).get("exec_events"),
        "sleep_ms_total": scan.sleep_ms,
        "termination": term,
        "ended_shortly_after_check": shortly,
        "outcome_anomaly": anomaly,
        "window_titles": windows,
        "vm_window_titles": vm_windows,
        "signals": signals,
        "evasion_suspected": suspected,
        "evidence": evidence,
    }


def compact(analysis: dict) -> dict:
    """The subset carried in campaign verdicts (no per-check listings)."""
    activity = analysis.get("activity") or {}
    return {
        "evasion_suspected": analysis.get("evasion_suspected"),
        "evidence": [{k: v for k, v in e.items() if k != "first"}
                     for e in analysis.get("evidence") or []],
        "checks_by_kind_origin": analysis.get("checks_by_kind_origin"),
        "red_checks_total": analysis.get("red_checks_total"),
        "termination": analysis.get("termination"),
        "outcome_anomaly": analysis.get("outcome_anomaly"),
        "ended_shortly_after_check": analysis.get("ended_shortly_after_check"),
        "exec_before_first_red_check": (activity.get("before_first_red_check")
                                        or {}).get("exec"),
        "exec_after_first_red_check": (activity.get("after_first_red_check")
                                       or {}).get("exec"),
        "exec_total": (activity.get("total") or {}).get("exec"),
        "vm_window_titles": analysis.get("vm_window_titles"),
        "signals": sorted(analysis.get("signals") or {}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--meta", type=Path)
    parser.add_argument("--windows", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    meta = None
    if args.meta and args.meta.is_file():
        try:
            meta = json.loads(args.meta.read_text(encoding="utf-8"))
        except ValueError:
            meta = None
    result = analyse(args.trace, meta, read_windows(args.windows))
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
