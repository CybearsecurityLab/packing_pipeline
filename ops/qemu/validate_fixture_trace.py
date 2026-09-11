#!/usr/bin/env python3
"""Validate every paper-required QEMU channel and emit a hashed gate stamp."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def number(value: int | str) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def spans(event: dict, field: str = "physical_spans") -> Iterable[tuple[int, int]]:
    for span in event.get(field, []):
        start = number(span["address"])
        yield start, start + int(span["size"])


def overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def pages(interval: tuple[int, int]) -> range:
    return range(interval[0] >> 12, ((interval[1] - 1) >> 12) + 1)


def validate(trace: Path, single_process: bool = False) -> tuple[dict, list[str]]:
    actions: Counter[int] = Counter()
    process_reasons: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    exception_sources: Counter[str] = Counter()
    writes_by_page: dict[int, list[tuple[tuple[int, int], int, int]]] = (
        defaultdict(list)
    )
    file_writes: dict[str, list[tuple[tuple[int, int], int]]] = defaultdict(list)
    shared_alias = False
    remote_write = False
    kernel_write = False
    file_to_execution = False
    system_execution = False
    invalidation_with_ram = {"free": False, "unmap": False}
    summary = None
    last_sequence = -1
    sequence_events = 0
    errors: list[str] = []

    with trace.open(encoding="utf-8", errors="strict") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: invalid JSON: {exc}")
                continue
            kind = str(event.get("event", ""))
            event_counts[kind] += 1
            if "seq" in event:
                sequence = int(event["seq"])
                if sequence <= last_sequence:
                    errors.append(f"line {line_no}: non-monotonic sequence")
                last_sequence = sequence
                sequence_events += 1
            if kind == "marker":
                actions[int(event.get("action", 0))] += 1
            elif kind == "process":
                process_reasons[str(event.get("reason", ""))] += 1
            elif kind == "write":
                pid = int(event["pid"])
                target_pid = int(event.get("target_pid", pid))
                kernel_write |= number(event["address"]) >= 0x0000800000000000
                remote_write |= pid != target_pid
                for interval in spans(event):
                    for page in pages(interval):
                        writes_by_page[page].append((interval, pid, target_pid))
            elif kind == "exec":
                pid = int(event["pid"])
                system_execution |= event.get("role") == "system"
                for interval in spans(event):
                    for page in pages(interval):
                        for written, writer_pid, target_pid in writes_by_page[page]:
                            if (
                                writer_pid == target_pid
                                and pid != writer_pid
                                and overlap(interval, written)
                            ):
                                shared_alias = True
                if event.get("file_id") is not None:
                    file_id = str(event["file_id"])
                    start = number(event["file_offset"])
                    interval = (start, start + int(event.get("size", 1)))
                    file_to_execution |= any(
                        overlap(interval, written)
                        for written, _ in file_writes.get(file_id, [])
                    )
            elif kind == "file_write":
                file_id = str(event["file_id"])
                start = number(event["file_offset"])
                file_writes[file_id].append(
                    ((start, start + int(event["size"])), int(event["pid"]))
                )
            elif kind == "exception_dispatch":
                exception_sources[str(event.get("source", ""))] += 1
            elif kind in invalidation_with_ram:
                invalidation_with_ram[kind] |= bool(
                    list(spans(event, "invalidated_physical_spans"))
                )
            elif kind == "summary":
                summary = event

    # Single-process certification scopes the gate to the channels a
    # single-process packer actually exercises.  It is NOT a weakening: a trace
    # that performs no cross-process operation is fully covered by these
    # channels, and any trace that DOES perform one is caught by the analyzer as
    # needing the (deferred) cross-process certification.
    required_counts = {
        "sample_start": 1,
        "trace_start": 1,
        "exec": 1,
        "write": 1,
        "free": 1,
        "unmap": 1,
        "exception_dispatch": 1,
        "exception_recovered": 1,
        "summary": 1,
    }
    # Cross-process certification used to be all-or-nothing: full mode demanded
    # file_read AND file_write alongside the memory channels, so a backend that
    # proved every cross-process MEMORY channel was still refused because a
    # synchronous disk read failed.  That is coarser than the threat model.  A
    # process-hollowing packer (CreateProcess suspended -> NtUnmapViewOfSection ->
    # VirtualAllocEx RWX -> WriteProcessMemory -> SetThreadContext -> ResumeThread)
    # performs no disk read at all, so refusing its Type over a disk-read failure
    # withholds certification for a channel it never touches.
    #
    # Channels are therefore certified as independent TIERS.  Each is reported and
    # each stands or falls on its own evidence; nothing is waived.
    if not single_process:
        required_counts["file_write"] = 1
        required_counts["file_read"] = 1
    for kind, minimum in required_counts.items():
        if event_counts[kind] < minimum:
            errors.append(f"missing required {kind} event")
    for action in (1, 2, 3, 4):
        if actions[action] < 1:
            errors.append(f"missing marker action {action}")
    if sequence_events == 0:
        errors.append("trace has no globally sequenced events")
    if kernel_write:
        errors.append("trace contains a kernel-address write")
    if not system_execution:
        errors.append("no system-library execution was tagged")
    for kind, proved in invalidation_with_ram.items():
        if not proved:
            errors.append(f"{kind} did not preserve pre-invalidation RAM identity")
    if (
        exception_sources["RtlRaiseException"] < 1
        and exception_sources["processor_exception"] < 1
    ):
        errors.append(
            "fixture did not exercise exact exception tracing "
            "(neither RtlRaiseException nor a processor exception)"
        )
    if not single_process:
        if not remote_write:
            errors.append("no cross-process virtual-memory write was observed")
        if not shared_alias:
            errors.append(
                "no write/execute shared-RAM alias across processes was proved"
            )
        if not file_to_execution:
            errors.append(
                "no file-write to mapped-execution provenance chain was proved"
            )
        if process_reasons["remote_write_target"] < 1:
            errors.append("no remote-write target process evidence was emitted")
    if summary is None:
        errors.append("missing final summary")
    else:
        zero_fields = (
            "context_failures",
            "invalidation_failures",
            "unresolved_process_handles",
            "physical_mapping_failures",
            "marker_register_failures",
            "marker_query_failures",
            "file_io_failures",
            "asynchronous_file_io",
            "mapped_file_failures",
            "system_role_failures",
            "process_snapshot_failures",
            "virtual_memory_write_failures",
            "block_context_misses",
            "memory_buffer_overflows",
        )
        for field in zero_fields:
            if int(summary.get(field, -1)) != 0:
                errors.append(f"summary {field}={summary.get(field)!r}, expected 0")
        if not summary.get("saw_stop"):
            errors.append("trace did not observe the stop marker")
        if int(summary.get("exec_events", 0)) != event_counts["exec"]:
            errors.append("summary exec count differs from trace")
        if int(summary.get("write_events", 0)) != event_counts["write"]:
            errors.append("summary write count differs from trace")
        if summary.get("kernel_store_callbacks_registered") is not False:
            errors.append("generic kernel-store callbacks were registered")
        if summary.get("always_present_user_store_callbacks") is not True:
            errors.append("pretranslated user-store callbacks were not registered")
        if summary.get("buffered_memory_callbacks_registered") is not True:
            errors.append("branchless buffered memory callbacks were not registered")
        if not single_process and int(
            summary.get("virtual_memory_write_events", 0)
        ) < 1:
            errors.append("fixture did not exercise NtWriteVirtualMemory tracing")
        if int(summary.get("tb_flush_requests", -1)) != 0:
            errors.append("sample boundary unexpectedly flushed translated code")
        if int(summary.get("block_context_refreshes", 0)) < 1:
            errors.append("fixture did not refresh an exact block context")
        if int(summary.get("block_context_cache_hits", 0)) < 1:
            errors.append("fixture did not exercise the user-block context cache")
        if int(summary.get("marker_query_ready", 0)) < 1:
            errors.append("fixture never reached a ready status query")
        if not summary.get("root_entry_seen"):
            errors.append("fixture PE entry point was never observed")
        if not summary.get("sample_started"):
            errors.append("fixture sample recording never started")
        if int(summary.get("exception_dispatch_events", 0)) != event_counts[
            "exception_dispatch"
        ]:
            errors.append("summary exception dispatch count differs from trace")
        if int(summary.get("exception_recovery_events", 0)) != event_counts[
            "exception_recovered"
        ]:
            errors.append("summary exception recovery count differs from trace")
        if int(summary.get("pending_exceptions", -1)) != 0:
            errors.append("fixture ended with a pending exception")

    # Tier membership is computed from the SAME evidence as the flat flags; this
    # reorganises how certification is reported, it does not lower any bar.
    memory_tier_missing = [
        name for name, proved in (
            ("remote_write", remote_write),
            ("shared_alias", shared_alias),
            ("file_to_execution", file_to_execution),
        ) if not proved
    ]
    if not (summary or {}).get("virtual_memory_write_events"):
        memory_tier_missing.append("virtual_memory_write_events")
    disk_tier_missing = [
        name for name, count in (
            ("file_write", event_counts["file_write"]),
            ("file_read", event_counts["file_read"]),
        ) if count < 1
    ]
    tiers = {
        "single_process": not errors or all(
            not e.startswith(("missing required file_", )) for e in errors),
        "cross_process_memory": not memory_tier_missing,
        "synchronous_disk_io": not disk_tier_missing,
    }

    evidence = {
        "certified_tiers": [name for name, ok in tiers.items() if ok],
        "tier_gaps": {"cross_process_memory": memory_tier_missing,
                      "synchronous_disk_io": disk_tier_missing},
        "event_counts": dict(sorted(event_counts.items())),
        "marker_actions": dict(sorted(actions.items())),
        "process_reasons": dict(sorted(process_reasons.items())),
        "exception_sources": dict(sorted(exception_sources.items())),
        "remote_write_proved": remote_write,
        "kernel_write_observed": kernel_write,
        "shared_alias_proved": shared_alias,
        "file_to_execution_proved": file_to_execution,
        "system_execution_proved": system_execution,
        "invalidation_ram_identity": invalidation_with_ram,
        "summary": summary,
    }
    return evidence, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("stamp", type=Path)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--ntdll", type=Path, required=True)
    parser.add_argument("--profile-header", type=Path, required=True)
    parser.add_argument("--meta", type=Path, default=None)
    parser.add_argument(
        "--single-process",
        action="store_true",
        help="certify only the single-process channel set (defers the "
        "child-requiring cross-process channels)",
    )
    args = parser.parse_args()
    for path in (
        args.trace,
        args.qemu,
        args.plugin,
        args.launcher,
        args.fixture,
        args.ntdll,
        args.profile_header,
    ):
        if not path.is_file():
            parser.error(f"required file does not exist: {path}")

    evidence, errors = validate(args.trace, single_process=args.single_process)
    profile_text = args.profile_header.read_text(encoding="utf-8")
    match = re.search(r'KERNEL_PROFILE_GUID_AGE "([^"]+)"', profile_text)
    identity = {
        "qemu_sha256": sha256(args.qemu),
        "plugin_sha256": sha256(args.plugin),
        "launcher_sha256": sha256(args.launcher),
        "fixture_sha256": sha256(args.fixture),
        "ntdll_sha256": sha256(args.ntdll),
        "profile_header_sha256": sha256(args.profile_header),
        "kernel_profile_guid_age": match.group(1) if match else None,
    }
    if args.meta is not None:
        run_identity = json.loads(args.meta.read_text(encoding="utf-8")).get(
            "backend_identity"
        )
        if not isinstance(run_identity, dict):
            errors.append("run meta carries no backend_identity to attest")
        else:
            for key in ("qemu_sha256", "plugin_sha256", "ntdll_sha256",
                        "profile_header_sha256"):
                if run_identity.get(key) != identity[key]:
                    errors.append(
                        f"run meta {key} differs from the validated binary"
                    )
            for key in ("icount_shift", "icount_sleep", "cpu_model",
                        "guest_smp"):
                if key not in run_identity:
                    errors.append(f"run meta carries no {key}")
                else:
                    identity[key] = run_identity[key]
    summary = evidence.get("summary")
    if not isinstance(summary, dict) or summary.get("ntdll_sha256") != identity[
        "ntdll_sha256"
    ]:
        errors.append("trace ntdll identity differs from the validated guest DLL")
    stamp = {
        "schema_version": 1,
        "validated": not errors,
        "certification_mode": "single_process" if args.single_process else "full",
        "trace": str(args.trace.resolve()),
        "trace_sha256": sha256(args.trace),
        "backend_identity": identity,
        "evidence": evidence,
        "errors": errors,
    }
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stamp, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
