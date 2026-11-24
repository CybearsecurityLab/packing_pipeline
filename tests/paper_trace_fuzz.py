from __future__ import annotations

import dataclasses
import json
import random
from pathlib import Path

from empirical_types import paper

PIDS = (100, 200, 300)
TIDS = (1, 2)
PAGES = (0x1000, 0x2000, 0x9000, 0x20000, 0x21000, 0x50000, 0x7FF000)
PHYSICAL = (0x100000, 0x100020, 0x200000, 0x300000)
FILE_IDS = (7, 18446744073709551615, "f", "g", "7")


def _number(rng: random.Random, value: int):
    roll = rng.random()
    if roll < 0.05:
        return hex(value)
    if roll < 0.07:
        return str(value)
    return value


def _address(rng: random.Random) -> int:
    return rng.choice(PAGES) + rng.choice((0, 0, 1, 4, 8, 16, 60, 4090))


def _size(rng: random.Random) -> int:
    roll = rng.random()
    if roll < 0.04:
        return 0
    if roll < 0.08:
        return rng.randint(9, 40)
    return rng.randint(1, 8)


def _spans(rng: random.Random, size: int, key: str, partial: bool, faults: bool = False):
    if size == 0:
        return [] if rng.random() < 0.5 else None
    base = rng.choice(PHYSICAL) + rng.randint(0, 12)
    cuts = sorted(rng.sample(range(1, size), min(size - 1, rng.randint(0, 2)))) if size > 1 else []
    bounds = [0, *cuts, size]
    spans = []
    for left, right in zip(bounds, bounds[1:]):
        address = base + left if rng.random() < 0.7 else rng.choice(PHYSICAL) + left
        spans.append({"offset": left, "size": right - left, "address": _number(rng, address)})
    if partial:
        spans = [span for span in spans if rng.random() < 0.6]
    roll = rng.random() if faults else 1.0
    if roll < 0.2 and spans:
        spans.append(dict(spans[0]))
    elif roll < 0.4 and spans:
        spans[0] = {**spans[0], "size": spans[0]["size"] + size}
    elif roll < 0.6 and len(spans) > 1 and not partial:
        spans.pop()
    elif roll < 0.7 and spans:
        spans[0] = {key: value for key, value in spans[0].items() if key != "address"}
    rng.shuffle(spans)
    return spans


def _event(rng: random.Random, faults: bool) -> dict | str:
    pid = rng.choices(PIDS, weights=(6, 2, 1))[0]
    tid = rng.choice(TIDS)
    kinds = [
        ("exec", 40), ("write", 25), ("file_write", 4), ("file_read", 3),
        ("unmap", 2), ("free", 2), ("invalidate", 2), ("process", 1),
        ("marker", 1), ("root_image", 0.5), ("descendant_debug", 1),
        ("summary", 0.3), ("register_handles", 0.3), ("sample_start", 0.2),
        ("trace_start", 0.2), ("exception_dispatch", 0.2), ("root_debug", 0.1),
        ("prestart_exec", 0.2), ("exception_recovered", 0.1),
        ("evasion_check", 0.5),
    ]
    if faults:
        kinds += [("unknown", 8), ("malformed", 8)]
    kind = rng.choices([k for k, _ in kinds], weights=[w for _, w in kinds])[0]
    if kind == "malformed":
        return rng.choice(['{"event":"exec","pid":1', '{"event":', "not json", '{"a":1,}', '{"pid":1}{'])
    if kind == "unknown":
        return {"event": rng.choice(["virtual_memory_write", "mystery", 5, None, True, "Exec"]),
                "pid": pid, "tid": tid}
    event: dict = {"event": kind}
    if kind == "exec":
        size = _size(rng)
        event.update(pid=pid, tid=tid, address=_number(rng, _address(rng)), size=size)
        roll = rng.random()
        if roll < 0.75:
            spans = _spans(rng, size, "address", False, faults)
            if spans is not None:
                event["physical_spans"] = spans
        elif roll < 0.85:
            event["physical_address"] = _number(rng, rng.choice(PHYSICAL))
        if rng.random() < 0.35:
            event["file_id"] = rng.choice(FILE_IDS)
            event["file_offset"] = _number(rng, rng.randint(0, 24))
        elif rng.random() < 0.05:
            event["file_id"] = None
        roll = rng.random()
        if roll < 0.1:
            event["role"] = "system"
        elif roll < 0.15:
            event["role"] = rng.choice(["application", "packer", None])
    elif kind == "write":
        size = _size(rng)
        event.update(pid=pid, tid=tid, address=_number(rng, _address(rng)), size=size)
        if rng.random() < 0.85:
            event["target_pid"] = pid if rng.random() < 0.7 else rng.choice(PIDS)
        if rng.random() < 0.7:
            spans = _spans(rng, size, "address", False)
            if spans is not None:
                event["physical_spans"] = spans
        elif rng.random() < 0.3:
            event["physical_address"] = rng.choice(PHYSICAL)
        if rng.random() < 0.05:
            event["source_layer"] = rng.randint(0, 3)
        if rng.random() < 0.03:
            event["role"] = "system"
    elif kind == "file_write":
        event.update(pid=pid, tid=tid, file_id=rng.choice(FILE_IDS),
                     file_offset=_number(rng, rng.randint(0, 20)), size=_size(rng))
        if rng.random() < 0.5:
            event["target_pid"] = pid
    elif kind == "file_read":
        size = _size(rng)
        event.update(pid=pid, tid=tid, address=_number(rng, _address(rng)), size=size,
                     file_id=rng.choice(FILE_IDS), file_offset=_number(rng, rng.randint(0, 20)))
        if rng.random() < 0.8:
            event["target_pid"] = pid if rng.random() < 0.6 else rng.choice(PIDS)
        if rng.random() < 0.3:
            spans = _spans(rng, size, "address", False)
            if spans is not None:
                event["physical_spans"] = spans
    elif kind in {"unmap", "free", "invalidate"}:
        size = rng.choice((_size(rng), 4096, 64))
        address = rng.choice(PAGES) if size >= 64 else _address(rng)
        event.update(pid=pid, tid=tid, address=_number(rng, address), size=size)
        if rng.random() < 0.8:
            event["target_pid"] = pid if rng.random() < 0.7 else rng.choice(PIDS)
        if rng.random() < 0.7 and size <= 64:
            spans = _spans(rng, size, "address", True, faults)
            if spans is not None:
                event["invalidated_physical_spans"] = spans
    elif kind == "process":
        event.update(pid=rng.choice(PIDS), parent_pid=rng.choice(PIDS),
                     reason=rng.choice(["root_marker", "child", "injected", 3]))
        if rng.random() < 0.2:
            del event["reason"]
    elif kind == "marker":
        event.update(pid=rng.choice(PIDS), action=rng.choice([1, 1, 2, 4]), detail=rng.randint(0, 9))
        if rng.random() < 0.1:
            del event["action"]
    elif kind == "root_image":
        event.update(pid=rng.choice(PIDS), image_base=0x1000, entrypoint=0x1000)
    elif kind == "descendant_debug":
        event.update(pid=rng.choice(PIDS), parent_pid=rng.choice([*PIDS, True, "100", None]),
                     after_cutoff=rng.choice([True, False, 1, None]),
                     job_matches=rng.choice([True, False, 1]))
    elif kind == "summary":
        event.update(exec_events=rng.randint(0, 100), saw_stop=True, ratio=0.5)
    elif kind == "register_handles":
        event.update(vcpu=0, rax=True)
    elif kind == "evasion_check":
        event.update(pid=pid, tid=tid, pc=hex(_address(rng)),
                     kind=rng.choice(["cpuid", "syscall", "rdtsc_pair"]),
                     origin=rng.choice(["system", "sample", "dynamic"]),
                     detail={"leaf": "0x40000000", "flagged": True,
                             "path": "\\Registry\\Machine\\HARDWARE"})
    else:
        event.update(pid=pid, tid=tid, address=_address(rng))
    if faults:
        roll = rng.random()
        if roll < 0.15 and "tid" in event:
            del event["tid"]
        elif roll < 0.25 and "pid" in event:
            event["pid"] = float(event["pid"])
        elif roll < 0.35 and "address" in event:
            del event["address"]
        elif roll < 0.4 and "file_offset" in event:
            del event["file_offset"]
        elif roll < 0.45 and "size" in event:
            event["size"] = rng.choice([-1, 2.0, "4", None])
        elif roll < 0.5 and "pid" in event:
            event["pid"] = str(event["pid"])
    return event


def generate_trace(seed: int) -> bytes:
    rng = random.Random(seed)
    lines: list[str] = []
    seq = 0
    use_seq = rng.random() < 0.8
    if rng.random() < 0.8:
        lines.append(json.dumps({"event": "process", "seq": 1, "pid": 100,
                                 "parent_pid": 0, "reason": "root_marker"}))
        seq = 1
    count = rng.randint(0, 120)
    fault_at = rng.randrange(count) if count and rng.random() < 0.3 else -1
    for index in range(count):
        event = _event(rng, index == fault_at)
        if isinstance(event, str):
            lines.append(event)
            continue
        if use_seq and rng.random() < 0.98:
            seq += rng.choice((1, 1, 1, 2))
            if index == fault_at and rng.random() < 0.2:
                seq -= 3
            event = {"seq": seq, **event}
        text = json.dumps(event)
        if rng.random() < 0.01:
            text = "  " + text + " "
        lines.append(text)
        if rng.random() < 0.01:
            lines.append(rng.choice(["", "   ", "\t"]))
    body = "\n".join(lines)
    roll = rng.random()
    if roll < 0.3 and lines:
        body += "\n"
    elif roll < 0.6:
        tail = json.dumps({"seq": seq + 1, "event": "exec", "pid": 100, "tid": 1,
                           "address": 0x1000, "size": 4})
        body += "\n" + tail[: rng.randint(1, len(tail) - 1)]
    elif roll < 0.65:
        body += "\n" + "{\"event\":\"exec\"" + "\n"
    elif roll < 0.68:
        body += "\n\n   "
    return body.encode()


def outcome_python(path: Path):
    try:
        evidence = paper._analyze_paper_jsonl_python(path, "s")
    except Exception as error:
        return ("error", type(error).__name__, str(error))
    return ("ok", json.loads(json.dumps(dataclasses.asdict(evidence), default=repr, sort_keys=True)))


def outcome_core(binary: Path, path: Path):
    try:
        evidence = paper._analyze_paper_jsonl_core(binary, path, "s")
    except paper._PaperCoreFallback:
        return ("fallback",)
    except Exception as error:
        return ("error", type(error).__name__, str(error))
    return ("ok", json.loads(json.dumps(dataclasses.asdict(evidence), default=repr, sort_keys=True)))


def _features(result: dict):
    checks = {
        "layers>=2": result["layers"] >= 2,
        "layers>=3": result["layers"] >= 3,
        "processes>1": result["processes"] > 1,
        "frames>1": len(result["frame_sizes"]) > 1,
        "nonzero_frame_size": any(result["frame_sizes"]),
        "multiframe_bytes": result["candidate_multiframe_bytes"] > 0,
        "repacked": result["repacked_original_bytes"] > 0,
        "backward": result["backward_transitions"] > 0,
        "tail": result["tail_transition"],
        "interleaved": result["interleaved"],
        "all_packer": result["all_code_flagged_packer"],
        "linear": result["linear_transition_model"],
        "cross_process": result["cross_process_activity"],
        "ratio_none": result["original_multiframe_ratio"] is None,
    }
    return [name for name, hit in checks.items() if hit]


def run(binary: Path, directory: Path, seeds) -> dict:
    stats = {"cases": 0, "ok": 0, "errors": 0, "fallbacks": 0, "kinds": {},
             "coverage": {}, "mismatches": []}
    for seed in seeds:
        path = directory / f"trace_{seed}.jsonl"
        path.write_bytes(generate_trace(seed))
        expected = outcome_python(path)
        actual = outcome_core(binary, path)
        stats["cases"] += 1
        label = expected[1] if expected[0] == "error" else "ok"
        stats["kinds"][label] = stats["kinds"].get(label, 0) + 1
        if expected[0] == "ok":
            for feature in _features(expected[1]):
                stats["coverage"][feature] = stats["coverage"].get(feature, 0) + 1
        if actual == ("fallback",):
            stats["fallbacks"] += 1
            actual = outcome_python(path)
        elif actual[0] == "error":
            stats["errors"] += 1
        else:
            stats["ok"] += 1
        if actual != expected:
            stats["mismatches"].append((seed, expected, actual))
        else:
            path.unlink()
    return stats


if __name__ == "__main__":
    import sys
    import tempfile

    binary = paper._paper_core_binary()
    if binary is None:
        raise SystemExit("paper core binary not found")
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    keep = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(tempfile.mkdtemp(prefix="paper_fuzz_"))
    keep.mkdir(parents=True, exist_ok=True)
    result = run(binary, keep, range(start, start + count))
    print(json.dumps({k: v for k, v in result.items() if k != "mismatches"}))
    for seed, expected, actual in result["mismatches"][:20]:
        print("MISMATCH", seed, keep / f"trace_{seed}.jsonl")
        print("  python:", expected)
        print("  core:  ", actual)
