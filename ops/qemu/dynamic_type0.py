#!/usr/bin/env python3
"""Decide TYPE_0 for one traced run from its own evidence.

TYPE_0 = the packer transformed the file but nothing is unpacked at runtime: the
program's own code executes directly from the file. A run qualifies only if all hold:

  1. no write-then-execute: the paper classifier saw a single layer and no
     transitions, and no executed block inside the root image overlaps a write;
  2. a natural end: the guest idled or every monitored process exited (no crash,
     no instruction budget or guest cap, no timeout);
  3. the original program ran: the executed blocks inside the root image match the
     ORIGINAL payload's bytes at the same RVA for at least MATCH_FRACTION of the
     executed image bytes, and at least MIN_EXECUTED_BYTES in MIN_EXECUTED_BLOCKS distinct blocks were executed.

    dynamic_type0.py RUN_DIR --original ORIGINAL.exe --packed PACKED.exe [--output OUT.json]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace_store  # noqa: E402

NATURAL_ENDS = {"two_minutes_idle", "two_minutes_idle_host_observed",
                "all_monitored_processes_exited"}
MATCH_FRACTION = 0.95
MIN_EXECUTED_BYTES = 256
MIN_EXECUTED_BLOCKS = 10


class Image:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional = struct.unpack_from("<H", self.data, pe + 20)[0]
        self.size_of_image = struct.unpack_from("<I", self.data, pe + 24 + 56)[0]
        base = pe + 24 + optional
        self.sections = []
        for i in range(count):
            _, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", self.data, base + 40 * i)
            self.sections.append((va, max(vsize, rsize), rptr, rsize))

    def read(self, rva: int, size: int) -> bytes | None:
        for va, span, rptr, rsize in self.sections:
            if va <= rva and rva + size <= va + span:
                offset = rva - va
                if offset + size > rsize:
                    return None
                return self.data[rptr + offset:rptr + offset + size]
        return None


def scan(trace: Path, packed: Image, original: Image) -> dict:
    root_pid = image_base = None
    blocks: dict[tuple[int, int], None] = {}
    writes: list[tuple[int, int]] = []
    with trace.open("rb") as handle:
        for line in handle:
            if b'"event":"root_image"' in line:
                event = json.loads(line)
                root_pid, image_base = event.get("pid"), event.get("image_base")
                continue
            is_exec = b'"event":"exec"' in line
            if not is_exec and b'"event":"write"' not in line:
                continue
            event = json.loads(line)
            if image_base is None or event.get("pid") != root_pid:
                continue
            address, size = event.get("address", 0), event.get("size", 0)
            if not (image_base <= address < image_base + packed.size_of_image):
                continue
            if is_exec:
                blocks[(address, size)] = None
            else:
                writes.append((address, address + size))
    executed = matched = 0
    written_exec = unmatched_blocks = 0
    writes.sort()
    for address, size in blocks:
        rva = address - image_base
        executed += size
        if any(w0 < address + size and address < w1 for w0, w1 in writes):
            written_exec += 1
        mine, theirs = packed.read(rva, size), original.read(rva, size)
        if mine is not None and mine == theirs:
            matched += size
        else:
            unmatched_blocks += 1
    return {"root_pid": root_pid, "image_base": image_base, "executed_image_blocks": len(blocks),
            "executed_image_bytes": executed, "matched_original_bytes": matched,
            "match_fraction": matched / executed if executed else 0.0,
            "unmatched_blocks": unmatched_blocks, "executed_blocks_overlapping_writes": written_exec}


def decide(run: Path, original: Path, packed: Path) -> dict:
    classification = json.loads((run / "classification.json").read_text())
    meta = json.loads((run / "meta.json").read_text())
    tap = (run / "trace.jsonl.zst").exists() and not (run / "trace.jsonl").exists()
    with trace_store.raw_view(run / "trace.jsonl", tap) as source:
        evidence = scan(source, Image(packed), Image(original))
    checks = {
        "no_write_then_execute": (classification.get("layers") == 1
                                  and not classification.get("forward_transitions")
                                  and evidence["executed_blocks_overlapping_writes"] == 0),
        "natural_end": meta.get("paper_termination_reason") in NATURAL_ENDS,
        "original_code_executed": (evidence["executed_image_bytes"] >= MIN_EXECUTED_BYTES
                                   and evidence["executed_image_blocks"] >= MIN_EXECUTED_BLOCKS
                                   and evidence["match_fraction"] >= MATCH_FRACTION),
    }
    return {"run": run.name, "type0": all(checks.values()), "checks": checks,
            "termination": meta.get("paper_termination_reason"),
            "classifier_type": classification.get("complexity_type"),
            "layers": classification.get("layers"), **evidence}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--packed", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = decide(args.run, args.original, args.packed)
    text = json.dumps(result, indent=1)
    if args.output:
        args.output.write_text(text)
    print(text)
    return 0 if result["type0"] else 1


if __name__ == "__main__":
    sys.exit(main())
