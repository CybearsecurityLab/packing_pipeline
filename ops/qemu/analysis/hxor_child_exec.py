#!/usr/bin/env python3
"""Answer one question about a hollowing trace: did the injected child ever
execute the code that was written into it?

Reports, per process: exec/write counts, whether any executed page had no file
provenance (anonymous -> unpacked), and every cross-process write whose target
physical page is later executed by the target process (the W->X pair that a
RunPE hollow produces).  Run on a retained trace.jsonl.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

PAGE = 0xFFFFFFFFFFFFF000


def main(path: str) -> int:
    execs = defaultdict(int)
    writes = defaultdict(int)
    anon_exec = defaultdict(int)
    exec_pages = defaultdict(set)
    first_exec = {}
    cross = []
    procs = {}
    roots = {}
    for line in open(path):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        ev = e.get("event")
        if ev == "exec":
            pid = e["pid"]
            execs[pid] += 1
            if e.get("file_id") in (None, 0):
                anon_exec[pid] += 1
            for s in e.get("physical_spans", ()):
                exec_pages[pid].add(s["address"] & PAGE)
            first_exec.setdefault(pid, (e["seq"], e["address"]))
        elif ev == "write":
            pid = e["pid"]
            writes[pid] += 1
            tgt = e.get("target_pid")
            if tgt is not None and tgt != pid:
                for s in e.get("physical_spans", ()):
                    cross.append((e["seq"], pid, tgt, s["address"] & PAGE,
                                  e.get("address")))
        elif ev == "process":
            procs[e["pid"]] = e.get("reason")
        elif ev == "root_image":
            roots[e["pid"]] = (e.get("image_base"), e.get("entrypoint"))

    print(f"trace: {path}")
    print(f"processes: {procs}")
    print(f"root_image: {roots}")
    print(f"{'pid':>7} {'execs':>10} {'writes':>10} {'anon_exec':>10}  first_exec")
    for pid in sorted(set(execs) | set(writes)):
        fe = first_exec.get(pid)
        fes = f"seq={fe[0]} pc=0x{fe[1]:x}" if fe else "-"
        print(f"{pid:>7} {execs[pid]:>10} {writes[pid]:>10} "
              f"{anon_exec[pid]:>10}  {fes}")

    confirmed = [c for c in cross if (c[3] in exec_pages.get(c[2], ()))]
    print(f"\ncross-process writes: {len(cross)}")
    print(f"cross-process writes to a page the TARGET later executes: "
          f"{len(confirmed)}")
    seen = set()
    for seq, src, tgt, phys, va in confirmed[:20]:
        key = (src, tgt, phys)
        if key in seen:
            continue
        seen.add(key)
        print(f"  seq={seq} pid {src} -> pid {tgt} phys=0x{phys:x} va=0x{va:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
