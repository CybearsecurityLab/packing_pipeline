#!/usr/bin/env python3
"""Merge the deduplicated EMBER2024 Win32 train and test manifests into one list.

EMBER2024 ships every record TWICE: the published Win32 zips carry 3,120,000 train
and 720,000 test lines for 1,560,000 and 359,994 distinct sha256.  The pairs differ
only in `caps`/`ttps`/`mbc` and agree on everything else, so the deduplicated count
is the real one and matches EMBER's own documented totals.  Stock
`thrember.read_metadata()` double-counts.  The per-split manifests this reads are
already deduplicated; this merges them and re-checks.

It also tests for CROSS-SPLIT leakage.  EMBER claims a temporal split (train ends
2024-09-21, test starts 2024-09-22) so no sha256 should appear in both; given the
duplication defect that claim is worth verifying rather than assuming, because a
sha256 in both splits would mean the held-out set is not held out.
"""
from __future__ import annotations

import collections
import csv
import pathlib
import sys

DATA = pathlib.Path("/data/ember2024")
SPLITS = {"train": DATA / "win32_train_manifest.csv",
          "test": DATA / "win32_test_manifest.csv"}
OUT = DATA / "win32_manifest_dedup.csv"
csv.field_size_limit(10 * 1024 * 1024)


def main() -> int:
    seen: dict[str, str] = {}
    dupes_in_split = collections.Counter()
    cross = []
    per_split = collections.Counter()
    labels = collections.Counter()
    packers = collections.Counter()
    fields = None
    rows_written = 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = None
        for split, path in SPLITS.items():
            if not path.exists():
                sys.exit(f"missing {path}")
            with path.open(newline="") as src:
                reader = csv.DictReader(src)
                if writer is None:
                    fields = list(reader.fieldnames)
                    writer = csv.DictWriter(fh, fieldnames=fields)
                    writer.writeheader()
                for row in reader:
                    h = (row.get("sha256") or "").strip().lower()
                    if not h:
                        continue
                    prior = seen.get(h)
                    if prior is not None:
                        if prior == split:
                            dupes_in_split[split] += 1
                        else:
                            cross.append(h)
                        continue
                    seen[h] = split
                    row["split"] = split
                    writer.writerow({k: row.get(k, "") for k in fields})
                    rows_written += 1
                    per_split[split] += 1
                    labels[(split, row.get("label", ""))] += 1
                    p = (row.get("packer") or "").strip()
                    if p:
                        packers[(split, p)] += 1

    print(f"wrote {OUT}")
    print(f"  distinct sha256      : {rows_written}")
    for s in SPLITS:
        print(f"  {s:<6}              : {per_split[s]}")
    print(f"  residual in-split dupes: {dict(dupes_in_split) or 'none'}")
    print(f"  CROSS-SPLIT sha256   : {len(cross)}"
          + (f"  e.g. {cross[:3]}" if cross else "   (no leakage)"))
    for s in SPLITS:
        lab = {k[1]: v for k, v in labels.items() if k[0] == s}
        pk = sum(v for k, v in packers.items() if k[0] == s)
        distinct = len({k[1] for k in packers if k[0] == s})
        print(f"  {s}: labels {lab}, packer-labelled {pk} "
              f"({pk / max(1, per_split[s]) * 100:.2f}%) across {distinct} values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
