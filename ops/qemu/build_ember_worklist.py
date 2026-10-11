#!/usr/bin/env python3
from __future__ import annotations

import collections
import csv
import json
import pathlib

MANIFEST = pathlib.Path("/data/ember2024/testset_manifest.csv")
OUT = pathlib.Path("/data/ember2024/worklist.jsonl")
csv.field_size_limit(10 * 1024 * 1024)


def main() -> int:
    rows = list(csv.DictReader(MANIFEST.open()))
    kept, skipped = [], collections.Counter()
    for row in rows:
        if row.get("ft_status") != "ok":
            skipped[row.get("ft_status", "?")] += 1
            continue
        if row.get("file_type") != "Win32":
            skipped[row.get("file_type") or "unknown"] += 1
            continue
        if str(row.get("sha256_verified")).lower() != "true":
            skipped["sha256_unverified"] += 1
            continue
        kept.append({
            "zip_file": f"{row['sha256']}.zip",
            "sample_file": row["sha256"],
            "packer_label": (row.get("packer") or "").strip().lower(),
            "source": "ember2024",
            "split": row.get("split", ""),
            "ember_family": row.get("family", ""),
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for row in kept:
            fh.write(json.dumps(row) + "\n")

    by_split = collections.Counter(r["split"] for r in kept)
    by_packer = collections.Counter(r["packer_label"] for r in kept)
    print(f"wrote {OUT}")
    print(f"  manifest rows : {len(rows)}")
    print(f"  to trace      : {len(kept)}")
    print(f"  skipped       : {dict(skipped)}")
    print(f"  by split      : {dict(by_split)}")
    print(f"  top packers   : {by_packer.most_common(8)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
