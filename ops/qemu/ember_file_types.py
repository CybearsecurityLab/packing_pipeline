#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import io
import json
import pathlib
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

import pyzipper

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ops/qemu"))
from classify_file_types import classify  # noqa: E402

BINARIES = pathlib.Path("/data/ember2024/binaries")
EMBER_MANIFEST = pathlib.Path("/data/ember2024/win32_manifest_dedup.csv")
CACHE = pathlib.Path("/data/ember2024/binaries_filetypes.jsonl")
OUT = pathlib.Path("/data/ember2024/testset_manifest.csv")
MAX_MEMBER_BYTES = 128 * 1024 * 1024
csv.field_size_limit(10 * 1024 * 1024)


def inspect(path_str: str) -> dict:
    path = pathlib.Path(path_str)
    out = {"sha256": path.stem, "file_type": "", "arch": "", "size_bytes": 0,
           "sha256_verified": False, "status": "ok"}
    try:
        with pyzipper.AESZipFile(path) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if not members:
                out["status"] = "empty_zip"
                return out
            info = max(members, key=lambda i: i.file_size)
            if info.file_size > MAX_MEMBER_BYTES:
                out["status"] = f"oversize:{info.file_size}"
                return out
            data = zf.read(info, pwd=b"infected")
    except Exception as exc:
        out["status"] = f"extract_failed:{type(exc).__name__}"
        return out
    out["size_bytes"] = len(data)
    out["sha256_verified"] = hashlib.sha256(data).hexdigest() == path.stem
    out["file_type"], out["arch"] = classify(data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()

    done = {}
    if CACHE.exists():
        for line in CACHE.open():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            done[r["sha256"]] = r
    todo = [p for p in sorted(BINARIES.glob("*.zip")) if p.stem not in done]
    print(f"[ember-ft] archives {len(done) + len(todo)}, cached {len(done)}, "
          f"to inspect {len(todo)}", flush=True)

    if todo:
        with CACHE.open("a") as out, ProcessPoolExecutor(args.jobs) as ex:
            futures = [ex.submit(inspect, str(p)) for p in todo]
            for i, fut in enumerate(as_completed(futures), 1):
                rec = fut.result()
                out.write(json.dumps(rec) + "\n")
                out.flush()
                done[rec["sha256"]] = rec
                if i % 1000 == 0:
                    print(f"[ember-ft] {i}/{len(todo)}", flush=True)

    labels = {}
    with EMBER_MANIFEST.open(newline="") as fh:
        for row in csv.DictReader(fh):
            h = row["sha256"].lower()
            if h in done:
                labels[h] = row

    fields = ["sha256", "split", "packer", "family", "label", "file_type", "arch",
              "size_bytes", "sha256_verified", "ft_status", "archive"]
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for h, rec in sorted(done.items()):
            lab = labels.get(h, {})
            writer.writerow({
                "sha256": h, "split": lab.get("split", ""),
                "packer": lab.get("packer", ""), "family": lab.get("family", ""),
                "label": lab.get("label", ""),
                "file_type": rec.get("file_type", ""), "arch": rec.get("arch", ""),
                "size_bytes": rec.get("size_bytes", ""),
                "sha256_verified": rec.get("sha256_verified", ""),
                "ft_status": rec.get("status", ""),
                "archive": str(BINARIES / f"{h}.zip"),
            })

    types = collections.Counter(r.get("file_type") for r in done.values()
                                if r.get("status") == "ok")
    bad = collections.Counter(r.get("status") for r in done.values()
                              if r.get("status") != "ok")
    unverified = sum(1 for r in done.values() if not r.get("sha256_verified"))
    print(f"[ember-ft] wrote {OUT}  ({len(done)} archives)")
    print(f"[ember-ft] file types: {dict(types.most_common(8))}")
    print(f"[ember-ft] sha256 mismatches: {unverified}")
    if bad:
        print(f"[ember-ft] failures: {dict(bad.most_common(5))}")
    launchable = types.get("Win32", 0)
    print(f"[ember-ft] LAUNCHABLE Win32 executables: {launchable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
