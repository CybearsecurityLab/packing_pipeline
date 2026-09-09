#!/usr/bin/env python3
"""Remove the simpledpack condition from the packer corpus: manifests, generated
artifacts, and the staged NAS payloads.  Text-level edits keep YAML anchors and
formatting intact; every touched file is re-parsed afterwards to prove it is
still valid."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
DRY = "--apply" not in sys.argv


def drop_block(path: pathlib.Path, start_pred, end_pred) -> int:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    out, removed, i = [], 0, 0
    while i < len(lines):
        if start_pred(lines[i]):
            j = i + 1
            while j < len(lines) and not end_pred(lines[j]):
                j += 1
            removed += j - i
            i = j
            continue
        out.append(lines[i])
        i += 1
    if removed and not DRY:
        path.write_text("".join(out), encoding="utf-8")
    return removed


def main() -> int:
    print(f"mode: {'DRY RUN' if DRY else 'APPLY'}\n")

    n = drop_block(
        REPO / "manifest/empirical_types.yaml",
        lambda l: l.rstrip() == "- packer_family: simpledpack",
        lambda l: l.startswith("- packer_family:"),
    )
    print(f"empirical_types.yaml           : {n} lines")

    n = drop_block(
        REPO / "manifest/packer_corpus.yaml",
        lambda l: l.rstrip() == "- &simpledpack_v053".rjust(len("- &simpledpack_v053") + 2),
        lambda l: l.startswith("  - &"),
    )
    print(f"packer_corpus.yaml (packer)    : {n} lines")

    n = drop_block(
        REPO / "manifest/packer_corpus.yaml",
        lambda l: "--- SimpleDpack Test Group ---" in l,
        lambda l: l.lstrip().startswith("# ---") and "SimpleDpack" not in l,
    )
    print(f"packer_corpus.yaml (test group): {n} lines")

    stats = REPO / "manifest/dataset_stats.json"
    d = json.loads(stats.read_text())

    def prune(o):
        if isinstance(o, dict):
            return {k: prune(v) for k, v in o.items()
                    if "simpledpack" not in str(k).lower()}
        if isinstance(o, list):
            return [prune(v) for v in o
                    if "simpledpack" not in str(v).lower()]
        return o

    d2 = prune(d)
    if not DRY:
        stats.write_text(json.dumps(d2, indent=2) + "\n", encoding="utf-8")
    print(f"dataset_stats.json             : pruned={d != d2}")

    targets = [
        REPO / "manifest/type/empirical_types_simpledpack_v0.5.3_0.5.3.yaml",
        REPO / "empirical_results/full_matrix/simpledpack_v0.5.3_0.5.3_labels.json",
        REPO / "empirical_results/full_matrix/simpledpack_v0.5.3_0.5.3.done",
        REPO / "empirical_results/qemu_runtime/simpledpack_v0.5.3_0.5.3_s1",
        REPO / "empirical_results/qemu_runtime/simpledpack_v0.5.3_0.5.3_s2",
        REPO / "empirical_results/qemu_runtime/configs/simpledpack_v0.5.3_0.5.3.json",
    ]
    for t in targets:
        if not t.exists():
            print(f"  (absent) {t.relative_to(REPO)}")
            continue
        print(f"  remove   {t.relative_to(REPO)}")
        if not DRY:
            shutil.rmtree(t) if t.is_dir() else t.unlink()

    for p in ("manifest/empirical_types.yaml", "manifest/packer_corpus.yaml"):
        data = yaml.safe_load((REPO / p).read_text())
        left = [c for c in (data.get("conditions") or data.get("packers") or [])
                if "simpledpack" in str(c).lower()]
        print(f"revalidated {p}: OK, residual simpledpack entries={len(left)}")

    print("\n=== NAS ===")
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ[k.strip()] = v.strip()
    import smbclient
    smbclient.ClientConfig(username=os.environ["PACKER_NAS_USERNAME"],
                           password=os.environ["PACKER_NAS_PASSWORD"])
    base = "//10.100.99.29/samples/benign_packed"
    for e in smbclient.scandir(base):
        if "simpledpack" not in e.name.lower():
            continue
        root = f"{base}/{e.name}"
        files = 0
        for sub in smbclient.scandir(root):
            p = f"{root}/{sub.name}"
            if sub.is_dir():
                for f in smbclient.scandir(p):
                    files += 1
                    if not DRY:
                        smbclient.remove(f"{p}/{f.name}")
                if not DRY:
                    smbclient.rmdir(p)
            else:
                files += 1
                if not DRY:
                    smbclient.remove(p)
        if not DRY:
            smbclient.rmdir(root)
        print(f"  {'would remove' if DRY else 'removed'} {e.name} ({files} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
