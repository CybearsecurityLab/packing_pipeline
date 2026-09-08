#!/usr/bin/env python3
"""Assign a Type to an unlabelled condition from its own family's labelled versions.

Rationale
---------
A packer's unpacking architecture is a property of the tool, not of a point release,
so a version that could not be measured can inherit the family's measured Type. This
is an INFERENCE, not a measurement, and is recorded as such: `label_status` is
`empirical_family_version_inference`, never `empirical_exact_trace_consensus`.

Aggregation when a family's versions disagree
---------------------------------------------
yoda_protector measured TYPE_I at 1.0 and TYPE_IV at 1.02, so "invariant across
versions" is false for at least one family in this corpus. The tie-break is the SoK's
own cross-version rule (Sec V-C, claim C4/V2 in sok_consensus_methodology.md): "the
highest complexity observed among the different packer versions tested". An observed
Type is a lower bound -- under-observation can only depress it -- so the maximum is
the defensible aggregate.

Scope: only conditions inside the curated corpus (worklist.json), and only those with
no label of their own. Never overwrites a measured label.

Usage:
    python3 ops/qemu/apply_family_type_inference.py [--apply]
Default is a dry run.
"""
from __future__ import annotations

import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKLIST = REPO / "empirical_results/qemu_runtime/worklist.json"

TYPE_ORDER = [
    "TYPE_0", "TYPE_I", "TYPE_II", "TYPE_III", "TYPE_IV",
    "TYPE_V-P", "TYPE_V-F", "TYPE_V-B", "TYPE_V-G",
    "TYPE_VI-P", "TYPE_VI-F", "TYPE_VI-B", "TYPE_VI-G",
]
RULE = ("Type inherited from the same packer family's measured versions; "
        "ties broken by Ugarte SoK Sec V-C (highest complexity observed across "
        "packer versions). Inference, not a measurement.")


def rank(value: str) -> int:
    return TYPE_ORDER.index(value) if value in TYPE_ORDER else -1


def main() -> int:
    apply_changes = "--apply" in sys.argv
    corpus = {
        (str(e["family"]).lower(), str(e["version"]))
        for e in json.loads(WORKLIST.read_text(encoding="utf-8"))
    }

    labelled_by_family: dict[str, dict[str, str]] = defaultdict(dict)
    unlabelled: list[tuple[str, str, str]] = []   # (path, family, version)

    for path in sorted(glob.glob(str(REPO / "manifest" / "empirical_types_*.yaml"))):
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for cond in data.get("conditions", []):
            family = str(cond.get("packer_family")).lower()
            version = str(cond.get("packer_version"))
            if (family, version) not in corpus:
                continue
            if cond.get("label"):
                labelled_by_family[family][version] = cond["label"]
            else:
                unlabelled.append((path, family, version))

    inferred, orphaned = [], []
    for path, family, version in unlabelled:
        siblings = {v: t for v, t in labelled_by_family[family].items() if v != version}
        if siblings:
            best = max(siblings.values(), key=rank)
            inferred.append((path, family, version, best, siblings))
        else:
            orphaned.append((family, version))

    print(f"inferable from a labelled sibling : {len(inferred)}")
    for _p, fam, ver, best, sib in inferred:
        detail = ", ".join(f"{v}={t}" for v, t in sorted(sib.items()))
        flag = "  <-- family versions DISAGREE" if len(set(sib.values())) > 1 else ""
        print(f"   {fam} {ver:<14} -> {best:<10} from [{detail}]{flag}")

    print()
    print(f"NO labelled sibling (genuinely unresolved) : {len(orphaned)}")
    for fam, ver in sorted(set(orphaned)):
        print(f"   {fam} {ver}")

    if not apply_changes:
        print("\n(dry run -- pass --apply to write these into the manifests)")
        return 0

    for path, family, version, best, siblings in inferred:
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        changed = False
        for cond in data.get("conditions", []):
            if (str(cond.get("packer_family")).lower() == family
                    and str(cond.get("packer_version")) == version
                    and not cond.get("label")):
                cond["label"] = best
                cond["label_status"] = "empirical_family_version_inference"
                cond["label_rule"] = RULE
                cond["family_inference_evidence"] = dict(sorted(siblings.items()))
                changed = True
        if changed:
            p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            print(f"wrote {p.name}: {family} {version} -> {best}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
