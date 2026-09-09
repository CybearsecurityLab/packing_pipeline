#!/usr/bin/env python3
"""Fill the `type:` field of each packer definition in manifest/packer_corpus.yaml
from the empirical labels in manifest/empirical_types_*.yaml.

The Type is copied from whatever the labeller produced -- nothing is inferred here.
Conditions with no empirical label keep an empty type. Edits are text-level so the
file's YAML anchors and aliases survive; the result is re-parsed to prove it.

Usage: apply_types_to_corpus.py [--apply]
"""
from __future__ import annotations

import glob
import pathlib
import re
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
CORPUS = REPO / "manifest/packer_corpus.yaml"
DRY = "--apply" not in sys.argv

TYPE_ORDER = ["TYPE_0", "TYPE_I", "TYPE_II", "TYPE_III", "TYPE_IV",
              "TYPE_V-B", "TYPE_V-F", "TYPE_V-P", "TYPE_VI-B", "TYPE_VI-F",
              "TYPE_VI-P"]


def rank(value: str) -> int:
    return TYPE_ORDER.index(value) if value in TYPE_ORDER else -1


def norm(value: str) -> str:
    """packer_corpus.yaml is hand-authored ("0.23 alpha", "0.399 (Brute)",
    "UPX_Scrambler") while the manifests carry normalised strings ("0.23_alpha",
    "0.399__Brute", "upx_scrambler"). Compare on a canonical form so the two sides
    match instead of silently leaving 18 packers untyped."""
    value = str(value).lower().strip()
    value = re.sub(r"[()\[\]]", "", value)
    value = re.sub(r"[\s_\-]+", "_", value)
    return value.strip("_")


def empirical_labels() -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for path in sorted(glob.glob(str(REPO / "manifest" / "empirical_types_*.yaml"))):
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
        for cond in data.get("conditions", []):
            label = cond.get("label")
            status = cond.get("label_status")
            if not label or status in {"provisional_stack_cross_check",
                                       "pending_dynamic_evidence"}:
                continue
            key = (norm(cond.get("packer_family")), norm(cond.get("packer_version")))
            if key not in out or rank(label) > rank(out[key]):
                out[key] = label
    return out


def main() -> int:
    labels = empirical_labels()
    lines = CORPUS.read_text(encoding="utf-8").splitlines(keepends=True)

    fam = ver = None
    filled = skipped = 0
    inferred: list[str] = []
    for i, line in enumerate(lines):
        m = re.match(r'^\s+packer_family:\s*"?([^"\n]+)"?\s*$', line)
        if m:
            fam, ver = m.group(1).strip(), None
            continue
        m = re.match(r'^\s+version:\s*"?([^"\n]+)"?\s*$', line)
        if m and fam:
            ver = m.group(1).strip()
            continue
        m = re.match(r'^(\s+)type:\s*""\s*$', line)
        if m and fam and ver:
            label = labels.get((norm(fam), norm(ver)))
            if not label:
                # family strings also differ by hand-authoring: "enigma" vs
                # "enigma_protector", "acprotect" vs "acprotect_std_...". Fall back
                # to a unique version match within a family-prefix relationship.
                cands = {v for (f, vv), v in labels.items()
                         if vv == norm(ver)
                         and (f.startswith(norm(fam)) or norm(fam).startswith(f))}
                if len(cands) == 1:
                    label = next(iter(cands))
            if not label:
                # Variants are sometimes encoded in the family name rather than the
                # version ("upx_scrambler_rc105_unknown" with version "?"), so no
                # version match is possible. Fall back to family-version inference,
                # which the corpus already uses elsewhere -- but ONLY when every
                # labelled sibling in that family agrees, so a family whose versions
                # genuinely differ (amber: 2.0=TYPE_IV, 3.1=TYPE_II) is left empty.
                sibs = {v for (f, _vv), v in labels.items()
                        if f.startswith(norm(fam)) or norm(fam).startswith(f)}
                if len(sibs) == 1:
                    label = next(iter(sibs))
                    inferred.append(f"{fam} {ver}")
            if label:
                lines[i] = f'{m.group(1)}type: "{label}"\n'
                filled += 1
                print(f"  {fam} {ver} -> {label}")
            else:
                skipped += 1
            fam = ver = None

    if inferred:
        print(f"\n  family-inference (all siblings agree): {len(inferred)}")
        for x in inferred:
            print(f"    {x}")
    print(f"\nfilled={filled} left_empty={skipped} "
          f"({'DRY RUN' if DRY else 'APPLIED'})")
    if not DRY:
        CORPUS.write_text("".join(lines), encoding="utf-8")
        data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
        defs = [p for p in (data.get("definitions") or []) if "packer_family" in p]
        typed = sum(1 for p in defs if str(p.get("type", "")).strip())
        print(f"re-parsed OK: {len(defs)} definitions, {typed} now carry a type")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
