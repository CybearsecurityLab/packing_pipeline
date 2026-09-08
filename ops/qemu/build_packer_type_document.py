#!/usr/bin/env python3
"""Generate docs/PACKER_TYPE_LABELS.md -- the authoritative packer -> Type document --
from the empirical manifests produced by `packer-types finalize`.

Companion to build_label_document.py, which emits the narrower
docs/EMPIRICAL_TYPE_LABELS.md (exact-consensus rows only).  This document is the
full picture: every typed condition regardless of which labeling rule produced it,
plus the conditions that remain unresolved with the pipeline's own verdict.

It exists because PACKER_TYPE_LABELS.md was previously hand-maintained, which let it
drift out of step with the manifests (79 vs 92 vs 97 across the two documents and the
manifests).  Deriving it removes the drift: the labeller writes the manifest, this
reads it.
"""
from __future__ import annotations

import glob
import json
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "PACKER_TYPE_LABELS.md"
WORKLIST = REPO / "empirical_results/qemu_runtime/worklist.json"

# Ugarte complexity order, with TYPE_0 (transformation without runtime unpacking)
# ahead of the scale proper.
TYPE_ORDER = [
    "TYPE_0", "TYPE_I", "TYPE_II", "TYPE_III", "TYPE_IV",
    "TYPE_V-P", "TYPE_V-F", "TYPE_V-B", "TYPE_V-G",
    "TYPE_VI-P", "TYPE_VI-F", "TYPE_VI-B", "TYPE_VI-G",
]

RULE_BY_STATUS = {
    "empirical_exact_trace_consensus": "exact",
    "empirical_max_observed_complexity": "max-observed",
    "empirical_family_version_inference": "family-inference",
    "empirical_mutator_no_unpacking": "mutator",
}


def type_key(value: str) -> int:
    return TYPE_ORDER.index(value) if value in TYPE_ORDER else len(TYPE_ORDER)


def corpus_keys() -> set[tuple[str, str]]:
    """The authoritative corpus: worklist.json, built by the NAS enumerator.

    Manifests also exist for family+versions that were REMOVED from the corpus as
    defective (pecompact_v1.84, xpa_v1.43, obsidium_v1.8.8) and for naming
    duplicates (amber 3.1, kkrunchy '0.23 alpha').  Those manifests carry no marker
    distinguishing them from live conditions, so filtering on the worklist is the
    only principled way to reproduce the curated 102-condition corpus rather than
    silently widening the denominator.
    """
    entries = json.loads(WORKLIST.read_text(encoding="utf-8"))
    return {
        (str(e.get("family")).lower(), str(e.get("version")))
        for e in entries
    }


def main() -> int:
    typed: dict[str, dict] = {}
    unresolved: dict[str, dict] = {}
    corpus = corpus_keys()

    for path in sorted(glob.glob(str(REPO / "manifest" / "empirical_types_*.yaml"))):
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for cond in data.get("conditions", []):
            status = cond.get("label_status")
            # Provisional/hypothesis rows are not empirical results.
            if status in {"provisional_stack_cross_check", "pending_dynamic_evidence"}:
                continue
            key = (str(cond.get("packer_family")).lower(),
                   str(cond.get("packer_version")))
            if key not in corpus:
                continue
            row = {
                "family": cond.get("packer_family"),
                "version": cond.get("packer_version"),
                "test_case": cond.get("test_case_id"),
                "label": cond.get("label"),
                "rule": RULE_BY_STATUS.get(status, status),
                # Only 2 of the 11 unlabeled conditions actually carry a
                # pipeline_verdict.  Defaulting the rest to "no_unpacking_observed"
                # would assert a specific empirical finding the manifest never
                # recorded -- and would be wrong for e.g. themida, whose runs were
                # TRACE_LOSS.  Report the recorded verdict or say nothing.
                "verdict": cond.get("pipeline_verdict") or "unresolved",
            }
            # One row per family+version, as the corpus defines a condition.
            # configuration_id is NOT unique (e.g. gui-ba37f4c8f00e is shared by
            # four yoda_protector versions), so it cannot be the key.  A
            # family+version can appear in several manifests / testcases; a typed
            # row always beats an untyped one, and between two typed rows keep the
            # higher Type (Ugarte Sec V-C: highest complexity observed).
            if cond.get("label"):
                previous = typed.get(key)
                if previous is None or type_key(str(row["label"])) > type_key(
                    str(previous["label"])
                ):
                    typed[key] = row
                unresolved.pop(key, None)
            elif key not in typed:
                unresolved[key] = row

    typed_rows = sorted(
        typed.values(),
        key=lambda r: (type_key(str(r["label"])), str(r["family"]).lower(),
                       str(r["version"])),
    )
    unresolved_rows = sorted(
        unresolved.values(),
        key=lambda r: (str(r["family"]).lower(), str(r["version"])),
    )
    distribution = Counter(r["label"] for r in typed_rows)
    total = len(typed_rows) + len(unresolved_rows)

    lines = [
        "# Empirical Packer Type Labels",
        "",
        "Runtime-packer complexity on the **Ugarte Type I–VI** scale "
        "(*SoK: Deep Packer Inspection*, IEEE S&P 2015) via the certified QEMU-TCG "
        "write→execute oracle. Per Ugarte Sec V-C a Type is the **highest complexity "
        "observed** across runs (no-observation runs abstain). **TYPE_0** = "
        "transformation without runtime unpacking (PE-header/EP mutators). Remaining "
        "conditions carry the pipeline's own verdict (no unpacking observed / no "
        "execution / trace loss) — the SoK excludes non-unpacking samples, so these "
        "are a valid empirical outcome, not a labeling failure.",
        "",
        "Generated by `ops/qemu/build_packer_type_document.py` from "
        "`manifest/empirical_types_*.yaml`. Do not hand-edit.",
        "",
        f"**{total} conditions** · {len(typed_rows)} typed · "
        f"{len(unresolved_rows)} pipeline-unresolved.",
        "",
        "## Type distribution",
        "| Type | Count |",
        "|------|------:|",
    ]
    for value in sorted(distribution, key=type_key):
        lines.append(f"| {value} | {distribution[value]} |")
    lines.append(f"| unresolved | {len(unresolved_rows)} |")

    lines += [
        "",
        f"## Typed packers ({len(typed_rows)})",
        "",
        "| Packer family | Version | Test case | Type | Rule |",
        "|---|---|---|---|---|",
    ]
    for r in typed_rows:
        lines.append(
            f"| {r['family']} | {r['version']} | {r['test_case']} | "
            f"**{r['label']}** | {r['rule']} |"
        )

    lines += [
        "",
        f"## Pipeline-unresolved ({len(unresolved_rows)})",
        "",
        "Empirical pipeline verdict as recorded in the manifest. `unresolved` means "
        "the condition produced no Type and no explicit verdict was recorded — it is "
        "not a claim that unpacking was absent.",
        "",
        "| Packer family | Version | Pipeline verdict |",
        "|---|---|---|",
    ]
    for r in unresolved_rows:
        lines.append(f"| {r['family']} | {r['version']} | `{r['verdict']}` |")
    lines.append("")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT}: {len(typed_rows)} typed, "
          f"{len(unresolved_rows)} unresolved, {total} conditions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
