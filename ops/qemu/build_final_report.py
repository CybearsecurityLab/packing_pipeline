#!/usr/bin/env python3
"""Build the COMPLETE results document: every NAS packer family+version accounted
for -- either with its exact empirical Type, or as unresolved WITH a root cause.

`build_label_document.py` emits only the exact-consensus Type rows (the successes).
This report is the delivery artifact: it covers the whole corpus so nothing is
silently missing, and it states, for each unresolved condition, whether the cause is
a corpus/sample defect, a limitation of the write->execute methodology, or a
retryable infrastructure failure.

Inputs:
  manifest/empirical_types_*.yaml                      the FINAL labels
  empirical_results/full_matrix/unresolved_rootcause.json  (investigate_unresolved.py)
  empirical_results/qemu_runtime/worklist.json         corpus membership + tags
Output:
  docs/EMPIRICAL_TYPE_RESULTS.md

The manifests are the authority, not the sweep's *.done files.  A condition can be
labelled after its sweep (a re-run under different settings) or by a rule that never
runs a sweep at all (family/version inference from an already-labelled sibling), and
neither writes a .done -- so reading .done reported 15 conditions as unresolved that
the manifests had already typed.
"""
from __future__ import annotations

import glob
import json
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
DONE = REPO / "empirical_results/full_matrix"
RT = REPO / "empirical_results/qemu_runtime"
OUT = REPO / "docs/EMPIRICAL_TYPE_RESULTS.md"

RULE_BY_STATUS = {
    "empirical_exact_trace_consensus": "exact",
    "empirical_max_observed_complexity": "max-observed",
    "empirical_family_version_inference": "family-inference",
    "empirical_mutator_no_unpacking": "mutator",
}

ROOTCAUSE_BLURB = {
    "SAMPLE_NOT_PACKED": "corpus defect — payload is not actually packed",
    "METHODOLOGY_LIMIT": "methodology limit — unpacking invisible to write→execute",
    "INFRASTRUCTURE": "infrastructure — trace truncated/timed out (retryable)",
    "NO_CONSENSUS": "runs disagreed — no exact consensus",
    "UNKNOWN": "insufficient evidence — needs re-run",
}


def _load(p: Path, default=None):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default if default is not None else {}


def main() -> int:
    work = {w["nas_dir"]: w for w in _load(RT / "worklist.json", [])}
    causes = {r["tag"]: r for r in _load(DONE / "unresolved_rootcause.json", [])}
    corpus = {(str(w.get("family")).lower(), str(w.get("version"))): tag
              for tag, w in work.items()}

    best: dict[tuple[str, str], dict] = {}
    for path in sorted(glob.glob(str(REPO / "manifest" / "empirical_types_*.yaml"))):
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for cond in data.get("conditions", []):
            status = cond.get("label_status")
            if status in {"provisional_stack_cross_check", "pending_dynamic_evidence"}:
                continue
            key = (str(cond.get("packer_family")).lower(),
                   str(cond.get("packer_version")))
            if key not in corpus:
                continue
            tag = corpus[key]
            row = {
                "tag": tag,
                "family": cond.get("packer_family"),
                "version": cond.get("packer_version"),
                "testcase": cond.get("test_case_id") or ".",
                "label": cond.get("label") or "UNRESOLVED",
                "status": status,
                "runs": cond.get("completed_runs") or 0,
                "cause": (causes.get(tag) or {}).get("verdict"),
                "why": cond.get("pipeline_evidence")
                or (causes.get(tag) or {}).get("why"),
            }
            previous = best.get(key)
            if previous is None or (
                str(row["label"]).startswith("TYPE_")
                and not str(previous["label"]).startswith("TYPE_")
            ):
                best[key] = row
    rows = list(best.values())

    labeled = [r for r in rows if str(r["label"]).startswith("TYPE_")]
    unres = [r for r in rows if not str(r["label"]).startswith("TYPE_")]
    total_corpus = len(work) or len(rows)
    dist = Counter(r["label"] for r in labeled)
    causedist = Counter(r["cause"] or "UNCLASSIFIED" for r in unres)

    L = []
    L.append("# Empirical Packer-Type Results — Complete Corpus\n")
    L.append("Every packer family+version in the NAS corpus, accounted for. Types are "
             "Ugarte et al. I–VI assigned **empirically** from real dynamic traces "
             "(see [AUTOMATIC_LABELING.md](AUTOMATIC_LABELING.md)). Generated from "
             "`manifest/empirical_types_*.yaml` — the final labels — so this document "
             "always matches the manifests rather than any one sweep. The `Rule` column "
             "records which labelling rule produced each Type, so the strongest evidence "
             "class stays distinguishable from the weaker ones.\n")
    L.append("Unlike [EMPIRICAL_TYPE_LABELS.md](EMPIRICAL_TYPE_LABELS.md), which lists "
             "only successful labels, this document also states **why** each unresolved "
             "condition is unresolved, so no condition is silently missing.\n")

    L.append("## Summary\n")
    L.append(f"- Corpus: **{total_corpus}** packer family+versions")
    L.append(f"- Empirically typed: **{len(labeled)}**")
    L.append(f"- Unresolved: **{len(unres)}**\n")
    L.append("| Type | Conditions |")
    L.append("|---|---|")
    for t, c in sorted(dist.items()):
        L.append(f"| **{t}** | {c} |")
    L.append("")

    if unres:
        L.append("### Why the unresolved are unresolved\n")
        L.append("| Root cause | Conditions | Meaning |")
        L.append("|---|---|---|")
        for c, n in causedist.most_common():
            L.append(f"| {c} | {n} | {ROOTCAUSE_BLURB.get(c, '')} |")
        L.append("")
        L.append("A `SAMPLE_NOT_PACKED` verdict is a **corpus** problem, not a classifier "
                 "one: the payload runs as an ordinary unpacked binary, so there is no "
                 "unpacking to observe. `INFRASTRUCTURE` is retryable and says nothing "
                 "about the packer. Only `METHODOLOGY_LIMIT` reflects a genuine boundary "
                 "of the runtime write→execute model.\n")

    L.append("## Empirically typed conditions\n")
    L.append("| Packer family | Version | Test case | Empirical Type | Runs | Rule |")
    L.append("|---|---|---|---|---|---|")
    for r in sorted(labeled, key=lambda r: (str(r["family"]), str(r["version"]))):
        L.append(f"| {r['family']} | {r['version']} | {r['testcase']} | "
                 f"**{r['label']}** | {r['runs']} | "
                 f"{RULE_BY_STATUS.get(r['status'], r['status'] or '—')} |")
    L.append("")

    if unres:
        L.append("## Unresolved conditions (with root cause)\n")
        L.append("| Packer family | Version | Root cause | Detail |")
        L.append("|---|---|---|---|")
        for r in sorted(unres, key=lambda r: (r["cause"] or "", r["family"])):
            why = (r["why"] or "—").replace("|", "/").replace("\n", " ")
            if len(why) > 180:
                why = why[:177] + "..."
            L.append(f"| {r['family']} | {r['version']} | "
                     f"{r['cause'] or 'UNCLASSIFIED'} | {why} |")
        L.append("")

    L.append("## Reproducing\n")
    L.append("```bash\n"
             "ops/qemu/cert_retry_loop.sh                  # certify the backend\n"
             "LABEL_CONDITIONS=3 LABEL_JOBS=6 \\\n"
             "  python3 ops/qemu/label_all.py              # sweep the whole corpus\n"
             "python3 ops/qemu/investigate_unresolved.py   # root-cause the unresolved\n"
             "python3 ops/qemu/build_final_report.py       # regenerate this document\n"
             "```\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"[report] {len(labeled)} typed, {len(unres)} unresolved, "
          f"{total_corpus} in corpus -> {OUT}")
    for t, c in sorted(dist.items()):
        print(f"    {t}: {c}")
    for c, n in causedist.most_common():
        print(f"    unresolved/{c}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
