#!/usr/bin/env python3
"""Emit empirical_results/full_matrix/protection_class.json -- the axis orthogonal
to the Ugarte Type I-VI labels.  Reads existing traces only; never re-traces.

Every condition in the worklist is reported.  A condition whose manifest carries a
consensus Type_* label is `unpacking_observed` (no trace needed -- classical
packer).  An UNRESOLVED condition with a kept trace is classified from that trace by
`empirical_types.protection`.  A host TIMEOUT is NOT treated as a recording failure:
a run that executed millions of blocks and then hit the timeout is still
mechanically analysable.  Only an absent/lost trace is `recording_failed`.
"""
from __future__ import annotations

import json
import glob
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml

from empirical_types.protection import analyze

RUNS = REPO / "empirical_results/qemu_runtime/all_runs"
WORKLIST = REPO / "empirical_results/qemu_runtime/worklist.json"
OUT = REPO / "empirical_results/full_matrix/protection_class.json"

TRACE_LOSS_TERMS = {"trace_loss", "crash", "unrecovered_exception_two_minutes"}


def resolved_label(tag: str) -> str | None:
    mf = REPO / f"manifest/type/empirical_types_{tag}.yaml"
    if not mf.exists():
        return None
    try:
        model = yaml.safe_load(mf.read_text()) or {}
    except Exception:
        return None
    for cond in model.get("conditions", []):
        if cond.get("label_status") == "empirical_exact_trace_consensus" and cond.get("label"):
            return cond["label"]
    return None


def rep_recording_failed(run_dir: Path) -> bool:
    """True only when the trace is unusable -- absent or explicitly lost/crashed.
    A host timeout with real execution is NOT a recording failure."""
    if not (run_dir / "trace.jsonl").exists():
        return True
    meta = run_dir / "meta.json"
    if not meta.exists():
        return False
    try:
        data = json.loads(meta.read_text())
    except Exception:
        return False
    reason = str(data.get("paper_termination_reason") or "")
    return any(term in reason for term in TRACE_LOSS_TERMS)


def scan_condition(tag: str, resolved: str | None) -> dict:
    if resolved and resolved.startswith("TYPE_"):
        return {"tag": tag, "resolved_type": resolved,
                "protection_class": "unpacking_observed", "votes": {}, "reps": []}
    run_dirs = sorted(p.parent for p in RUNS.glob(f"{tag}/*/trace.jsonl"))
    if not run_dirs:
        return {"tag": tag, "resolved_type": resolved,
                "protection_class": "inconclusive", "votes": {"no_trace": 1}, "reps": []}
    reps = []
    for run_dir in run_dirs:
        result = analyze(
            run_dir / "trace.jsonl",
            resolved_type=resolved,
            recording_failed=rep_recording_failed(run_dir),
        )
        result["rep"] = run_dir.name
        reps.append(result)
    votes = Counter(r["protection_class"] for r in reps)
    decisive = Counter({k: v for k, v in votes.items() if k != "inconclusive"})
    verdict = (decisive.most_common(1) or votes.most_common(1))[0][0]
    return {"tag": tag, "resolved_type": resolved,
            "protection_class": verdict, "votes": dict(votes), "reps": reps}


def main() -> int:
    tags = []
    if WORKLIST.exists():
        tags = sorted(w["nas_dir"] for w in json.loads(WORKLIST.read_text()))
    else:
        tags = sorted({Path(p).parents[1].name
                       for p in glob.glob(str(RUNS / "*/*/trace.jsonl"))})
    conditions = [scan_condition(tag, resolved_label(tag)) for tag in tags]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(conditions, indent=2))
    axis = Counter(c["protection_class"] for c in conditions)
    print(f"[protection] {len(conditions)} conditions -> {OUT}")
    print(f"[protection] axis distribution: {dict(axis)}")
    residue = [c for c in conditions if c["protection_class"] != "unpacking_observed"]
    print(f"[protection] non-classical (W->X-blind / no-exec / inconclusive): {len(residue)}")
    for c in residue:
        s = c["reps"][0]["signals"] if c["reps"] else {}
        hint = " high_reexec" if s.get("high_reexec") else ""
        print(f"    {c['tag']:42} {c['protection_class']:17} "
              f"(type={c['resolved_type'] or 'UNRESOLVED'}, "
              f"exec={s.get('total_exec','-')}, mapped={s.get('mapped_exec_ratio','-')}{hint})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
