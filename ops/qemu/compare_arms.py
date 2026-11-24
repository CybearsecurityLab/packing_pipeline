#!/usr/bin/env python3
"""Compare the certified lane with the VM arm for one sample or condition.

Each arm is a list of reps; a rep is built from classification.json + meta.json
(+ the VM arm's evasion analysis), or from a campaign verdict's rep_diag entry.

vm_arm_outcome:
  evasion_confirmed        the VM arm yields a Type (or layers > 1) the certified
                           lane did not, or termination / post-check execution
                           diverges between the arms
  virtualization_suspected both arms ran to budget at layers <= 1 with no evasion
                           signal, and the protector is a code virtualizer
  genuine_no_unpacking     both arms agree on no Type, stopped naturally, no evasion
  inconclusive             anything else

    compare_arms.py --certified DIR [DIR...] --vmarm DIR [DIR...] [--protector LABEL]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evasion_analysis import TERMINATION_OUTCOME, compact  # noqa: E402

EVASION_CONFIRMED = "evasion_confirmed"
VIRTUALIZATION_SUSPECTED = "virtualization_suspected"
GENUINE_NO_UNPACKING = "genuine_no_unpacking"
INCONCLUSIVE = "inconclusive"
OUTCOMES = (EVASION_CONFIRMED, VIRTUALIZATION_SUSPECTED, GENUINE_NO_UNPACKING,
            INCONCLUSIVE)

TYPE_ORDER = ["TYPE_0", "TYPE_I", "TYPE_II", "TYPE_III", "TYPE_IV",
              "TYPE_V-P", "TYPE_V-F", "TYPE_V-B", "TYPE_V-G",
              "TYPE_VI-P", "TYPE_VI-F", "TYPE_VI-B", "TYPE_VI-G"]
VIRTUALIZING_PROTECTORS = ("vmprotect", "themida", "winlicense", "enigma")
EXEC_DIVERGENCE_FACTOR = 4
EXEC_DIVERGENCE_MIN = 10_000


def _typed(label) -> str | None:
    text = str(label or "")
    return text if text.startswith("TYPE_") else None


def _int(value) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _read_json(path: Path | None) -> dict | None:
    if path is None or not Path(path).is_file():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except ValueError:
        return None


def rep_from_files(classification: dict | None, meta: dict | None,
                   evasion: dict | None = None) -> dict:
    classification = classification or {}
    meta = meta or {}
    summary = meta.get("summary") or {}
    if evasion is not None and "activity" in evasion:
        evasion = compact(evasion)
    return {"label": classification.get("complexity_type"),
            "layers": _int(classification.get("layers")),
            "termination": meta.get("paper_termination_reason"),
            "exec_events": _int(summary.get("exec_events")),
            "evasion": evasion}


def rep_from_dir(directory: Path) -> dict:
    directory = Path(directory)
    return rep_from_files(_read_json(directory / "classification.json"),
                          _read_json(directory / "meta.json"),
                          _read_json(directory / "evasion.json"))


def reps_from_verdict(verdict: dict) -> list[dict]:
    labels = verdict.get("reps") or []
    diags = verdict.get("rep_diag") or []
    out = []
    for index, label in enumerate(labels):
        diag = (diags[index] if index < len(diags) else None) or {}
        classifier = diag.get("classifier") or {}
        out.append({"label": label,
                    "layers": _int(classifier.get("layers")),
                    "termination": diag.get("termination"),
                    "exec_events": _int(diag.get("exec_events")),
                    "evasion": diag.get("evasion")})
    return out


def best_type(reps: list[dict]) -> str | None:
    typed = [t for t in (_typed(r.get("label")) for r in reps) if t]
    if not typed:
        return None
    return max(typed, key=lambda t: TYPE_ORDER.index(t) if t in TYPE_ORDER else -1)


def _outcome(termination) -> str:
    return TERMINATION_OUTCOME.get(termination, "unknown") if termination else "unknown"


def _outcomes(reps: list[dict]) -> set[str]:
    return {_outcome(r.get("termination")) for r in reps}


def _max_layers(reps: list[dict]) -> int:
    return max((r.get("layers") or 0 for r in reps), default=0)


def _median(values: list[int]) -> int | None:
    values = sorted(v for v in values if v is not None)
    return values[len(values) // 2] if values else None


def _evasions(reps: list[dict]) -> list[dict]:
    return [r["evasion"] for r in reps if isinstance(r.get("evasion"), dict)]


def _suspected(reps: list[dict]) -> bool:
    return any(e.get("evasion_suspected") for e in _evasions(reps))


def _red_checks(reps: list[dict]) -> int:
    return sum(int(e.get("red_checks_total") or 0) for e in _evasions(reps))


def _post_check_exec(reps: list[dict], pre_check: int | None) -> int | None:
    values = []
    for r in reps:
        ev = r.get("evasion") or {}
        after = ev.get("exec_after_first_red_check")
        if after is None and pre_check is not None and r.get("exec_events") is not None:
            after = max(0, r["exec_events"] - pre_check)
        values.append(after)
    return _median(values)


def _diverges(a: int | None, b: int | None) -> bool:
    if a is None or b is None:
        return False
    low, high = sorted((a, b))
    return high - low >= EXEC_DIVERGENCE_MIN and high >= EXEC_DIVERGENCE_FACTOR * max(low, 1)


def compare(certified: list[dict], vmarm: list[dict], protector: str | None = None) -> dict:
    cert_type, vm_type = best_type(certified), best_type(vmarm)
    cert_layers, vm_layers = _max_layers(certified), _max_layers(vmarm)
    cert_outcomes, vm_outcomes = _outcomes(certified), _outcomes(vmarm)
    suspected = _suspected(vmarm)
    red_checks = _red_checks(vmarm)
    evidence: list[dict] = []
    for e in _evasions(vmarm):
        evidence += [x for x in e.get("evidence") or [] if x not in evidence]

    result = {"vm_arm_type": vm_type, "certified_type": cert_type,
              "evasion_suspected": suspected, "certified_layers": cert_layers,
              "vm_arm_layers": vm_layers,
              "certified_terminations": sorted(cert_outcomes),
              "vm_arm_terminations": sorted(vm_outcomes)}

    def done(outcome: str, *reasons: dict) -> dict:
        return {"vm_arm_outcome": outcome, **result,
                "evidence": [*reasons, *evidence]}

    if not certified or not vmarm:
        return done(INCONCLUSIVE, {"signal": "missing_arm",
                                   "certified_reps": len(certified),
                                   "vm_arm_reps": len(vmarm)})
    if vm_type and not cert_type:
        return done(EVASION_CONFIRMED, {"signal": "type_only_in_vm_arm", "type": vm_type})
    if vm_layers > 1 and cert_layers <= 1:
        return done(EVASION_CONFIRMED, {"signal": "layers_only_in_vm_arm",
                                        "vm_arm_layers": vm_layers,
                                        "certified_layers": cert_layers})
    if red_checks:
        if (len(cert_outcomes) == 1 and len(vm_outcomes) == 1
                and "unknown" not in cert_outcomes | vm_outcomes
                and cert_outcomes != vm_outcomes):
            return done(EVASION_CONFIRMED, {"signal": "termination_diverges",
                                            "certified": sorted(cert_outcomes),
                                            "vm_arm": sorted(vm_outcomes)})
        pre = _median([(r.get("evasion") or {}).get("exec_before_first_red_check")
                       for r in vmarm])
        cert_post, vm_post = _post_check_exec(certified, pre), _post_check_exec(vmarm, pre)
        if _diverges(cert_post, vm_post):
            return done(EVASION_CONFIRMED, {"signal": "post_check_exec_diverges",
                                            "certified_exec_after_check": cert_post,
                                            "vm_arm_exec_after_check": vm_post,
                                            "certified_estimated_from_vm_prefix": all(
                                                (r.get("evasion") or {}).get(
                                                    "exec_after_first_red_check") is None
                                                for r in certified)})
    no_signal = not suspected and not any(
        x.get("tier") in ("high", "medium") for x in evidence)
    if (cert_outcomes == {"budget"} and vm_outcomes == {"budget"}
            and cert_layers <= 1 and vm_layers <= 1 and no_signal
            and protector and any(p in protector.lower() for p in VIRTUALIZING_PROTECTORS)):
        return done(VIRTUALIZATION_SUSPECTED, {"signal": "budget_bound_virtualizer",
                                               "protector": protector})
    natural = {"exited", "idled"}
    if (not cert_type and not vm_type and not suspected
            and cert_outcomes <= natural and vm_outcomes <= natural
            and cert_outcomes and vm_outcomes
            and {r.get("label") for r in certified} == {r.get("label") for r in vmarm}):
        return done(GENUINE_NO_UNPACKING, {"signal": "arms_agree_natural_stop"})
    if suspected:
        return done(INCONCLUSIVE, {"signal": "evasion_suspected_without_divergence"})
    return done(INCONCLUSIVE, {"signal": "no_rule_matched"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--certified", type=Path, nargs="+", required=True,
                        help="certified rep directories (classification.json + meta.json)")
    parser.add_argument("--vmarm", type=Path, nargs="+", required=True,
                        help="VM-arm rep directories (+ evasion.json)")
    parser.add_argument("--protector")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = compare([rep_from_dir(d) for d in args.certified],
                     [rep_from_dir(d) for d in args.vmarm], args.protector)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
