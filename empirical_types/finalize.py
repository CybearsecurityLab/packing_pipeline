from __future__ import annotations

import csv
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from .provisional import (
    dynamic_validation,
    repetition_identity,
    sample_identity,
)


EXACT_TYPE_PATTERN = re.compile(
    r"^(?:TYPE_(?:I|II|III|IV)|TYPE_(?:V|VI)-[PFBG])$"
)

# Ugarte SoK Sec V-C aggregation.  Verified against the paper in
# .superpowers/sok_consensus_methodology.md (claims C3/C4/C8, V1/V2): the SoK
# assigns a Type from ONE run per sample and, across multiple observations,
# reports "the highest complexity observed".  It has no cross-run unanimity
# requirement at all, so our exact-consensus gate is strictly stricter than the
# paper that defines the scale.
MAX_OBSERVED_MIN_PAYLOADS = int(
    os.environ.get("PACKER_MAX_OBSERVED_MIN_PAYLOADS", "1"))
MAX_OBSERVED_RULE = (
    "Ugarte SoK Sec V-C: highest complexity observed; no-observation reps abstain"
)

_NUMERAL_RANK = {"I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6}


def _type_rank(value: str) -> int:
    """Complexity order of an exact Type.

    An observed Type is a LOWER BOUND on complexity: under-observation (truncated
    run, evasion triggered, tracer blind spot) can only depress what was seen, and
    the SoK's own classifier defaults downward on missing evidence.  So a lower-Type
    minority rep cannot outvote positive structural evidence of a higher Type.
    The -P/-F/-B/-G suffix is a sub-variant of the same numeral and does not affect
    complexity order.
    """
    numeral = value.removeprefix("TYPE_").split("-", 1)[0]
    return _NUMERAL_RANK.get(numeral, 0)


def _raw_classification(run_dir: Path, expected_sample_id: str) -> str | None:
    """The run's recorded complexity_type verbatim, resolved or not.

    Used only to record WHICH reps abstained, so a consensus failure stays
    auditable in max_observed_evidence.  Never feeds the label decision.
    """
    path = run_dir / "classification.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("sample_id") != expected_sample_id:
        return None
    value = data.get("complexity_type")
    return value if isinstance(value, str) else None


def _resolved_classification(run_dir: Path, expected_sample_id: str) -> str | None:
    path = run_dir / "classification.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data.get("complexity_type")
    if not isinstance(value, str) or not EXACT_TYPE_PATTERN.fullmatch(value):
        return None
    if data.get("sample_id") != expected_sample_id:
        return None
    if data.get("termination") != "completed":
        return None
    if data.get("trace_complete") is not True:
        # A bounded observation (host timeout while the sample was still running) is
        # admissible ONLY when explicitly opted into. The Type is a lower bound, which
        # is already the semantics of the max-observed rule. Default OFF so the
        # certified packer labels keep the strict completion gate they were made under.
        if not (data.get("bounded_observation")
                and os.environ.get("PACKER_ACCEPT_BOUNDED") == "1"):
            return None
    if data.get("taxonomy_basis") == "paper_runtime_heuristic":
        return value
    if data.get("original_match_available") is not True:
        return None
    coverage = data.get("union_code_coverage")
    if not isinstance(coverage, (int, float)) or coverage < 0.05:
        return None
    return value


def finalize_labels(
    plan_path: Path,
    runs: Path,
    minimum_repetitions: int,
    minimum_distinct_samples: int,
    output_json: Path,
    output_yaml: Path,
    output_csv: Path | None = None,
) -> list[dict]:
    # Labels already recorded for these conditions.  finalize rewrites the manifest
    # from scratch, so without this a re-run whose evidence does not reach a
    # labelling decision SILENTLY DELETES an existing label (observed: asm_guard_2.9.4
    # went TYPE_VI-F -> null on a re-run that produced *better* evidence).  A label is
    # a measurement that was made; a later run that measures nothing does not unmake
    # it.  Only ever carried forward when the new evidence yields no label at all.
    previous_labels: dict[str, dict] = {}
    if output_yaml.exists():
        try:
            existing = yaml.safe_load(output_yaml.read_text(encoding="utf-8")) or {}
            for cond in existing.get("conditions", []):
                if cond.get("label"):
                    previous_labels[cond.get("configuration_id")] = cond
        except Exception:
            previous_labels = {}

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    executions = []
    for run_path in runs.rglob("run.json"):
        row = dynamic_validation(run_path.parent)
        row["resolved_classification"] = _resolved_classification(
            run_path.parent, row["sample_id"]
        )
        row["raw_classification"] = _raw_classification(
            run_path.parent, row["sample_id"]
        )
        executions.append(row)
    by_configuration = defaultdict(list)
    for row in executions:
        by_configuration[row["configuration_id"]].append(row)

    conditions = []
    for planned in plan["conditions"]:
        members = by_configuration.get(planned["configuration_id"], [])
        validated = [row for row in members if row["dynamically_validated"]]
        exact = [
            row["resolved_classification"]
            for row in members
            if row["resolved_classification"]
        ]
        exact_counts = Counter(exact)
        original_mapped_samples = {
            sample_identity(row) for row in members if row.get("original_path")
        }
        target_event_totals = Counter()
        for row in validated:
            target_event_totals.update(row.get("target_event_counts", {}))
        retry_runs = [row for row in members if row["retry_for_dynamic_gate"]]
        distinct_validated = len({sample_identity(row) for row in validated})
        validated_by_sample: dict[str, set[str]] = defaultdict(set)
        for row in validated:
            validated_by_sample[sample_identity(row)].add(repetition_identity(row))
        qualifying_samples = {
            sample_id for sample_id, repetitions in validated_by_sample.items()
            if len(repetitions) >= minimum_repetitions
        }
        meets_dynamic_gate = len(qualifying_samples) >= minimum_distinct_samples
        label = None
        status = None
        confidence = 0.0
        evidence_level = None
        exact_by_sample: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        for row in members:
            if row["resolved_classification"]:
                exact_by_sample[sample_identity(row)][repetition_identity(row)].add(
                    row["resolved_classification"]
                )
        exact_qualifying_samples = {
            sample_id: next(iter(all_values))
            for sample_id, repetitions in exact_by_sample.items()
            if len(repetitions) >= minimum_repetitions
            and all(len(values) == 1 for values in repetitions.values())
            and len(
                all_values := {
                    value for values in repetitions.values() for value in values
                }
            )
            == 1
        }
        exact_consensus = set(exact_qualifying_samples.values())
        if (
            len(exact_qualifying_samples) >= minimum_distinct_samples
            and len(exact_consensus) == 1
        ):
            label = next(iter(exact_consensus))
            status = "empirical_exact_trace_consensus"
            confidence = 0.95
            evidence_level = "A_exact_layer_frame_trace"
        max_observed_evidence: dict[str, int] = {}
        if label is None and exact:
            # Ugarte Sec V-C fallback.  Reps that observed NO unpacking abstain --
            # they are failed measurements, not competing labels -- so they are
            # already absent from `exact`.  Among reps that DID observe unpacking,
            # take the highest complexity seen.
            best = max(exact, key=_type_rank)
            payloads_with_best = {
                sample_identity(row)
                for row in members
                if row["resolved_classification"] == best
            }
            # Ugarte Sec V-C literally: the highest complexity OBSERVED, with
            # non-observing reps abstaining.  One real observation is enough, which
            # is what MAX_OBSERVED_MIN_PAYLOADS=1 encodes.  Raising it to 2 restores
            # the stricter cross-payload generalization gate this repo used earlier
            # -- that is strictly beyond the SoK, and only ever withholds labels.
            if len(payloads_with_best) >= MAX_OBSERVED_MIN_PAYLOADS:
                label = best
                status = "empirical_max_observed_complexity"
                confidence = (
                    round(exact_counts[best] / len(members), 3) if members else 0.0
                )
                max_observed_evidence = dict(
                    Counter(
                        row["raw_classification"]
                        for row in members
                        if row["raw_classification"]
                    )
                )
        carried_forward = None
        if label is None:
            carried_forward = previous_labels.get(planned["configuration_id"])
            if carried_forward:
                label = carried_forward.get("label")
                status = carried_forward.get("label_status")
                confidence = carried_forward.get("confidence", 0.0)
                evidence_level = carried_forward.get("paper_evidence_level")
        conditions.append(
            {
                "packer_family": planned["packer_family"],
                "packer_version": planned["packer_version"],
                "configuration_id": planned["configuration_id"],
                "test_case_id": planned["test_case_id"],
                "condition_source": planned["source"],
                "nas_status": planned["status"],
                "available_nas_samples": planned["available_samples"],
                "minimum_repetitions_per_sample": minimum_repetitions,
                "minimum_distinct_samples": minimum_distinct_samples,
                "minimum_total_validated_runs": (
                    minimum_repetitions * minimum_distinct_samples
                ),
                "completed_runs": len(members),
                "validated_runs": len(validated),
                "retry_runs": len(retry_runs),
                "in_place_validation_runs": sum(
                    row.get("retry_mode") == "in_place_validation"
                    for row in retry_runs
                ),
                "alternate_payload_runs": sum(
                    row.get("retry_mode") == "alternate_payload"
                    for row in retry_runs
                ),
                "validated_distinct_samples": distinct_validated,
                "qualifying_distinct_samples": len(qualifying_samples),
                "validated_target_events": sum(
                    row.get("target_events", 0) for row in validated
                ),
                "target_event_totals": dict(target_event_totals),
                "original_mapped_distinct_samples": len(original_mapped_samples),
                "exact_trace_resolved_runs": len(exact),
                "exact_trace_distribution": dict(exact_counts),
                "dynamic_failure_reasons": dict(
                    Counter(
                        row["dynamic_failure_reason"]
                        for row in members
                        if row["dynamic_failure_reason"]
                    )
                ),
                "label": label,
                "label_status": status,
                "confidence": confidence,
                "paper_evidence_level": evidence_level,
                **(
                    {
                        "max_observed_evidence": max_observed_evidence,
                        "label_rule": MAX_OBSERVED_RULE,
                    }
                    if status == "empirical_max_observed_complexity"
                    and not carried_forward
                    else {}
                ),
                **(
                    {
                        k: v
                        for k, v in carried_forward.items()
                        if k in ("max_observed_evidence", "label_rule")
                    }
                    if carried_forward
                    else {}
                ),
                **(
                    {"label_carried_forward": True} if carried_forward else {}
                ),
                "executions": members,
            }
        )

    label_status_distribution = Counter(row["label_status"] for row in conditions)
    label_distribution = Counter(row["label"] for row in conditions)
    nas_status_distribution = Counter(row["nas_status"] for row in conditions)
    dynamic_gate_complete_conditions = sum(
        row["qualifying_distinct_samples"] >= minimum_distinct_samples
        for row in conditions
    )
    retry_run_count = sum(row["retry_runs"] for row in conditions)
    in_place_validation_run_count = sum(
        row["in_place_validation_runs"] for row in conditions
    )
    alternate_payload_run_count = sum(
        row["alternate_payload_runs"] for row in conditions
    )
    summary = {
        "schema_version": 1,
        "taxonomy": "Ugarte et al. Type I-VI",
        "minimum_repetitions_per_sample": minimum_repetitions,
        "minimum_distinct_samples": minimum_distinct_samples,
        "condition_count": len(conditions),
        "label_status_distribution": dict(label_status_distribution),
        "label_distribution": dict(label_distribution),
        "nas_status_distribution": dict(nas_status_distribution),
        "dynamic_gate_complete_conditions": dynamic_gate_complete_conditions,
        "retry_run_count": retry_run_count,
        "in_place_validation_run_count": in_place_validation_run_count,
        "alternate_payload_run_count": alternate_payload_run_count,
        "conditions": conditions,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    compact = []
    for condition in conditions:
        compact.append(
            {key: value for key, value in condition.items() if key != "executions"}
        )
    output_yaml.parent.mkdir(parents=True, exist_ok=True)
    output_yaml.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "taxonomy": "Ugarte et al. Type I-VI",
                "warning": (
                    "Only empirical_exact_trace_consensus is an exact paper-faithful "
                    "measurement; conditions without it remain explicitly unresolved."
                ),
                "minimum_repetitions_per_sample": minimum_repetitions,
                "minimum_distinct_samples": minimum_distinct_samples,
                "condition_count": len(conditions),
                "label_status_distribution": dict(label_status_distribution),
                "label_distribution": dict(label_distribution),
                "nas_status_distribution": dict(nas_status_distribution),
                "dynamic_gate_complete_conditions": dynamic_gate_complete_conditions,
                "retry_run_count": retry_run_count,
                "in_place_validation_run_count": in_place_validation_run_count,
                "alternate_payload_run_count": alternate_payload_run_count,
                "conditions": compact,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    if output_csv:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "packer_family",
            "packer_version",
            "test_case_id",
            "configuration_id",
            "condition_source",
            "nas_status",
            "available_nas_samples",
            "completed_runs",
            "validated_runs",
            "retry_runs",
            "in_place_validation_runs",
            "alternate_payload_runs",
            "validated_distinct_samples",
            "qualifying_distinct_samples",
            "validated_target_events",
            "target_event_totals",
            "original_mapped_distinct_samples",
            "exact_trace_resolved_runs",
            "label",
            "label_status",
            "confidence",
            "paper_evidence_level",
            "dynamic_failure_reasons",
            "exact_trace_distribution",
        ]
        with output_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for condition in conditions:
                row = {key: condition.get(key) for key in fields}
                row["dynamic_failure_reasons"] = json.dumps(
                    row["dynamic_failure_reasons"], sort_keys=True
                )
                row["target_event_totals"] = json.dumps(
                    row["target_event_totals"], sort_keys=True
                )
                row["exact_trace_distribution"] = json.dumps(
                    row["exact_trace_distribution"], sort_keys=True
                )
                writer.writerow(row)
    return conditions
