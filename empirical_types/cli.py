from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from .audit import audit_matrix
from .classifier import classify
from .finalize import finalize_labels
from .manifest import inventory
from .nas import plan_matrix, stage_matrix, stage_retry_matrix, stage_tree
from .paper import analyze_paper_jsonl
from .provisional import sample_identity
from .trace import analyze_jsonl
from .verify import verify_artifacts


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "manifest" / "packer_corpus.yaml"


def write_jsonl(rows, output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="packer-types", description="Empirical Type I-VI collection"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("inventory", help="build a sample-to-condition inventory")
    inv.add_argument("sample_root", type=Path)
    inv.add_argument("--original-root", type=Path)
    inv.add_argument("--case-id")
    inv.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    inv.add_argument(
        "--output", type=Path, default=ROOT / "empirical_results" / "inventory.jsonl"
    )
    nas = sub.add_parser(
        "stage-nas", help="stage executables from SMB; credentials are environment-only"
    )
    nas.add_argument("--server", default="10.100.99.29")
    nas.add_argument("--share", default="samples")
    nas.add_argument("--remote", default="")
    nas.add_argument("--destination", type=Path, required=True)
    nas.add_argument("--limit", type=int)
    plan_nas = sub.add_parser(
        "plan-nas", help="plan two-payload coverage for every YAML/GUI condition"
    )
    plan_nas.add_argument("--server", default="10.100.99.29")
    plan_nas.add_argument("--share", default="samples")
    plan_nas.add_argument("--remote", default="benign_packed")
    plan_nas.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    plan_nas.add_argument("--samples-per-condition", type=int, default=2)
    plan_nas.add_argument(
        "--output", type=Path, default=ROOT / "empirical_results" / "matrix_plan.json"
    )
    stage_plan = sub.add_parser(
        "stage-plan", help="download only the samples selected by plan-nas"
    )
    stage_plan.add_argument("plan", type=Path)
    stage_plan.add_argument("--destination", type=Path, required=True)
    stage_plan.add_argument(
        "--inventory",
        type=Path,
        default=ROOT / "empirical_results" / "matrix_inventory.jsonl",
    )
    retry_plan = sub.add_parser(
        "stage-retries",
        help="stage unused NAS alternates for conditions below the dynamic gate",
    )
    retry_plan.add_argument("plan", type=Path)
    retry_plan.add_argument("runs", type=Path)
    retry_plan.add_argument("--destination", type=Path, required=True)
    retry_plan.add_argument("-n", "--minimum-repetitions", type=int, default=3)
    retry_plan.add_argument("--minimum-distinct-samples", type=int, default=2)
    retry_plan.add_argument(
        "--inventory",
        type=Path,
        default=ROOT / "empirical_results" / "retry_inventory.jsonl",
    )
    retry_plan.add_argument("--report", type=Path)
    ana = sub.add_parser("classify-trace", help="classify a normalized deep trace")
    ana.add_argument("trace", type=Path)
    ana.add_argument("--sample-id", required=True)
    ana.add_argument("--original-code-bytes", type=int)
    ana.add_argument("--output", type=Path)
    paper_ana = sub.add_parser(
        "classify-paper-trace",
        help="classify a paper-runtime trace only when every required channel is present",
    )
    paper_ana.add_argument("trace", type=Path)
    paper_ana.add_argument("--sample-id", required=True)
    paper_ana.add_argument("--meta", type=Path, required=True)
    paper_ana.add_argument("--output", type=Path)
    paper_ana.add_argument(
        "--accept-bounded",
        action="store_true",
        help="treat a trace cut by the host timeout while the sample was STILL "
        "RUNNING as a bounded observation rather than trace loss. The decision "
        "hierarchy still returns trace_loss for layers==0 and no_unpacking for "
        "layers==1, so only a trace that actually exhibited write->execute yields a "
        "Type -- and that Type is a LOWER BOUND, since truncation can only reduce "
        "observed layers. Off by default: the certified packer labels depend on the "
        "strict completion gate.",
    )
    rep = sub.add_parser("report", help="aggregate classification JSON files")
    rep.add_argument("runs", type=Path)
    rep.add_argument(
        "--output", type=Path, default=ROOT / "empirical_results" / "summary.csv"
    )
    rep.add_argument("-n", "--minimum-repetitions", type=int, default=3)
    rep.add_argument("--minimum-distinct-samples", type=int, default=2)
    final = sub.add_parser(
        "finalize", help="produce complete tiered labels for every planned condition"
    )
    final.add_argument("plan", type=Path)
    final.add_argument("runs", type=Path)
    final.add_argument("-n", "--minimum-repetitions", type=int, default=3)
    final.add_argument("--minimum-distinct-samples", type=int, default=2)
    final.add_argument(
        "--output", type=Path, default=ROOT / "empirical_results" / "full_labels.json"
    )
    final.add_argument(
        "--yaml-output", type=Path, default=ROOT / "manifest" / "empirical_types.yaml"
    )
    final.add_argument(
        "--csv-output",
        type=Path,
        default=ROOT / "empirical_results" / "full_matrix" / "labels.csv",
    )
    audit = sub.add_parser(
        "audit", help="audit exact 3x2 execution and dynamic-validation coverage"
    )
    audit.add_argument("plan", type=Path)
    audit.add_argument("runs", type=Path)
    audit.add_argument("-n", "--minimum-repetitions", type=int, default=3)
    audit.add_argument("--minimum-distinct-samples", type=int, default=2)
    audit.add_argument(
        "--output", type=Path, default=ROOT / "empirical_results" / "audit.json"
    )
    verify = sub.add_parser(
        "verify", help="cross-check final plan, audit, JSON, YAML, and CSV artifacts"
    )
    verify.add_argument("plan", type=Path)
    verify.add_argument("audit", type=Path)
    verify.add_argument("labels_json", type=Path)
    verify.add_argument("labels_yaml", type=Path)
    verify.add_argument("labels_csv", type=Path)
    verify.add_argument("--require-all-populated-dynamic", action="store_true")
    verify.add_argument("--retry-report", type=Path)
    verify.add_argument("--require-retry-accounting", action="store_true")
    verify.add_argument(
        "--output",
        type=Path,
        default=ROOT / "empirical_results" / "verification.json",
    )
    args = parser.parse_args(argv)
    if args.command == "inventory":
        count = write_jsonl(
            inventory(
                args.sample_root,
                args.manifest,
                args.original_root,
                args.case_id,
            ),
            args.output,
        )
        print(f"wrote {count} samples to {args.output}")
    elif args.command == "stage-nas":
        count = stage_tree(
            args.server, args.share, args.remote, args.destination, args.limit
        )
        print(f"staged {count} executables in {args.destination}")
    elif args.command == "plan-nas":
        plan = plan_matrix(
            args.server,
            args.share,
            args.remote,
            args.manifest,
            args.samples_per_condition,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        counts = Counter(condition["status"] for condition in plan["conditions"])
        print(
            f"wrote {len(plan['conditions'])} conditions to {args.output}: {dict(counts)}"
        )
    elif args.command == "stage-plan":
        count = stage_matrix(args.plan, args.destination, args.inventory)
        print(f"staged {count} samples; inventory written to {args.inventory}")
    elif args.command == "stage-retries":
        result = stage_retry_matrix(
            args.plan,
            args.runs,
            args.destination,
            args.inventory,
            args.minimum_repetitions,
            args.minimum_distinct_samples,
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"staged {result['staged_samples']} retry samples for "
            f"{result['conditions_below_gate']} conditions; inventory written to "
            f"{args.inventory}"
        )
    elif args.command == "classify-trace":
        result = classify(
            analyze_jsonl(args.trace, args.sample_id, args.original_code_bytes)
        )
        rendered = json.dumps(result.to_dict(), indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "classify-paper-trace":
        evidence = analyze_paper_jsonl(args.trace, args.sample_id)
        metadata = json.loads(args.meta.read_text(encoding="utf-8"))
        termination = metadata.get("termination")
        if termination in {"timeout", "crash", "backend_failure"}:
            evidence.termination = termination
        if not metadata.get("paper_label_eligible", False):
            evidence.trace_complete = False
            reason = metadata.get("ineligible_reason", "required trace channel missing")
            evidence.notes.append(reason)
            # ONLY a host-timeout cut counts as a bounded observation. A launch
            # failure, crash, or missing channel is genuinely absent evidence and
            # must remain trace_loss.
            if getattr(args, "accept_bounded", False) and metadata.get(
                    "paper_termination_reason") == "maximum_timeout_host":
                evidence.bounded_observation = True
        if metadata.get("certification_mode") == "single_process":
            evidence.cross_process_certified = False
            evidence.notes.append(
                "backend certified for single-process channels only"
            )
        result = classify(evidence)
        rendered = json.dumps(result.to_dict(), indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "report":
        rows = []
        for path in args.runs.rglob("classification.json"):
            row = json.loads(path.read_text(encoding="utf-8"))
            sample_path = path.parent / "sample.json"
            if sample_path.exists():
                row.update(json.loads(sample_path.read_text(encoding="utf-8")))
            run_path = path.parent / "run.json"
            if run_path.exists():
                row["backend_return_code"] = json.loads(
                    run_path.read_text(encoding="utf-8")
                ).get("return_code")
            rows.append(row)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "sample_id",
            "packed_sha256",
            "packer_family",
            "packer_version",
            "test_case_id",
            "configuration_id",
            "complexity_type",
            "confidence",
            "backend_return_code",
            "layers",
            "processes",
            "threads",
            "backward_transitions",
            "original_code_frames",
            "maximum_simultaneous_code_coverage",
            "union_code_coverage",
            "repacked_original_bytes",
        ]
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fields)
            writer.writeheader()
            writer.writerows({k: row.get(k) for k in fields} for row in rows)
        print(f"wrote {len(rows)} results to {args.output}")
        grouped = defaultdict(list)
        for row in rows:
            grouped[
                (
                    row.get("packer_family"),
                    row.get("packer_version"),
                    row.get("configuration_id"),
                )
            ].append(row)
        conditions = []
        for (family, version, configuration_id), members in sorted(grouped.items()):
            distribution = Counter(row["complexity_type"] for row in members)
            resolved = [
                row
                for row in members
                if not row["complexity_type"].startswith("UNRESOLVED_")
            ]
            resolved_distribution = Counter(row["complexity_type"] for row in resolved)
            resolved_by_sample = defaultdict(list)
            for row in resolved:
                resolved_by_sample[sample_identity(row)].append(
                    row["complexity_type"]
                )
            qualifying_samples = {
                identity: values
                for identity, values in resolved_by_sample.items()
                if len(values) >= args.minimum_repetitions and len(set(values)) == 1
            }
            consensus = {values[0] for values in qualifying_samples.values()}
            empirical_type = None
            if (
                len(qualifying_samples) >= args.minimum_distinct_samples
                and len(consensus) == 1
            ):
                empirical_type = next(iter(consensus))
            conditions.append(
                {
                    "packer_family": family,
                    "packer_version": version,
                    "configuration_id": configuration_id,
                    "run_count": len(members),
                    "sample_count": len({sample_identity(row) for row in members}),
                    "successful_backend_runs": sum(
                        row.get("backend_return_code") == 0 for row in members
                    ),
                    "resolved_count": len(resolved),
                    "distribution": dict(distribution),
                    "resolved_distribution": dict(resolved_distribution),
                    "minimum_repetitions_per_sample": args.minimum_repetitions,
                    "minimum_distinct_samples": args.minimum_distinct_samples,
                    "qualifying_distinct_samples": len(qualifying_samples),
                    "eligible_to_fill_manifest": empirical_type is not None,
                    "empirical_type": empirical_type,
                }
            )
        condition_output = args.output.with_suffix(".conditions.json")
        condition_output.write_text(
            json.dumps(conditions, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {len(conditions)} conditions to {condition_output}")
    elif args.command == "finalize":
        conditions = finalize_labels(
            args.plan,
            args.runs,
            args.minimum_repetitions,
            args.minimum_distinct_samples,
            args.output,
            args.yaml_output,
            args.csv_output,
        )
        statuses = Counter(condition["label_status"] for condition in conditions)
        print(f"wrote {len(conditions)} complete labels: {dict(statuses)}")
    elif args.command == "audit":
        result = audit_matrix(
            args.plan,
            args.runs,
            args.minimum_repetitions,
            args.minimum_distinct_samples,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"audited {result['condition_count']} conditions: "
            f"{result['dynamic_gate_complete_conditions']} dynamically complete, "
            f"{result['observed_run_count']}/{result['expected_primary_run_count']} "
            f"primary runs observed; wrote {args.output}"
        )
    elif args.command == "verify":
        result = verify_artifacts(
            args.plan,
            args.audit,
            args.labels_json,
            args.labels_yaml,
            args.labels_csv,
            args.require_all_populated_dynamic,
            args.retry_report,
            args.require_retry_accounting,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"verified {result['condition_count']} conditions: "
            f"valid={result['valid']}, errors={len(result['errors'])}, "
            f"warnings={len(result['warnings'])}; wrote {args.output}"
        )
        if not result["valid"]:
            return 1
    return 0
