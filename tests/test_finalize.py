import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.finalize import finalize_labels


class FinalizeTests(unittest.TestCase):
    @staticmethod
    def _write_run(root: Path, sample_id: str, repetition: int) -> None:
        run = root / "runs" / sample_id / f"rep_{repetition:03d}"
        drakrun = run / "drakrun"
        drakrun.mkdir(parents=True)
        (run / "run.json").write_text('{"return_code": 0}', encoding="utf-8")
        (run / "sample.json").write_text(
            json.dumps(
                {
                    "sample_id": sample_id,
                    "packer_family": "p",
                    "packer_version": "1",
                    "configuration_id": "c",
                    "test_case_id": "CASE",
                    "repetition": repetition,
                }
            ),
            encoding="utf-8",
        )
        (run / "classification.json").write_text(
            json.dumps(
                {
                    "complexity_type": "TYPE_I",
                    "sample_id": sample_id,
                    "termination": "completed",
                    "trace_complete": True,
                    "original_match_available": True,
                    "union_code_coverage": 0.8,
                }
            ),
            encoding="utf-8",
        )
        (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
        (drakrun / "inject.log").write_text(
            '{"Status":"Success","InjectedPid":7}\n', encoding="utf-8"
        )
        (drakrun / "apimon.log").write_text(
            '{"PID":7,"Method":"X"}\n', encoding="utf-8"
        )

    def _finalize_over_previous(self, previous_label):
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(json.dumps({"conditions": [{
                "packer_family": "p", "packer_version": "1", "configuration_id": "c",
                "test_case_id": "CASE", "source": "yaml_test_case", "status": "planned",
                "available_samples": 2}]}), encoding="utf-8")
            (root / "runs").mkdir()
            (root / "out.yaml").write_text(yaml.safe_dump({"conditions": [{
                "configuration_id": "c", "label": previous_label,
                "label_status": "empirical_exact_trace_consensus", "confidence": 1.0}]}),
                encoding="utf-8")
            return finalize_labels(plan, root / "runs", 3, 2, root / "out.json",
                                   root / "out.yaml", root / "out.csv")[0]

    def test_only_type_0_is_carried_forward(self):
        self.assertIsNone(self._finalize_over_previous("TYPE_IV")["label"])
        kept = self._finalize_over_previous("TYPE_0")
        self.assertEqual(kept["label"], "TYPE_0")
        self.assertTrue(kept["label_carried_forward"])

    def test_unresolved_condition_receives_no_label(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "empty_on_nas",
                                "available_samples": 0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            conditions = finalize_labels(
                plan,
                root / "runs",
                3,
                2,
                root / "out.json",
                root / "out.yaml",
                root / "out.csv",
            )
            self.assertIsNone(conditions[0]["label"])
            self.assertIsNone(conditions[0]["label_status"])
            self.assertEqual(len((root / "out.csv").read_text().splitlines()), 2)

    def test_exact_consensus_requires_repetitions_from_two_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "type_hypothesis": "Type I",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for repetition in range(1, 7):
                self._write_run(root, "sample-a", repetition)
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            self.assertIsNone(conditions[0]["label_status"])
            self.assertEqual(conditions[0]["original_mapped_distinct_samples"], 0)
            self.assertEqual(conditions[0]["exact_trace_resolved_runs"], 6)
            for repetition in range(1, 4):
                self._write_run(root, "sample-b", repetition)
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            self.assertEqual(
                conditions[0]["label_status"], "empirical_exact_trace_consensus"
            )
            self.assertEqual(conditions[0]["original_mapped_distinct_samples"], 0)
            self.assertEqual(conditions[0]["exact_trace_resolved_runs"], 9)
            classification = (
                root / "runs" / "sample-b" / "rep_003" / "classification.json"
            )
            incomplete = json.loads(classification.read_text())
            incomplete["trace_complete"] = False
            classification.write_text(json.dumps(incomplete), encoding="utf-8")
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            self.assertIsNone(conditions[0]["label_status"])
            self.assertEqual(conditions[0]["exact_trace_resolved_runs"], 8)

    def test_does_not_copy_labels_across_configurations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE_A",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "type_hypothesis": "Type I",
                            },
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "d",
                                "test_case_id": "CASE_B",
                                "source": "yaml_test_case",
                                "status": "empty_on_nas",
                                "available_samples": 0,
                                "type_hypothesis": "Type V",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for sample in ("sample-a", "sample-b"):
                for repetition in range(1, 4):
                    self._write_run(root, sample, repetition)
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            by_configuration = {row["configuration_id"]: row for row in conditions}
            self.assertIsNone(by_configuration["d"]["label"])
            self.assertIsNone(by_configuration["d"]["label_status"])

    def test_duplicate_hashes_do_not_count_as_distinct_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "type_hypothesis": "Type I",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for sample in ("sample-a", "sample-b"):
                for repetition in range(1, 4):
                    self._write_run(root, sample, repetition)
                    sample_path = (
                        root
                        / "runs"
                        / sample
                        / f"rep_{repetition:03d}"
                        / "sample.json"
                    )
                    record = json.loads(sample_path.read_text())
                    record["packed_sha256"] = "same-content"
                    sample_path.write_text(json.dumps(record), encoding="utf-8")
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            self.assertEqual(conditions[0]["exact_trace_resolved_runs"], 6)
            self.assertIsNone(conditions[0]["label_status"])

    def test_duplicate_repetition_does_not_satisfy_independent_run_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "type_hypothesis": "Type I",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for alias in ("sample-a-copy-1", "sample-a-copy-2", "sample-a-copy-3"):
                self._write_run(root, alias, 1)
                sample_path = root / "runs" / alias / "rep_001" / "sample.json"
                record = json.loads(sample_path.read_text())
                record["packed_sha256"] = "sample-a-content"
                sample_path.write_text(json.dumps(record), encoding="utf-8")
            for repetition in range(1, 4):
                self._write_run(root, "sample-b", repetition)
                sample_path = (
                    root
                    / "runs"
                    / "sample-b"
                    / f"rep_{repetition:03d}"
                    / "sample.json"
                )
                record = json.loads(sample_path.read_text())
                record["packed_sha256"] = "sample-b-content"
                sample_path.write_text(json.dumps(record), encoding="utf-8")
            conditions = finalize_labels(
                plan, root / "runs", 3, 2, root / "out.json", root / "out.yaml"
            )
            self.assertEqual(conditions[0]["exact_trace_resolved_runs"], 6)
            self.assertIsNone(conditions[0]["label_status"])


if __name__ == "__main__":
    unittest.main()
