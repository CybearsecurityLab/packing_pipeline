import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ops/qemu" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "ops/qemu"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class MalwareFailureTests(unittest.TestCase):
    def setUp(self):
        self.lmt = load("label_malware_types")

    def test_infrastructure_outcomes_are_failures(self):
        for source in ("failed:never_started", "error:KeyError", "sample_would_not_launch",
                       "not_process_launchable:truncated_image", "extract_failed",
                       "trace_oversize"):
            self.assertTrue(self.lmt._is_failure({"type_source": source}), source)

    def test_findings_are_kept(self):
        self.assertFalse(self.lmt._is_failure({"type_source": "dynamic", "reps": ["TYPE_I"]}))
        self.assertFalse(self.lmt._is_failure(
            {"type_source": "unresolved", "reps": ["UNRESOLVED_NO_UNPACKING_OBSERVED"]}))

    def test_trace_loss_on_every_rep_is_a_failure(self):
        self.assertTrue(self.lmt._is_failure(
            {"type_source": "unresolved", "reps": ["UNRESOLVED_TRACE_LOSS"]}))


class PackerFailureTests(unittest.TestCase):
    def setUp(self):
        self.la = load("label_all")

    def marker(self, runs, label="TYPE_I"):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "x.done"
        path.write_text(json.dumps({"label": label, "runs": runs}))
        return path

    def test_complete_conditions_are_kept(self):
        self.assertFalse(self.la._failed_condition(self.marker(
            {"a": "TYPE_I", "b": "UNRESOLVED_NO_UNPACKING_OBSERVED"})))

    def test_infrastructure_runs_fail_the_condition(self):
        self.assertTrue(self.la._failed_condition(self.marker(
            {"a": "TYPE_I", "b": "UNRESOLVED_TRACE_LOSS"})))
        self.assertTrue(self.la._failed_condition(self.marker({}, label="UNRESOLVED")))


if __name__ == "__main__":
    unittest.main()
