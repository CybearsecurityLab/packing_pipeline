import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.cli import main

CLEAN = {"stop_marker": False, "executed_blocks": True, "writes": True, "context": True}


class BoundedAcceptanceTests(unittest.TestCase):
    def classify(self, **meta):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "trace.jsonl"
            events = [
                {"event": "exec", "pid": 1, "tid": 1, "address": 0x1000, "size": 1},
                {"event": "write", "pid": 1, "tid": 1, "address": 0x20000, "size": 1},
                {"event": "exec", "pid": 1, "tid": 1, "address": 0x20000, "size": 1},
            ]
            trace.write_text("".join(json.dumps(e) + "\n" for e in events))
            base = {"paper_label_eligible": False, "ineligible_reason": "x",
                    "paper_termination_reason": "maximum_timeout_host",
                    "backend_validation_complete": True, "trace_integrity": CLEAN,
                    "certified_tiers": ["single_process", "cross_process_memory"]}
            base.update(meta)
            (root / "meta.json").write_text(json.dumps(base))
            out = root / "cls.json"
            main(["classify-paper-trace", str(trace), "--sample-id", "s",
                  "--meta", str(root / "meta.json"), "--accept-bounded",
                  "--output", str(out)])
            return json.loads(out.read_text())["complexity_type"]

    def test_certified_clean_timeout_run_is_typed(self):
        self.assertEqual(self.classify(), "TYPE_I")

    def test_uncertified_timeout_run_is_trace_loss(self):
        self.assertEqual(self.classify(backend_validation_complete=False),
                         "UNRESOLVED_TRACE_LOSS")

    def test_timeout_run_with_dirty_channel_is_trace_loss(self):
        self.assertEqual(self.classify(trace_integrity={**CLEAN, "context": False}),
                         "UNRESOLVED_TRACE_LOSS")

    def test_idle_run_is_not_rescued_by_bounded_mode(self):
        self.assertEqual(
            self.classify(paper_termination_reason="two_minutes_idle_host_observed"),
            "UNRESOLVED_TRACE_LOSS")


if __name__ == "__main__":
    unittest.main()
