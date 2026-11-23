import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.classifier import classify
from empirical_types.paper import analyze_paper_jsonl


def execute(address, *, pid=1, tid=1, size=1):
    return {"event": "exec", "pid": pid, "tid": tid, "address": address, "size": size}


def write(address, *, pid=1, tid=1, size=1):
    return {"event": "write", "pid": pid, "tid": tid, "address": address, "size": size}


class PaperFaithfulTraceTests(unittest.TestCase):
    def analyze(self, events):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            return analyze_paper_jsonl(path, "sample")

    def test_type_i_without_original_binary_labels(self):
        evidence = self.analyze(
            [execute(0x1000), write(0x20000), execute(0x20000)]
        )
        self.assertEqual(evidence.taxonomy_basis, "paper_runtime_heuristic")
        self.assertFalse(evidence.original_match_available)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_reexecuting_dropped_file_code_is_one_frame(self):
        drop = [execute(0x1000), {"event": "file_write", "pid": 1, "tid": 1,
                                  "file_id": "f", "file_offset": 0, "size": 1}]
        mapped = {**execute(0x50000), "file_id": "f", "file_offset": 0}
        evidence = self.analyze(drop + [mapped, execute(0x1000)] * 5)
        written = [execute(0x1000), write(0x50000)] + [execute(0x50000), execute(0x1000)] * 5
        reference = self.analyze(written)
        self.assertEqual(len(evidence.frame_sizes), len(reference.frame_sizes))
        self.assertEqual(classify(evidence).complexity_type,
                         classify(reference).complexity_type)

    def test_rewritten_dropped_file_starts_a_new_frame(self):
        drop = {"event": "file_write", "pid": 1, "tid": 1,
                "file_id": "f", "file_offset": 0, "size": 1}
        mapped = {**execute(0x50000), "file_id": "f", "file_offset": 0}
        once = self.analyze([execute(0x1000), drop, mapped, execute(0x1000), mapped])
        twice = self.analyze([execute(0x1000), drop, mapped, execute(0x1000), drop, mapped])
        self.assertGreater(len(twice.frame_sizes), len(once.frame_sizes))

    def test_empty_paper_trace_is_unresolved(self):
        evidence = self.analyze([])
        self.assertEqual(
            classify(evidence).complexity_type,
            "UNRESOLVED_TRACE_LOSS",
        )

    def test_type_ii_requires_exact_linear_transition_model(self):
        evidence = self.analyze(
            [
                execute(0x1000),
                write(0x20000),
                execute(0x20000),
                write(0x40000),
                execute(0x40000),
            ]
        )
        self.assertTrue(evidence.linear_transition_model)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_II")

    def test_context_switch_layer_transitions_are_global(self):
        evidence = self.analyze(
            [
                execute(0x1000, tid=1),
                write(0x20000, tid=1),
                execute(0x20000, tid=2),
                execute(0x1000, tid=1),
            ]
        )
        self.assertEqual(evidence.backward_transitions, 1)
        self.assertFalse(evidence.linear_transition_model)

    def test_shared_physical_page_links_process_address_spaces(self):
        evidence = self.analyze(
            [
                {
                    **execute(0x1000, pid=1),
                    "physical_address": 0xA000,
                },
                {
                    **write(0x20000, pid=1),
                    "physical_address": 0xB000,
                },
                {
                    **execute(0x30000, pid=2),
                    "physical_address": 0xB000,
                },
            ]
        )
        self.assertEqual(evidence.processes, 2)
        self.assertEqual(evidence.layers, 2)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_unrelated_descendant_does_not_change_root_classification(self):
        evidence = self.analyze(
            [
                {"event": "marker", "pid": 1, "action": 1, "detail": 0},
                {"event": "process", "pid": 2, "parent_pid": 1,
                 "reason": "descendant"},
                execute(0x1000, pid=1),
                write(0x20000, pid=1),
                execute(0x20000, pid=1),
                execute(0x50000, pid=2),
            ]
        )
        self.assertEqual(evidence.processes, 1)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_remote_write_connects_secondary_process_to_root(self):
        evidence = self.analyze(
            [
                {"event": "marker", "pid": 1, "action": 1, "detail": 0},
                execute(0x1000, pid=1),
                {**write(0x30000, pid=1), "target_pid": 2},
                execute(0x30000, pid=2),
            ]
        )
        self.assertEqual(evidence.processes, 2)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_cross_page_physical_spans_preserve_shared_aliases(self):
        evidence = self.analyze(
            [
                execute(0x1000, pid=1),
                {
                    **write(0x2FFE, pid=1, size=4),
                    "physical_spans": [
                        {"offset": 0, "size": 2, "address": 0xAFFE},
                        {"offset": 2, "size": 2, "address": 0xC000},
                    ],
                },
                {
                    **execute(0x4FFE, pid=2, size=4),
                    "physical_spans": [
                        {"offset": 0, "size": 2, "address": 0xAFFE},
                        {"offset": 2, "size": 2, "address": 0xC000},
                    ],
                },
            ]
        )
        self.assertEqual(evidence.layers, 2)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_disk_dropper_provenance_creates_the_next_layer(self):
        evidence = self.analyze(
            [
                execute(0x1000, pid=1),
                {
                    "event": "file_write",
                    "pid": 1,
                    "tid": 1,
                    "file_id": "volume/path/payload.exe",
                    "file_offset": 0x200,
                    "size": 2,
                },
                {
                    **execute(0x401000, pid=2, size=2),
                    "file_id": "volume/path/payload.exe",
                    "file_offset": 0x200,
                },
            ]
        )
        self.assertEqual(evidence.layers, 2)
        self.assertEqual(evidence.processes, 2)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_unmap_does_not_become_the_writer_of_reused_virtual_memory(self):
        evidence = self.analyze(
            [
                execute(0x1000),
                write(0x20000),
                execute(0x20000),
                {"event": "unmap", "pid": 1, "tid": 1,
                 "target_pid": 1, "address": 0x20000, "size": 1},
                execute(0x1000),
                write(0x20000),
                execute(0x20000),
            ]
        )
        self.assertEqual(evidence.layers, 2)

    def test_unmap_clears_stale_physical_alias_provenance(self):
        evidence = self.analyze(
            [
                execute(0x1000),
                {**write(0x20000), "physical_address": 0xA000},
                {**execute(0x20000), "physical_address": 0xA000},
                {
                    "event": "free",
                    "pid": 1,
                    "tid": 1,
                    "target_pid": 1,
                    "address": 0x20000,
                    "size": 1,
                    "invalidated_physical_spans": [
                        {"offset": 0, "size": 1, "address": 0xA000}
                    ],
                },
                {**execute(0x30000), "physical_address": 0xA000},
            ]
        )
        self.assertEqual(evidence.layers, 2)
        self.assertEqual(evidence.backward_transitions, 1)

    def test_tracer_metadata_and_global_sequence_are_accepted(self):
        evidence = self.analyze(
            [
                {"event": "process", "seq": 1, "pid": 1},
                {"event": "register_handles", "vcpu": 0, "rax": True},
                {**execute(0x1000), "seq": 2},
                {"event": "exception_dispatch", "seq": 3,
                 "pid": 1, "tid": 1, "address": 0x7FFF0000},
                {"event": "exception_recovered", "seq": 4,
                 "pid": 1, "tid": 1, "address": 0x1000},
                {**write(0x20000), "seq": 5},
                {**execute(0x20000), "seq": 6},
                {"event": "summary", "seq": 7},
            ]
        )
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_type_iv_interleaves_single_frame_application(self):
        evidence = self.analyze(
            [
                execute(0x1000),
                write(0x20000),
                execute(0x20000),
                execute(0x1000),
            ]
        )
        self.assertEqual(classify(evidence).complexity_type, "TYPE_IV")

    def test_type_v_and_vi_use_only_paper_suffixes(self):
        incremental = [
            execute(0x1000),
            write(0x20000, size=2),
            execute(0x20000),
            execute(0x1000),
            write(0x21000, size=2),
            execute(0x21000),
            execute(0x1000),
        ]
        type_v = classify(self.analyze(incremental)).complexity_type
        self.assertEqual(type_v, "TYPE_V-B")
        self.assertNotIn("-G", type_v)

        shifting = [
            execute(0x1000),
            write(0x20000, size=2),
            execute(0x20000),
            execute(0x1000),
            write(0x20000, size=2),
            execute(0x20000),
            execute(0x1000),
        ]
        type_vi = classify(self.analyze(shifting)).complexity_type
        self.assertEqual(type_vi, "TYPE_VI-B")

        function_sized = [
            execute(0x1000),
            write(0x20000, size=16),
            execute(0x20000),
            execute(0x20008),
            execute(0x1000),
            write(0x21000, size=24),
            execute(0x21000),
            execute(0x21008),
            execute(0x1000),
        ]
        self.assertEqual(
            classify(self.analyze(function_sized)).complexity_type,
            "TYPE_V-F",
        )

    def test_stack_writes_do_not_hide_page_granularity(self):
        events = []
        for page in (0x20000, 0x21000, 0x22000):
            events += [execute(0x1000), write(0x7FF000, size=8),
                       write(page, size=4096), execute(page)]
        events.append(execute(0x1000))
        self.assertEqual(classify(self.analyze(events)).complexity_type, "TYPE_V-P")

    def test_packer_only_frames_do_not_make_application_multiframe(self):
        app = [execute(0x20000 + i * 16, size=16) for i in range(64)]
        stub = [write(0x200000, size=32), execute(0x200000, size=32)]
        events = ([execute(0x1000), write(0x20000, size=1024)] + app + [execute(0x1000)]
                  + stub + [execute(0x1000)] + app + [execute(0x1000)] + stub
                  + [execute(0x1000)])
        self.assertEqual(classify(self.analyze(events)).complexity_type, "TYPE_IV")

    def test_ten_page_separation_and_type_iii_fallback(self):
        evidence = self.analyze(
            [
                execute(0x1000),
                write(0x20000),
                write(0x22000),
                execute(0x20000),
                write(0x1000),
                execute(0x22000),
            ]
        )
        self.assertTrue(evidence.all_code_flagged_packer)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_III")

    def _free(self, address):
        return {"event": "free", "pid": 1, "tid": 1, "target_pid": 1,
                "address": address, "size": 1}

    def test_freeing_never_executed_data_is_not_repacking(self):
        events = [
            execute(0x1000),
            write(0x20000),
            execute(0x20000),
            write(0x90000),
            execute(0x20000),
            self._free(0x90000),
            execute(0x20000),
        ]
        for evidence in (self.analyze(events), self.analyze_python(events)):
            self.assertTrue(evidence.tail_transition)
            self.assertFalse(evidence.all_code_flagged_packer)
            self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_freeing_another_layers_executed_code_is_repacking(self):
        events = [
            execute(0x1000),
            write(0x20000),
            execute(0x20000),
            self._free(0x1000),
            execute(0x20000),
        ]
        for evidence in (self.analyze(events), self.analyze_python(events)):
            self.assertFalse(evidence.tail_transition)
            self.assertTrue(evidence.all_code_flagged_packer)

    def analyze_python(self, events):
        from empirical_types.paper import _analyze_paper_jsonl_python
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            return _analyze_paper_jsonl_python(path, "sample")


if __name__ == "__main__":
    unittest.main()
