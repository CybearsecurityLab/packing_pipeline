import json
import os
import tempfile
import unittest
from pathlib import Path

from empirical_types import paper

try:
    from tests import paper_trace_fuzz
except ImportError:
    import paper_trace_fuzz

BINARY = paper._paper_core_binary()
CASES = int(os.environ.get("PAPER_FUZZ_CASES", "300"))
FIRST_SEED = int(os.environ.get("PAPER_FUZZ_SEED", "0"))


def _line(event) -> str:
    return event if isinstance(event, str) else json.dumps(event)


EXEC = {"event": "exec", "pid": 1, "tid": 1, "address": 4096, "size": 4}
WRITE = {"event": "write", "pid": 1, "tid": 1, "address": 0x20000, "size": 4}
LAYER2 = {"event": "exec", "pid": 1, "tid": 1, "address": 0x20000, "size": 4}

EDGE_CASES = {
    "empty": b"",
    "blank_lines_only": b"\n  \n\t\n",
    "truncated_final_line": ("\n".join(map(_line, [EXEC, WRITE, LAYER2])) + '\n{"event":"ex').encode(),
    "truncated_final_line_with_newline": ("\n".join(map(_line, [EXEC, WRITE])) + '\n{"event":"ex\n').encode(),
    "malformed_middle_line": ("\n".join(map(_line, [EXEC, '{"event":', WRITE])) + "\n").encode(),
    "malformed_then_blank_final": ("\n".join(map(_line, [EXEC, '{"event":'])) + "\n   ").encode(),
    "unknown_kind": ("\n".join(map(_line, [EXEC, {"event": "virtual_memory_write", "pid": 1}])) + "\n").encode(),
    "missing_kind": ("\n".join(map(_line, [EXEC, {"pid": 1}])) + "\n").encode(),
    "non_monotonic": ("\n".join(map(_line, [{**EXEC, "seq": 5}, {**WRITE, "seq": 5}])) + "\n").encode(),
    "hex_string_addresses": ("\n".join(map(_line, [
        {**EXEC, "address": "0x1000"},
        {**WRITE, "address": "0x20000", "physical_address": "0x9000"},
        {**LAYER2, "address": "131072"},
    ])) + "\n").encode(),
    "u64_max_file_id": ("\n".join(map(_line, [
        EXEC,
        {"event": "file_write", "pid": 1, "tid": 1, "file_id": 18446744073709551615, "file_offset": 0, "size": 4},
        {**EXEC, "address": 0x50000, "file_id": "18446744073709551615", "file_offset": 0},
    ])) + "\n").encode(),
    "missing_tid": ("\n".join(map(_line, [EXEC, {"event": "write", "pid": 1, "address": 1}])) + "\n").encode(),
    "span_overlap": ("\n".join(map(_line, [{**EXEC, "physical_spans": [
        {"offset": 0, "size": 4, "address": 0}, {"offset": 1, "size": 1, "address": 9}]}])) + "\n").encode(),
    "span_outside": ("\n".join(map(_line, [{**EXEC, "physical_spans": [
        {"offset": 2, "size": 4, "address": 0}]}])) + "\n").encode(),
    "span_partial": ("\n".join(map(_line, [{**EXEC, "physical_spans": [
        {"offset": 0, "size": 2, "address": 0}]}])) + "\n").encode(),
    "float_pid_falls_back": ("\n".join(map(_line, [{**EXEC, "pid": 1.0}])) + "\n").encode(),
    "escaped_kind": b'{"event":"e\\u0078ec","pid":1,"tid":1,"address":4096}\n',
    "invalid_utf8_final": b'{"event":"exec","pid":1,"tid":1,"address":4096}\n{"event":"\xff"}',
}


@unittest.skipIf(BINARY is None, "paper core binary is not built")
class PaperCoreEquivalenceTests(unittest.TestCase):
    def test_edge_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in EDGE_CASES.items():
                with self.subTest(name=name):
                    path = Path(directory) / f"{name}.jsonl"
                    path.write_bytes(content)
                    expected = paper_trace_fuzz.outcome_python(path)
                    actual = paper_trace_fuzz.outcome_core(BINARY, path)
                    if actual == ("fallback",):
                        actual = paper_trace_fuzz.outcome_python(path)
                    self.assertEqual(actual, expected)

    def test_random_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = paper_trace_fuzz.run(BINARY, Path(directory), range(FIRST_SEED, FIRST_SEED + CASES))
        self.assertEqual(stats["mismatches"], [])
        self.assertGreater(stats["ok"], stats["cases"] // 2)

    def test_public_entry_point_uses_core(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_bytes(EDGE_CASES["truncated_final_line"])
            with self.assertNoLogs(paper._LOG, level="WARNING"):
                evidence = paper.analyze_paper_jsonl(path, "s")
            self.assertEqual(evidence, paper._analyze_paper_jsonl_python(path, "s"))


if __name__ == "__main__":
    unittest.main()
