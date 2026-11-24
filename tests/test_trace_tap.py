import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ops/qemu"))

import run_trace  # noqa: E402
import trace_tap  # noqa: E402


def lines(n_exec=50_000):
    c = (",", ":")
    out = [json.dumps({"event": "marker", "action": 1}, separators=c),
           json.dumps({"event": "sample_start"}, separators=c)]
    out += [json.dumps({"event": "exec", "seq": i, "pc": i * 16}, separators=(",", ":"))
            for i in range(n_exec)]
    out += [json.dumps({"event": "write", "seq": n_exec}, separators=(",", ":")),
            json.dumps({"event": "marker", "action": 3}, separators=(",", ":")),
            json.dumps({"event": "summary", "exec_events": n_exec, "root_pid": 7},
                       separators=(",", ":"))]
    return ("\n".join(out) + "\n").encode()


class TraceTapTests(unittest.TestCase):
    def run_tap(self, data: bytes, piece: int):
        d = Path(tempfile.mkdtemp())
        fifo, output, status = run_trace.tap_paths(d / "trace.jsonl")
        os.mkfifo(fifo)
        tap = subprocess.Popen([sys.executable, str(REPO / "ops/qemu/trace_tap.py"),
                                str(fifo), str(output), str(status)])

        def write():
            with fifo.open("wb", buffering=0) as w:
                for i in range(0, len(data), piece):
                    w.write(data[i:i + piece])

        t = threading.Thread(target=write)
        t.start()
        t.join()
        self.assertEqual(tap.wait(timeout=60), 0)
        raw = subprocess.run(["zstd", "-dc", str(output)], capture_output=True, check=True).stdout
        return raw, json.loads(status.read_text()), status

    def test_round_trip_hash_summary_and_markers(self):
        data = lines()
        for piece in (7, 4096, 1 << 20):
            raw, state, status = self.run_tap(data, piece)
            self.assertEqual(raw, data)
            self.assertEqual(state["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(state["raw_bytes"], len(data))
            self.assertTrue(state["complete"] and state["sample_start"] and state["stop_marker"])
            self.assertEqual(state["summary"]["exec_events"], 50_000)
            self.assertEqual(run_trace._tap_activity(status, 0)[:2], (1, 1))
            self.assertEqual(run_trace._tap_activity(status, len(data))[:2], (0, 0))

    def test_marker_counted_only_when_it_ends_in_fresh_bytes(self):
        carry = b'xx"event":"exec"'
        self.assertFalse(trace_tap.fresh_marker(carry + b"zzzz", trace_tap.EXEC, len(carry)))
        split = b'xxxx"event":"ex'
        self.assertTrue(trace_tap.fresh_marker(split + b'ec"', trace_tap.EXEC, len(split)))

    def test_writer_that_never_opens_is_released(self):
        d = Path(tempfile.mkdtemp())
        fifo, output, status = run_trace.tap_paths(d / "trace.jsonl")
        os.mkfifo(fifo)
        tap = subprocess.Popen([sys.executable, str(REPO / "ops/qemu/trace_tap.py"),
                                str(fifo), str(output), str(status)])
        run_trace._release_tap(fifo, tap)
        self.assertEqual(tap.returncode, 0)
        self.assertEqual(json.loads(status.read_text())["raw_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
