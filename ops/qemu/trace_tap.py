#!/usr/bin/env python3
"""Compress the plugin's trace stream while publishing what the host watcher needs.

The plugin writes JSONL into a FIFO; this process stores it zstd-compressed and keeps
a small status file (raw byte count, the raw offset of the last exec/write marker,
sample_start / stop-marker flags, and at EOF the raw SHA-256 and the final summary
event). The raw stream is never stored, so the trace cap applies to the compressed
size, and the hash matches what an uncompressed trace.jsonl would have had.

    trace_tap.py FIFO OUTPUT.zst STATUS.json
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CHUNK = 8 * 1024 * 1024
OVERLAP = 64
TAIL = 8 * 1024 * 1024
STATUS_EVERY = 0.5
EXEC = b'"event":"exec"'
WRITE = b'"event":"write"'
START = b'"event":"sample_start"'
STOP = b'"action":3'


def fresh_marker(window: bytes, marker: bytes, carried: int) -> bool:
    return window.find(marker, max(0, carried - len(marker) + 1)) != -1


def last_summary(tail: bytes) -> dict | None:
    result = None
    for line in tail.split(b"\n"):
        if b'"event":"summary"' not in line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event") == "summary":
            result = event
    return result


class Tap:
    def __init__(self, status: Path):
        self.status = status
        self.raw = 0
        self.last_activity = 0
        self.last_write = 0
        self.started = False
        self.stopped = False
        self.digest = hashlib.sha256()
        self.carry = b""
        self.tail = bytearray()
        self.published = 0.0

    def feed(self, data: bytes) -> None:
        self.digest.update(data)
        window = self.carry + data
        end = self.raw + len(data)
        wrote = fresh_marker(window, WRITE, len(self.carry))
        if wrote or fresh_marker(window, EXEC, len(self.carry)):
            self.last_activity = end
        if wrote:
            self.last_write = end
        if not self.started and START in window:
            self.started = True
        if not self.stopped and STOP in window:
            self.stopped = True
        self.raw = end
        self.carry = window[-OVERLAP:]
        self.tail += data
        if len(self.tail) > 2 * TAIL:
            del self.tail[:-TAIL]

    def publish(self, final: bool = False) -> None:
        now = time.monotonic()
        if not final and now - self.published < STATUS_EVERY:
            return
        self.published = now
        state = {"raw_bytes": self.raw, "last_activity_raw": self.last_activity,
                 "last_write_raw": self.last_write, "sample_start": self.started,
                 "stop_marker": self.stopped, "complete": final}
        if final:
            state["sha256"] = self.digest.hexdigest()
            state["summary"] = last_summary(bytes(self.tail[-TAIL:]))
        tmp = self.status.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, self.status)


def main(argv: list[str]) -> int:
    fifo, output, status = (Path(a) for a in argv)
    tap = Tap(status)
    tap.publish(final=False)
    with output.open("wb") as sink:
        zstd = subprocess.Popen(["zstd", "-1", "-T2", "-q", "-c"], stdin=subprocess.PIPE,
                                stdout=sink)
        with fifo.open("rb", buffering=0) as source:
            while True:
                data = source.read(CHUNK)
                if not data:
                    break
                tap.feed(data)
                zstd.stdin.write(data)
                tap.publish()
        zstd.stdin.close()
        rc = zstd.wait()
    tap.publish(final=True)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
