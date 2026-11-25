"""Where a run's trace is stored, and a raw single-pass view of it.

With run_trace.py --trace-tap the trace lives as TRACE.zst; readers that need the raw
JSONL (the paper classifier, the evasion analysis) read it once, front to back,
through a FIFO fed by zstd.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from pathlib import Path


def stored(trace: Path, tap: bool) -> Path:
    return trace.with_name(trace.name + ".zst") if tap else trace


@contextlib.contextmanager
def raw_view(trace: Path, tap: bool):
    source = stored(trace, tap)
    if source == trace:
        yield trace
        return
    fifo = trace.with_suffix(".raw.fifo")
    fifo.unlink(missing_ok=True)
    os.mkfifo(fifo, 0o600)
    feeder = subprocess.Popen(["sh", "-c", 'exec zstd -dcq -- "$1" > "$2"', "sh",
                               str(source), str(fifo)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        yield fifo
    finally:
        if feeder.poll() is None:
            try:
                os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
            except OSError:
                pass
            feeder.kill()
        feeder.wait()
        fifo.unlink(missing_ok=True)
