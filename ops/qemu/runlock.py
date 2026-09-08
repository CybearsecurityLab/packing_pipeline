#!/usr/bin/env python3
"""Mutual exclusion between campaign runs and infrastructure work.

WHY: a snapshot build stages through /dev/nbd* and rewrites the shared base image --
the same resources a running campaign needs. Running both at once starved the pilot's
guests so badly that every sample came back never_started, and the validity guard
halted a run that was otherwise healthy. Nothing in the tooling prevented that; this
does.

Advisory, not enforced by the kernel: an flock on a well-known file, held for the
lifetime of the holding process. Stale locks clear automatically when that process
dies, so a crashed run never wedges the machine.

Usage:
    from runlock import hold
    with hold("campaign"):   # blocks/refuses if another holder is active
        ...

    python3 ops/qemu/runlock.py status     # who holds it
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import sys
import time
from pathlib import Path

LOCK_PATH = Path(os.environ.get("CORPUS_RUNLOCK", "/tmp/corpus_qemu_runlock"))


@contextlib.contextmanager
def hold(label: str, wait_seconds: int = 0):
    """Hold the exclusive run lock, or fail loudly explaining who has it."""
    LOCK_PATH.touch(exist_ok=True)
    try:
        LOCK_PATH.chmod(0o666)          # several accounts run these tools
    except OSError:
        pass
    handle = LOCK_PATH.open("r+")
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            holder = handle.read().strip() or "(unknown)"
            handle.seek(0)
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"REFUSING TO START: the QEMU run lock is held by {holder}.\n"
                    f"  Running two of these at once competes for /dev/nbd* and the\n"
                    f"  shared base image, which starves guests and produces\n"
                    f"  fabricated 'never_started' results.\n"
                    f"  Wait for it to finish, or clear a stale lock with:\n"
                    f"    python3 ops/qemu/runlock.py status")
            time.sleep(5)
    handle.seek(0)
    handle.truncate()
    handle.write(f"{label} pid={os.getpid()} since={time.strftime('%H:%M:%S')}\n")
    handle.flush()
    try:
        yield
    finally:
        try:
            handle.seek(0)
            handle.truncate()
            handle.flush()
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        if not LOCK_PATH.exists():
            print("run lock: free (no lock file)")
            return 0
        with LOCK_PATH.open("r+") as h:
            try:
                fcntl.flock(h, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(h, fcntl.LOCK_UN)
                print("run lock: FREE")
            except BlockingIOError:
                print(f"run lock: HELD by {h.read().strip() or '(unknown)'}")
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
