"""Build the delivery CD byte-reproducibly.

genisoimage stamps the current time into the volume descriptors and file entries,
so the same sample produced a different ISO on every invocation: a guest-visible
input that differed between otherwise identical runs. xorriso with a fixed
SOURCE_DATE_EPOCH, a fixed volume modification date and pinned file times yields
identical bytes for identical content.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

EPOCH = 1735689600
VOLUME_DATE = "2025010100000000"


def build(source_dir: Path, output: Path) -> int:
    for path in sorted(Path(source_dir).rglob("*")):
        os.utime(path, (EPOCH, EPOCH))
    os.utime(source_dir, (EPOCH, EPOCH))
    output.unlink(missing_ok=True)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
    return subprocess.run(
        ["xorriso", "-as", "mkisofs", "-quiet", "-J", "-r", "-V", "DELIVERY",
         f"--modification-date={VOLUME_DATE}", "-o", str(output), str(source_dir)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
