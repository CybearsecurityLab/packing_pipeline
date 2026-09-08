#!/usr/bin/env python3
"""Build a tiny FAT16 disk image carrying one sample, for snapshot-resume runs.

WHY A SECOND DISK: a savevm snapshot captures a RUNNING guest, so its NTFS volume is
dirty. ntfs-3g refuses read-write on it, and forcing the mount risks corrupting both
the filesystem and the captured VM state -- so the sample cannot be written into the
snapshot from the host. Attaching a separate, freshly-built disk sidesteps that
entirely: nothing in the snapshot is modified.

FAT16 is used because the guest mounts it without a filesystem check (unlike NTFS,
which is what caused the problem in the first place) and mtools can build it on the
host with no root and no loop device.

The guest-side launcher polls C:\\Panda\\sample.exe; a small startup copy from the
delivery volume puts the file there. Sample bytes are never modified.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def build(sample: Path, out: Path, size_mb: int | None = None) -> None:
    """Write an ISO carrying the sample as SAMPLE.EXE in its root.

    CD-ROM, not a second hard disk. A guest resumed from saved RAM state only has the
    devices that existed at capture time, so a fixed IDE disk attached at resume is
    invisible to Windows -- measured: 0 read ops on such a device after a full resume,
    versus 7416 on the boot disk. A media CHANGE on the already-enumerated CD drive IS
    honoured across resume (measured: 23 read ops), which is why delivery rides on
    removable media.

    (size_mb is accepted and ignored; an ISO is sized to its contents.)
    """
    del size_mb
    if not sample.is_file():
        sys.exit(f"sample not found: {sample}")
    tool = shutil.which("genisoimage") or shutil.which("mkisofs")
    if tool is None:
        sys.exit("need genisoimage or mkisofs to build the delivery ISO")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as staging:
        # Fixed in-image name so the guest never needs the sample's real filename.
        shutil.copy2(sample, Path(staging) / "SAMPLE.EXE")
        subprocess.run(
            [tool, "-quiet", "-J", "-r", "-V", "DELIVERY", "-o", str(out), staging],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    out.chmod(0o666)          # QEMU runs as an unprivileged service account


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sample", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--size-mb", type=int, default=None)
    args = ap.parse_args()
    build(args.sample, args.out, args.size_mb)
    print(f"delivery disk: {args.out} ({args.out.stat().st_size // (1024*1024)} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
