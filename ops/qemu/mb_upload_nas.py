#!/usr/bin/env python3
"""Mirror downloaded EMBER/MalwareBazaar binaries to the NAS.

Archives are moved EXACTLY as MalwareBazaar served them: zipped, password
"infected", never extracted. Nothing is ever decompressed to the NAS or to local
disk outside the traced guest.

Incremental and safe to re-run: a sample already present on the NAS with a matching
size is skipped, and the local copy is only removed with --prune after the remote
size has been confirmed.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCAL = pathlib.Path("/data/ember2024/binaries")
REMOTE = "//10.100.99.29/samples/ember2024_testset/binaries"
LEDGER = pathlib.Path("/data/ember2024/uploaded.jsonl")


def smb():
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session("10.100.99.29",
                               username=os.environ["PACKER_NAS_USERNAME"],
                               password=os.environ["PACKER_NAS_PASSWORD"],
                               connection_timeout=60)
    return smbclient


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prune", action="store_true",
                    help="delete the local copy once the NAS size is confirmed")
    args = ap.parse_args()
    s = smb()
    for part in ("//10.100.99.29/samples/ember2024_testset", REMOTE):
        try:
            s.makedirs(part, exist_ok=True)
        except Exception as exc:
            print(f"mkdir {part}: {type(exc).__name__} {exc}", file=sys.stderr)
    local = sorted(LOCAL.glob("*.zip"))
    print(f"local archives: {len(local)}", flush=True)
    sent = skipped = failed = 0
    with LEDGER.open("a") as ledger:
        for path in local:
            size = path.stat().st_size
            target = f"{REMOTE}/{path.name}"
            try:
                if s.stat(target).st_size == size:
                    skipped += 1
                    if args.prune:
                        path.unlink()
                    continue
            except Exception:
                pass
            try:
                data = path.read_bytes()
                with s.open_file(target, mode="wb") as fh:
                    fh.write(data)
                if s.stat(target).st_size != size:
                    raise IOError("size mismatch after write")
            except Exception as exc:
                print(f"{path.name}: {type(exc).__name__} {exc}", file=sys.stderr)
                failed += 1
                continue
            ledger.write(json.dumps({"sha256": path.stem, "bytes": size,
                                     "remote": target}) + "\n")
            ledger.flush()
            sent += 1
            if args.prune:
                path.unlink()
            if sent % 100 == 0:
                print(f"  uploaded {sent}", flush=True)
    print(f"uploaded {sent}, already present {skipped}, failed {failed}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
