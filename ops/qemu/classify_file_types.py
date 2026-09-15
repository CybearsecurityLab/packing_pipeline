#!/usr/bin/env python3
"""Add sha256, md5 and a static file_type/arch to every row of the malware manifest.

THE SAMPLES ARE NEVER EXECUTED. Every field here comes from parsing bytes:
the zip member is read into memory and the PE/ELF/container headers are decoded in
pure Python. No `file`/libmagic, no 7z, no subprocess touches sample data at all,
so there is no code path that could run a sample or hand it to a parser with a CVE
history. A decompression cap bounds zip bombs.

Why it exists: the manifest identifies samples only by filename, whose hash may be
md5, sha1 or sha256 depending on the source. EMBER2024 and MalwareBazaar are both
keyed on sha256, so cross-referencing either one needs a real sha256 for every
sample. The same single pass also yields the file type, which is what separates
Win32 from Win64/.NET/ELF/APK.

Resumable: every result is appended to a JSON Lines cache keyed by zip_file, so an
interrupted run re-reads nothing.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import pathlib
import struct
import threading
import time
import zipfile

import pyzipper
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = REPO / "empirical_results/malware/manifest.csv"
CACHE = REPO / "empirical_results/malware/file_types.jsonl"
OUT = REPO / "empirical_results/malware/manifest_with_filetypes.csv"
NAS_DIR = "//10.100.99.29/samples/flat_zip_malware"
# A local mirror of the same archives (ops/qemu/mirror_malware_local.py).  Reading
# from disk instead of SMB turns a ~3 h pass into minutes and stops competing with
# the typing campaign for the NAS link.  Falls back to the NAS per-file when a
# mirrored copy is absent, so a partial mirror is still usable.
LOCAL_MIRROR = pathlib.Path("/data/malware_zips")
ZIP_PASSWORD = b"infected"
MAX_MEMBER_BYTES = 128 * 1024 * 1024      # zip-bomb guard

MACHINE = {0x014c: "x86", 0x8664: "x64", 0x01c0: "arm", 0x01c4: "armnt",
           0xaa64: "arm64", 0x0200: "ia64", 0x0166: "mips", 0x01f0: "ppc"}
_SESSION_LOCK = threading.Lock()
_REGISTERED = False


def smb():
    """One shared session. Registering concurrently from worker threads races and
    the server answers SMBAuthenticationError, so registration happens once under a
    lock and every thread reuses it."""
    global _REGISTERED
    import smbclient
    if _REGISTERED:
        return smbclient
    with _SESSION_LOCK:
        if not _REGISTERED:
            for line in (REPO / ".env").read_text().splitlines():
                if line.startswith("PACKER_NAS_"):
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
            smbclient.register_session(
                "10.100.99.29", username=os.environ["PACKER_NAS_USERNAME"],
                password=os.environ["PACKER_NAS_PASSWORD"],
                connection_timeout=60)
            _REGISTERED = True
    return smbclient


def classify(data: bytes) -> tuple[str, str]:
    """(file_type, arch) from bytes alone. Never executes anything."""
    if len(data) < 4:
        return "empty", ""
    if data[:4] == b"\x7fELF":
        bits = {1: "32", 2: "64"}.get(data[4], "?")
        return f"ELF{bits}", {3: "x86", 62: "x64", 40: "arm", 183: "arm64"}.get(
            struct.unpack_from("<H", data, 18)[0], "")
    if data[:4] == b"%PDF":
        return "PDF", ""
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE", ""
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
            if any(n == "AndroidManifest.xml" for n in names):
                return "APK", ""
            if any(n.startswith("META-INF/") for n in names):
                return "JAR", ""
        except Exception:
            pass
        return "ZIP", ""
    if data[:2] != b"MZ":
        return "other", ""
    try:
        pe_off = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe_off:pe_off + 4] != b"PE\0\0":
            return "MZ_dos", ""
        machine, _sections = struct.unpack_from("<HH", data, pe_off + 4)
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        bits = {0x10b: "PE32", 0x20b: "PE32+", 0x107: "ROM"}.get(magic, "PE?")
        arch = MACHINE.get(machine, hex(machine))
        # data directory 14 = CLR runtime header -> managed (.NET)
        dd_off = opt_off + (96 if magic == 0x10b else 112)
        n_dirs = struct.unpack_from("<I", data, opt_off + (92 if magic == 0x10b else 108))[0]
        if n_dirs >= 15:
            rva, size = struct.unpack_from("<II", data, dd_off + 14 * 8)
            if rva and size:
                return "DOTNET", arch
        if bits == "PE32" and arch == "x86":
            return "Win32", arch
        if bits == "PE32+" and arch in {"x64", "arm64", "ia64"}:
            return "Win64", arch
        return bits, arch
    except Exception as exc:
        return f"pe_parse_error:{type(exc).__name__}", ""


def inspect(row: dict) -> dict:
    out = {"zip_file": row["zip_file"], "sample_file": row["sample_file"],
           "sha256": "", "sha1": "", "md5": "", "size_bytes": 0,
           "file_type": "", "arch": "", "status": "ok"}
    # The NAS drops connections under concurrency; a single attempt lost ~15% of
    # rows to SMBException at 24 threads.  Retry with backoff, and let the caller
    # know it is a transient fetch failure so it is NOT cached as a verdict.
    blob = None
    last = ""
    local = LOCAL_MIRROR / row["zip_file"]
    try:
        if local.is_file():
            blob = local.read_bytes()
    except Exception:
        blob = None
    for attempt in range(4):
        if blob is not None:
            break
        try:
            s = smb()
            with s.open_file(f"{NAS_DIR}/{row['zip_file']}", mode="rb") as fh:
                blob = fh.read()
            break
        except Exception as exc:
            last = type(exc).__name__
            time.sleep(1.5 * (attempt + 1))
    if blob is None:
        out["status"] = f"fetch_failed:{last}"
        return out
    # 80% of these archives are WinZip AES (compress_type 99), which the stdlib
    # cannot read at all -- it raises NotImplementedError, not a bad-password error.
    # pyzipper handles AES and ZipCrypto both, so it is the only reader used.
    try:
        with pyzipper.AESZipFile(io.BytesIO(blob)) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if not members:
                out["status"] = "empty_zip"
                return out
            info = max(members, key=lambda i: i.file_size)
            if info.file_size > MAX_MEMBER_BYTES:
                out["status"] = f"oversize:{info.file_size}"
                return out
            try:
                data = zf.read(info, pwd=ZIP_PASSWORD)
            except RuntimeError:
                data = zf.read(info)
    except Exception as exc:
        out["status"] = f"extract_failed:{type(exc).__name__}"
        return out
    out["size_bytes"] = len(data)
    # All three digests in one pass so no dataset cross-reference ever needs a
    # re-read: EMBER and MalwareBazaar key on sha256, older corpora on md5, and
    # some feeds on sha1.
    out["sha256"] = hashlib.sha256(data).hexdigest()
    out["sha1"] = hashlib.sha1(data).hexdigest()
    out["md5"] = hashlib.md5(data).hexdigest()
    out["file_type"], out["arch"] = classify(data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="0 = whole manifest")
    ap.add_argument("--jobs", type=int, default=16)
    args = ap.parse_args()

    done = {}
    if CACHE.exists():
        for line in CACHE.open():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            done[r["zip_file"]] = r
    rows = list(csv.DictReader(MANIFEST.open()))
    todo = [r for r in rows if r["zip_file"] not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"[ft] manifest {len(rows)}, cached {len(done)}, to inspect {len(todo)}",
          flush=True)

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    smb()                       # register once, before any worker starts
    lock = threading.Lock()
    n = 0
    with CACHE.open("a") as out, ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(inspect, r): r for r in todo}
        for fut in as_completed(futs):
            rec = fut.result()
            with lock:
                # A transient fetch failure is not a verdict: leave it out of the
                # cache so the next run retries it instead of skipping it forever.
                if not rec["status"].startswith("fetch_failed"):
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                done[rec["zip_file"]] = rec
                n += 1
                if n % 500 == 0:
                    print(f"[ft] {n}/{len(todo)}", flush=True)

    fields = list(rows[0].keys()) + ["sha256", "sha1", "md5", "file_type", "arch",
                                     "size_bytes", "ft_status"]
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            rec = done.get(r["zip_file"], {})
            r.update({"sha256": rec.get("sha256", ""), "sha1": rec.get("sha1", ""),
                      "md5": rec.get("md5", ""),
                      "file_type": rec.get("file_type", ""),
                      "arch": rec.get("arch", ""),
                      "size_bytes": rec.get("size_bytes", ""),
                      "ft_status": rec.get("status", "")})
            w.writerow(r)
    import collections
    types = collections.Counter(v.get("file_type", "") for v in done.values())
    bad = collections.Counter(v.get("status") for v in done.values()
                              if v.get("status") != "ok")
    print(f"[ft] wrote {OUT}")
    print("[ft] file_type:", dict(types.most_common(12)))
    if bad:
        print("[ft] failures:", dict(bad.most_common(8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
