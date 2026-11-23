#!/usr/bin/env python3
"""Enumerate EVERY packer family+version in benign_packed, gathering candidate
.exe samples across ALL of a family+version's testcases (the Type is invariant
across testcases, so the >=2 distinct payloads a consensus label needs may be
drawn from any testcase(s)).  Emits worklist.json with a per-family sample pool.

Also cross-references manifest/*.yaml to recover the configuration_id/family/
version when available; synthesizes them from the dir name otherwise.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"


def session():
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session(
        "10.100.99.29",
        username=os.environ["PACKER_NAS_USERNAME"],
        password=os.environ["PACKER_NAS_PASSWORD"],
    )
    return smbclient


def split_family_version(nas_dir: str):
    """astral_pe_1.6.0.0 -> (astral_pe, 1.6.0.0); upx_v3.95_3.95 -> (upx, 3.95)."""
    m = re.match(r"^(.*?)_v?[\d].*?_([\d][\w.]*)$", nas_dir)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^(.*?)_([\d][\w.]*)$", nas_dir)
    if m:
        return m.group(1), m.group(2)
    return nas_dir, "?"


import hashlib

HASH_MAX_BYTES = 700_000
HASH_PER_DIR = 90
TRACE_MAX_BYTES = 40_000_000
MIN_PACKED_BYTES = 4096


def _remote(base, nas_dir, tc, nm):
    return f"{base}/{nas_dir}/{tc}/{nm}" if tc else f"{base}/{nas_dir}/{nm}"


def main() -> int:
    smb = session()
    base = os.environ.get("ENUM_BASE") or "//10.100.99.29/samples/benign_packed"
    only = {x for x in os.environ.get("ENUM_ONLY", "").split(",") if x}
    families = sorted(e.name for e in smb.scandir(base) if e.is_dir()
                      and (not only or e.name in only))

    per_dir = {}
    hash_dirs = {}
    sha_of = {}
    for nas_dir in families:
        try:
            entries = list(smb.scandir(f"{base}/{nas_dir}"))
        except Exception as ex:
            print(f"[warn] {nas_dir}: scandir failed {ex}")
            continue
        exes = []
        rep_tc = None
        for e in entries:
            if not e.is_dir() and e.name.lower().endswith(".exe"):
                try:
                    sz = smb.stat(f"{base}/{nas_dir}/{e.name}").st_size
                except Exception:
                    sz = 1 << 40
                exes.append((sz, "", e.name))
        if exes:
            rep_tc = ""
        for tc in sorted(e.name for e in entries if e.is_dir()
                         and e.name.lower() != "logs"
                         and not e.name.lower().lstrip("_").startswith("temp")):
            try:
                for e in smb.scandir(f"{base}/{nas_dir}/{tc}"):
                    if e.name.lower().endswith(".exe"):
                        try:
                            sz = smb.stat(f"{base}/{nas_dir}/{tc}/{e.name}").st_size
                        except Exception:
                            sz = 1 << 40
                        exes.append((sz, tc, e.name))
            except Exception:
                pass
            if rep_tc is None and exes:
                rep_tc = tc
        if len(exes) < 2:
            print(f"[skip] {nas_dir}: only {len(exes)} exe(s)")
            continue
        exes.sort()
        per_dir[nas_dir] = {"exes": exes, "rep_tc": rep_tc}
        hashed = 0
        for sz, tc, nm in exes:
            if sz > HASH_MAX_BYTES:
                continue
            try:
                with smb.open_file(_remote(base, nas_dir, tc, nm), mode="rb") as fh:
                    h = hashlib.sha256(fh.read()).hexdigest()
            except Exception:
                continue
            sha_of[(nas_dir, tc, nm)] = h
            hash_dirs.setdefault(h, set()).add(nas_dir)
            hashed += 1
            if hashed >= HASH_PER_DIR:
                break

    shared = {h for h, dirs in hash_dirs.items() if len(dirs) >= 2}
    print(f"[enum] hashed candidates; {len(shared)} cross-dir duplicate hashes "
          f"(unpacked originals) will be excluded")

    work = []
    for nas_dir, info in per_dir.items():
        fam, ver = split_family_version(nas_dir)
        exes = info["exes"]
        packed, contaminated = [], []
        for sz, tc, nm in exes:
            if sz < MIN_PACKED_BYTES or sz > TRACE_MAX_BYTES:
                continue
            h = sha_of.get((nas_dir, tc, nm))
            if h is not None and h in shared:
                contaminated.append((sz, tc, nm))
                continue
            packed.append((sz, tc, nm))
        chosen = packed or contaminated
        if len(chosen) < 2:
            chosen = [e for e in exes if e[0] >= MIN_PACKED_BYTES][:8] or exes[:8]
        chosen.sort()
        samples = [
            {"testcase": tc, "name": nm, "size": sz,
             "sha256": sha_of.get((nas_dir, tc, nm)),
             "remote": _remote(base, nas_dir, tc, nm)}
            for sz, tc, nm in chosen[:8]
        ]
        n_excluded = len(contaminated)
        if n_excluded and packed:
            print(f"[enum] {nas_dir}: excluded {n_excluded} unpacked-original "
                  f"candidate(s); pool now genuinely packed")
        work.append({
            "nas_dir": nas_dir,
            "family": fam,
            "version": ver,
            "testcase": info["rep_tc"] or ".",
            "n": len(exes),
            "cid": None,
            "samples": samples,
        })

    try:
        import yaml
        for mf in (REPO / "manifest").glob("*.yaml"):
            try:
                m = yaml.safe_load(mf.read_text()) or {}
            except Exception:
                continue
            for c in (m.get("conditions") or []):
                cid = c.get("configuration_id")
                fam = str(c.get("packer_family", "")).lower()
                verc = str(c.get("packer_version", ""))
                if not cid:
                    continue
                for w in work:
                    if w["cid"] is None and w["family"].lower().startswith(fam[:4]) \
                       and verc and verc in w["nas_dir"]:
                        w["cid"] = cid
    except Exception:
        pass

    out = Path(os.environ.get("ENUM_OUT") or RT / "worklist.json")
    out.write_text(json.dumps(work, indent=2))
    fams = sorted({w["family"] for w in work})
    print(f"[enum] {len(work)} family+versions, {len(fams)} families")
    print("[enum] families:", ", ".join(fams))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
