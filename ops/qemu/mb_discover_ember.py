#!/usr/bin/env python3
"""Discovery pass: which packer-labelled EMBER2024 Win32 samples does MalwareBazaar hold?

Metadata only (`query=get_info`). Downloads nothing -- abuse.ch caps file downloads
at 2,000 per IP per day, so discovery has to finish before any download campaign is
planned. Fair use: 1 request/second, every response cached so a hash is never asked
twice, 5xx backed off and retried, 429/403 stops immediately and permanently.

Emits per-packer-family hit rates, which is what a download plan should be built on:
a 300-hash pilot measured 30% for themida and 0.8% for upx, a ~35x spread, so the
aggregate rate is useless for planning.
"""
from __future__ import annotations

import collections
import csv
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = pathlib.Path("/data/ember2024/win32_manifest_dedup.csv")
CACHE = pathlib.Path("/data/ember2024/mb_discovery.jsonl")
SEED = pathlib.Path("/data/ember2024/mb_packer_probe.jsonl")
ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
csv.field_size_limit(10 * 1024 * 1024)


def key() -> str:
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("MALWAREBAZAAR_AUTH_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("MALWAREBAZAAR_AUTH_KEY missing from .env")


def load_done() -> dict:
    done = {}
    for path in (SEED, CACHE):
        if path.exists():
            for line in path.open():
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                done[r["hash"]] = r
    return done


def main() -> int:
    auth = key()
    done = load_done()
    todo = []
    with MANIFEST.open(newline="") as fh:
        for row in csv.DictReader(fh):
            p = (row.get("packer") or "").strip()
            if not p:
                continue
            h = row["sha256"].lower()
            if h not in done:
                todo.append((h, row["split"], p, row.get("family", "")))
    print(f"[mb] packer-labelled: {len(todo) + len(done)}, cached {len(done)}, "
          f"to query {len(todo)}  (~{len(todo) / 3600:.1f} h at 1/s)", flush=True)

    hits = 0
    with CACHE.open("a") as out:
        for i, (h, split, packer, fam) in enumerate(todo, 1):
            payload = None
            for attempt in range(5):
                try:
                    req = urllib.request.Request(
                        ENDPOINT,
                        data=urllib.parse.urlencode(
                            {"query": "get_info", "hash": h}).encode(),
                        headers={"Auth-Key": auth,
                                 "User-Agent": "packing-pipeline-research/1.0"})
                    payload = json.loads(
                        urllib.request.urlopen(req, timeout=45).read().decode())
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code in (429, 403):
                        print(f"[mb] HTTP {exc.code} -- throttled, stopping",
                              flush=True)
                        return 1
                    time.sleep(8 * (attempt + 1))
                except Exception:
                    time.sleep(8 * (attempt + 1))
            if payload is None:
                print("[mb] 5 consecutive failures -- stopping", flush=True)
                return 1
            status = payload.get("query_status")
            if status in {"rate_limit_exceeded", "illegal_auth_key",
                          "unauthenticated"}:
                print(f"[mb] query_status={status} -- stopping", flush=True)
                return 1
            entry = (payload.get("data") or [{}])[0] if status == "ok" else {}
            out.write(json.dumps({
                "hash": h, "split": split, "ember_packer": packer,
                "ember_family": fam, "query_status": status,
                "mb_signature": entry.get("signature"),
                "mb_tags": entry.get("tags") or [],
                "mb_file_type": entry.get("file_type"),
                "mb_size": entry.get("file_size")}) + "\n")
            out.flush()
            if status == "ok":
                hits += 1
            if i % 500 == 0:
                print(f"[mb] {i}/{len(todo)}  hits {hits} "
                      f"({hits / i * 100:.2f}%)", flush=True)
            time.sleep(1.0)
    print(f"[mb] done: {len(todo)} queried, {hits} found", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
