#!/usr/bin/env python3
"""Ask MalwareBazaar what it knows about manifest samples that carry no packer_label.

Fair use (https://abuse.ch/terms-of-use/): the API is free for NOT-FOR-PROFIT use,
subject to unpublished "Query Volume Limits" that abuse.ch may enforce at its
discretion. So this tool: caches every response and never re-queries a hash, rate
limits (default 1 req/s), runs a bounded --limit per invocation, and stops on the
first sign of throttling. It queries metadata only and downloads no samples.

Auth: MALWAREBAZAAR_AUTH_KEY, read from the environment or the gitignored .env.
Sent as the Auth-Key HTTP header to https://mb-api.abuse.ch/api/v1/.

It does NOT edit the alias table. A wrong alias silently mislabels thousands of
samples, so this only reports candidate names and their counts for review.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = REPO / "empirical_results/malware/manifest.csv"
CACHE = REPO / "empirical_results/malware/mb_cache.jsonl"
ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
HASH_RE = re.compile(r"\b([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b")


def auth_key() -> str:
    key = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
    if not key:
        env = REPO / ".env"
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith("MALWAREBAZAAR_AUTH_KEY="):
                    key = line.split("=", 1)[1].strip()
                    break
    if not key:
        sys.exit("MALWAREBAZAAR_AUTH_KEY is not set (environment or .env)")
    return key


def load_cache() -> dict:
    cache = {}
    if CACHE.exists():
        for line in CACHE.open():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            cache[row["hash"]] = row
    return cache


def query(h: str, key: str, timeout: int) -> dict:
    data = urllib.parse.urlencode({"query": "get_info", "hash": h}).encode()
    req = urllib.request.Request(
        ENDPOINT, data=data,
        headers={"Auth-Key": key, "User-Agent": "packing-pipeline-research/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        return json.loads(fh.read().decode("utf-8", "replace"))


def signals(payload: dict) -> dict:
    """Everything MalwareBazaar offers that could name a packer."""
    out = {"tags": [], "signature": None, "yara": [], "packer": None}
    data = (payload or {}).get("data") or []
    if not data:
        return out
    entry = data[0]
    out["tags"] = entry.get("tags") or []
    out["signature"] = entry.get("signature")
    out["packer"] = (entry.get("file_information") or {}).get("packer") \
        if isinstance(entry.get("file_information"), dict) else None
    for rule in entry.get("yara_rules") or []:
        name = rule.get("rule_name") if isinstance(rule, dict) else None
        if name:
            out["yara"].append(name)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=100,
                    help="maximum NEW queries this invocation (fair use)")
    ap.add_argument("--sleep", type=float, default=1.0,
                    help="seconds between queries")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--only-unlabelled", action="store_true", default=True)
    ap.add_argument("--all-rows", dest="only_unlabelled", action="store_false",
                    help="also query rows that already have a packer_label")
    args = ap.parse_args()

    key = auth_key()
    cache = load_cache()
    rows = list(csv.DictReader(MANIFEST.open()))
    wanted = []
    for row in rows:
        if args.only_unlabelled and (row.get("packer_label") or "").strip():
            continue
        m = HASH_RE.search((row.get("sample_file") or "").lower())
        if m and m.group(1) not in cache:
            wanted.append(m.group(1))
    seen = set()
    wanted = [h for h in wanted if not (h in seen or seen.add(h))]
    print(f"[mb] manifest rows {len(rows)}, cached {len(cache)}, "
          f"uncached candidates {len(wanted)}, querying {min(args.limit, len(wanted))}")

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    written = found = 0
    with CACHE.open("a") as out:
        for h in wanted[: args.limit]:
            try:
                payload = query(h, key, args.timeout)
            except urllib.error.HTTPError as exc:
                print(f"[mb] HTTP {exc.code} on {h[:12]} -- stopping")
                break
            except Exception as exc:
                print(f"[mb] {type(exc).__name__} on {h[:12]} -- stopping: {exc}")
                break
            status = payload.get("query_status")
            if status in {"http_post_expected", "illegal_auth_key",
                          "unauthenticated", "rate_limit_exceeded"}:
                print(f"[mb] query_status={status} -- stopping")
                break
            record = {"hash": h, "query_status": status, **signals(payload)}
            out.write(json.dumps(record) + "\n")
            out.flush()
            written += 1
            if status == "ok":
                found += 1
            time.sleep(args.sleep)
    print(f"[mb] queried {written}, known to MalwareBazaar {found}, "
          f"unknown {written - found}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
