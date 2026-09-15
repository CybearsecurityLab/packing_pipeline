#!/usr/bin/env python3
"""Download the MalwareBazaar-resident EMBER samples that discovery has found.

abuse.ch caps the file download API at 2,000 per IP per day, so this tracks its own
daily count in a state file and stops at the cap rather than discovering it by being
throttled.  It runs alongside the discovery pass: discovery keeps finding hits, this
drains them, and a day's quota is never left unused.

Every archive is kept EXACTLY as MalwareBazaar serves it -- zipped, password
"infected", never extracted to disk.  The sha256 is verified in memory against the
hash we asked for, so a wrong or truncated sample is rejected rather than stored.
Resumable: an already-downloaded hash is skipped.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

import pyzipper

REPO = pathlib.Path(__file__).resolve().parents[2]
DISCOVERY = [pathlib.Path("/data/ember2024/mb_discovery.jsonl"),
             pathlib.Path("/data/ember2024/mb_packer_probe.jsonl")]
OUT_DIR = pathlib.Path("/data/ember2024/binaries")
STATE = pathlib.Path("/data/ember2024/download_state.json")
LEDGER = pathlib.Path("/data/ember2024/downloaded.jsonl")
ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
DAILY_CAP = 2000


def auth_key() -> str:
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("MALWAREBAZAAR_AUTH_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("MALWAREBAZAAR_AUTH_KEY missing")


def load_state() -> dict:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    if STATE.exists():
        s = json.loads(STATE.read_text())
        if s.get("date") == today:
            return s
    return {"date": today, "count": 0}


def save_state(s: dict) -> None:
    STATE.write_text(json.dumps(s))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sleep", type=float, default=1.0)
    ap.add_argument("--cap", type=int, default=DAILY_CAP)
    args = ap.parse_args()

    key = auth_key()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    have = {p.stem for p in OUT_DIR.glob("*.zip")}
    hits = {}
    for path in DISCOVERY:
        if not path.exists():
            continue
        for line in path.open():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("query_status") == "ok" and r["hash"] not in have:
                hits[r["hash"]] = r
    state = load_state()
    budget = max(0, args.cap - state["count"])
    print(f"[dl] hits available {len(hits)}, already stored {len(have)}, "
          f"today's remaining quota {budget}/{args.cap}", flush=True)
    if not budget or not hits:
        return 0

    got = bad = 0
    with LEDGER.open("a") as ledger:
        for h, rec in list(hits.items())[:budget]:
            data = None
            for attempt in range(4):
                try:
                    req = urllib.request.Request(
                        ENDPOINT,
                        data=urllib.parse.urlencode(
                            {"query": "get_file", "sha256_hash": h}).encode(),
                        headers={"Auth-Key": key,
                                 "User-Agent": "packing-pipeline-research/1.0"})
                    data = urllib.request.urlopen(req, timeout=120).read()
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code in (429, 403):
                        print(f"[dl] HTTP {exc.code} -- throttled, stopping",
                              flush=True)
                        save_state(state)
                        return 1
                    time.sleep(8 * (attempt + 1))
                except Exception:
                    time.sleep(8 * (attempt + 1))
            if data is None:
                print("[dl] repeated failures -- stopping", flush=True)
                break
            # A JSON body means an error response, not a file.
            if data[:1] == b"{":
                try:
                    status = json.loads(data).get("query_status")
                except ValueError:
                    status = "unparseable"
                if status in {"rate_limit_exceeded", "unauthenticated",
                              "illegal_auth_key"}:
                    print(f"[dl] {status} -- stopping", flush=True)
                    save_state(state)
                    return 1
                bad += 1
                continue
            # verify in memory: the archive must really contain the hash we asked for
            try:
                with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
                    member = max((i for i in zf.infolist() if not i.is_dir()),
                                 key=lambda i: i.file_size)
                    payload = zf.read(member, pwd=b"infected")
                digest = hashlib.sha256(payload).hexdigest()
            except Exception as exc:
                print(f"[dl] {h[:12]} unreadable archive: {type(exc).__name__}",
                      flush=True)
                bad += 1
                continue
            if digest != h:
                print(f"[dl] {h[:12]} SHA MISMATCH (got {digest[:12]}) -- discarded",
                      flush=True)
                bad += 1
                continue
            (OUT_DIR / f"{h}.zip").write_bytes(data)
            ledger.write(json.dumps({
                "sha256": h, "bytes_zip": len(data), "bytes_raw": len(payload),
                "ember_packer": rec.get("ember_packer"),
                "ember_family": rec.get("ember_family"),
                "split": rec.get("split"),
                "mb_signature": rec.get("mb_signature")}) + "\n")
            ledger.flush()
            got += 1
            state["count"] += 1
            save_state(state)
            if got % 50 == 0:
                print(f"[dl] {got} downloaded, {bad} rejected, "
                      f"quota used {state['count']}/{args.cap}", flush=True)
            time.sleep(args.sleep)
    print(f"[dl] done: {got} stored, {bad} rejected, "
          f"quota used {state['count']}/{args.cap}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
