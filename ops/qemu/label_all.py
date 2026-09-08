#!/usr/bin/env python3
"""Empirically label EVERY packer family+version in the NAS (one representative
testcase per family_version -- the Type is invariant across a family+version's
testcases).  Resumable; commits+pushes each label.  Sample-fallback: if the chosen
payloads do not yield a consensus Type (a sample that evades/crashes/doesn't
unpack), it retries with DIFFERENT samples before recording an UNRESOLVED reason.

Reads empirical_results/qemu_runtime/worklist.json (built by the enumerator).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"
SUDO_PW = "resbears"
MAX_SAMPLE_ATTEMPTS = 4
REPS = 3
MIN_MEANINGFUL_EXEC = 50_000
CONDITIONS = max(1, int(os.environ.get("LABEL_CONDITIONS", "1")))
# Where per-condition run artifacts land, relative to the repo.  Each condition's
# directory is rm -rf'd before its runs, so a non-certified experiment (e.g.
# LABEL_TRANSPARENT=1, a different backend identity) pointed at the default root
# DESTROYS the certified traces/metas for that condition.  Override it to keep the
# arms separate.
RUNS_ROOT = os.environ.get("LABEL_RUNS_ROOT",
                           "empirical_results/qemu_runtime/all_runs").strip("/")
STAGE_LOCK = threading.Lock()
GIT_LOCK = threading.Lock()
SMB_LOCK = threading.Lock()


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=str(REPO), **kw)


def _session():
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session("10.100.99.29",
                               username=os.environ["PACKER_NAS_USERNAME"],
                               password=os.environ["PACKER_NAS_PASSWORD"])
    return smbclient


def candidate_samples(w: dict, limit: int = 8):
    """Candidate (remote, name) payloads for a family+version.

    The enumerator pre-collects a sample pool spanning ALL of the family+version's
    testcases (Type is invariant across testcases, so the >=2 distinct payloads a
    consensus needs may come from any testcase).  Fall back to a live single-
    testcase scan only if the worklist entry predates the pooled format.
    """
    pool = w.get("samples")
    if pool:
        return [(s["remote"], s["name"]) for s in pool[:limit]]
    smb = _session()
    base = f"//10.100.99.29/samples/benign_packed/{w['nas_dir']}/{w['testcase']}"
    cand = []
    for e in smb.scandir(base):
        if e.name.lower().endswith(".exe"):
            try:
                cand.append((smb.stat(base + "/" + e.name).st_size, e.name))
            except Exception:
                pass
    cand.sort()
    return [(base + "/" + nm, nm) for _, nm in cand[:limit]]


def fetch(remote: str, dest: Path) -> str:
    last = None
    for attempt in range(4):
        try:
            with SMB_LOCK:
                smb = _session()
                with smb.open_file(remote, mode="rb") as sf:
                    data = sf.read()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            last = e
            print(f"[smb] fetch retry {attempt+1}/4 for {Path(remote).name}: {e}",
                  flush=True)
            time.sleep(5 * (attempt + 1))
            try:
                import smbclient
                smbclient.reset_connection_cache()
            except Exception:
                pass
    raise RuntimeError(f"SMB fetch failed after retries: {last}")


def stage(sample: Path, image: Path) -> bool:
    with STAGE_LOCK:
        p = subprocess.run(["sudo", "-S", "ops/qemu/stage_sample.sh", str(sample),
                            str(image), "300"], cwd=str(REPO), input=SUDO_PW + "\n",
                           text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def run_pair(tag: str, cond: dict, pair) -> tuple[str, dict]:
    """Run n=REPS x 2 payloads for one pair; return (label, per-run types)."""
    images = []
    for i, (remote, nm) in enumerate(pair, 1):
        sample = RT / f"{tag}_s{i}" / "sample.exe"
        sha = fetch(remote, sample)
        img = RT / f"windows10-qemu-{tag}{i}.qcow2"
        if not stage(sample, img):
            return "STAGE_FAILED", {}
        images.append([f"empirical_results/qemu_runtime/windows10-qemu-{tag}{i}.qcow2",
                       sha, f"{tag}{chr(64+i)}"])
    runs_dir = f"{RUNS_ROOT}/{tag}"
    cfg = {"condition": cond, "payloads": images, "reps": REPS, "runs_dir": runs_dir}
    cfg_path = RT / "configs" / f"{tag}.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    sh(["rm", "-rf", str(REPO / runs_dir)])
    sh(["python3", "ops/qemu/run_condition_matrix.py", str(cfg_path)])
    types = {}
    d = REPO / runs_dir
    for rd in sorted(d.glob("*/")):
        cj = rd / "classification.json"
        if cj.exists():
            try:
                types[rd.name] = json.loads(cj.read_text())["complexity_type"]
            except Exception:
                types[rd.name] = "?"
    per_payload: dict[str, list[int]] = {}
    for rd in sorted(d.glob("*/")):
        mj = rd / "meta.json"
        if not mj.exists():
            continue
        try:
            summ = (json.loads(mj.read_text()).get("summary") or {})
            ex = int(summ.get("exec_events") or 0)
        except Exception:
            continue
        key = "A" if "A_rep" in rd.name else ("B" if "B_rep" in rd.name else "?")
        per_payload.setdefault(key, []).append(ex)
    if len(per_payload) >= 2:
        med = {k: sorted(v)[len(v) // 2] for k, v in per_payload.items() if v}
        if med:
            hi_k = max(med, key=lambda k: med[k])
            lo_k = min(med, key=lambda k: med[k])
            hi, lo = med[hi_k], med[lo_k]
            if hi >= MIN_MEANINGFUL_EXEC and lo < MIN_MEANINGFUL_EXEC and hi > 20 * max(lo, 1):
                print(f"[dud] {tag}: payload {lo_k} executed only {lo} blocks vs "
                      f"{hi} for {hi_k} -- treating as a failed observation, not a "
                      f"verdict; trying a different payload", flush=True)
                return f"BAD_PAYLOAD:{lo_k}", types
            if hi == 0:
                print(f"[dud] {tag}: no payload executed a single block "
                      f"(loaded but never started) -- both are duds, trying two "
                      f"different payloads", flush=True)
                return "BAD_PAYLOAD:BOTH", types
    plan = REPO / runs_dir / "plan.json"
    if plan.exists():
        pd = json.loads(plan.read_text())
        for c in pd["conditions"]:
            c.setdefault("source", "yaml_test_case")
            c.setdefault("status", "planned")
            c.setdefault("available_samples", 2)
        plan.write_text(json.dumps(pd, indent=2))
        sh(["uv", "run", "packer-types", "finalize", str(plan), str(REPO / runs_dir),
            "--yaml-output", f"manifest/empirical_types_{tag}.yaml",
            "--output", f"empirical_results/full_matrix/{tag}_labels.json"])
        import yaml
        m = yaml.safe_load((REPO / f"manifest/empirical_types_{tag}.yaml").read_text())
        for c in m.get("conditions", []):
            if c.get("label_status") == "empirical_exact_trace_consensus" and c.get("label"):
                return c["label"], types
    return "UNRESOLVED", types


def already_labeled(tag: str) -> bool:
    if (REPO / f"empirical_results/full_matrix/{tag}.done").exists():
        return True
    f = REPO / f"manifest/empirical_types_{tag}.yaml"
    if not f.exists():
        return False
    import yaml
    m = yaml.safe_load(f.read_text()) or {}
    for c in m.get("conditions", []):
        if c.get("label_status") == "empirical_exact_trace_consensus":
            return True
    return False


def label_condition(w: dict) -> None:
    tag = w["nas_dir"]
    if already_labeled(tag):
        print(f"[skip] {tag} already labeled", flush=True)
        return
    cond = {
        "packer_family": w.get("family") or w["nas_dir"].split("_v")[0],
        "packer_version": w.get("version") or "?",
        "test_case_id": w["testcase"],
        "configuration_id": w.get("cid") or f"{tag}-auto",
        "type_hypothesis": None, "source": "yaml_test_case",
        "status": "planned", "available_samples": 2,
    }
    cands = candidate_samples(w, limit=2 * MAX_SAMPLE_ATTEMPTS)
    print(f"[cond] {tag}: {len(cands)} candidate samples", flush=True)
    label, all_types = "UNRESOLVED", {}
    if len(cands) < 2:
        print(f"[cond] {tag}: fewer than 2 candidates; cannot form a consensus pair",
              flush=True)
        return
    pair = [cands[0], cands[1]]
    nxt = 2
    for attempt in range(MAX_SAMPLE_ATTEMPTS):
        print(f"[try] {tag} attempt {attempt+1}: {[p[1] for p in pair]}", flush=True)
        label, types = run_pair(tag, cond, pair)
        all_types = types
        print(f"[try] {tag} attempt {attempt+1} -> {label} (runs: {types})", flush=True)
        if label.startswith("TYPE_"):
            break
        if label == "BAD_PAYLOAD:BOTH":
            if nxt >= len(cands):
                print(f"[swap] {tag}: candidate pool exhausted; no payload ever "
                      f"executed -- UNRESOLVED", flush=True)
                label = "UNRESOLVED"
                break
            repl = [cands[nxt]]
            nxt += 1
            if nxt < len(cands):
                repl.append(cands[nxt])
                nxt += 1
            else:
                repl.append(pair[1])
            print(f"[swap] {tag}: no payload ran; replacing both with "
                  f"{[p[1] for p in repl]}", flush=True)
            pair = repl
            continue
        if label.startswith("BAD_PAYLOAD:"):
            i = 0 if label.split(":", 1)[1] == "A" else 1
            if nxt >= len(cands):
                print(f"[swap] {tag}: candidate pool exhausted; keeping "
                      f"{pair[1 - i][1]} but no replacement left", flush=True)
                break
            print(f"[swap] {tag}: keeping {pair[1 - i][1]} (it ran), replacing dud "
                  f"{pair[i][1]} with {cands[nxt][1]}", flush=True)
            pair[i] = cands[nxt]
            nxt += 1
            continue
        if nxt + 1 < len(cands):
            pair = [cands[nxt], cands[nxt + 1]]
            nxt += 2
        else:
            break
    if label == "STAGE_FAILED":
        print(f"[LABEL] {tag} -> STAGE_FAILED (not recorded; will retry next run)",
              flush=True)
        return
    if label.startswith("BAD_PAYLOAD"):
        label = "UNRESOLVED"
    (REPO / f"empirical_results/full_matrix/{tag}.done").write_text(
        json.dumps({"label": label, "runs": all_types}), encoding="utf-8")
    with GIT_LOCK:
        sh(["python3", "ops/qemu/build_label_document.py"])
        # PACKER_TYPE_LABELS.md is the authoritative packer->Type document (all
        # labelling rules + the unresolved residue), where EMPIRICAL_TYPE_LABELS.md
        # covers exact-consensus rows only.  It used to be hand-maintained, which let
        # the two documents and the manifests drift apart (79 vs 92 vs 97).  Generate
        # it here so it stays derived from whatever the labeller just wrote.
        sh(["python3", "ops/qemu/build_packer_type_document.py"])
        sh(["git", "add", "-f", f"manifest/empirical_types_{tag}.yaml",
            "docs/EMPIRICAL_TYPE_LABELS.md", "docs/PACKER_TYPE_LABELS.md"])
        sh(["git", "add", f"empirical_results/qemu_runtime/configs/{tag}.json"])
        sh(["git", "commit", "-q", "-m",
            f"Empirical label: {tag} -> {label} ({w['testcase']})"])
        sh(["git", "push", "origin", "feature/empirical-type-backend"],
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rd = REPO / f"{RUNS_ROOT}/{tag}"
    traces = sorted(rd.glob("*/trace.jsonl"))
    keep = set()
    if traces and not label.startswith("TYPE_"):
        keep.add(traces[0])
    for junk in traces + list(rd.glob("*/work.qcow2")):
        if junk in keep:
            continue
        try:
            junk.unlink()
        except Exception:
            pass
    for img in RT.glob(f"windows10-qemu-{tag}[12].qcow2"):
        try:
            img.unlink()
        except Exception:
            pass
    print(f"[LABEL] {tag} -> {label}", flush=True)


_PROTECTORS = {
    "acprotect_std_standard__installer", "alienyze_protector", "armadillo",
    "asm_guard", "astral_pe", "enigma_protector", "obsidium", "pelock", "telock",
    "themida", "zprotect", "yoda_protector", "pezor", "hyperion",
}


def _tier(w: dict) -> int:
    fam = str(w.get("family", "")).lower()
    if fam in _PROTECTORS:
        return 2
    if fam.startswith("upx"):
        return 0
    return 1


def _process(idx_total_w) -> None:
    i, total, w = idx_total_w
    print(f"===== [{i}/{total}] {w['nas_dir']} =====", flush=True)
    try:
        label_condition(w)
    except Exception as e:
        print(f"[error] {w['nas_dir']}: {e}", flush=True)


def main() -> int:
    work = json.loads((RT / "worklist.json").read_text())
    work.sort(key=lambda w: (_tier(w), w["nas_dir"]))
    todo = [w for w in work if not already_labeled(w["nas_dir"])]
    print(f"[all] {len(work)} conditions ({len(todo)} to do); "
          f"{CONDITIONS} parallel x {os.environ.get('LABEL_JOBS','1')} runs each",
          flush=True)
    subprocess.run(["pkill", "-f", "qemu-system-x86_64 -name paper"], check=False)
    time.sleep(2)
    runs_root = REPO / RUNS_ROOT
    freed = 0
    for pat in ("*/trace.jsonl", "*/work.qcow2"):
        for stale in runs_root.glob(pat):
            try:
                freed += stale.stat().st_size
                stale.unlink()
            except Exception:
                pass
    if freed:
        print(f"[all] purged {freed // (1024 ** 3)}GB of stale traces from prior runs",
              flush=True)
    items = [(i, len(todo), w) for i, w in enumerate(todo, 1)]
    if CONDITIONS <= 1:
        for it in items:
            _process(it)
    else:
        with ThreadPoolExecutor(max_workers=CONDITIONS) as ex:
            list(ex.map(_process, items))
    print("[all] DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
