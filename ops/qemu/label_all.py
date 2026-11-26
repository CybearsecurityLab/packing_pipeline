#!/usr/bin/env python3
"""Empirically label EVERY packer family+version in the NAS (one representative
testcase per family_version -- the Type is invariant across a family+version's
testcases).  Resumable; commits+pushes each label.  Sample-fallback: if the chosen
payloads do not yield a consensus Type (a sample that evades/crashes/doesn't
unpack), it retries with DIFFERENT samples before recording an UNRESOLVED reason.

Reads empirical_results/qemu_runtime/worklist.json (built by the enumerator).

LABEL_ARM=vmarm runs the VM arm instead: only conditions whose certified
`<tag>.done` label is UNRESOLVED, traced with run_trace.py --profile vmarm on the
certified payload pair, compared with the certified runs (compare_arms.py), and
recorded as `<tag>.vmarm.done` plus a `vm_arm` block in the condition's manifest
YAML. The certified `label` is never changed.
"""
from __future__ import annotations

import hashlib
import json
import shutil
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
ARM = os.environ.get("LABEL_ARM", "")
if ARM not in ("", "vmarm"):
    raise SystemExit(f"LABEL_ARM must be unset or 'vmarm', not {ARM!r}")
VMARM = ARM == "vmarm"
# Where per-condition run artifacts land, relative to the repo.  Each condition's
# directory is rm -rf'd before its runs, so a non-certified experiment (e.g.
# LABEL_TRANSPARENT=1, a different backend identity) pointed at the default root
# DESTROYS the certified traces/metas for that condition.  Override it to keep the
# arms separate.
RUNS_ROOT = os.environ.get("LABEL_RUNS_ROOT",
                           "empirical_results/qemu_runtime/vmarm_runs" if VMARM
                           else "empirical_results/qemu_runtime/all_runs").strip("/")
CERT_RUNS_ROOT = os.environ.get("LABEL_CERTIFIED_RUNS_ROOT",
                                "empirical_results/qemu_runtime/all_runs").strip("/")
VMARM_DIR = REPO / os.environ.get("LABEL_VMARM_DIR", "empirical_results/full_matrix_vmarm")
DONE_DIR = REPO / os.environ.get("LABEL_DONE_DIR", "empirical_results/full_matrix")
RELABEL = os.environ.get("LABEL_RELABEL") == "1"
NO_GIT = os.environ.get("LABEL_NO_GIT") == "1"
RERUN_FAILED = "--rerun-failed" in sys.argv or os.environ.get("LABEL_RERUN_FAILED") == "1"
NEUTRAL_ONLY = os.environ.get("LABEL_NEUTRAL_ONLY") == "1"


def neutral_payload(name: str) -> bool:
    return "_portable_" in name
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
        usable = [s for s in pool if not _truncated_payload(s["remote"])
                  and (not NEUTRAL_ONLY or neutral_payload(s["name"]))]
        return [(s["remote"], s["name"]) for s in usable[:limit]]
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


LOCAL_MIRROR = os.environ.get("LABEL_LOCAL_MIRROR")
NAS_ROOT = "//10.100.99.29/samples/benign_packed/"


def _truncated_payload(remote: str) -> bool:
    if not (LOCAL_MIRROR and remote.startswith(NAS_ROOT)):
        return False
    local = Path(LOCAL_MIRROR) / remote[len(NAS_ROOT):]
    try:
        size = local.stat().st_size
        with local.open("rb") as handle:
            head = handle.read(65536)
        pe = int.from_bytes(head[0x3C:0x40], "little")
        if head[:2] != b"MZ" or head[pe:pe + 4] != b"PE\0\0":
            return False
        sections = int.from_bytes(head[pe + 6:pe + 8], "little")
        table = pe + 24 + int.from_bytes(head[pe + 20:pe + 22], "little")
        needed = 0
        for index in range(sections):
            entry = table + 40 * index
            raw_size = int.from_bytes(head[entry + 16:entry + 20], "little")
            raw_pointer = int.from_bytes(head[entry + 20:entry + 24], "little")
            if raw_size:
                needed = max(needed, raw_pointer + raw_size)
    except (OSError, ValueError):
        return False
    return needed > size


def fetch(remote: str, dest: Path) -> str:
    if LOCAL_MIRROR and remote.startswith(NAS_ROOT):
        local = Path(LOCAL_MIRROR) / remote[len(NAS_ROOT):]
        if local.is_file():
            data = local.read_bytes()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return hashlib.sha256(data).hexdigest()
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
        stage_env = [f"{k}={os.environ[k]}" for k in
                     ("STAGE_BASE", "STAGE_LAUNCHER", "STAGE_OVERLAY", "STAGE_NBD")
                     if os.environ.get(k)]
        p = subprocess.run(["sudo", "-S", "env", *stage_env, "ops/qemu/stage_sample.sh",
                            str(sample), str(image),
                            os.environ.get("LABEL_STAGE_TIMEOUT", "300")],
                           cwd=str(REPO), input=SUDO_PW + "\n",
                           text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def run_pair(tag: str, cond: dict, pair) -> tuple[str, dict]:
    """Run n=REPS x 2 payloads for one pair; return (label, per-run types)."""
    images = []
    arm_tag = f"{tag}_vmarm" if VMARM else tag
    for i, (remote, nm) in enumerate(pair, 1):
        sample = RT / f"{arm_tag}_s{i}" / "sample.exe"
        sha = fetch(remote, sample)
        if os.environ.get("LABEL_INCOMING"):
            images.append([str(sample.relative_to(REPO)), sha, f"{tag}{chr(64+i)}"])
            continue
        img = RT / f"windows10-qemu-{arm_tag}{i}.qcow2"
        if not stage(sample, img):
            return "STAGE_FAILED", {}
        images.append([f"empirical_results/qemu_runtime/windows10-qemu-{arm_tag}{i}.qcow2",
                       sha, f"{tag}{chr(64+i)}"])
    runs_dir = f"{RUNS_ROOT}/{tag}"
    cfg = {"condition": cond, "payloads": images, "reps": REPS, "runs_dir": runs_dir}
    cfg_path = RT / "configs" / (f"{tag}.vmarm.json" if VMARM else f"{tag}.json")
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    previous = REPO / runs_dir
    if previous.exists():
        attempts = previous.parent / f"{tag}.attempts"
        archive = attempts / str(len(list(attempts.glob("*"))) if attempts.exists() else 0)
        for rd in sorted(previous.glob("*/")):
            for keep in ("classification.json", "meta.json", "sample.json"):
                if (rd / keep).exists():
                    (archive / rd.name).mkdir(parents=True, exist_ok=True)
                    shutil.copy2(rd / keep, archive / rd.name / keep)
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
        yaml_out = (str(VMARM_DIR / f"empirical_types_{tag}.yaml") if VMARM
                    else f"manifest/type/empirical_types_{tag}.yaml")
        labels_out = (str(VMARM_DIR / f"{tag}_labels.json") if VMARM
                      else f"empirical_results/full_matrix/{tag}_labels.json")
        sh(["uv", "run", "packer-types", "finalize", str(plan), str(REPO / runs_dir),
            "--yaml-output", yaml_out, "--output", labels_out])
        import yaml
        m = yaml.safe_load((REPO / yaml_out).read_text())
        for c in m.get("conditions", []):
            if (c.get("label_status") == "empirical_exact_trace_consensus" and c.get("label")
                    and not c.get("label_carried_forward")):
                return c["label"], types
    return "UNRESOLVED", types


def _failed_condition(marker: Path) -> bool:
    try:
        done = json.loads(marker.read_text())
    except (OSError, ValueError):
        return True
    runs = list((done.get("runs") or {}).values())
    if not runs:
        return True
    return any(not (str(t).startswith("TYPE_") or t == "UNRESOLVED_NO_UNPACKING_OBSERVED")
               for t in runs)


def already_labeled(tag: str) -> bool:
    marker = DONE_DIR / f"{tag}.done"
    if marker.exists():
        if RERUN_FAILED and _failed_condition(marker):
            archive = DONE_DIR.parent / f"{DONE_DIR.name}.rerun-failed"
            archive.mkdir(exist_ok=True)
            shutil.move(str(marker), str(archive / marker.name))
            runs = REPO / RUNS_ROOT / tag
            if runs.exists():
                shutil.move(str(runs), str(archive / tag))
            return False
        return True
    if RELABEL:
        return False
    f = REPO / f"manifest/type/empirical_types_{tag}.yaml"
    if not f.exists():
        return False
    import yaml
    m = yaml.safe_load(f.read_text()) or {}
    for c in m.get("conditions", []):
        if c.get("label_status") == "empirical_exact_trace_consensus":
            return True
    return False


def _condition(w: dict) -> dict:
    tag = w["nas_dir"]
    return {
        "packer_family": w.get("family") or w["nas_dir"].split("_v")[0],
        "packer_version": w.get("version") or "?",
        "test_case_id": w["testcase"],
        "configuration_id": w.get("cid") or f"{tag}-auto",
        "type_hypothesis": None, "source": "yaml_test_case",
        "status": "planned", "available_samples": 2,
    }


def certified_unresolved(tag: str) -> bool:
    try:
        done = json.loads((DONE_DIR / f"{tag}.done").read_text())
    except (OSError, ValueError):
        return False
    return done.get("label") == "UNRESOLVED"


def vmarm_pending(tag: str) -> bool:
    if not certified_unresolved(tag):
        return False
    return RELABEL or not (DONE_DIR / f"{tag}.vmarm.done").exists()


def certified_pair(tag: str, cands: list) -> list:
    """The candidates whose sha256 matches the certified run's payloads, in order."""
    try:
        cfg = json.loads((RT / "configs" / f"{tag}.json").read_text())
        wanted = [p[1] for p in cfg.get("payloads") or []]
    except (OSError, ValueError, IndexError, TypeError):
        wanted = []
    found: dict[str, tuple] = {}
    probe = RT / f"{tag}_vmarm_probe" / "sample.exe"
    for cand in cands:
        if len(found) == len(set(wanted)):
            break
        try:
            sha = fetch(cand[0], probe)
        except Exception:
            continue
        if sha in wanted and sha not in found:
            found[sha] = cand
    shutil.rmtree(probe.parent, ignore_errors=True)
    pair = [found[sha] for sha in wanted if sha in found]
    return pair if len(pair) >= 2 else list(cands[:2])


def _ops(name: str):
    if str(REPO / "ops/qemu") not in sys.path:
        sys.path.insert(0, str(REPO / "ops/qemu"))
    return __import__(name)


def vmarm_result(tag: str, family: str | None, label: str, types: dict) -> dict:
    compare_arms = _ops("compare_arms")
    cert_dirs = [d for d in sorted((REPO / CERT_RUNS_ROOT / tag).glob("*/"))
                 if (d / "classification.json").exists() or (d / "meta.json").exists()]
    vm_dirs = [d for d in sorted((REPO / RUNS_ROOT / tag).glob("*/"))
               if (d / "classification.json").exists() or (d / "meta.json").exists()]
    comparison = compare_arms.compare([compare_arms.rep_from_dir(d) for d in cert_dirs],
                                      [compare_arms.rep_from_dir(d) for d in vm_dirs],
                                      family)
    consensus = label if label.startswith("TYPE_") else None
    vm_type = consensus or comparison["vm_arm_type"]
    return {
        "label": label,
        "runs": types,
        "vm_arm_outcome": comparison["vm_arm_outcome"],
        "vm_arm_type": vm_type,
        "vm_arm_type_rule": "exact" if consensus else "max-observed" if vm_type else None,
        "evasion_suspected": comparison["evasion_suspected"],
        "evidence": comparison["evidence"],
        "arm_comparison": {k: v for k, v in comparison.items()
                           if k not in ("vm_arm_outcome", "vm_arm_type",
                                        "evasion_suspected", "evidence")},
    }


def annotate_manifest(tag: str, result: dict) -> Path | None:
    import yaml
    path = REPO / f"manifest/type/empirical_types_{tag}.yaml"
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    block = {
        "outcome": result["vm_arm_outcome"],
        "type": result["vm_arm_type"],
        "type_rule": result["vm_arm_type_rule"],
        "consensus_label": result["label"],
        "evasion_suspected": result["evasion_suspected"],
        "evidence": sorted({str(e.get("signal")) for e in result["evidence"]
                            if e.get("signal")}),
        "done_marker": os.path.relpath(DONE_DIR / f"{tag}.vmarm.done", REPO),
    }
    for cond in data.get("conditions") or []:
        cond["vm_arm"] = block
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def label_condition_vmarm(w: dict) -> None:
    tag = w["nas_dir"]
    if not vmarm_pending(tag):
        print(f"[skip] {tag} not pending for the VM arm", flush=True)
        return
    cands = candidate_samples(w, limit=2 * MAX_SAMPLE_ATTEMPTS)
    if len(cands) < 2:
        print(f"[vmarm] {tag}: fewer than 2 candidates", flush=True)
        return
    pair = certified_pair(tag, cands)
    print(f"[vmarm] {tag}: {[p[1] for p in pair]}", flush=True)
    label, types = run_pair(tag, _condition(w), pair)
    if label == "STAGE_FAILED":
        print(f"[VMARM] {tag} -> STAGE_FAILED (not recorded)", flush=True)
        return
    if label.startswith("BAD_PAYLOAD"):
        label = "UNRESOLVED"
    result = vmarm_result(tag, w.get("family"), label, types)
    DONE_DIR.mkdir(parents=True, exist_ok=True)
    (DONE_DIR / f"{tag}.vmarm.done").write_text(json.dumps(result), encoding="utf-8")
    manifest = annotate_manifest(tag, result)
    with GIT_LOCK:
        sh(["python3", "ops/qemu/build_label_document.py"])
    if not NO_GIT and manifest is not None:
        with GIT_LOCK:
            sh(["git", "add", "-f", str(manifest.relative_to(REPO)),
                "docs/EMPIRICAL_TYPE_LABELS.md"])
            sh(["git", "commit", "-q", "-m",
                f"VM arm: {tag} -> {result['vm_arm_outcome']} "
                f"({result['vm_arm_type'] or 'no Type'})"])
            sh(["git", "push", "origin", "feature/empirical-type-backend"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rd = REPO / f"{RUNS_ROOT}/{tag}"
    traces = sorted(rd.glob("*/trace.jsonl"))
    keep = {traces[0]} if traces and not result["vm_arm_type"] else set()
    for junk in traces + list(rd.glob("*/work.qcow2")):
        if junk not in keep:
            junk.unlink(missing_ok=True)
    for img in RT.glob(f"windows10-qemu-{tag}_vmarm[12].qcow2"):
        img.unlink(missing_ok=True)
    print(f"[VMARM] {tag} -> {result['vm_arm_outcome']} type={result['vm_arm_type']}",
          flush=True)


def label_condition(w: dict) -> None:
    tag = w["nas_dir"]
    if already_labeled(tag):
        print(f"[skip] {tag} already labeled", flush=True)
        return
    cond = _condition(w)
    cands = candidate_samples(w, limit=2 * MAX_SAMPLE_ATTEMPTS)
    print(f"[cond] {tag}: {len(cands)} candidate samples", flush=True)
    label, all_types = "UNRESOLVED", {}
    if len(cands) < 2:
        print(f"[cond] {tag}: fewer than 2 candidates; cannot form a consensus pair",
              flush=True)
        pool = w.get("samples") or []
        if pool and len(pool) - sum(_truncated_payload(s["remote"]) for s in pool) < 2:
            DONE_DIR.mkdir(parents=True, exist_ok=True)
            (DONE_DIR / f"{tag}.done").write_text(json.dumps(
                {"label": "UNRESOLVED", "reason": "no_valid_payload", "runs": {},
                 "truncated_payloads": sum(_truncated_payload(s["remote"]) for s in pool),
                 "pool": len(pool)}), encoding="utf-8")
            print(f"[LABEL] {tag} -> UNRESOLVED (no_valid_payload)", flush=True)
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
    DONE_DIR.mkdir(parents=True, exist_ok=True)
    (DONE_DIR / f"{tag}.done").write_text(
        json.dumps({"label": label, "runs": all_types,
                    "payloads": [p[1] for p in pair]}), encoding="utf-8")
    with GIT_LOCK:
        sh(["python3", "ops/qemu/build_label_document.py"])
        # PACKER_TYPE_LABELS.md is the authoritative packer->Type document (all
        # labelling rules + the unresolved residue), where EMPIRICAL_TYPE_LABELS.md
        # covers exact-consensus rows only.  It used to be hand-maintained, which let
        # the two documents and the manifests drift apart (79 vs 92 vs 97).  Generate
        # it here so it stays derived from whatever the labeller just wrote.
        sh(["python3", "ops/qemu/build_packer_type_document.py"])
    if not NO_GIT:
        with GIT_LOCK:
            sh(["git", "add", "-f", f"manifest/type/empirical_types_{tag}.yaml",
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
        (label_condition_vmarm if VMARM else label_condition)(w)
    except Exception as e:
        print(f"[error] {w['nas_dir']}: {e}", flush=True)


def main() -> int:
    work = json.loads(Path(os.environ.get("LABEL_WORKLIST") or RT / "worklist.json").read_text())
    work.sort(key=lambda w: (_tier(w), w["nas_dir"]))
    only = {x for x in os.environ.get("LABEL_ONLY", "").split(",") if x}
    if VMARM:
        if not (os.environ.get("LABEL_INCOMING") or os.environ.get("STAGE_BASE")):
            raise SystemExit("LABEL_ARM=vmarm needs the VM arm's guest: set LABEL_INCOMING/"
                             "LABEL_BOOTED_BASE (snapshot) or STAGE_BASE (hardened image)")
        os.environ.setdefault("LABEL_SUDO_PW", SUDO_PW)
        os.environ.setdefault("STAGE_LAUNCHER",
                              str(REPO / "ops/panda/build/guest_launcher_vmarm.exe"))
        todo = [w for w in work if vmarm_pending(w["nas_dir"])
                and (not only or w["nas_dir"] in only)]
    else:
        todo = [w for w in work if not already_labeled(w["nas_dir"])
                and (not only or w["nas_dir"] in only)]
    print(f"[all] {len(work)} conditions ({len(todo)} to do); "
          f"{CONDITIONS} parallel x {os.environ.get('LABEL_JOBS','1')} runs each",
          flush=True)
    subprocess.run(["pkill", "-u", str(os.getuid()), "-f",
                    f"qemu-system-x86_64 -name paper.*{REPO / RUNS_ROOT}/"], check=False)
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
