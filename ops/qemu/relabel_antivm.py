#!/usr/bin/env python3
"""Re-trace the anti-VM protectors that trace but never unpack under the plain
qemu64 backend, using the transparency mitigation plus bounded observation.

Payloads are already staged on disk from the original sweep, so this does not
touch the NAS.  Each condition keeps the configuration_id its existing manifest
carries, so the regenerated document replaces the unresolved row in place.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"
RUNS_ROOT = Path(os.environ.get("ANTIVM_RUNS_ROOT", "/data/antivm_runs"))
SUDO_PW = "resbears"

CONDITIONS = [
    ("themida_v3.2.4.34_3.2.4.34", "themida", "3.2.4.34"),
    ("armadillo_252b2", "armadillo", "252b2"),
    ("telock_v0.98_0.98", "telock", "0.98"),
    ("obsidium_v1.5.2_1.5.2.11", "obsidium", "1.5.2.11"),
]


def existing_cid(tag: str, family: str, version: str) -> str | None:
    path = REPO / f"manifest/type/empirical_types_{tag}.yaml"
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
        for c in data.get("conditions", []):
            if str(c.get("packer_family", "")).lower() == family.lower():
                return c.get("configuration_id")
    data = yaml.safe_load((REPO / "manifest/empirical_types.yaml").read_text()) or {}
    for c in data.get("conditions", []):
        if (str(c.get("packer_family", "")).lower() == family.lower()
                and str(c.get("packer_version")) == str(version)):
            return c.get("configuration_id")
    return None


def stage(sample: Path, image: Path) -> bool:
    image.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "STAGE_OVERLAY": "1"}
    p = subprocess.run(
        ["sudo", "-S", "-E", "ops/qemu/stage_sample.sh", str(sample), str(image), "300"],
        cwd=str(REPO), input=SUDO_PW + "\n", text=True, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    return p.returncode == 0


def run_condition(tag: str, family: str, version: str) -> str:
    cid = existing_cid(tag, family, version)
    if not cid:
        print(f"[skip] {tag}: no configuration_id", flush=True)
        return "NO_CID"
    payloads = []
    for i in (1, 2):
        sample = RT / f"{tag}_s{i}" / "sample.exe"
        if not sample.exists():
            print(f"[skip] {tag}: missing {sample}", flush=True)
            return "MISSING_SAMPLE"
        image = RUNS_ROOT / "images" / f"{tag}_{i}.qcow2"
        if not stage(sample, image):
            print(f"[skip] {tag}: staging failed for s{i}", flush=True)
            return "STAGE_FAIL"
        sha = hashlib.sha256(sample.read_bytes()).hexdigest()
        payloads.append([str(image), sha, f"{family}{chr(64 + i)}"])
        print(f"[staged] {tag}_s{i} sha {sha[:16]}", flush=True)

    runs_dir = str(RUNS_ROOT / tag)
    cfg = {
        "condition": {
            "packer_family": family, "packer_version": version,
            "test_case_id": None, "configuration_id": cid,
            "type_hypothesis": None, "source": "yaml_test_case",
            "status": "planned", "available_samples": 2,
        },
        "payloads": payloads, "reps": 3, "runs_dir": runs_dir,
    }
    cfg_path = RT / "configs" / f"antivm_{tag}.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))

    subprocess.run(["rm", "-rf", str(REPO / runs_dir)], cwd=str(REPO))
    subprocess.run(["uv", "run", "python", "ops/qemu/run_condition_matrix.py",
                    str(cfg_path)], cwd=str(REPO))

    plan = REPO / runs_dir / "plan.json"
    if not plan.exists():
        print(f"[warn] {tag}: no plan.json produced", flush=True)
        return "NO_PLAN"
    pd = json.loads(plan.read_text())
    for c in pd["conditions"]:
        c.setdefault("source", "yaml_test_case")
        c.setdefault("status", "planned")
        c.setdefault("available_samples", 2)
    plan.write_text(json.dumps(pd, indent=2))

    subprocess.run(
        ["uv", "run", "packer-types", "finalize", str(plan), str(REPO / runs_dir),
         "--yaml-output", f"manifest/type/empirical_types_{tag}.yaml",
         "--output", f"empirical_results/full_matrix/{tag}_labels.json"],
        cwd=str(REPO),
    )
    m = yaml.safe_load((REPO / f"manifest/type/empirical_types_{tag}.yaml").read_text())
    dist = m.get("label_distribution")
    print(f"[{family} {version}] label_distribution: {dist}", flush=True)
    return json.dumps(dist)


def main() -> int:
    os.environ.setdefault("LABEL_TRANSPARENT", "1")
    os.environ.setdefault("LABEL_ACCEPT_BOUNDED", "1")
    os.environ.setdefault("LABEL_HOST_TIMEOUT", "1800")
    os.environ.setdefault("LABEL_JOBS", "2")
    os.environ.setdefault("LABEL_DELETE_TRACE", "1")
    os.environ.setdefault("PACKER_ACCEPT_BOUNDED", "1")
    only = sys.argv[1] if len(sys.argv) > 1 else None
    results = {}
    for tag, family, version in CONDITIONS:
        if only and only != tag:
            continue
        print(f"===== {family} {version} "
              f"(transparent={os.environ['LABEL_TRANSPARENT']} "
              f"bounded={os.environ['LABEL_ACCEPT_BOUNDED']}) =====", flush=True)
        try:
            results[tag] = run_condition(tag, family, version)
        except Exception as e:
            results[tag] = f"ERROR {type(e).__name__}: {e}"
            print(f"[error] {tag}: {e}", flush=True)
    subprocess.run(["python3", "ops/qemu/build_packer_type_document.py"], cwd=str(REPO))
    print("\n===== SUMMARY =====")
    for tag, res in results.items():
        print(f"  {tag:<34} {res}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
