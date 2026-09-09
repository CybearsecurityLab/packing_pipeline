#!/usr/bin/env python3
"""One-command empirical labeling of a NAS packer condition, end to end:
fetch 2 distinct packed payloads -> stage 2 disposable guest images -> run the
certified tracer n=3 x 2 -> classify -> finalize -> regenerate the label document.

Usage:
  python3 ops/qemu/label_nas_condition.py <nas_family_dir> <testcase> <family> <version>
e.g. python3 ops/qemu/label_nas_condition.py hyperion_v2.3.1_2.3.1 HYPERION_001_DEFAULT hyperion 2.3.1
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
SUDO_PW = "resbears"


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=str(REPO), **kw)


def configuration_id(family: str, version: str, testcase: str) -> str | None:
    data = yaml.safe_load((REPO / "manifest/empirical_types.yaml").read_text())
    for c in data.get("conditions", []):
        if (str(c.get("packer_family", "")).lower() == family.lower()
                and str(c.get("packer_version")) == str(version)
                and str(c.get("test_case_id")) == testcase):
            return c.get("configuration_id")
    return None


def fetch_two(nas_dir: str, testcase: str, tag: str) -> list[tuple[str, str]]:
    import smbclient
    for k in ("PACKER_NAS_USERNAME", "PACKER_NAS_PASSWORD"):
        if k not in os.environ:  # load .env
            for line in (REPO / ".env").read_text().splitlines():
                if line.startswith("PACKER_NAS_"):
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())
    srv, share = "10.100.99.29", "samples"
    smbclient.register_session(srv, username=os.environ["PACKER_NAS_USERNAME"],
                               password=os.environ["PACKER_NAS_PASSWORD"])
    base = f"//{srv}/{share}/benign_packed/{nas_dir}/{testcase}"
    cand = []
    for e in smbclient.scandir(base):
        if e.name.lower().endswith(".exe"):
            try:
                cand.append((smbclient.stat(base + "/" + e.name).st_size, e.name))
            except Exception:
                pass
    cand.sort()
    out = []
    for i, (_, nm) in enumerate(cand[:2], 1):
        with smbclient.open_file(base + "/" + nm, mode="rb") as sf:
            data = sf.read()
        d = RT / f"{tag}_s{i}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "sample.exe").write_bytes(data)
        out.append((str(d / "sample.exe"), hashlib.sha256(data).hexdigest()))
        print(f"fetched {tag}_s{i}: {nm} sha {out[-1][1][:16]}", flush=True)
    return out


def stage(sample: str, image: str) -> None:
    # -E + STAGE_OVERLAY: without it stage_sample.sh does a real copy of the 11.3 GB
    # base per image, which fills the 250 GB root filesystem well before a sweep of
    # any size completes.
    env = {**os.environ, "STAGE_OVERLAY": os.environ.get("STAGE_OVERLAY", "1")}
    p = subprocess.run(["sudo", "-S", "-E", "ops/qemu/stage_sample.sh",
                        sample, image, "300"],
                       cwd=str(REPO), input=SUDO_PW + "\n", text=True, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        raise SystemExit(f"staging failed for {sample}")
    print(f"staged {image}", flush=True)


def main() -> int:
    nas_dir, testcase, family, version = sys.argv[1:5]
    cid = configuration_id(family, version, testcase)
    if not cid:
        raise SystemExit(f"no configuration_id for {family} {version} {testcase}")
    tag = family.lower()
    payloads = fetch_two(nas_dir, testcase, tag)
    if len(payloads) < 2:
        raise SystemExit("need 2 distinct payloads")
    images = []
    for i, (sample, sha) in enumerate(payloads, 1):
        img = str(RT / f"windows10-qemu-{tag}{i}.qcow2")
        stage(sample, img)
        images.append([f"empirical_results/qemu_runtime/windows10-qemu-{tag}{i}.qcow2",
                       sha, f"{tag}{chr(64+i)}"])
    runs_dir = f"empirical_results/qemu_runtime/{tag}_runs"
    cfg = {
        "condition": {"packer_family": family, "packer_version": version,
                      "test_case_id": testcase, "configuration_id": cid,
                      "type_hypothesis": None, "source": "yaml_test_case",
                      "status": "planned", "available_samples": 2},
        "payloads": images, "reps": 3, "runs_dir": runs_dir,
    }
    cfg_path = RT / "configs" / f"{tag}.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    sh(["rm", "-rf", str(REPO / runs_dir)])
    sh(["python3", "ops/qemu/run_condition_matrix.py", str(cfg_path)])
    # ensure plan has finalize fields
    plan = REPO / runs_dir / "plan.json"
    pd = json.loads(plan.read_text())
    for c in pd["conditions"]:
        c.setdefault("source", "yaml_test_case")
        c.setdefault("status", "planned")
        c.setdefault("available_samples", 2)
    plan.write_text(json.dumps(pd, indent=2))
    sh(["uv", "run", "packer-types", "finalize", str(plan), str(REPO / runs_dir),
        "--yaml-output", f"manifest/type/empirical_types_{tag}.yaml",
        "--output", f"empirical_results/full_matrix/{tag}_labels.json"])
    sh(["python3", "ops/qemu/build_label_document.py"])
    # Also regenerate the authoritative packer->Type document, which covers every
    # labelling rule plus the unresolved residue (build_label_document.py emits only
    # the exact-consensus subset).  Keeping it generated is what stops it drifting
    # from the manifests, as it did while hand-maintained.
    sh(["python3", "ops/qemu/build_packer_type_document.py"])
    m = yaml.safe_load((REPO / f"manifest/type/empirical_types_{tag}.yaml").read_text())
    print(f"[{family} {version} {testcase}] label_distribution:",
          m.get("label_distribution"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
