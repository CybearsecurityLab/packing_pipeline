#!/usr/bin/env python3
"""Run one paper-faithful condition (>=3 reps x >=2 distinct payloads) through the
certified QEMU tracer + classifier, writing finalize-compatible run directories
(run.json + sample.json + classification.json) so `packer-types finalize` can emit
an exact-consensus empirical label.  icount makes each run reliable (no retries)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
QEMU = REPO / "empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"
PLUGIN = REPO / "ops/qemu/paper_trace.so"

_DEFAULT = {
    "condition": {
        "packer_family": "UPX", "packer_version": "3.95",
        "test_case_id": "UPX_V395_001_DEFAULT",
        "configuration_id": "upx_v395_001_default-348ddc970297",
        "type_hypothesis": None,
    },
    "payloads": [
        ["empirical_results/qemu_runtime/windows10-qemu-upxpilot.qcow2",
         "3b26652eb16587e35e7fe8670a9df1b2bc1cf4f7075c48baf9a445f65986d47f", "ansi2knr"],
        ["empirical_results/qemu_runtime/windows10-qemu-upxpilot2.qcow2",
         "b2070461ca787fe43c346f530d0387bbfc446cf5fb266ab38a2594c2a5af0542", "cksum"],
    ],
    "reps": 3,
    "runs_dir": "empirical_results/qemu_runtime/matrix_runs",
}

_cfg = _DEFAULT
if len(sys.argv) > 1:
    _cfg = json.loads(Path(sys.argv[1]).read_text())
CONDITION = _cfg["condition"]
PAYLOADS = [(REPO / p[0], p[1], p[2]) for p in _cfg["payloads"]]
REPS = int(_cfg.get("reps", 3))
RUNS = REPO / _cfg.get("runs_dir", "empirical_results/qemu_runtime/matrix_runs")
JOBS = max(1, int(_cfg.get("jobs") or os.environ.get("LABEL_JOBS", "1")))
HOST_TIMEOUT = str(int(_cfg.get("host_timeout") or
                       os.environ.get("LABEL_HOST_TIMEOUT", "1200")))
WRITE_SETTLED = str(int(_cfg.get("write_settled_seconds") or
                        os.environ.get("LABEL_WRITE_SETTLED", "0")))
# Anti-VM transparency (run_trace.py --transparent): a realistic CPU model with
# -hypervisor, which clears QEMU's CPUID hypervisor-present bit, 0x40000000 vendor
# leaf and "QEMU Virtual CPU" brand string.  Anti-VM protectors (telock, yoda,
# armadillo, themida) read those and bail to an evasion path, which is why they
# trace but never unpack.  OFF by default so the certified qemu64 results stand;
# a transparent run is a DIFFERENT backend identity and must not be mixed with them.
TRANSPARENT = bool(_cfg.get("transparent") or
                   os.environ.get("LABEL_TRANSPARENT", "").lower()
                   in {"1", "true", "yes"})
CPU_MODEL = str(_cfg.get("cpu_model") or
                os.environ.get("LABEL_CPU_MODEL", "") or "").strip()
ACCEPT_BOUNDED = bool(_cfg.get("accept_bounded") or
                      os.environ.get("LABEL_ACCEPT_BOUNDED", "").lower()
                      in {"1", "true", "yes"})
DELETE_TRACE = bool(_cfg.get("delete_trace") or
                    os.environ.get("LABEL_DELETE_TRACE", "").lower()
                    in {"1", "true", "yes"})
ICOUNT_SHIFT = str(_cfg.get("icount_shift") if _cfg.get("icount_shift") is not None
                   else os.environ.get("LABEL_ICOUNT_SHIFT", "2"))
ICOUNT_SLEEP = str(_cfg.get("icount_sleep")
                   or os.environ.get("LABEL_ICOUNT_SLEEP", "on"))
PLUGIN_ARGS = [a for a in (os.environ.get("LABEL_PLUGIN_ARGS", "").split(","))
               if a.strip()]
CLASSIFY_SEM = threading.Semaphore(
    max(1, int(os.environ.get("LABEL_CLASSIFY_JOBS", "4"))))


def run_one(image: Path, sha: str, name: str, rep: int) -> str:
    sample_id = f"{CONDITION['test_case_id']}__{name}__rep{rep}"
    d = RUNS / f"{name}_rep{rep}"
    if d.exists():
        cj = d / "classification.json"
        if cj.exists():
            print(f"[skip] {sample_id} already done", flush=True)
            return sample_id
    subprocess.run(["rm", "-rf", str(d)], check=False)
    d.mkdir(parents=True, exist_ok=True)
    print(f"[run] {sample_id}", flush=True)
    mon = Path("/tmp/qm") / (hashlib.md5(f"{sample_id}".encode()).hexdigest()[:12] + ".sock")
    mon.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rm", "-f", str(mon)], check=False)
    command = [
        "uv", "run", "python", str(REPO / "ops/qemu/run_trace.py"),
        str(image), str(d / "work.qcow2"), str(d / "trace.jsonl"),
        "--meta", str(d / "meta.json"), "--log", str(d / "qemu.log"),
        "--monitor", str(mon), "--host-timeout", HOST_TIMEOUT,
        "--write-settled-seconds", WRITE_SETTLED,
        "--guest-memory", "4G", "--qemu", str(QEMU), "--plugin", str(PLUGIN),
        "--icount-shift", ICOUNT_SHIFT, "--icount-sleep", ICOUNT_SLEEP,
    ]
    for plugin_arg in PLUGIN_ARGS:
        command += ["--plugin-arg", plugin_arg]
    if TRANSPARENT:
        command.append("--transparent")
    if CPU_MODEL:
        command += ["--cpu-model", CPU_MODEL]
    proc = subprocess.Popen(
        command,
        stdout=(d / "runner.out").open("w"), stderr=subprocess.STDOUT, cwd=str(REPO),
    )
    proc.wait()
    with CLASSIFY_SEM:
        classify_command = [
            "uv", "run", "packer-types", "classify-paper-trace", str(d / "trace.jsonl"),
            "--sample-id", sample_id, "--meta", str(d / "meta.json"),
            "--output", str(d / "classification.json"),
        ]
        if ACCEPT_BOUNDED:
            classify_command.append("--accept-bounded")
        subprocess.run(classify_command, cwd=str(REPO), check=False)
    if DELETE_TRACE:
        for artifact in (d / "trace.jsonl", d / "work.qcow2"):
            try:
                artifact.unlink()
            except OSError:
                pass
    (d / "sample.json").write_text(json.dumps({
        "sample_id": sample_id,
        "packed_sha256": sha,
        "repetition": rep,
        **CONDITION,
    }, indent=2), encoding="utf-8")
    (d / "run.json").write_text(json.dumps({"return_code": 0}, indent=2),
                                encoding="utf-8")
    ctype = "?"
    try:
        ctype = json.loads((d / "classification.json").read_text())["complexity_type"]
    except Exception:
        pass
    print(f"[done] {sample_id} -> {ctype}", flush=True)
    return sample_id


def main() -> int:
    RUNS.mkdir(parents=True, exist_ok=True)
    start = time.time()
    tasks = [(image, sha, name, rep)
             for image, sha, name in PAYLOADS
             for rep in range(1, REPS + 1)]
    if JOBS <= 1:
        for t in tasks:
            run_one(*t)
    else:
        print(f"[matrix] running {len(tasks)} traces with {JOBS} parallel workers",
              flush=True)
        with ThreadPoolExecutor(max_workers=JOBS) as ex:
            futs = {ex.submit(run_one, *t): t for t in tasks}
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:
                    print(f"[run-error] {futs[f][2]} rep{futs[f][3]}: {e}", flush=True)
    print(f"[matrix] all runs done in {int((time.time()-start)/60)} min", flush=True)
    plan = {"conditions": [CONDITION]}
    plan_path = RUNS / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"[matrix] plan at {plan_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
