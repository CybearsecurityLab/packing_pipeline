#!/usr/bin/env python3
"""Two-pass VMHunt virtualization detection for one condition.

Pass 1 runs the certified paper_trace plugin to recover the sample's CR3 (asid)
from its root_image event.  Pass 2 re-stages the same base (icount determinism ->
same CR3) and runs the vmhunt_trace plugin asid-scoped, producing a per-vcpu
per-instruction trace in VMHunt's format, bounded by size + wall-clock so a
runaway VM does not fill the disk.  Then s3team's vmextract is run on each vcpu
trace; a written vmN.txt (a paired 7-push/7-pop context switch) => virtualized.

Usage: run_vmhunt.py <nas_dir>
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"
QEMU = RT / "qemu-build/qemu-system-x86_64"
PAPER = REPO / "ops/qemu/paper_trace.so"
VMHUNT = REPO / "ops/qemu/vmhunt_trace.so"
def _vmextract_path() -> Path:
    """s3team/VMHunt `vmextract`.

    Was previously pinned to a session scratchpad under /tmp, which is deleted
    between sessions -- the extraction half of the pipeline had been silently dead.
    Resolve from $VMEXTRACT first, then a repo-local checkout.

    Build with:  git clone --depth 1 https://github.com/s3team/VMHunt.git \\
                     .superpowers/src/VMHunt && make -C .superpowers/src/VMHunt vmextract
    """
    override = os.environ.get("VMEXTRACT")
    if override:
        return Path(override)
    for candidate in (
        REPO / ".superpowers/src/VMHunt/vmextract",
        REPO / "empirical_results/qemu_runtime/VMHunt/vmextract",
    ):
        if candidate.exists():
            return candidate
    return REPO / ".superpowers/src/VMHunt/vmextract"


VMEXTRACT = _vmextract_path()
SUDO_PW = "resbears"
# Per-vcpu file cap and wall-clock cap on the vmhunt pass.  The defaults (2 GiB /
# 360 s) are far too small for a protector that runs for the whole trace window:
# themida executes 50-65M blocks over 1800 s under paper_trace, so a 6-minute
# window captures startup only and any interpreter that engages later is missed.
# Raise both for such samples.
CAP_BYTES = int(os.environ.get("VMHUNT_CAP_GB", "2")) * 1024 ** 3
VM_TIMEOUT = int(os.environ.get("VMHUNT_TIMEOUT", "360"))
PAPER_TIMEOUT = 600                 # cap on the CR3-discovery pass


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=str(REPO), **kw)


def stage(sample: Path, image: Path) -> bool:
    p = sh(["sudo", "-S", "ops/qemu/stage_sample.sh", str(sample), str(image), "300"],
           input=SUDO_PW + "\n", text=True,
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


# Anti-VM transparency, same knob as run_trace.py --transparent.  The protectors
# VMHunt is aimed at (themida especially) read QEMU's CPUID hypervisor bit,
# 0x40000000 vendor leaf and "QEMU Virtual CPU" brand string and bail before the
# marker scope opens -- which is why the existing themida/molebox vmhunt runs
# captured insns=0 and their "no_vm_detected" verdict is vacuous.  Off by default
# so the certified backend identity is unchanged.
TRANSPARENT = os.environ.get("VMHUNT_TRANSPARENT", "").lower() in {"1", "true", "yes"}
CPU_MODEL = os.environ.get("VMHUNT_CPU_MODEL", "") or ("Nehalem" if TRANSPARENT
                                                       else "qemu64")


def qemu_command(work: Path, plugin_arg: str, monitor: Path) -> list[str]:
    return [
        str(QEMU), "-name", "vmhunt",
        "-machine", "pc-i440fx-5.2", "-accel", "tcg,thread=single",
        "-cpu", (CPU_MODEL + ",-hypervisor") if TRANSPARENT else CPU_MODEL,
        "-m", "4G", "-smp", "2",
        "-icount", "shift=2,sleep=on", "-rtc", "base=localtime,clock=vm",
        "-display", "none", "-monitor", f"unix:{monitor.resolve()},server=on,wait=off",
        "-serial", "none", "-parallel", "none", "-net", "none", "-no-reboot",
        "-drive", f"file={work},format=qcow2,if=ide,cache=writeback",
        "-plugin", plugin_arg,
    ]


def extract_cr3(trace: Path) -> int | None:
    """Sample CR3 = current_asid at the root_image event."""
    last = None
    with open(trace) as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event") == "root_debug" and e.get("current_asid"):
                last = e["current_asid"]
            if e.get("event") == "root_image":
                return last
    return last


def run_bounded(command: list[str], outfiles_glob: str, timeout: int) -> None:
    """Run qemu, killing it on timeout or when any output file exceeds CAP_BYTES."""
    import glob
    mon_dir = Path("/tmp/qm")
    mon_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, cwd=str(REPO))
    start = time.monotonic()
    while proc.poll() is None:
        time.sleep(5)
        if time.monotonic() - start >= timeout:
            break
        if any(os.path.getsize(f) >= CAP_BYTES for f in glob.glob(outfiles_glob)):
            break
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main() -> int:
    import glob
    tag = sys.argv[1]
    work_dir = RT / "vmhunt" / tag
    work_dir.mkdir(parents=True, exist_ok=True)
    wl = {w["nas_dir"]: w for w in json.loads((RT / "worklist.json").read_text())}
    entry = wl.get(tag)
    if not entry or not entry.get("samples"):
        print(f"[vmhunt] {tag}: no sample in worklist"); return 2
    sample = REPO / "empirical_results/qemu_runtime" / "vmhunt" / tag / "sample.exe"
    # fetch the sample bytes from the NAS via the same remote path
    remote = entry["samples"][0]["remote"]
    base = RT / "windows10-qemu-repair.qcow2"
    staged = work_dir / "staged.qcow2"

    print(f"[vmhunt] {tag}: fetching + staging {entry['samples'][0]['name']}", flush=True)
    # reuse the SMB fetch used elsewhere
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("="); os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session("10.100.99.29",
                               username=os.environ["PACKER_NAS_USERNAME"],
                               password=os.environ["PACKER_NAS_PASSWORD"])
    with smbclient.open_file(remote, mode="rb") as rf, open(sample, "wb") as wf:
        wf.write(rf.read())
    if not stage(sample, staged):
        print(f"[vmhunt] {tag}: staging failed"); return 3

    # Single pass: vmhunt_trace self-scopes via the guest_launcher PACK marker,
    # capturing the sample's live CR3 in this run (CR3 isn't reproducible across runs).
    run_work = work_dir / "run.qcow2"
    sh(["cp", "--reflink=auto", str(staged), str(run_work)])
    outbase = work_dir / "vm.trace"
    for old in glob.glob(str(outbase) + ".*"):
        os.remove(old)
    mon2 = Path("/tmp/qm") / f"vmh_{tag[:8]}.sock"
    plugin_arg = f"{VMHUNT.resolve()},outfile={outbase.resolve()}"
    print(f"[vmhunt] {tag}: vmhunt trace (marker self-scoped, bounded "
          f"{VM_TIMEOUT}s/{CAP_BYTES//1024**3}GB)", flush=True)
    run_bounded(qemu_command(run_work, plugin_arg, mon2), str(outbase) + ".*", VM_TIMEOUT)

    # vmextract per vcpu
    vfiles = sorted(glob.glob(str(outbase) + ".*"))
    detected = False; detail = []
    for vf in vfiles:
        lines = sum(1 for _ in open(vf))
        # vmextract writes vmN.txt into CWD on detection
        for stale in glob.glob("vm*.txt"):
            os.remove(stale)
        r = subprocess.run([str(VMEXTRACT), vf], cwd=str(work_dir),
                           capture_output=True, text=True, timeout=1800)
        vms = glob.glob(str(work_dir / "vm*.txt"))
        detail.append({"vcpu_file": os.path.basename(vf), "insns": lines,
                       "vmextract_stdout": r.stdout.strip()[:200], "vm_regions": len(vms)})
        if vms:
            detected = True
    verdict = "virtualized" if detected else "no_vm_detected"
    result = {"tag": tag, "scoping": "marker_self", "verdict": verdict, "vcpus": detail}
    (work_dir / "vmhunt_result.json").write_text(json.dumps(result, indent=2))
    print(f"[vmhunt] {tag}: VERDICT = {verdict}")
    print(json.dumps(detail, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
