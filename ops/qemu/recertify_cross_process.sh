#!/bin/bash
# Attempt a FULL (cross-process) backend certification, WITHOUT touching the
# shared stamp.  The new stamp is written to a temporary path and diffed against
# the live one; promotion is a separate, deliberate step.
#
# Why this exists alongside recertify_backend.sh, which cannot do this job:
#   1. it invokes stage_fixture_launcher.sh through `sudo -S` with no -E, so
#      SINGLE_PROCESS=0 never reaches the staging script and the fixture is staged
#      with C:\Panda\single_process.txt present -- which makes validation_fixture.c
#      ExitProcess() before mapped_file_execute/shared_parent/remote_parent/
#      disk_drop ever run, so the cross-process channels are never exercised and
#      the result is single_process certification again;
#   2. it points validate_fixture_trace.py straight at the live stamp, so a run
#      that proves LESS than the current stamp (the CreateProcess stall the flag
#      exists to avoid) silently makes every run in the corpus ineligible;
#   3. it wants an uncontended host, and says so, but does not check.
#
# Run it when the box is quiet.  Nothing here modifies ops/qemu/backend_validation.json.
#
# Usage: MALWARE_SUDO_PW=... bash ops/qemu/recertify_cross_process.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

RT=empirical_results/qemu_runtime
LIVE=ops/qemu/backend_validation.json
OUT=$RT/recert_xproc
CAND=$OUT/backend_validation.candidate.json
TIMEOUT=${RECERT_TIMEOUT:-2700}
: "${MALWARE_SUDO_PW:?set MALWARE_SUDO_PW}"

busy=$(pgrep -x qemu-system-x86 2>/dev/null | grep -c . || true)
if [ "${busy:-0}" -gt 0 ] && [ "${RECERT_FORCE:-0}" != "1" ]; then
    echo "refusing: $busy qemu process(es) running." >&2
    echo "The fixture needs an uncontended host -- CreateProcess under exact" >&2
    echo "instrumentation is what stalls and yields a failed certification." >&2
    echo "Wait, or set RECERT_FORCE=1 if you accept the risk." >&2
    exit 1
fi

mkdir -p "$OUT"
echo "[xproc] identity check (a full cert is only comparable if these match)"
python3 - "$LIVE" <<'PY'
import hashlib,json,sys
bi=json.load(open(sys.argv[1]))["backend_identity"]
def sh(p):
    try: return hashlib.sha256(open(p,'rb').read()).hexdigest()
    except OSError: return None
cur={"qemu_sha256":sh("empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"),
     "plugin_sha256":sh("ops/qemu/paper_trace.so"),
     "launcher_sha256":sh("ops/panda/build/guest_launcher.exe")}
bad=[k for k,v in cur.items() if bi.get(k)!=v]
for k,v in cur.items():
    print(f"   {k:<18}{'OK' if bi.get(k)==v else 'MISMATCH'}  {str(v)[:16]}")
raise SystemExit(1 if bad else 0)
PY

echo "[xproc] building the fixture"
bash ops/qemu/build_validation_fixture.sh

echo "[xproc] staging WITHOUT the single_process flag (full cross-process mode)"
echo "$MALWARE_SUDO_PW" | sudo -S -E env SINGLE_PROCESS=0 \
    bash ops/qemu/stage_fixture_launcher.sh "$OUT/fixture.qcow2" 2>&1 | tail -4

echo "[xproc] tracing the fixture (host-idle disabled; the cross-process steps pause)"
rm -f "$OUT/fixture.trace.jsonl" "$OUT/monitor.sock"
uv run python ops/qemu/run_trace.py \
    "$OUT/fixture.qcow2" "$OUT/fixture.work.qcow2" "$OUT/fixture.trace.jsonl" \
    --meta "$OUT/fixture.meta.json" --log "$OUT/fixture.qemu.log" \
    --monitor "$OUT/monitor.sock" --host-timeout "$TIMEOUT" \
    --host-idle-seconds 0 --guest-memory 4G \
    --qemu "$RT/qemu-build/qemu-system-x86_64" \
    --plugin ops/qemu/paper_trace.so 2>&1 | tail -4

echo "[xproc] validating into a CANDIDATE stamp (live stamp untouched)"
cp "$LIVE" "$CAND"
uv run python ops/qemu/validate_fixture_trace.py \
    "$OUT/fixture.trace.jsonl" "$CAND" \
    --qemu "$RT/qemu-build/qemu-system-x86_64" \
    --plugin ops/qemu/paper_trace.so \
    --launcher ops/panda/build/guest_launcher.exe \
    --fixture ops/qemu/build/validation_fixture.exe \
    --ntdll "$RT/ntdll.dll" \
    --profile-header ops/qemu/win10_profile.h || true

echo
echo "[xproc] candidate vs live:"
python3 - "$LIVE" "$CAND" <<'PY'
import json,sys
live=json.load(open(sys.argv[1])); cand=json.load(open(sys.argv[2]))
def flat(o,p=""):
    out={}
    for k,v in (o or {}).items():
        if isinstance(v,dict): out.update(flat(v,p+k+"."))
        else: out[p+k]=v
    return out
L,C=flat(live),flat(cand)
regress=[];improve=[]
for k in sorted(set(L)|set(C)):
    a,b=L.get(k),C.get(k)
    if a==b: continue
    mark="  "
    if a is True and b is not True: regress.append(k); mark="!!"
    elif a is not True and b is True: improve.append(k); mark="++"
    print(f" {mark} {k}: {a} -> {b}")
print()
print("IMPROVED :", improve or "none")
print("REGRESSED:", regress or "none")
print()
if regress:
    print("DO NOT PROMOTE: the candidate proves less than the live stamp.")
    print("Promoting it would make previously-eligible runs ineligible.")
else:
    print("Candidate is not a regression.  To promote deliberately:")
    print(f"   cp {sys.argv[2]} {sys.argv[1]}")
PY
