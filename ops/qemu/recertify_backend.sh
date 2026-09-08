#!/bin/bash
# Re-certify the backend after a component change, and re-stamp backend_validation.json.
#
# WHY THIS IS NEEDED NOW: guest_launcher.c gained wait_for_sample() for
# snapshot-resume, so launcher_sha256 changed from 8361d9c3... to 17c76722.... Until
# the fixture validation is re-run and re-stamped, results from the new launcher are
# NOT certified-comparable to the existing 96 packer labels.
#
# The stamp is produced by validate_fixture_trace.py from the ACTUAL fixture trace --
# it is never hand-edited. That is the whole point: the identity is earned by passing
# the channel fixture, not asserted.
#
# The previous stamp is archived first so the old identity can always be restored.
#
# Usage: MALWARE_SUDO_PW=... bash ops/qemu/recertify_backend.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

RT=empirical_results/qemu_runtime
STAMP=ops/qemu/backend_validation.json
OUT=$RT/recert
TIMEOUT=${RECERT_TIMEOUT:-1800}
: "${MALWARE_SUDO_PW:?set MALWARE_SUDO_PW}"

mkdir -p "$OUT"
STAMP_BAK="$OUT/backend_validation.$(date +%Y%m%d_%H%M%S).json"
cp "$STAMP" "$STAMP_BAK"
echo "[recert] archived previous stamp -> $STAMP_BAK"
echo "[recert] previous launcher_sha256: $(python3 -c "
import json;print(json.load(open('$STAMP'))['backend_identity']['launcher_sha256'])")"
echo "[recert] current  launcher_sha256: $(sha256sum ops/panda/build/guest_launcher.exe | cut -d' ' -f1)"

echo "[recert] building the validation fixture"
bash ops/qemu/build_validation_fixture.sh

echo "[recert] staging fixture + launcher into a disposable image"
echo "$MALWARE_SUDO_PW" | sudo -S bash ops/qemu/stage_fixture_launcher.sh \
    "$OUT/fixture.qcow2" 2>&1 | tail -3

echo "[recert] tracing the fixture (single guest, no contention)"
rm -f "$OUT/fixture.trace.jsonl" "$OUT/monitor.sock"
uv run python ops/qemu/run_trace.py \
    "$OUT/fixture.qcow2" "$OUT/fixture.work.qcow2" "$OUT/fixture.trace.jsonl" \
    --meta "$OUT/fixture.meta.json" --log "$OUT/fixture.qemu.log" \
    --monitor "$OUT/monitor.sock" --host-timeout "$TIMEOUT" \
    --host-idle-seconds 0 \
    --guest-memory 4G \
    --qemu "$RT/qemu-build/qemu-system-x86_64" \
    --plugin ops/qemu/paper_trace.so 2>&1 | tail -4

echo "[recert] validating channels and emitting the new stamp"
uv run python ops/qemu/validate_fixture_trace.py \
    "$OUT/fixture.trace.jsonl" "$STAMP" \
    --qemu "$RT/qemu-build/qemu-system-x86_64" \
    --plugin ops/qemu/paper_trace.so \
    --launcher ops/panda/build/guest_launcher.exe \
    --fixture ops/qemu/build/validation_fixture.exe \
    --ntdll "$RT/ntdll.dll" \
    --profile-header ops/qemu/win10_profile.h

echo
echo "[recert] new identity:"
python3 -c "
import json
d=json.load(open('$STAMP'))
for k,v in (d.get('backend_identity') or {}).items(): print(f'   {k:<24} {v}')
print('   validated:', d.get('validated'))"
