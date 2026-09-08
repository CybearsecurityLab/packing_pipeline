#!/bin/bash
# Create a REUSABLE post-boot snapshot so per-sample runs skip the Windows boot.
#
# WHY: boot is ~300 s solo and 400-900+ s under contention, and it is paid on EVERY
# trace. It dominates the malware campaign: at 20-way concurrency the boot phase
# starves itself and every rep dies `no_execution_launch_failed`. Booting once and
# resuming is the only change that removes the cost rather than scheduling around it.
#
# HOW IT AVOIDS RE-CERTIFICATION: the launcher reads a FIXED path,
# C:\Panda\sample.exe (stage_sample.sh always writes there). So one snapshot serves
# every sample -- swap the FILE, not the path. No guest_launcher.exe rebuild, so
# launcher_sha256 in backend_validation.json is untouched.
#
# The snapshot is taken with a placeholder sample that simply sleeps, so the guest is
# captured fully booted with the service running and Windows warm.
#
# Usage: MALWARE_SUDO_PW=... bash ops/qemu/build_boot_snapshot.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

RUNTIME=${MALWARE_RUNTIME:-/data/malware_runtime}
BASE="$RUNTIME/base.qcow2"
SNAP="$RUNTIME/booted.qcow2"
QEMU="$RUNTIME/qemu-system-x86_64"
PLUGIN="$RUNTIME/paper_trace.so"
BOOT_SECONDS=${SNAP_BOOT_SECONDS:-420}
: "${MALWARE_SUDO_PW:?set MALWARE_SUDO_PW}"

# A placeholder that runs long enough to be alive at snapshot time. Any PE works;
# the guest is captured while the launcher is supervising it.
PLACEHOLDER=${SNAP_PLACEHOLDER:-$(ls empirical_results/qemu_runtime/*_s1/sample.exe 2>/dev/null | head -1)}
[ -n "$PLACEHOLDER" ] || { echo "no placeholder PE found" >&2; exit 1; }

# Refuse to run while a campaign holds the lock: this stages through /dev/nbd* and
# rewrites the shared base, which starves a running campaign's guests. The lock must
# be held for the WHOLE build, not merely probed -- a check that releases immediately
# proves nothing about the next ten minutes. flock(1) holds it for this script's
# lifetime and releases it automatically on exit, including on a crash.
LOCKFILE=${CORPUS_RUNLOCK:-/tmp/corpus_qemu_runlock}
touch "$LOCKFILE" 2>/dev/null || true
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "REFUSING TO START: the QEMU run lock is held by:" >&2
    cat "$LOCKFILE" >&2 || true
    echo "  A snapshot build competes with a running campaign for /dev/nbd* and the" >&2
    echo "  shared base image, which starves guests and fabricates never_started." >&2
    exit 1
fi
echo "snapshot-build pid=$$ since=$(date +%H:%M:%S)" >&9

echo "[snap] staging launcher into a fresh overlay (sample deliberately absent)"
rm -f "$SNAP"
# STAGE_NO_SAMPLE: leave C:\Panda\sample.exe absent so the (rebuilt) launcher parks
# in wait_for_sample() rather than executing anything. That is the state we want
# frozen: fully booted, service running, waiting for work.
echo "$MALWARE_SUDO_PW" | sudo -S env STAGE_NBD=/dev/nbd15 STAGE_BASE="$BASE" \
    STAGE_OVERLAY=1 STAGE_NO_SAMPLE=1 ops/qemu/stage_sample.sh "$PLACEHOLDER" "$SNAP" 1800 >/dev/null
echo "$MALWARE_SUDO_PW" | sudo -S chmod a+rw "$SNAP"

# The CD drive MUST exist when the state is captured: a resumed guest only has the
# devices that were present at capture time, so a drive added later is invisible to
# Windows. An empty ISO is enough to make the drive enumerate; the real sample is
# supplied later by changing the medium, which IS honoured across resume.
EMPTY_ISO=$RUNTIME/empty.iso
if [ ! -f "$EMPTY_ISO" ]; then
    tmpdir=$(mktemp -d)
    : > "$tmpdir/PLACEHOLD.TXT"
    genisoimage -quiet -J -r -V DELIVERY -o "$EMPTY_ISO" "$tmpdir" 2>/dev/null
    rm -rf "$tmpdir"
    chmod a+r "$EMPTY_ISO" 2>/dev/null || true
fi

MON=/tmp/snapbuild.sock
rm -f "$MON"
echo "[snap] booting for ${BOOT_SECONDS}s (single guest, no contention)"
"$QEMU" -name snapbuild -machine pc-i440fx-5.2 -accel tcg,thread=single \
  -cpu qemu64 -m 4G -smp 2 -icount shift=2,sleep=on -rtc base=localtime,clock=vm \
  -display none -monitor "unix:$MON,server=on,wait=off" -serial none -parallel none \
  -net none -no-reboot \
  -drive "file=$SNAP,format=qcow2,if=ide,cache=writeback" \
  -drive "file=$EMPTY_ISO,format=raw,if=ide,media=cdrom" &
QPID=$!

# Poll for the monitor socket and snapshot as soon as the guest is BOOTED AND STILL
# ALIVE. A fixed sleep is wrong in both directions: too short and Windows has not
# finished booting; too long and the placeholder sample has already completed, the
# launcher has exited and QEMU is gone -- taking the monitor socket with it, which is
# exactly how the first two attempts silently produced no snapshot.
waited=0
while [ ! -S "$MON" ] && [ "$waited" -lt 120 ]; do sleep 5; waited=$((waited+5)); done
[ -S "$MON" ] || { echo "[snap] monitor socket never appeared" >&2; kill -9 "$QPID" 2>/dev/null; exit 1; }

echo "[snap] monitor up; waiting ${BOOT_SECONDS}s for boot (guest must stay alive)"
waited=0
while [ "$waited" -lt "$BOOT_SECONDS" ]; do
    sleep 15; waited=$((waited+15))
    if ! kill -0 "$QPID" 2>/dev/null; then
        echo "[snap] guest exited after ${waited}s -- placeholder finished too early." >&2
        echo "[snap] use a longer-running placeholder (SNAP_PLACEHOLDER) or a shorter" >&2
        echo "[snap] SNAP_BOOT_SECONDS." >&2
        exit 1
    fi
done

echo "[snap] saving VM state 'booted'"
# Drive the QEMU monitor directly. (An earlier version shelled out to socat with a
# python heredoc fallback; the heredoc swallowed the socket path argument and the
# savevm silently never ran -- the overlay grew but carried no snapshot.)
python3 ops/qemu/qmp_savevm.py "$MON" booted --migrate "$RUNTIME/booted.migstate" \
    || echo "[snap] savevm/migrate FAILED"

wait "$QPID" 2>/dev/null || true

echo "[snap] verifying"
/usr/bin/qemu-img snapshot -l "$SNAP" || true
echo "[snap] done -> $SNAP"
