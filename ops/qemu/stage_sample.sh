#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runtime="$repo/empirical_results/qemu_runtime"
# STAGE_BASE lets a caller point at a different base image. The malware campaign
# uses a FLATTENED standalone base on /data: the default base has a 6-level backing
# chain reaching into /home/resbears and /var/lib/drakrun, which an unprivileged
# service account cannot traverse (bwrap: "Permission denied").
base="${STAGE_BASE:-$runtime/windows10-qemu-repair.qcow2}"
launcher="$repo/ops/panda/build/guest_launcher.exe"
sample="${1:?usage: stage_sample.sh <sample.exe> <out_image.qcow2> [timeout]}"
out="${2:?usage: stage_sample.sh <sample.exe> <out_image.qcow2> [timeout]}"
timeout="${3:-300}"
# The nbd device to stage through. Hardcoding /dev/nbd0 serialised EVERY staging
# operation in the whole pipeline onto one exclusive device -- fine for a 102-condition
# sweep, but the binding constraint at malware scale (tens of thousands of stagings).
# This box has /dev/nbd0..15, so callers can stage ~16-way in parallel by passing
# STAGE_NBD. Default is unchanged so existing callers behave exactly as before.
nbd=${STAGE_NBD:-/dev/nbd0}
[ -b "$nbd" ] || { echo "not a block device: $nbd" >&2; exit 1; }
mnt=$(mktemp -d)

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$base" "$launcher" "$sample"; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

cleanup() {
    mountpoint -q "$mnt" && umount "$mnt" || true
    qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
    rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

echo "== base integrity =="
qemu-img check "$base"
echo "== make working copy (base stays pristine) =="
if [ "${STAGE_OVERLAY:-0}" = "1" ]; then
    # /data is ext4, which has no reflink: `cp` of the flattened 11.3 GB base would
    # be a REAL 11.3 GB write per staging (~579 TB across the malware campaign).
    # A qcow2 overlay is instant and keeps the base read-only and shared.
    rm -f "$out"
    qemu-img create -f qcow2 -b "$base" -F qcow2 "$out" >/dev/null
else
    cp --reflink=auto "$base" "$out"
fi

echo "== connect $out via $nbd =="
qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
qemu-nbd --connect="$nbd" "$out"
sleep 1; partprobe "$nbd" 2>/dev/null || true; sleep 1

target=""
for part in "$nbd"p1 "$nbd"p2 "$nbd"p3 "$nbd"p4 "$nbd"; do
    [ -b "$part" ] || continue
    umount "$mnt" 2>/dev/null || true
    if mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null; then
        if [ -d "$mnt/Panda" ] && [ -f "$mnt/Windows/System32/config/SYSTEM" ]; then
            target="$part"; umount "$mnt"; break
        fi
        umount "$mnt"
    fi
done
[ -n "$target" ] || { echo "could not locate Windows/Panda partition" >&2; exit 1; }
echo "Windows partition: $target"

echo "== refuse hibernated/dirty NTFS =="
mount -t ntfs-3g -o rw "$target" "$mnt"

echo "== stage sample.exe + launcher; clear fixture-only flags =="
cp -f "$launcher" "$mnt/Panda/guest_launcher.exe"
if [ "${STAGE_NO_SAMPLE:-0}" = "1" ]; then
    # Snapshot-BUILD mode: deliberately leave C:\Panda\sample.exe ABSENT so the
    # launcher parks in wait_for_sample() instead of running something. The guest is
    # then snapshotted in that state and every later run resumes into it, supplying
    # the real sample on a secondary disk. Without this the snapshot would capture a
    # guest already busy with (or finished with) a placeholder.
    rm -f "$mnt/Panda/sample.exe"
else
    cp -f "$sample"   "$mnt/Panda/sample.exe"
fi
rm -f "$mnt/Panda/single_process.txt"   # live mode: sample runs to exit/idle
rm -f "$mnt/Panda/idle_ms.txt"          # live default idle (launcher clamps 120s)
sync

echo "== switch PandaPilot ImagePath to sample mode (offline hive) =="
python3 "$repo/ops/qemu/set_pilot_imagepath.py" \
    "$mnt/Windows/System32/config/SYSTEM" \
    --image 'C:\Panda\sample.exe' --timeout "$timeout"

if [ "${STAGE_NO_SAMPLE:-0}" = "1" ]; then
    echo "== snapshot-build mode: sample intentionally absent, skipping SHA gate =="
else
echo "== verify sample SHA-256 in image =="
want=$(sha256sum "$sample" | awk '{print $1}')
got=$(sha256sum "$mnt/Panda/sample.exe" | awk '{print $1}')
echo "sample want=$want"; echo "sample got =$got"
[ "$want" = "$got" ] || { echo "sample hash MISMATCH" >&2; exit 1; }
fi

umount "$mnt"
qemu-nbd --disconnect "$nbd"
trap - EXIT
rmdir "$mnt" 2>/dev/null || true

echo "== final integrity =="
qemu-img check "$out"
echo "OK: staged sample into $out (timeout ${timeout}s, live mode)"
