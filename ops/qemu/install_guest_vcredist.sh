#!/bin/sh
# Install the x86 VC++ runtime DLL into a guest qcow2.
#
# Why: AlushPacker's builder appends a precompiled MSVC-built stub
# (Builder/builder.c:298-308), so every alushpacker output imports
# VCRUNTIME140.dll.  Our Windows 10 guest has no VC++ redistributable -- neither
# System32 nor SysWOW64 carries VCRUNTIME140.dll (only the .NET-private
# vcruntime140_clr0400.dll, which does not satisfy an import by that name), and
# WinSxS holds only vc80/vc90 CRTs.  Import resolution therefore fails before the
# entry point, which the tracer records as exec_events=0 with
# no_execution_launch_failed, sample_started=false and root_entry_seen=false while
# the launcher's own PACK markers still fire.  That is an environment defect and
# must not be read as the packer emitting a broken PE.
#
# The samples are PE32 on a 64-bit guest, so they run under WOW64 and resolve
# DLLs from C:\Windows\SysWOW64 -- the x86 DLL goes there, not System32.
#
# This touches no component of the backend identity pin (qemu, plugin, launcher,
# ntdll, kernel profile), so certification is preserved.
#
# Provenance of the DLL (reproducible, no browser):
#   pip download --platform win32 --python-version 39 --only-binary=:all: \
#       --no-deps msvc-runtime==14.29.30133 -d .
#   unzip -o msvc_runtime-14.29.30133-cp39-cp39-win32.whl -d x
#   x/msvc_runtime-14.29.30133.data/data/Scripts/vcruntime140.dll
# machine=0x14c (x86), 76168 bytes, Authenticode signature present,
# sha256 1e0f8f7f13502f5cee17232e9bebca7b44dd6ec29f1842bb61033044c65b2bbf.
# Note that later msvc-runtime releases ship x64 binaries under a win32 wheel tag;
# 14.29.30133 is the version that actually carries an x86 build.
#
# SAFETY: pass an OVERLAY, or the base only when no qemu is running.  Running
# guests hold the base as a backing file and writing it under them corrupts them.
#
# Usage: sudo ops/qemu/install_guest_vcredist.sh <image.qcow2> [dll] [nbd]
set -e
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
img="$1"
dll="${2:-$repo/empirical_results/qemu_runtime/guest_deps/VCRUNTIME140.x86.dll}"
nbd="${3:-/dev/nbd14}"
mnt=/tmp/vcrtinst.$$
[ -f "$img" ] || { echo "no such image: $img" >&2; exit 1; }
[ -f "$dll" ] || { echo "no such dll: $dll (see provenance in this script)" >&2; exit 1; }

running=$(pgrep -x qemu-system-x86 2>/dev/null | wc -l)
case "$img" in
  *windows10-qemu-repair.qcow2)
    if [ "$running" -gt 0 ]; then
        echo "refusing: $running qemu process(es) running and this is the BASE image;" >&2
        echo "their overlays would be corrupted.  Wait for them to finish." >&2
        exit 1
    fi;;
esac

mkdir -p "$mnt"
cleanup(){ mountpoint -q "$mnt" && umount "$mnt" || true
           qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true; rmdir "$mnt" 2>/dev/null || true; }
trap cleanup EXIT
qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
qemu-nbd --connect="$nbd" "$img"
sleep 1; partprobe "$nbd" 2>/dev/null || true; sleep 1
for part in "$nbd"p1 "$nbd"p2 "$nbd"p3 "$nbd"p4; do
    [ -b "$part" ] || continue
    umount "$mnt" 2>/dev/null || true
    mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null || continue
    if [ -f "$mnt/Windows/System32/config/SYSTEM" ]; then
        umount "$mnt"
        mount -t ntfs-3g -o rw "$part" "$mnt"
        cp -f "$dll" "$mnt/Windows/SysWOW64/VCRUNTIME140.dll"
        sync
        echo "installed SysWOW64/VCRUNTIME140.dll into $img"
        sha256sum "$mnt/Windows/SysWOW64/VCRUNTIME140.dll"
        umount "$mnt"
        exit 0
    fi
    umount "$mnt"
done
echo "could not locate the Windows partition in $img" >&2
exit 1
