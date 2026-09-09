#!/bin/bash
# Install the VC++ runtime redistributable DLLs into a guest qcow2.
#
# WHY: AlushPacker's builder appends a precompiled MSVC-built stub
# (Builder/builder.c:298-308), so every alushpacker output imports
# VCRUNTIME140.dll.  Our Windows 10 guest ships no VC++ redistributable --
# neither System32 nor SysWOW64 has VCRUNTIME140.dll (only the .NET-private
# vcruntime140_clr0400.dll, which does not satisfy an import by that name), and
# WinSxS carries only vc80/vc90 CRTs.  Import resolution therefore fails before
# the entry point.  The tracer records that as exec_events=0 with
# no_execution_launch_failed, sample_started=false and root_entry_seen=false while
# the launcher's own PACK markers still fire -- which reads exactly like a packer
# emitting an unloadable PE, and is not.  Any MSVC-built stub hits this.
#
# The api-ms-win-crt-* imports are NOT implicated: those are API sets the Win10
# apiset schema resolves to ucrtbase.dll, which is present.
#
# x86 -> SysWOW64 and x64 -> System32, mirroring VC_redist.x86.exe and
# VC_redist.x64.exe.  PE32 samples run under WOW64 and resolve from SysWOW64.
# Existing files are never overwritten, so nothing Windows shipped is perturbed.
#
# Installing these touches no component of the backend identity pin (qemu, plugin,
# launcher, ntdll, kernel profile), so certification is preserved.
#
# DLL provenance (reproducible with pip alone, no browser):
#   x86: pip download --platform win32 --python-version 39 --only-binary=:all: \
#            --no-deps msvc-runtime==14.29.30133
#   x64: ... msvc-runtime==14.44.35112
#   then unzip and take the PE32/PE32+ DLLs respectively.
# Note 14.29.30133 is the version whose win32 wheel actually ships x86 binaries;
# later releases ship x64 under a win32 wheel tag.  vcruntime140.dll x86 is
# sha256 1e0f8f7f13502f5cee17232e9bebca7b44dd6ec29f1842bb61033044c65b2bbf with an
# Authenticode signature present.
#
# SAFETY: pass an overlay freely.  The BASE image may only be written when no qemu
# is running -- running guests hold it as a backing file and writing under them
# corrupts every one of them.
#
# Usage: sudo ops/qemu/install_guest_vcredist.sh <image.qcow2> [nbd]
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
img="${1:?usage: install_guest_vcredist.sh <image.qcow2> [nbd]}"
nbd="${2:-/dev/nbd14}"
deps="$repo/empirical_results/qemu_runtime/guest_deps"
mnt=/tmp/vcrtinst.$$

[ -f "$img" ] || { echo "no such image: $img" >&2; exit 1; }
[ -d "$deps/x86" ] || { echo "missing $deps/x86 (see provenance above)" >&2; exit 1; }

running=$(pgrep -x qemu-system-x86 2>/dev/null | grep -c . || true)
case "$img" in
  *windows10-qemu-repair.qcow2)
    if [ "${running:-0}" -gt 0 ]; then
        echo "REFUSING: $running qemu process(es) running and this is the BASE image." >&2
        echo "Their overlays would be corrupted.  Stop them first." >&2
        exit 1
    fi
    echo "[vcredist] BASE image, host is quiet ($running qemu) -- proceeding";;
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
        inst=0; skip=0
        for pair in "x86:SysWOW64" "x64:System32"; do
            set -- $(echo "$pair" | tr ':' ' ')
            src="$deps/$1"; dstdir="$mnt/Windows/$2"
            [ -d "$dstdir" ] || { echo "[vcredist] no $2 in guest, skipping $1"; continue; }
            for f in "$src"/*.dll; do
                b=$(basename "$f")
                # match the guest's own casing convention for these names
                target="$dstdir/$(echo "$b" | tr '[:lower:]' '[:upper:]' | sed 's/\.DLL$/.dll/')"
                if [ -e "$dstdir/$b" ] || [ -e "$target" ]; then
                    skip=$((skip+1)); continue
                fi
                cp -f "$f" "$dstdir/$b"; inst=$((inst+1))
            done
            echo "[vcredist] $1 -> Windows/$2"
        done
        sync
        echo "[vcredist] installed $inst dll(s), skipped $skip already present"
        echo "[vcredist] verify:"
        ls -l "$mnt/Windows/SysWOW64/vcruntime140.dll" 2>/dev/null || echo "   MISSING SysWOW64/vcruntime140.dll"
        ls -l "$mnt/Windows/System32/vcruntime140.dll" 2>/dev/null || echo "   MISSING System32/vcruntime140.dll"
        umount "$mnt"
        exit 0
    fi
    umount "$mnt"
done
echo "could not locate the Windows partition in $img" >&2
exit 1
