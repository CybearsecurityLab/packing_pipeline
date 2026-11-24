#!/bin/sh
# Copy one file out of a finished guest's disk image, read-only (VM arm: the
# launcher's C:\Panda\windows.txt). The image is attached with qemu-nbd --read-only
# and mounted ntfs-3g ro, so neither the overlay nor its backing chain is modified.
#
# Usage (root): STAGE_NBD=/dev/nbdN extract_guest_file.sh <image.qcow2> <guest/rel/path> <dest>
set -eu

image="${1:?usage: extract_guest_file.sh <image> <guest path> <dest>}"
inner="${2:?usage: extract_guest_file.sh <image> <guest path> <dest>}"
dest="${3:?usage: extract_guest_file.sh <image> <guest path> <dest>}"
nbd=${STAGE_NBD:-/dev/nbd0}
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
[ -b "$nbd" ] || { echo "not a block device: $nbd" >&2; exit 1; }
[ -f "$image" ] || { echo "missing: $image" >&2; exit 1; }
mnt=$(mktemp -d)

cleanup() {
    mountpoint -q "$mnt" && umount "$mnt" || true
    qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
    rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
qemu-nbd --read-only --connect="$nbd" "$image"
sleep 1; partprobe "$nbd" 2>/dev/null || true; sleep 1

for part in "$nbd"p1 "$nbd"p2 "$nbd"p3 "$nbd"p4 "$nbd"; do
    [ -b "$part" ] || continue
    umount "$mnt" 2>/dev/null || true
    if mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null; then
        if [ -f "$mnt/$inner" ]; then
            cp -f "$mnt/$inner" "$dest"
            chmod 0644 "$dest"
            exit 0
        fi
        umount "$mnt"
    fi
done
echo "not found in any partition: $inner" >&2
exit 3
