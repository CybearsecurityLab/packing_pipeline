#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=${QEMU_BUILD:-"$repo/empirical_results/qemu_runtime/qemu-build"}
profile=${KERNEL_PROFILE:-/var/lib/drakrun/profiles/kernel.json}

python3 "$repo/ops/qemu/build_profile_header.py" \
    "$profile" "$repo/ops/qemu/win10_profile.h"
cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
    $(pkg-config --cflags glib-2.0) \
    -I"$build" -I"$build/include" \
    -I"$repo/empirical_results/qemu_runtime/qemu-src/include/plugins" \
    -I"$repo/ops/qemu" \
    "$repo/ops/qemu/paper_trace.c" \
    -o "$repo/ops/qemu/paper_trace.so.new" \
    $(pkg-config --libs glib-2.0)
# Install by rename, never by writing in place.  A running QEMU has this .so
# mmap'd; rewriting the same inode invalidates its mapped pages and the guest
# dies with SIGBUS mid-trace, losing the run with an empty trace and a null
# summary.  rename() swaps the directory entry and leaves the old inode intact
# for processes already using it.
mv -f "$repo/ops/qemu/paper_trace.so.new" "$repo/ops/qemu/paper_trace.so"
