#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=${QEMU_BUILD:-"$repo/empirical_results/qemu_runtime/qemu-build"}
profile=${KERNEL_PROFILE:-/var/lib/drakrun/profiles/kernel.json}
plugin_include=${QEMU_PLUGIN_INCLUDE:-"$repo/empirical_results/qemu_runtime/qemu-src/include/plugins"}
output=${PLUGIN_OUTPUT:-"$repo/ops/qemu/paper_trace.so"}

python3 "$repo/ops/qemu/build_profile_header.py" \
    "$profile" "$repo/ops/qemu/win10_profile.h"
cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
    $(pkg-config --cflags glib-2.0) \
    -I"$build" -I"$build/include" \
    -I"$plugin_include" \
    -I"$repo/ops/qemu" \
    "$repo/ops/qemu/paper_trace.c" \
    -o "$output.new" \
    $(pkg-config --libs glib-2.0)
# Install by rename, never by writing in place.  A running QEMU has this .so
# mmap'd; rewriting the same inode invalidates its mapped pages and the guest
# dies with SIGBUS mid-trace, losing the run with an empty trace and a null
# summary.  rename() swaps the directory entry and leaves the old inode intact
# for processes already using it.
mv -f "$output.new" "$output"
