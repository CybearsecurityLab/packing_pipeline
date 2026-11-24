#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$root/ops/panda/build"
x86_64-w64-mingw32-gcc \
  -O2 -Wall -Wextra -Werror -static \
  -DVMARM \
  -Wl,--no-insert-timestamp \
  "$root/ops/panda/guest_launcher.c" \
  -o "$root/ops/panda/build/guest_launcher_vmarm.exe" \
  -lwtsapi32 -luserenv
