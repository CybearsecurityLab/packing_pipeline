#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."

export LABEL_JOBS="${LABEL_JOBS:-2}"
export LABEL_HOST_TIMEOUT="${LABEL_HOST_TIMEOUT:-1200}"
export LABEL_ACCEPT_BOUNDED="${LABEL_ACCEPT_BOUNDED:-1}"
export PACKER_ACCEPT_BOUNDED="${PACKER_ACCEPT_BOUNDED:-1}"
export LABEL_DELETE_TRACE="${LABEL_DELETE_TRACE:-1}"

run() {
    echo "===== $3 $4 ($2) ====="
    uv run python ops/qemu/label_nas_condition.py "$1" "$2" "$3" "$4" \
        || echo "!! $3 $4 did not complete"
}

run alushpacker_1.0.0     ALUSHPACKER_001_DEFAULT  alushpacker 1.0.0
run hxor_packer_0.1       HXOR_001_DEFAULT         hxor_packer 0.1
run hyperion_v1.2_1.2     HYPERION_V12_001_DEFAULT hyperion    1.2
run hyperion_v2.3.1_2.3.1 HYPERION_001_DEFAULT     hyperion    2.3.1

uv run python ops/qemu/build_packer_type_document.py
echo "===== NEW_CONDITIONS_DONE ====="
