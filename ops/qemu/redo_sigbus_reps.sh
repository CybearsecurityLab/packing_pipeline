#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."

QEMU=empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64
PLUGIN=ops/qemu/paper_trace.so

wait_for() {
    while pgrep -f "$1" >/dev/null 2>&1; do sleep 30; done
    echo "[redo] '$1' finished"
}

redo() {
    image="$1"; dir="$2"; sid="$3"; transparent="$4"
    mkdir -p "$dir"
    rm -f "$dir/work.qcow2" "$dir/trace.jsonl" "$dir/meta.json" \
          "$dir/classification.json"
    mon=/tmp/qm/redo_$(basename "$dir").sock
    mkdir -p /tmp/qm; rm -f "$mon"
    echo "[redo] $sid"
    set -- uv run python ops/qemu/run_trace.py \
        "$image" "$dir/work.qcow2" "$dir/trace.jsonl" \
        --meta "$dir/meta.json" --log "$dir/qemu.log" --monitor "$mon" \
        --host-timeout "${LABEL_HOST_TIMEOUT:-1200}" \
        --guest-memory 4G --qemu "$QEMU" --plugin "$PLUGIN"
    if [ "$transparent" = "1" ]; then
        set -- "$@" --transparent
    fi
    "$@" > "$dir/runner.out" 2>&1 || true
    uv run packer-types classify-paper-trace "$dir/trace.jsonl" \
        --sample-id "$sid" --meta "$dir/meta.json" \
        --output "$dir/classification.json" --accept-bounded >/dev/null 2>&1 || true
    rm -f "$dir/trace.jsonl" "$dir/work.qcow2"
    echo "[redo] $sid -> $(uv run python -c "
import json,sys
try: print(json.load(open('$dir/classification.json'))['complexity_type'])
except Exception: print('NO_CLASSIFICATION')")"
}

wait_for "run_condition_matrix.py .*antivm_obsidium"
O=/data/antivm_runs/obsidium_v1.5.2_1.5.2.11
I=/data/antivm_runs/images
redo "$I/obsidium_v1.5.2_1.5.2.11_1.qcow2" "$O/obsidiumA_rep3" "None__obsidiumA__rep3" 1
redo "$I/obsidium_v1.5.2_1.5.2.11_2.qcow2" "$O/obsidiumB_rep1" "None__obsidiumB__rep1" 1
PACKER_ACCEPT_BOUNDED=1 uv run packer-types finalize "$O/plan.json" "$O" \
    --yaml-output manifest/type/empirical_types_obsidium_v1.5.2_1.5.2.11.yaml \
    --output empirical_results/full_matrix/obsidium_v1.5.2_1.5.2.11_labels.json

wait_for "label_nas_condition.py hxor_packer_0.1"
H=empirical_results/qemu_runtime/hxor_packer_runs
redo empirical_results/qemu_runtime/windows10-qemu-hxor_packer1.qcow2 \
     "$H/hxor_packerA_rep1" "HXOR_001_DEFAULT__hxor_packerA__rep1" 0
redo empirical_results/qemu_runtime/windows10-qemu-hxor_packer1.qcow2 \
     "$H/hxor_packerA_rep2" "HXOR_001_DEFAULT__hxor_packerA__rep2" 0
PACKER_ACCEPT_BOUNDED=1 uv run packer-types finalize "$H/plan.json" "$H" \
    --yaml-output manifest/type/empirical_types_hxor_packer.yaml \
    --output empirical_results/full_matrix/hxor_packer_labels.json

uv run python ops/qemu/build_packer_type_document.py
echo "===== REDO_DONE ====="
