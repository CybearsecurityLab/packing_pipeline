#!/bin/sh
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

label_one() {  # <nas_dir> <testcase> <family> <version>
  echo "===== labeling $3 $4 $2 ====="
  ps ax | grep 'qemu-system-x86_64 -name paper' | grep -v grep | awk '{print $1}' | xargs -r kill -KILL 2>/dev/null
  sleep 2
  .venv/bin/python ops/qemu/label_nas_condition.py "$1" "$2" "$3" "$4" || {
    echo "!! $3 $4 failed; continuing"; return 0; }
  tag=$(printf '%s' "$3" | tr 'A-Z' 'a-z')
  git add -f "manifest/type/empirical_types_${tag}.yaml" docs/EMPIRICAL_TYPE_LABELS.md docs/PACKER_TYPE_LABELS.md 2>/dev/null
  git add "empirical_results/qemu_runtime/configs/${tag}.json" 2>/dev/null || true
  git commit -q -m "Empirical label: $3 $4 $2 (see docs/EMPIRICAL_TYPE_LABELS.md)" || true
  git push origin feature/empirical-type-backend 2>&1 | tail -1
}

label_one hyperion_v2.3.1_2.3.1        HYPERION_001_DEFAULT hyperion    2.3.1
label_one pezor_3.3.0                  PEZOR_001_DEFAULT_32 pezor       3.3.0
label_one kkrunchy_v0.23a_0.23_alpha   KKRUNCHY_003_NEW     kkrunchy    "0.23 alpha"
echo "===== QUEUE DONE ====="
python3 ops/qemu/build_label_document.py
python3 ops/qemu/build_packer_type_document.py
sed -n '/Conditions empirically/,$p' docs/EMPIRICAL_TYPE_LABELS.md
