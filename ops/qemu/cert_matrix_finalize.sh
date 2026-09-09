#!/bin/sh
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

echo "=== [1/3] re-certify plugin under icount ==="
ops/qemu/cert_retry_loop.sh > empirical_results/qemu_runtime/cert_loop_final.out 2>&1
VAL=$(python3 -c "import json;d=json.load(open('ops/qemu/backend_validation.json'));print(d.get('validated'),d.get('backend_identity',{}).get('plugin_sha256','')[:12])" 2>/dev/null)
echo "cert stamp: $VAL"
case "$VAL" in True*) : ;; *) echo "CERT FAILED; abort"; exit 1;; esac

echo "=== [2/3] run condition matrix (fresh, under new cert) ==="
rm -rf empirical_results/qemu_runtime/matrix_runs
python3 ops/qemu/run_condition_matrix.py >> empirical_results/qemu_runtime/matrix.out 2>&1
python3 -c "
import json
p='empirical_results/qemu_runtime/matrix_runs/plan.json'
d=json.load(open(p))
for c in d['conditions']:
    c.setdefault('source','yaml_test_case'); c.setdefault('status','planned'); c.setdefault('available_samples',2)
json.dump(d, open(p,'w'), indent=2)
"
echo "--- run classifications ---"
for d in empirical_results/qemu_runtime/matrix_runs/*/; do
  [ -f "$d/classification.json" ] && echo "  $(basename "$d"): $(python3 -c "import json;print(json.load(open('$d/classification.json'))['complexity_type'])" 2>/dev/null)"
done

echo "=== [3/3] finalize -> empirical manifest ==="
mkdir -p empirical_results/full_matrix
uv run packer-types finalize \
  empirical_results/qemu_runtime/matrix_runs/plan.json \
  empirical_results/qemu_runtime/matrix_runs \
  --yaml-output manifest/type/empirical_types_matrix.yaml \
  --output empirical_results/full_matrix/empirical_labels.json \
  --csv-output empirical_results/full_matrix/empirical_labels.csv 2>&1 | tail -3
echo "===== EMPIRICAL MANIFEST ====="
python3 -c "
import yaml
d=yaml.safe_load(open('manifest/type/empirical_types_matrix.yaml'))
print('label_distribution:', d.get('label_distribution'))
for c in d.get('conditions',[]):
    print('condition:', c.get('configuration_id'))
    for k in ('label','label_status','evidence_level','exact_trace_consensus_label','completed_runs','qualifying_distinct_samples'):
        if k in c: print('  ',k,'=',c[k])
"
echo "===== DONE ====="
