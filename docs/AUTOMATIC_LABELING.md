# Automatic Empirical Packer-Type Labeling

This subsystem assigns each packed sample an **exact Ugarte et al. Type I–VI label**
("SoK: Deep Packer Inspection") **empirically, from a real dynamic trace** — not
from static heuristics or hypotheses. It runs the packed sample inside an
instrumented Windows guest, records every executed basic block and every memory
store, reconstructs the paper's write→execute **layer-production topology**, and
classifies the Type from that topology. No approximations: a label is emitted only
when the exact channels are present and, per condition, only on **exact consensus**
across the paper's `n = 3 executions × ≥2 distinct payloads`.

- **Backend**: an upstream **QEMU 11 TCG plugin** (`ops/qemu/paper_trace.c`) traces
  the guest; it is gated by a purpose-built certification fixture and refuses to
  emit labels until the exact backend identity passes (`ops/qemu/backend_validation.json`).
- **Classifier**: `empirical_types/paper.py` + `classifier.py` implement Section
  III-E of the paper on the recorded trace.
- **Aggregation**: `empirical_types/finalize.py` turns per-run classifications into
  per-condition empirical labels and writes the manifest.

The **final packer→Type document** is [`EMPIRICAL_TYPE_LABELS.md`](EMPIRICAL_TYPE_LABELS.md),
regenerated from the empirical labels by `ops/qemu/build_label_document.py`.

---

## Architecture / data flow

```
NAS corpus sample (packed .exe)
   │  ops/qemu/stage_sample.sh  (copy pristine base image, place sample.exe +
   │                             guest_launcher.exe, flip PandaPilot ImagePath
   │                             to live sample mode via python-hivex)
   ▼
windows10-qemu-<sample>.qcow2 (disposable staged image, base never mutated)
   │  ops/qemu/run_trace.py  (upstream QEMU + paper_trace.so plugin,
   │                          -accel tcg,thread=single -smp 2 -icount shift=2)
   ▼
trace.jsonl  (exec / write / free / unmap / exception / marker events, one
   │          globally-ordered stream) + meta.json (eligibility, cert identity)
   │  packer-types classify-paper-trace   (empirical_types/paper.py + classifier.py)
   ▼
classification.json  (complexity_type = TYPE_I..VI, layers, tail, linear, ...)
   │  packer-types finalize   (exact consensus across reps × payloads)
   ▼
manifest/type/empirical_types_*.yaml  +  doc/EMPIRICAL_TYPE_LABELS.md
```

Why the specific QEMU flags:
- `-accel tcg,thread=single -smp 2` — both vCPUs form one ordered event stream, as
  the paper's transition model requires (MTTCG would break the ordering).
- `-icount shift=2` — a fixed instruction-counted virtual clock. Without it, heavy
  instrumentation dilates guest time so the Windows scheduler drowns in timer
  interrupts and starves the freshly-started sample thread (the "boot lottery").
  A fixed low shift makes runs reliable **and** near-deterministic. (Do **not** use
  `shift=auto` — it reconverges to real time and reproduces the starvation.)

---

## Installation guide

Target host: **Linux** (developed on Debian 12 / Xen dom0). The analysis guest is
Windows 10 x64; you do not install anything *into* it — a prepared guest image is
provided as a repo artifact.

### 1. System packages (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config ninja-build meson \
    libglib2.0-dev libpixman-1-dev libslirp-dev flex bison \  # QEMU build deps
    gcc-mingw-w64-x86-64 \                                    # guest fixture/launcher
    qemu-utils ntfs-3g \                                      # qemu-nbd, qemu-img, staging
    python3-hivex                                             # offline SYSTEM-hive edit
sudo modprobe nbd max_part=8                                  # qemu-nbd needs the nbd module
```

`stage_sample.sh` mounts the guest image via `qemu-nbd` + `ntfs-3g` and edits the
registry hive, so it needs **root** (`sudo`).

### 2. Python environment (uv)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # if uv is not installed
cd <repo>
uv sync                # installs the package (console script: packer-types)
# tests: PYTHONPATH=$PWD uv run --with pytest pytest -q
```

Key Python deps (in `pyproject.toml`): `pyyaml`, `smbprotocol` (NAS), `pefile`.

### 3. Build the QEMU backend (once)

```bash
ops/qemu/build_qemu.sh          # clones qemu-project, checks out the pinned rev
                                #   eca2c16212ef9dcb0871de39bb9d1c2efebe76be, builds
                                #   qemu-system-x86_64 into empirical_results/qemu_runtime/qemu-build
ops/qemu/build_plugin.sh        # builds ops/qemu/paper_trace.so (needs glib-2.0)
ops/qemu/build_validation_fixture.sh   # builds the cert fixture (mingw-w64)
# guest_launcher: ops/panda/build/guest_launcher.exe (mingw-w64)
```

### 4. Guest + profile artifacts (repo-provided, in `empirical_results/qemu_runtime/`)

- `windows10-qemu-repair.qcow2` — the pristine prepared Windows 10 x64 guest
  (PandaPilot service installed). **Never mutated**; staging copies it.
- `ntdll.dll` — the guest's exact ntdll (identity-checked into every trace).
- `ops/qemu/win10_profile.h` — the exact kernel PDB offset profile the plugin is
  built against (it refuses generic offsets). Regenerate with
  `ops/qemu/build_profile_header.py` if the guest kernel changes.

### 5. NAS credentials (packed-sample source)

Create `.env` (git-ignored) with the SMB corpus credentials:

```
PACKER_NAS_USERNAME=...
PACKER_NAS_PASSWORD=...
# NAS_SERVER / NAS_SHARE default to the corpus host/share
```

---

## Running the pipeline

### A. Certify the backend (required before any label is trusted)

```bash
ops/qemu/cert_retry_loop.sh      # runs the fixture under icount until it certifies;
                                 # writes ops/qemu/backend_validation.json (validated:true)
```
Any change to the plugin/QEMU/ntdll/profile changes the backend identity and
**requires re-certification** — an uncertified trace is classified `UNRESOLVED`.

### B. Label one condition end-to-end (n=3 × 2 payloads → exact consensus)

```bash
# 1) fetch 2 distinct packed payloads for the condition from the NAS, then stage:
sudo ops/qemu/stage_sample.sh <payload1.exe> windows10-qemu-cond1.qcow2 300
sudo ops/qemu/stage_sample.sh <payload2.exe> windows10-qemu-cond2.qcow2 300

# 2) write a condition config (see empirical_results/qemu_runtime/configs/*.json)
#    {condition:{...configuration_id...}, payloads:[[image,sha256,name],...], reps:3, runs_dir:...}
python3 ops/qemu/run_condition_matrix.py <config.json>   # 6 traces + classify -> run dirs
```

**Tuning knobs that decide whether a packer resolves at all.** The defaults are
tuned for fast unpackers; several packers produce `UNRESOLVED_NO_UNPACKING_OBSERVED`
purely because a default cut the recording short. Each is an environment variable
read by `run_condition_matrix.py` and passed through to `run_trace.py`.

| Variable | Default | When to change it |
|---|---|---|
| `LABEL_HOST_IDLE` | `120` | **The one that matters most.** The completion boundary is measured in HOST seconds of no newly-serialised exec/write records, and the plugin slows the guest heavily, so a guest sleep or a protector's timed pause trips it while the sample is still live. It then reports a normal completion. telock produced `UNRESOLVED_NO_UNPACKING_OBSERVED` in every certified rep at 120; at 900 the same sample runs to ~14.3M blocks and classifies **TYPE_VI-B**. Raise it for anything that pauses. |
| `LABEL_HOST_TIMEOUT` | `1200` | Raise for packers that are CPU-bound rather than idle. hyperion brute-forces its own AES key across 4096 candidates before decrypting anything and gets ~29% of the way in 1200s. |
| `LABEL_ICOUNT_SHIFT` | `2` | Changes guest virtual-ns per instruction, and so how much a timed check overshoots. hXOR's `runtimeDelay()` allows 550ms for a `Sleep(500)`: at shift=2 it detects and bails, at shift=0 it passes and the unpack proceeds. |
| `LABEL_ICOUNT_SLEEP` | `on` | `off` warps virtual time to the next deadline while idle instead of advancing it at real speed. |
| `LABEL_ACCEPT_BOUNDED` | unset | Accept a truncated trace as a **lower bound** on the Type. |
| `LABEL_DELETE_TRACE` | unset | Delete `trace.jsonl`/`work.qcow2` after classifying. Traces reach 8+ GB. |
| `LABEL_JOBS` | `1` | Parallel traces. **Raising this is not free**: host contention is itself what trips `LABEL_HOST_IDLE`, so parallelism can manufacture the truncation it is meant to outrun. |

There is a FOURTH limit not in this table: the **guest timeout**, baked into the
image by `stage_sample.sh <sample> <image> [timeout]` (default **300**). It is
written into the SYSTEM hive at staging time, not passed at run time, so changing it
means re-staging. It binds on packers that WAIT rather than compute — with
`icount sleep=on` the guest clock advances at real speed while the vCPU idles — which
is why telock's payload B hit it at 2.6M executed blocks while obsidium reached
22.2M under the same 300s.

If a condition comes back `UNRESOLVED_NO_UNPACKING_OBSERVED`, check
`paper_termination_reason` and `host_idle_seconds` in `meta.json` before concluding
anything about the packer. Per-packer values that are known to work, with the
evidence for each, are in [PACKER_RUN_PARAMETERS.md](PACKER_RUN_PARAMETERS.md).
See also [ORACLE_LIMITATIONS.md](ORACLE_LIMITATIONS.md).

```bash

# 3) aggregate into an empirical manifest:
uv run packer-types finalize <runs_dir>/plan.json <runs_dir> \
    --yaml-output manifest/type/empirical_types_<cond>.yaml
```

`ops/qemu/cert_matrix_finalize.sh` chains cert → matrix → finalize for one condition.

A condition needs **2 distinct payloads** for exact consensus. With only one,
`PACKER_MAX_OBSERVED_MIN_PAYLOADS=1` finalises under the Ugarte Sec V-C
max-observed rule instead; the label then records
`label_status: empirical_max_observed_complexity` and the single-payload basis is
visible in the manifest. Check the payload `sha256`s differ before trusting a
two-payload consensus — one binary was found filed under two families (obsidium
payload A and telock payload B are byte-identical), which a naive consensus would
have silently treated as independent evidence.

### C. Regenerate the documents

```bash
python3 ops/qemu/build_label_document.py         # -> docs/EMPIRICAL_TYPE_LABELS.md (exact-consensus only)
python3 ops/qemu/build_final_report.py           # -> docs/EMPIRICAL_TYPE_RESULTS.md (every condition + root cause)
python3 ops/qemu/build_packer_type_document.py   # -> docs/PACKER_TYPE_LABELS.md   (authoritative packer -> Type)
uv run python ops/qemu/apply_types_to_corpus.py --apply   # writes type: back into manifest/packer_corpus.yaml
```

`packer_corpus.yaml` is the curated membership and carries `type:`;
`worklist.json` is the NAS index carrying sample paths and hashes. Both are needed
and neither is the sole authority: filtering the document on the worklist hid four
corpus definitions that had never been enumerated into it, and filtering on the
yaml instead drops 13 typed rows whose manifests use NAS-derived naming
(`acprotect_std_standard__installer` vs `acprotect`/`Standard (installer)`).
`build_packer_type_document.py` takes the union of both.

---

## Faithfulness guarantees

- The label uses only the recorded trace's write→execute topology (Section III-E) —
  **no original binary** is consulted (the paper is runtime-only for Type I/II/III/
  V/VI; using ground truth to label would be unfaithful).
- Certification gates every channel; a trace missing a channel is `UNRESOLVED`.
- A trace exhibiting **cross-process** behavior under the single-process
  certification is `UNRESOLVED_UNCERTIFIED_CROSS_PROCESS` (never guessed).
- A condition gets an exact label only on **consensus** across ≥2 distinct payloads
  × ≥3 consistent repetitions; otherwise it stays provisional/hypothesis.

## Known limitations (fable faithfulness audit, 2026-07-18)

A fable agent audited `paper.py`/`classifier.py` against the paper's Figure-1
flowchart. Verdict: **a largely faithful reproduction** — layers, the Figure-2
frame FSM, the 10-page separation, repacking, granularity suffixes, and the
decision order all track the paper; 67 tests encode paper semantics. Fixes applied:
a `layers==1` (no unpacking observed) trace is now `UNRESOLVED_NO_UNPACKING_OBSERVED`
instead of falling through to Type IV.

**The one inherent limitation is TYPE IV.** Per the paper (§III-E), Type IV
(packer and original application code *interleaved*, no clean tail) is the ONE Type
that needs the **original binary** to cleanly separate packer code from application
code; Types I/II/III/V/VI are decided from the run-time topology alone. Runtime-only
(no original binary), the 10-page heuristic cannot perfectly tell an in-place
unpacker's own post-tail original code (Type I/II) from genuine interleaved packer
code (Type IV). Empirically verified: forcing the stricter Type-IV rule the audit
proposed mislabels **UPX and amber as TYPE_IV** (they are I/II). The classifier
therefore keeps the topology-based `tail` refinement, which correctly labels real
in-place unpackers, at the cost of possibly UNDER-detecting a genuine Type IV whose
packer code is non-writing and interleaved after the tail. Type IV IS detected in
the clear interleaved case (`tests/test_paper.py::test_type_iv...` passes); a
precise Type-IV-vs-I/II decision for in-place unpackers would require wiring the
original binary as a validation channel (deliberately not done, since using ground
truth to LABEL would deviate from the paper's runtime-only method).

Deferred audit items (do not affect the labels produced so far): compute the V/VI
`multi_frame` ratio from the candidate code's own frames rather than per-layer
frames; and emit an Evidence note when the topology `tail` refinement alone changed
the outcome. Full audit is in the session record.


## Backend profiles and the validation stamp

A condition may need tracing parameters the default certification does not cover.
`LABEL_PROFILE=<name>` reads `ops/qemu/profiles/<name>.json` for the parameters and
passes `ops/qemu/profiles/<name>.validation.json` to `run_trace.py` as
`--validation-stamp`, so the run is checked against the certification for THOSE
parameters. `icount_shift`, `icount_sleep`, `cpu_model` and `guest_smp` are part of
the pinned backend identity, so a run at non-default parameters is ineligible
unless a stamp attests them.

Certified profiles: `default` (shift=2, sleep=on) and `slow-timer` (shift=0,
sleep=off, for `hxor_packer 0.1`). See `docs/PACKER_RUN_PARAMETERS.md`.

## Labels from mixed reps: Ugarte Sec V-C

`finalize` first seeks **exact consensus** across `n = 3 x >= 2 payloads`. When reps
disagree it falls back to **maximum observed complexity**: reps that observed no
unpacking ABSTAIN — they are failed measurements, not competing labels — and the
highest complexity actually observed becomes the label, with status
`empirical_max_observed_complexity` and the full rep distribution recorded in
`max_observed_evidence`.

This matters for samples that gate unpacking on an anti-analysis check they only
sometimes fail. `hxor_packer 0.1` clears its own 550 ms timing check in roughly one
rep in four; the one rep that unpacked produced `TYPE_I`, the five that refused
abstained, and `max_observed_evidence` records
`{UNRESOLVED_NO_UNPACKING_OBSERVED: 5, TYPE_I: 1}`.

## Reading a sample's own diagnostics

Starting the plugin with `--plugin-arg file_io_payload=N` records `payload_hex` on
`file_read`/`file_write` events. A packer that prints why it refused to run then
becomes readable directly from the trace, without depending on the guest flushing
NTFS. Off by default.
