# Packer Corpus Orchestrator

**Automated Framework for Generating Packed Executable Datasets**

This repository serves as the "Orchestrator" for the **Leal Security Lab** automated packing research project. It manages the acquisition of benign executable sources, the configuration of packer tools, and the automated generation of packed artifacts for malware analysis and evasion research.

## 📂 Repository Structure

This project uses **Git Submodules** to keep heavy binary data (`inputs`, `tools`, `outputs`) separate from the logic.

```text
packer-corpus/
├── benign_sources/       # [Submodule] Input datasets (Linked to 'inputs' repo)
│   └── manifest/         # JSON tracking files (processed_ids.json, x64.json)
├── packers/              # [Submodule] Packer binaries (Linked to 'tools' repo)
│   └── exe32pack/
├── manifest/             # Configuration
│   └── packer_corpus.yaml # Main definition file for packers and test cases
├── utils/                # Python Automation Scripts
│   ├── beningn_source_downloader.py
│   ├── packer_runner.py
│   └── update_manifest.py
├── pyproject.toml        # Dependency definitions
└── uv.lock               # Lockfile for reproducible builds
```

Note: `packed_sources/` (the generated output artifacts) is **not committed to this repo** — it's produced by GitHub Actions runs and published to a separate `outputs` repo.

# 🚀 Prerequisites & Installation

This framework is designed for Windows environments (required for winget and PE-specific packers).

## 1. Install winget (Windows Package Manager)

Most modern Windows 10/11 builds have this pre-installed.

- **Check if you have it:** Open PowerShell and type `winget`.
- **If missing:** Install the "App Installer" from the Microsoft Store.

## 2. Install uv (Fast Python Package Manager)

We use `uv` for extremely fast dependency management and script execution. Run the following command in PowerShell:
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 3. Install Go (required for amber v2.0)

amber v2.0 shells out to `go build` to compile its runtime stub. The prebuilt amber.exe predates Go modules (no `go.mod` in its tree), so Go 1.21+ must be told to use the legacy GOPATH build mode.

- **Recommended:** Install Go via Scoop (`scoop install go`) — the runner auto-detects `C:\Users\<you>\scoop\shims\go.exe`.
- **Manual:** Install Go from <https://go.dev/dl/> and ensure `go.exe` is on `PATH`.

The runner also sets `GO111MODULE=off` automatically for `amber_v2.0`, so you don't need to change your global Go config.

## 4. Clone the Repository

Because this repo uses submodules, you must use the `--recurse-submodules` flag to pull the linked projects immediately.
```powershell
git clone --recurse-submodules https://github.com/BaylorSecurityLab/packing_pipeline.git
cd packing_pipeline
```

**Already cloned without submodules?** Run this to fix it:
```powershell
git submodule update --init --recursive
```

## 5. Install Dependencies

Initialize the environment and install dependencies defined in `pyproject.toml`.
```powershell
uv sync
```

## 6. Install WSL2 (required for PEzor)

PEzor shells into WSL2 to compile its C++ stub. Other packers are pure Windows binaries and don't need WSL.

```powershell
wsl --install
# Reboot if prompted, then set the default distro:
wsl --set-default-version 2
```

Inside WSL, install the build toolchain PEzor needs (clang, make, git):
```bash
wsl -d Ubuntu-26.04 -u root -- bash -c 'apt-get update && apt-get install -y build-essential clang git'
```

Verify with `wsl --status` — you should see `Default Version: 2`.

---

# 🛠️ Usage Guide

All scripts are located in the `utils/` folder. You should execute them from the project root using `uv run`.

## Phase 1: Acquire Data (Benign Sources)

This script queries the Winget API, downloads distinct executables, extracts them from installers/zips, and categorizes them into `benign_sources/x64` and `benign_sources/x86`.
```powershell
uv run utils/benign_source_downloader.py
```

- **Configuration:** Adjust the `LIMIT` variable inside the script to change how many samples are fetched per run.
- **Manifests:** It automatically tracks downloaded IDs in `benign_sources/manifest/processed_ids.json` to avoid duplicates.

## Phase 2: Run Packing Experiments

This script reads `manifest/packer_corpus.yaml` and executes defined test cases against your benign sources.

### Basic Usage:
```powershell
# Syntax: uv run utils/packer_runner.py <packer_name> [options]

# Example: Run 'exe32pack' test cases
uv run utils/packer_runner.py exe32pack
```

### Advanced Usage (Size Filtering):

Some shareware packers (like evaluation versions) have strict file size limits. You can filter inputs automatically:
```powershell
# Only pack files smaller than 80KB
uv run utils/packer_runner.py exe32pack --max-size-kb 80
```

### PEzor WSL worker count:

PEzor shells into WSL2 and compiles C++ per job. By default it runs **4 concurrent `wsl.exe` invocations**; bump it with `--wsl-workers N` (the runner caps N at the per-packer ceiling of 8 and logs the effective value at start-up):
```powershell
# Default 4 — fine for most boxes
uv run utils/packer_runner.py pezor

# Custom worker count (capped at 8 by the runner's per-packer ceiling)
uv run utils/packer_runner.py pezor --wsl-workers 6
```
The memory-budget scheduler is the real throttle for PEzor — the worker count is just an upper bound on simultaneous `wsl.exe` launches. If you raise `--wsl-workers` and the WSL VM OOMs, lower it.

## Phase 2b: Run GUI Packers

Some packers (FSG, Themida, Obsidium, Yoda's Crypter/Protector, PECompact, ZProtect, …) are **GUI-only** and cannot be scripted through `packer_runner.py`. They are driven by GUI-automation wrappers in `wrapper/` (built on `pyautogui` / `win32gui`) and orchestrated by **`wrapper/gui_runner.py`**.

> ⚠️ **Run on an interactive Windows desktop.** These wrappers move the real mouse and keyboard and need a visible screen — they will **not** work headless, over SSH, or in CI. Don't touch the machine while a run is in progress.

Paths are resolved relative to the script, so run these from the project root:
```powershell
# Pack every compatible file in benign_sources/x86 with FSG
uv run python wrapper/gui_runner.py --packer fsg_v1.0

# Smoke-test on a single input first (recommended)
uv run python wrapper/gui_runner.py --packer fsg_v1.0 --limit 1

# Pack one specific file
uv run python wrapper/gui_runner.py --packer fsg_v1.0 --file "benign_sources\x86\example.exe"

# Run every GUI packer in sequence
uv run python wrapper/gui_runner.py --packer all
```

Output goes to `packed_sources/<packer>_<version>/` (e.g. `packed_sources/fsg_v1.0_1.0/`). Already-packed inputs are skipped by default.

### Common options

| Flag | Description |
|------|-------------|
| `--packer <name>` | GUI packer to run (`fsg_v1.0`, `themida_v3.2.4.34`, …), or `all` for every one |
| `--file <path>` | Pack a single file instead of the whole batch |
| `--limit N` | Only process the first N files |
| `--dry-run` | List the files that would be packed, without packing |
| `--no-skip` | Re-pack files even if output already exists |
| `--recursive` | Scan sub-directories of the source dir |
| `--exclude <p1 p2>` | With `--packer all`, skip these packers |
| `--source-dir <dir>` | Input directory (default `benign_sources/x86`) |
| `--output-dir <dir>` | Override the output directory |
| `--list-packers` | List all GUI packers and their supported file types |
| `--packer-info <name>` | Show a packer's configurable options |

> ℹ️ FSG specifically needs a **PE32 / x86** input with an **ASCII-only path**, ideally **< 80 KB** — incompatible files trip a TLS dialog and are skipped automatically.

## Phase 4: Empirical Type I–VI collection

Type I–VI labels are assigned empirically from real dynamic traces. A label is
emitted only on exact consensus across ≥2 distinct payloads × 3 repetitions,
using the two-vCPU upstream-QEMU tracer with complete ordered
basic-block/write/IPC evidence and a passing eligibility gate. Backend details and validation status are in
[`ops/qemu/README.md`](ops/qemu/README.md); the collection workflow is in
[`docs/empirical_type_collection.md`](docs/empirical_type_collection.md).

### Certified deterministic backend

All labelling runs on one certified backend identity, recorded in
`ops/qemu/backend_validation.json` and checked before every label is issued:

| Component | Value |
|---|---|
| QEMU | `/data/determinism/qemu-det-build`, `-icount shift=2,sleep=off,det=on`, blkdet |
| Tracer plugin | `/data/determinism/paper_trace.final1.so` (sha256 `9b51dab0…`) |
| Guest | Windows 10 x64, Defender off, with VC++ 2010–2022 and DirectX 9–11 runtimes (`/data/determinism/snap_redist`), resumed per run, sample delivered on a CD |
| Launcher | `guest_launcher.delivery.exe` (sha256 `812b7303…`) |

Traces are byte-reproducible run to run. A run whose identity differs from the stamp is
never labelled. Recertify after changing any component with the channel fixture
(`ops/qemu/validate_fixture_trace.py`).

### Campaigns

| Corpus | Entry point | Scope |
|---|---|---|
| Benign packers | `ops/qemu/label_all.py` | 105 packer conditions, 2 payloads × 3 reps, exact consensus |
| EMBER 2024 test set | `ops/qemu/label_malware_types.py run` with `MALWARE_WORKLIST=/data/ember2024/worklist.jsonl` | 5,080 Win32 samples |
| Malware corpus | `ops/qemu/label_malware_types.py run` | 25,820 packed Win32 samples |

All three corpora are typed **dynamically only**. A static packer name never
assigns a Type; for malware samples whose static name maps to a labelled packer
family, that family's Type is kept as `static_family_type` purely for comparison.
Every run stops at the same bound: 100M sample instructions or a 20e9 guest-wide
instruction cap.

Campaign settings live in `.env` (`MALWARE_*`); packer settings are exported by
`LABEL_*` variables (`LABEL_QEMU`, `LABEL_PLUGIN`, `LABEL_TRACE_ARGS`,
`LABEL_INCOMING`, `LABEL_BOOTED_BASE`, `LABEL_WORKLIST`, `LABEL_LOCAL_MIRROR`,
`LABEL_RELABEL`, `LABEL_DONE_DIR`, `LABEL_RUNS_ROOT`, `LABEL_NO_GIT`,
`LABEL_ONLY`). Samples are read from local mirrors under `/data`
(`/data/benign_packed`, `/data/ember2024/binaries`, `/data/malware_zips`).
Guest and classification slots are separate (`MALWARE_GUEST_SLOTS`,
`MALWARE_CLASSIFY_SLOTS`); classification is the throughput bottleneck on large
traces.

Campaigns resume where they stopped: completed verdicts are kept and samples without a
verdict run. Pass `--rerun-failed` (or set `MALWARE_RERUN_FAILED=1` /
`LABEL_RERUN_FAILED=1`) to also re-queue failures: infrastructure outcomes such as
`failed:*`, `error:*`, `trace_oversize`, `sample_would_not_launch`, trace loss on every
rep, or a packer condition with any non-Type run. Re-queued verdicts are moved to a
`*.rerun-failed/` directory beside the originals, never deleted. Each malware verdict
records `guest_image`, a hash of the snapshot it ran on. EXEs whose section table is
larger than the file are skipped as `not_process_launchable:truncated_image`.

### VM arm

Samples and conditions the certified lane leaves without a Type are re-traced under
an anti-VM-hardened profile, `run_trace.py --profile vmarm`. It keeps qemu64's AMD
feature set and adds `hypervisor=off,tcg-cpuid=off`, a matching AMD brand string,
OEM-like SMBIOS types 0/1/2/3/4/17, ACPI OEM ids in place of BOCHS/BXPC, realistic
IDE disk and CD identify strings, a fixed RTC date, and the plugin's `evasion=on`
detector. The constants live in `ops/qemu/vm_profiles.py`, which both `run_trace.py`
and the snapshot builder read. The arm has its own backend identity (`profile` and
`machine_config_sha256`), stamp (`ops/qemu/backend_validation.vmarm.json`), guest
image and snapshot. A run never validates against the other arm's stamp. The default
`certified` profile produces exactly the certified command line.

| Step | Command |
|---|---|
| Snapshot | `SNAP_PROFILE=vmarm MALWARE_SUDO_PW=... bash ops/qemu/build_boot_snapshot.sh` (base.vmarm.qcow2 → booted.vmarm.{qcow2,migstate}, `guest_launcher_vmarm.exe`) |
| Malware / EMBER | `MALWARE_ARM=vmarm ... label_malware_types.py run --from-untyped empirical_results/malware/verdicts` → `verdicts_vmarm/` |
| Packer conditions | `LABEL_ARM=vmarm LABEL_INCOMING=... LABEL_BOOTED_BASE=... label_all.py` (only `<tag>.done` = UNRESOLVED) → `<tag>.vmarm.done` |
| One trace | `evasion_analysis.py trace.jsonl --meta meta.json [--windows windows.txt]`, then `compare_arms.py --certified DIRS --vmarm DIRS` |

`evasion_analysis.py` streams the trace and flags `evasion_suspected` with tiered
evidence. A high-tier check (hypervisor CPUID leaf, firmware-table query, VM registry
key, descriptor-table probe, VMware port, hypercall, VM-detection window title) flags
on its own. Medium- and low-tier checks flag only together with an outcome anomaly:
the sample exits, crashes or idles shortly after its last check. `compare_arms.py`
assigns `vm_arm_outcome`: `evasion_confirmed`, `virtualization_suspected`,
`genuine_no_unpacking` or `inconclusive`. VM-arm results are written to separate
fields: `vm_arm_outcome`, `vm_arm_type`, `evasion_suspected` and `evidence` in
malware verdicts, and a `vm_arm` block in packer manifests. They never overwrite the
certified label. `docs/EMPIRICAL_TYPE_LABELS.md` lists them in a separate VM-arm table.

---

# 🔒 SHA Quality Gate

Every produced sample is verified against a **SHA-256 gate** before it lands in `packed_sources/`. The gate prevents two recurring contamination classes from ever being published:

1. **Pass-throughs** — the packer returned the input bytes unchanged (`sha_out == sha_in`).
2. **Cross-packer duplicates** — the same SHA-256 already exists under a *different* `<packer>_<version>` directory (proves an unpacked original leaked in, or two packers produced identical bytes).

Both runners wire the same `utils/sha_gate.ShaGate` instance into their `pack_single_file` / `run_packer` paths, so a single rejected output is removed before any further accounting and surfaces in the final report as `PACK_FAILED_PASSTHROUGH`, `PACK_OUTPUT_MATCHES_OTHER_INPUT`, or `PACK_DUP_ACROSS_PACKERS`.

### Enable / disable

| Runner | Flag |
|---|---|
| `utils/packer_runner.py` | `--sha-gate` (default) / `--no-sha-gate` |
| `wrapper/gui_runner.py`  | `--sha-gate` (default) / `--no-sha-gate` |

`--no-sha-gate` is an escape hatch for diagnostic re-runs. The default is on; ship a PR that requires disabling it and reviewers will ask why.

### State files (under `packed_sources/_audit/`)

| File | Purpose |
|---|---|
| `published_shas.jsonl` | Authoritative cross-packer state. Reconciled with the on-disk tree (`size` + `mtime_ns`) at every launch so the 30 k+ file corpus does not require a full rehash. |
| `manifest.jsonl` | Append-only provenance log. One row per `verify_pack` call (accepted or rejected). |

Both runners share the audit dir; the gate reconciles state on startup so two processes launched back-to-back see each other's published outputs.

---

# 🧹 Cleanup pass (`utils/nas_cleanup.py`)

Once a SHA gate is in place it stops new contamination, but the existing corpus may already contain unpacked originals and pass-throughs. The cleanup pass walks `packed_sources/`, finds them, and moves them to `packed_sources/_quarantine/` (never deletes in place).

```powershell
# 1) Walk every .exe and write _audit/nas_inventory.jsonl (~30 k rows, minutes)
uv run python utils/nas_cleanup.py inventory

# 2) Diff the inventory against benign_sources/x86 and emit flagged rows
#    + a human-readable Markdown report.
uv run python utils/nas_cleanup.py report

# 3) Review packed_sources/_audit/nas_cleanup_report.md, then move
#    flagged files into packed_sources/_quarantine/. Idempotent;
#    refuses stale data; blocks packer_dirs that would drop below 2
#    genuine samples (those surface as "needs re-packing").
uv run python utils/nas_cleanup.py quarantine
```

Pass `--packed-root <dir>` / `--benign-dir <dir>` to point the script at a copy of the corpus (e.g. a snapshot on a different drive) — defaults are the live repo paths.

Outputs land under `<packed_root>/_audit/` and `<packed_root>/_quarantine/`.

---

# ⚙️ Configuration (packer_corpus.yaml)

The `manifest/packer_corpus.yaml` file is the source of truth for the experiment. It defines:

- **Packer Definitions:** Paths to binaries (in `packers/`), checksums, and metadata.
- **Test Cases:** Specific command-line arguments to run (e.g., "Maximum Compression", "Re-alignment").

### Example Entry:
```yaml
  - id: "EXE32PACK_001_DEFAULT"
    <<: *exe32pack_v142
    command_label: "Default Auto-Compression"
    cli_template: "{bin} /M:0 {in} {out}"
```

---

# ⚠️ Important Notes

## Antivirus Interference:

The `packed_sources/` directory will contain obfuscated binaries that will trigger Windows Defender or other AV solutions.

**Action:** Add a folder exclusion in Windows Security for your entire `packer-corpus` directory.

## Git Submodules:

If you need to update the tools or inputs, go into their respective folders (`packers/` or `benign_sources/`), pull changes, and then commit the new reference in the main repo.

---

# 🏷️ Automatic Empirical Type Labeling (Deep Packer Inspection)

Beyond *generating* the packed corpus, this repository now includes a subsystem
that assigns each packed sample its exact **Ugarte et al. Type I–VI** label
("SoK: Deep Packer Inspection") **empirically, from a real dynamic trace** — not
from static heuristics. A packed sample is executed inside an instrumented
Windows 10 guest under an upstream **QEMU 11 TCG plugin** that records every
executed basic block and memory store; the write→execute **layer-production
topology** is reconstructed and the Type is read off it. A label is emitted only
when a purpose-built certification fixture passes and, per condition, only on
**exact consensus** across `n = 3 executions × ≥2 distinct payloads`.

- **How to install & run it (all prerequisites, step by step):**
  [`doc/AUTOMATIC_LABELING.md`](doc/AUTOMATIC_LABELING.md)
- **The final packer → empirical Type document (generated):**
  [`doc/EMPIRICAL_TYPE_LABELS.md`](doc/EMPIRICAL_TYPE_LABELS.md)

Key components: `ops/qemu/` (QEMU build, `paper_trace.c` plugin, staging,
`run_trace.py`, `run_condition_matrix.py`, `cert_retry_loop.sh`),
`empirical_types/` (the paper's Section III-E classifier + `finalize`), and
`ops/qemu/backend_validation.json` (the certification stamp). Regenerate the
label document with `python3 ops/qemu/build_label_document.py`.

---

# 👥 Maintainers

**Leal Security Lab** (Baylor University)

**Current Maintainer:** Abanisenioluwa Kolawole Orojo
