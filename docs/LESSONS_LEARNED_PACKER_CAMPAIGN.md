# Lessons learned: benign packer campaign (November 2026)

Living document, updated as the campaign closes. Last update: 2026-11-26 (alienyze demo nag).

**Scope.** These lessons come from re-typing the 105 benign packer conditions with the deterministic Ugarte classifier. They cover what went wrong, how each problem was found and fixed, and what each one means for the EMBER 2024 and malware campaigns that follow.

**Status at this update**
- 103 of 105 conditions are typed. Each Type is deterministic, measured on neutral payloads, agreed by every run, and backed by runs that end cleanly.
- 1 is still running: yoda's Protector 1.01.2.
- alienyze_protector 1.4 is being re-packed. Its original pool is truncated.
- EMBER is held behind `packers_all_typed.py` until every condition passes.

---

## 1. The guest environment is part of the measurement

**What happened**
- Both guest snapshots were captured 4–11 guest minutes after boot. Windows post-boot work (SysMain, Search, Update, .NET ngen, maintenance) kept both vCPUs at 100% during every run.
- `Sleep(500)` measured 578–797 ms, and `Sleep(16)` measured 187 ms.
- hxor_packer's stub checks `Sleep(500) > 550 ms` and treats that as a sandbox. It never unpacked, so the condition looked untyped.
- A quiet guest fixed this: services disabled offline, a 1-hour boot (guest clock 43 min rather than 3:48), and both arms re-certified.
  - Sleep timing became 500–547 ms.
  - hxor typed TYPE_I.
  - Cold-boot certification dropped from hours to about 20 minutes.

**What it changed.** The Type of several packers changed with the guest, though each guest was deterministic:
- petite 2.4: IV → III
- obsidium 1.5.2: IV → VI-B
- armadillo 2.52b2: IV → I

**For EMBER and malware**
- Run only on the quiet snapshots: `snap_quiet` (certified) and `snap_vmarm_quiet` (VM arm). `.env` and `ember_gated.sh` already point there.
- A busy guest is a sandbox tell. Malware with timing checks (sleep-skew, GetTickCount deltas) would evade on the old guest, and so would loaders like hxor.
- Verify every new snapshot with `ops/qemu/sleep_probe.c` before use. Build snapshots with no campaign running, because the boot wait is in wall-clock time.
- A Type is a property of (sample, guest). Report the guest image ID with every verdict. The runner already records `guest_image`.

## 2. Payload choice contaminates the packer's Type

**What happened**
- 12 conditions had been labeled from pairs that included installer payloads (NSIS, Inno Setup).
- Installers write their own code and then execute it, so the Type measured packer plus installer. The bare originals measured NSIS 2.46 → TYPE_I and Inno Setup 5.4.2 → TYPE_VI-F on their own.
- amber_v2.0's "packed" samples were the bare installers and had never been packed.
- Selection was restricted to neutral `_portable_` console payloads (`LABEL_NEUTRAL_ONLY=1`). New samples were built where none existed:
  - Amber 2.0 was built from 2018 source.
  - PEzor 3.3.0 ran in a scratch directory on Linux.
  - Themida, the UPX Scramblers, WinUpack, yoda's Crypter/Protector, nspack and alienyze were packed in a QEMU Windows packing VM (`/data/packvm`).
- Every output was verified as genuinely packed.
- All 8 neutral originals measure no write-then-execute when run bare.

**For EMBER and malware**
- Malware cannot use neutral payloads. Its payload *is* the sample. An EMBER Type therefore describes the whole binary (packer + payload + any second-stage dropper or installer), not "the packer".
- Report EMBER Types as whole-sample complexity. Do not map them back to a packer name.
- EMBER's `packer_label` is static metadata only. It must never be used to infer or "correct" a Type (see §6).
- NSIS/Inno-wrapped malware (the EMBER `nsis` label) will show installer layers on top of the payload's own. Keep `/S /NCRC` so the installer proceeds non-interactively. Expect TYPE_I or higher from the installer alone.

## 3. Some Types depend on how long the payload lives

**What happened**
- Amber 2.0's Go runtime threads keep running stub code alongside the payload. A payload that stays alive (cat, chmod and bc wait on stdin) accumulates interleaving and classifies TYPE_IV. `basename` exits at once and classifies TYPE_II, which is an under-observation.
- WinUpack sits on the III/IV boundary: 7 of 8 payloads are TYPE_IV and bc is TYPE_III. All share the same cyclic 3-layer structure, but the tail-transition and interleaving heuristics flip by payload.

**For EMBER and malware**
- Short-lived samples, those that exit, crash or need arguments, can under-report Type. Record the termination reason with every verdict, and treat `all_monitored_processes_exited` with a low frame count as a lower bound.
- Boundary cases are expected. Record per-sample evidence: frames, transitions, the interleaving and tail flags. Do not collapse these to a single label without it.

## 4. Crash-terminated runs cannot support a Type

**What happened**
- yoda's Crypter 1.3 unpacked, in 4 layers, then crashed on most payloads. The crashing runs gave TYPE_II and TYPE_IV, depending on where the crash landed. Every run that ended cleanly gave TYPE_II.
- amber_v2.0's first TYPE_IV pair also came from crashing runs.
- Fix: `label_all` treats a payload whose runs end in `unrecovered_exception*` as a dud and swaps it, and the gate rejects consensus built on crashed runs. Several crashing payloads meant the attempt limit had to be raised (`LABEL_MAX_ATTEMPTS=8`).

**For EMBER and malware**
- Much malware crashes under analysis: environment checks that deliberately crash, missing dependencies, anti-debug faults.
- `label_malware_types.py` now records any verdict with a rep that ended in `unrecovered_exception*` as `type_source: crashed`, with no Type. The Types the crashed reps would have had are kept in `crashed_rep_types`.
- `crashed` is a finding, not an infrastructure failure: `--rerun-failed` leaves it alone, but `--from-untyped` sends it to the VM arm, because a deliberate crash can be an evasion response.
- Report how many samples are typed versus crashed.

## 5. Budgets must follow the packer, not a fixed tier

**What happened**
- Hyperion brute-forces its own AES key at runtime: 4,096 keys, about 6M instructions per try. The source (`decryptexecutable.asm`) together with an offline key search showed 2.3.1 needs about 23B instructions, beyond the 1B and 2B tiers. Both versions typed TYPE_I at 30B.
- kkrunchy's context-mixing decompressor needed 2B for PuTTY puttygen.

**For EMBER and malware**
- The 1B sample budget (200e9 guest cap) will leave slow decryptors and brute-force stubs untyped. These look identical to "no unpacking".
- Before concluding "no unpacking", check the termination reason. Budget-bound samples need a higher tier, not the VM arm.
- At 30B a raw trace is about 1 TB. That is only practical with the trace tap (§7).
- The whole-guest instruction cap matters as much as the sample budget.
  - A sample that loops in exception handling (yoda's Protector) never executes new code, and never reaches the sample budget.
  - Only the guest-wide cap ends it. The neutral re-runs briefly used 1e12, and such runs went 8+ hours.
  - Keep the standard pairs: 100M with a 20e9 guest cap, 1B and above with 200e9. EMBER's `ember_gated.sh` uses 200e9.

## 6. Labels must come only from current runs

**What happened**
- `finalize` carried the previous manifest label forward when new runs decided nothing, and `label_all` reported it as fresh consensus.
- exe32pack's committed TYPE_IV and molebox's quiet-campaign TYPE_IV were inherited this way, and all their runs were UNRESOLVED.
- Fix: only TYPE_0 may be carried forward (finalize, 3b9ac5b). Any other label must come from the runs being finalized (e07c225). The gate requires every run to equal the label.
- TYPE_0 is now assigned dynamically by `ops/qemu/dynamic_type0.py`. Every run must show:
  - no write-then-execute;
  - a natural end;
  - executed image blocks that match the original payload's bytes at the same RVA (at least 95%).
- Controls: a bare original passes; a PEzor-packed run fails all three checks.
- astral_pe 1.6.0.0 (neutral basename + bc, 1B tier, all 6 runs): TYPE_0, with 99.1% and 100% of executed image code matching the original. Only Astral's entry-point stub differs.
- The 100M tier's 20e9 guest cap stopped the runs before they could idle, so the 1B tier was needed for the natural end.
- No label in the corpus is inherited any more.

**For EMBER and malware.** The TYPE_0 rule needs the original payload, which malware never comes with. EMBER cannot be assigned TYPE_0; report "no unpacking observed" instead. Never seed a verdict from a previous run, a static name, or `packer_label`. Every EMBER and malware Type must be derivable from that verdict's own `rep_diag`.

## 7. Trace volume is an engineering limit

**What happened**
- At 1B instructions, 11 of 19 EMBER samples hit the 60 GB trace cap. Throughput was about 4 samples per hour.
- The trace tap fixes this (`run_trace.py --trace-tap`, `MALWARE_TRACE_TAP=1`). The plugin writes into a FIFO, which zstd compresses to about 2% of the raw size. The raw SHA-256 and the summary are kept, and the host idle watcher is fed from a status file.
- The tap is byte-identical to a plain trace (summary line excluded) on a Themida sample.
- Found by running it: a classifier error on a truncated trace re-opened the FIFO and hung for 3 hours. On a FIFO, errors now fail cleanly instead (870fd7b).

**For EMBER and malware**
- Run with the tap on; `ember_gated.sh` sets it.
- The 60 GB cap now applies to compressed size, which covers roughly 3 TB raw. The separate 250 GB large lane is no longer needed.
- Any reader of the trace must read it once, front to back.

## 8. Harness hygiene

- **Orphaned guests.** Killing a runner leaves its own-session `run_trace` children alive. Kill the process groups and the `malwarerun` QEMUs (4 orphaned EMBER guests were found).
- **Runners killing each other's guests.** `reap_orphans()` used to kill every `malwarerun` QEMU, so one runner's start or exit killed another runner's guests. It is now scoped to the runner's own scratch directory. Concurrent runners need distinct `MALWARE_SCRATCH` and `CORPUS_RUNLOCK` values.
- **Lost evidence.** `run_pair` cleared the runs directory before every attempt, which destroyed the evidence behind sample splits. Attempts are now archived under `<tag>.attempts/<n>/`.
- **Pipelines must gate on results, not exit codes.** `after_packers.sh` started EMBER because stage 1 returned 0 while 6 conditions were still untyped. `ember_gated.sh` now refuses unless `packers_all_typed.py` passes.
- **`compare_arms`** called budget-bound runs `evasion_confirmed` because their execution counts differed. Both arms run the same budget, so that is not evidence of evasion.
- **Hard limits stall runs.** Very slow GUI samples (puttytel, yoda's Protector) never idle and never reach their budget. Bound them with a host timeout that matches the budget, and prefer console payloads.

## 8b. Demo builds and interactive dialogs

**What happened**
- Alienyze 1.4 (demo) shows a nag MessageBox before unpacking: "This message won't appear in the registered version!"
- In the certified lane nothing clicks OK, so every run idles about 4.7M blocks in with no unpacking.
- In the VM arm the dialog is dismissed and the process exits 738 blocks later, still without unpacking. Its wrapper settings (Debugger, VM and Integrity detection set to Terminate) are the likely cause.
- `compare_arms` reported `evasion_confirmed` from the termination divergence. Its only CPUID evidence came from `bcryptprimitives.dll`, the system RNG, so the divergence is real but its cause is the dialog plus a detection exit, not hypervisor detection.
- The diagnostic build with detections off also waits on the nag, so the demo nag alone blocks unpacking.
- Fix: a delivery-CD flag (`DISMISS.TXT`, `LABEL_SAMPLE_DISMISS=1`) makes the launcher press OK on dialogs owned by the sample's job.
  - A first version that only posted `WM_COMMAND IDOK` did not close the box. In session 0 the dialog it found had no `IDOK` child.
  - The working version clicks every child button, then posts `IDOK` and `WM_CLOSE`. It was verified with a MessageBox probe: the trace shows `MessageBoxA` returning.
  - Only flagged runs use it, so no other condition's behavior changes.

**For EMBER and malware**
- Interactive dialogs block the trace and look like "no unpacking". Installers, nag screens, EULAs and error boxes all do this.
- The VM arm's window capture (`windows.txt`) is the tool that found this one. Keep it on.
- Check window titles before concluding "no unpacking" or "evasion".
- An `evasion_confirmed` verdict needs its evidence read: the module that issued each check, and the termination of each arm.

## 9. Checklist before starting EMBER

1. `packers_all_typed.py` passes: all 105 conditions are typed or excluded with a documented reason.
2. The relabel report and manifests are committed. No manifest carries an inherited label except astral_pe's source-review TYPE_0.
3. `.env` points at `snap_quiet`. `ember_gated.sh` uses `snap_vmarm_quiet` and `MALWARE_TRACE_TAP=1`.
4. Crash-terminated EMBER runs are reported as `crashed`, not typed (done, see §4).
5. Verdicts carry `guest_image`, the termination reason, payload-lifetime evidence and the evasion detector output.
6. Budget-bound EMBER samples go to a higher tier before the VM arm.

## Open items

- yoda's Protector 1.01.2: running (its first pair stalled for 8 hours; it is not a determinism issue).
- alienyze_protector 1.4: re-packing with GUI neutral payloads (PuTTY puttygen and pageant, PCI-Z), using the corpus wrapper's settings: Compression=Medium; Debugger, VM and Integrity detection=Terminate.
  - Alienyze rejects console programs ("invalid sub system 0x3"), and the 8 neutral console tools are all subsystem 3.
  - Forcing the GUI flag crashed the packer.
  - The packer may be what produced the old pool's truncated files (unconfirmed).
  - Because its VM check is set to Terminate, expect the VM arm to be needed.
- Record per-sample Type distributions for boundary packers (WinUpack, Amber) in their manifests.
- alienyze 1.4: the demo nag dialog blocks unpacking in every arm and setting (the detections-off diagnostic also waits on it). Typing it needs the nag dismissed (pending decision).
- Fix the line endings of Themida's `custom_vms/*.vm` in the packers repo (`-text` gitattribute).
