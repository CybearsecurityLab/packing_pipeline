# Known limitations of the W→X oracle and its harness

Hand-written. Records defects found by auditing the instrumentation rather than
the packers. Every one was originally mistaken for a packer property.

**Why fixed defects are still listed.** Fixing a defect changes what future runs
measure; it does not retroactively change labels already collected under it. The
status of each entry below says which existing results are implicated and what
would clear them. An entry marked RESOLVED with no residual impact is kept only
so the same mistake is not re-derived later.

The recurring lesson: an `UNRESOLVED_NO_UNPACKING_OBSERVED` verdict marked
*eligible* and *complete* is not evidence that a packer does not unpack.

## Status summary

| # | Defect | Status | Existing corpus implicated? |
|---|---|---|---|
| 1 | Host-time completion boundary | fixed forward | **YES — 638/639 eligible runs** |
| 2 | `file_io` gate biased against long runs | **OPEN** | **YES — disqualifies the longest runs** |
| 3 | `single_process` certification | being re-certified | **YES — no result is a true negative** |
| 4 | 64-bit validation fixture vs WOW64 samples | **OPEN** | yes, for PE32 samples |
| 5 | `filtered_kernel_write_events` dead counter | **OPEN** (cosmetic) | no — it never gated anything |
| 6 | icount shift changes packer behaviour | inherent, not a bug | yes — interpretive caveat |
| 7 | Guest missing VC++ redistributable | **RESOLVED** | only alushpacker; re-run pending |
| 8 | `guest_exit_code` without an observed exit | **RESOLVED** | no — no label consumed it |
| 9 | W→X cross-check false positives | **RESOLVED** | no — cross-check only, not a label source |

Clearing (1) requires re-running affected conditions with `LABEL_HOST_IDLE` raised;
it is not a re-analysis, because the recordings were truncated at capture time.

## 1. The host-observed idle boundary is measured in HOST time

`run_trace.py` closes a recording after `--host-idle-seconds` (default **120**) of
no newly-serialised `exec`/`write` records, and reports it as a normal completion
(`paper_termination_reason: two_minutes_idle_host_observed`). The plugin slows the
guest heavily, so a guest sleep or a protector's timed pause can exceed two host
minutes while the sample is still live.

**638 of 639 eligible runs in the corpus (99.8%) rest on this boundary.**

Demonstrated on telock: its certified reps stop at 1291552 / 1291510 / 1291806 /
1291396 and 1117661 / 1118065 / 1118084 executed blocks — a spread of a few
hundred in 1.3 million, i.e. a fixed instruction, cut off mid-pause and reported
as "no unpacking observed". The one run that got through the pause reached
13712759 blocks and classified **TYPE_VI-B** (2 layers, 15 forward / 15 backward
transitions), with 5 write-then-execute pages on an independent recount, one
written 5481 times before its first execution. Obsidium shows the same fixed-point
clustering at ~1.118M.

`--host-idle-seconds` existed but was never passed by `run_condition_matrix.py`,
so every condition ran at the 120s default. Now `LABEL_HOST_IDLE`.

## 2. `guest_exit_code` was reported when no exit was observed

Derived from `stop_detail`, which defaults to 0 when no stop marker was ever seen,
so a run ending on the idle boundary reported "exited cleanly with code 0" with
`saw_stop=false`. Now requires `saw_stop`. No label depended on it.

## 3. icount shift decides whether a timing check fires

hXOR-Packer's `runtimeDelay()` allows 550ms for a `Sleep(500)` measured with
`GetTickCount`. Overshoot is (instructions executed by other threads during the
wait) × (virtual ns per instruction), so it scales with `-icount shift`:

| configuration | outcome |
|---|---|
| shift=2 | `0x401afa` executes — **detected**, packer bails |
| shift=0, idle=120 | truncated mid-`Sleep`, comparison never reached |
| shift=0, idle=900 | `0x401b05` executes — **passes**, full unpack observed |

At shift=0 with a raised idle window the sample enumerates processes (656 events
in `isProcessRunning`), enters `unpackFiles` and `LoadEXE`, and its hollowed child
is enrolled (`descendant_enrolled=1`, `processes=2`).

This is an artefact of OUR slowdown, not the packer detecting virtualisation.

## 4. The guest shipped no VC++ redistributable

Any MSVC-built packer stub importing `VCRUNTIME140.dll` failed import resolution
before its entry point. The tracer records that as `exec_events=0`,
`no_execution_launch_failed`, `sample_started=false`, `root_entry_seen=false`,
while the launcher's own PACK markers still fire — indistinguishable from a packer
emitting an unloadable PE, which is how alushpacker was misdiagnosed
(`output_nonfunctional_confirmed`). Installing the redistributable took it from
**0 to 58k–165k executed blocks**. See `ops/qemu/install_guest_vcredist.sh`.

`api-ms-win-crt-*` imports are not implicated: the Win10 apiset schema resolves
them to `ucrtbase.dll`, which is present.

## 5. `file_io_failures` disqualifies long runs, and grows with run length

`run_trace.py` gates eligibility on `file_io_failures == 0` and
`asynchronous_file_io == 0` (zero tolerance). Armadillo:

| rep | exec | file_io events | failures | rate | eligible |
|---|---:|---:|---:|---:|---|
| A1 | 2512196 | 17 | 0 | 0% | yes |
| A2 | 3165889 | 92 | 0 | 0% | yes |
| B1 | 1620614 | 24 | 0 | 0% | yes |
| B2 | 14732758 | 71 | 34 | 32.4% | **no** |
| B3 | 25316292 | 100 | 175 | 63.6% | **no** |

Only the two longest runs fail, both on this channel. `paper_trace.c:1554`
increments the counter when `allocate_file_io()` exhausts `pending_file_io[4096]`;
entries are freed only on observed completion, so any missed completion leaks one
permanently and the table fills monotonically with run length. That matches the
signature but is not proved — the single counter aggregates **seven** distinct
failure sites (`paper_trace.c:1524,1529,1537,1549,1554,1594,1602`).

Consequence: the harness is biased against exactly the packers that need long runs
to reach their unpacking. Splitting the counter would settle it, but changing the
plugin changes `plugin_sha256` and therefore the certified identity, so it must be
done as a deliberate re-certification, not mid-corpus.

## 6. `filtered_kernel_write_events` is a dead counter

Declared at `paper_trace.c:234` and printed at `:2943`/`:3003`, never incremented.
Its zero measures nothing; it does not mean no kernel writes were excluded.

## 7. Certification is `single_process`, and the fixture is 64-bit

`backend_validation.json` records `certification_mode: single_process` with
`kernel_write_observed=false`, `remote_write_proved=false`,
`shared_alias_proved=false`, `file_to_execution_proved=false` and
`kernel_store_callbacks_registered=false`. Kernel, remote and shared-alias writes
are therefore absent from the trace entirely — no recount over a trace can find
them, and **no "no unpacking" result over these traces is a true negative**. The
defensible phrasing is "no unpacking observed within the retained, scoped trace".

The cause is `validation_fixture.c`: when `C:\Panda\single_process.txt` is present
it `ExitProcess()`es before `mapped_file_execute`/`shared_parent`/`remote_parent`/
`disk_drop` run, so the cross-process channels are never exercised.
`stage_fixture_launcher.sh` stages that flag unless `SINGLE_PROCESS=0`, and
`recertify_backend.sh` calls it through `sudo -S` without `-E`, so the variable
cannot reach it. `ops/qemu/recertify_cross_process.sh` fixes this and writes a
candidate stamp instead of the live one.

Note the fixture is built with `x86_64-w64-mingw32-gcc`. A full certification from
it proves the cross-process channels for **native 64-bit**; hxor_packer and
alushpacker are PE32 under WOW64.

## 8. Cross-checks that agree with the classifier are not independent

`ops/qemu/analysis/recount_wx.py` had three separate false-positive/negative
classes, each found only by testing the tool against known cases:

1. `first_write < first_exec` cannot see **X→W→X** (execute, modify, re-execute),
   the canonical decrypt-in-place shape. On `upx_label2` this reported 1 page
   where the corrected predicate reports 2, one with 32 write→exec epochs.
2. Page granularity manufactures hits when a write lands on data bytes and
   execution on code bytes in the same 4 KB page.
3. System-role execution (`role: "system"`) counted ntdll/kernel32 as packer code.
   alushpacker's only candidate was two system DLLs sharing a physical frame.

It also skips events lacking physical provenance: `armadilloB_rep3` has 327711
such writes (2.4%), `B_rep2` 414140 (12.3%). A reported 0 must always be quoted
with the coverage behind it.

The classifier does **not** share defect 1; that was the cross-check only. Its own
narrower gaps are alias writes and unmaps, which produce an extra frame with no
layer change — which is what armadillo A2's 43 frames at `layers=1` are, and they
are therefore not evidence of Type V/VI.
