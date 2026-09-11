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
| 2 | `file_io` gate biased against long runs | **FIXED** (plugin rebuilt) | **YES — results collected before the rebuild** |
| 3 | `single_process` certification | being re-certified | **YES — no result is a true negative** |
| 4 | 64-bit validation fixture vs WOW64 samples | **OPEN** | yes, for PE32 samples |
| 5 | `filtered_kernel_write_events` dead counter | **OPEN** (cosmetic) | no — it never gated anything |
| 6 | icount shift changes packer behaviour | inherent, not a bug | yes — interpretive caveat |
| 7 | Guest missing VC++ redistributable | **RESOLVED** | only alushpacker; re-run pending |
| 8 | `guest_exit_code` without an observed exit | **RESOLVED** | no — no label consumed it |
| 9 | W→X cross-check false positives | **RESOLVED** | no — cross-check only, not a label source |
| 10 | Duplicate samples in the STALE LOCAL cache | **RESOLVED upstream** | only runs before 2026-09-09 |
| 11 | Two runs traced with an uncertified plugin | recorded | yes — those two reps only |
| 12 | Document counted the NAS index, not the corpus | **RESOLVED** | reporting only, no label affected |
| 13 | armadillo's NAS output is not packed | **RESOLVED upstream** | fixed at source; armadillo now types TYPE_IV |
| 14 | `NtReadFile` Length read as 64-bit | **OPEN** | blocks full cross-process certification |
| 15 | hxor's hollowed child never reaches the payload | **OPEN — likely not a detector gap** | hxor only |

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
to reach their unpacking.

**FIXED.** `allocate_file_io()` now evicts the oldest entry instead of returning
NULL, counted separately as `file_io_evictions`, and each of the seven sites is
attributed (`file_io_register_failures`, `_handle_`, `_disk_`, `_argument_`,
`_status_`) with `file_io_failures` kept as their sum so the certification gate is
unchanged. All are emitted in the summary. This changed `plugin_sha256` from
`50a5aa94…` to `a17a5c71…`, so the backend must be re-certified; results collected
before the rebuild remain on the old identity.

Note the eligibility rule is narrower than assumed: `run_trace.py`'s
`trace_integrity` checks file-I/O failures and asynchronous I/O but **not**
`memory_buffer_overflows`; only `validate_fixture_trace.py` checks that. Runs
carrying overflows have therefore been accepted as eligible.

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

## 10. Duplicate samples — in the stale local cache, not the live NAS

A scan of `empirical_results/qemu_runtime/*_s[12]/sample.exe` found 11 sample
hashes appearing under more than one packer family across ~15 directories
(`91b639a4` and `d8e336ca` under all six upx_scrambler variants; `67454e77` under
obsidium, telock and two yoda_protector versions; `bbd79d49` under alienyze,
armadillo and pecompact).

**This is a stale-cache problem, not a live corpus problem.** Those staged copies
date from 2026-08-11/12. A sha-distinctness gate has since been added to the
production pipeline, and re-fetching from the NAS returns correct samples: the
current telock payloads are two distinct binaries with entry points in an unnamed
section, `.text` entropy 7.98, every section writable and `.idata` entropy 7.82 —
i.e. genuinely packed. The same file is 921,646 bytes in armadillo's NAS directory
and 154,624 in telock's, exactly as a compressor should behave.

Consequences that stand:

- Any result produced from a staged copy older than 2026-09-09 must be re-run from
  a fresh fetch, not merely re-analysed. telock's TYPE_VI-B was retracted on this
  basis: it had been measured on `61d4d99e`, a stock NSIS installer
  (`.text/.rdata/.data/.ndata/.rsrc`, linker 6.0, ordinary entry point) that was
  also filed as yoda_protector. The 4 layers and 444/437 transitions were NSIS's
  own self-extraction — a real measurement of the wrong program.
- Payload distinctness must be checked by **hash**, never by filename or
  directory. A two-payload "consensus" over a duplicated input is one observation
  reported as two.

## 11. Two obsidium reps were traced with an uncertified plugin

`obsidiumA_rep1` and `rep2` record `plugin_sha256 87a4bedd…`, not the pinned
`50a5aa94…`; they were captured while a rebuilt plugin was briefly installed
mid-sweep. Their `UNRESOLVED_TRACE_LOSS` is a backend-identity rejection, not a
dropped-event mechanism, and is unrelated to the `file_io` exhaustion in (2). Do
not read those two as evidence about obsidium.

## 12. The type document counted the NAS index rather than the corpus

`build_packer_type_document.py` filtered on `worklist.json`, so four corpus
definitions never enumerated into it (alushpacker, hxor_packer, hyperion 1.2 and
2.3.1) were dropped before counting, and it reported "2 unresolved" while six
definitions carried no type. Fixed by taking the union of the worklist and
`packer_corpus.yaml`, with the corpus `type:` field resolving family aliases.

## 13. armadillo's NAS output is not packed

Re-fetched from the NAS after the sha gate, both armadillo payloads are still
ordinary unpacked binaries: entry point in `.text`, `.text` entropy 6.59 and 6.70
(normal compiled code, not compressed), `.data` entropy 1.82 and 1.50, standard
`-X`/`W-` section flags, stock MSVC section layout with no Armadillo stub sections
and no CopyMem-II entry signature.

Compare telock's fresh output from the same pipeline: entry point in an unnamed
section, `.text` entropy 7.98, every section writable.

This explains the observation that never fitted the CopyMem-II story — no child
process, and no NtCreateUserProcess, NtDebugActiveProcess or NtWriteVirtualMemory
anywhere in the trace. The root never tried to create or debug a child because
there is no protector in the binary.

It also retires the theory that our backend is structurally blind to CopyMem-II.
It is not: `paper_trace.c` hooks NtWriteVirtualMemory at syscall entry and return,
emits a `write` carrying `target_pid` and target-directory physical spans, and
auto-monitors the target. A cross-process certification attempt on the current
backend proved `remote_write_proved`, `shared_alias_proved` and
`file_to_execution_proved` all true.

armadillo therefore cannot be typed until the protection tool actually produces
protected output. That is upstream of the tracer; no oracle or backend change
addresses it.

## 14. `NtReadFile`'s Length is read as 64-bit and then rejected for being too large

`NtReadFile`'s seventh parameter is `ULONG Length` — 32 bits. The hook declares
`uint64_t length` (`paper_trace.c:1546`) and captures it with
`read_u64(rsp + 0x38, &length)` (`:1595`), so the upper half of the eight-byte
stack slot — unrelated data, not part of the parameter — becomes part of the
value. The result then fails `length > UINT32_MAX` (`:1614`) and the read is
rejected.

That is the whole of `file_io_pointer_failures: 6`, and why `disk_drop()`'s
required `file_read` event is missing, and therefore why full cross-process
certification fails. `read_u32` already exists at `:486`.

Found by adversarial review, which also traced the fixture's control flow through
the successful read branch into the `WriteFile` block and confirmed the four
recorded writes total 258,859 bytes — exactly the fixture executable's size. So the
reads *happen*; only their capture fails.

Fixing it needs a plugin rebuild and a fourth re-certification. Note the counter
still merges two branches (bad pointers, oversized length) and emits neither the
rejected values nor any register state, so even now the summary cannot prove which
fired. Confirm with a diagnostic run on the unchanged plugin — it is unstripped and
carries debug info — before rebuilding. Two fixes here have already been aimed at
conditions that never fired.

## 15. hxor's hollowed child never reaches the payload

This is why hxor_packer cannot be typed, and it is **not** the certification gate
and **not** the `role: system` filter.

Its classification is `layers: 1`, zero transitions, `cross_process_activity: true`.
`classifier.py:117` returns `UNRESOLVED_NO_UNPACKING` at `layers == 1` regardless of
certification, so clearing the cross-process gate moves it from
`UNRESOLVED_UNCERTIFIED_CROSS_PROCESS` to `UNRESOLVED_NO_UNPACKING` — a different
unresolved verdict, not a Type. (An earlier claim in this work that tiering the
certification would unblock hxor was wrong.)

The trace shows the hollowing succeeding up to the write and then stopping:

| process | reason | exec events |
|---|---|---|
| 2972 | root_marker (the stub) | 7,347 own code + 473,443 system |
| 3264 | remote_write_target | 450,795 — **all** system |
| 3284 | job_descendant | 1,243,198 — all system |

Remote writes from 2972 into 3264: `0x400000` size 16384 (the payload PE image),
`0x0b0000` size 4544, `0x3fa2d8` size 8 (a PEB ImageBaseAddress patch), `0x3fb1e8`
size 4.

**Child 3264 executed zero blocks in `0x400000-0x404000`.** Its 450,795 events are
entirely at `0x077c00000` (WOW64 32-bit ntdll, 326,011) and `0x7ffa71700000`
(native 64-bit ntdll, 110,327), and its last executed address is in native ntdll.

So the payload was written and the child then ran 450k basic blocks inside the
loader without ever reaching it. Note the `role: system` filter is not what hides
this: after `NtUnmapViewOfSection` and `VirtualAllocEx` the region at `0x400000`
has no backing file, so execution there could not be system-role — there is simply
nothing there to filter.

That makes "no unpacking observed" plausibly a CORRECT empirical result for this
sample rather than a detector gap. The open question is whether the child stalls
because of something in our environment (the launcher's job object with no
breakaway, icount timing) or because of a defect in hxor itself — a 32-bit stub on
64-bit Windows must drive the hollowed thread through
`Wow64SetThreadContext`, not `SetThreadContext`, and using the wrong one would
leave the resumed thread in the loader exactly as observed. Under review.

Until that is settled, hxor should not be recorded as a methodology limit: the
evidence currently favours the payload genuinely not executing.


## Defects found 2026-09-10/11

### RESOLVED — `NtWriteFile` Length read as 64-bit (ULONG bug)
`file_io_return` read the `Length` argument with `read_u64` into a `uint64_t`,
pulling adjacent stack data into the high dword. Fixed to `read_u32` then widen.
Verified against the fixture: 9 file_io events, 0 failures, and a 23-byte `printf`
recorded byte-exactly. **Implicates any prior run whose disk-channel evidence
mattered**; single-process and cross-process evidence is unaffected.

### RESOLVED — the traced sample had no standard handles
`CreateProcessA` was called with `bInheritHandles=FALSE` and no
`STARTF_USESTDHANDLES`, so every sample ran with no stdin/stdout/stderr. A sample
that prints a diagnostic and exits looked identical to one that crashed. Now the
sample inherits a handle to `C:\Panda\sample_stdout.txt`.

### RESOLVED — root exit ended observation and killed surviving children
The launcher treated root exit as all-work-done. A hollowing packer calls
`ResumeThread` and returns immediately, so the stop marker was emitted (tracing
off) and `KILL_ON_JOB_CLOSE` then killed the payload. Root exit now only ARMS
completion; the idle window decides.

### RESOLVED — idle-window override could only LENGTHEN
`read_idle_milliseconds()` clamped the validation-only override to
`>= PACKER_IDLE_MILLISECONDS`, so it could not be shortened. Under icount a
120 guest-second window costs 6-10 h of host time and no host timeout ever
reached the fixture's stop marker. Clamp is now `[1 s, 30 min]`.

### RESOLVED — memory-callback ring overflow silently dropped writes
`qemu_plugin_mem_buffer_new(65536)` overflowed 3 times on a `shift=0` fixture run,
dropping memory-write batches. **A W→X oracle that loses writes under-reports
layers.** The fixture validator already demanded
`memory_buffer_overflows == 0` and caught it; the buffer is now 1,048,576 entries
with a `mem_buffer=N` plugin argument. Certifications before this fix were at
`shift=2`, where the counter read 0.

### RESOLVED — validator attested binaries but not tracing parameters
`validate_fixture_trace.py` emitted only binary hashes, so `icount_shift` was
absent from the stamp and the promotion gate rejected every otherwise-valid
certification. It now takes `--meta` and attests the run's tracing parameters.

### RESOLVED — non-default profiles were checked against the default stamp
`run_condition_matrix.py` passed no `--validation-stamp`, so profile runs failed
on `backend_identity_mismatches`. It now resolves
`profiles/<profile>.validation.json`.

### NEW CAPABILITY — file I/O payload logging
`paper_trace.c` records `payload_hex` on `file_read`/`file_write` when started with
`file_io_payload=N` (capped 4096, default off). The oracle previously recorded that
a program wrote N bytes but never what, so a sample's own diagnostics were
invisible. This is what recovered hxor's `offset: 532` measurement. Off by default,
so traces are unchanged unless requested.

### RESOLVED — certifications burned the full host timeout
The guest's `shutdown.exe` never completes under instrumentation, so every
certification waited out its host timeout (1.5-2.5 h) after the trace was already
complete at the stop marker. `run_trace.py` now quits 180 s after the stop marker
is seen and the trace goes quiet. A `shift=0` full certification fell from ~5 h
(timing out) to 4,915 s with `host_timed_out: False`.

### KNOWN — an instrument that perturbed what it measured
A timing probe added to `guest_launcher.c` ran its own `Sleep(500)` before every
sample. It produced nothing, because the launcher is not a monitored process and
its writes never reach the trace. Removed. Lesson: a probe belongs in a monitored
process, or it is pure perturbation.
