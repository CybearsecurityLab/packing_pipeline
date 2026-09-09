# Per-packer run parameters

Hand-written. Records which packers need non-default tracing parameters, what the
default does to them, and the evidence for each value.

**A packer that reports `UNRESOLVED_NO_UNPACKING_OBSERVED` on the defaults has not
necessarily resisted analysis.** Every packer in the table below produced that
verdict — marked eligible and complete — under at least one default, and typed once
the parameter was corrected. Check `paper_termination_reason` and
`host_idle_seconds` in `meta.json` before concluding anything about a packer.

## The four independent limits

They are separate mechanisms and are often confused:

| limit | set by | bounds | symptom when it binds |
|---|---|---|---|
| `LABEL_HOST_IDLE` | env → `--host-idle-seconds` | HOST seconds with no newly-serialised exec/write record | `two_minutes_idle_host_observed`, reported as a **normal completion** |
| `LABEL_HOST_TIMEOUT` | env → `--host-timeout` | total HOST seconds | `maximum_timeout_host`, ineligible |
| guest timeout | **baked into the image** by `stage_sample.sh <sample> <image> [timeout]`, default **300** | GUEST seconds | `maximum_30_minute_timeout`, ineligible |
| `LABEL_ICOUNT_SHIFT` | env → `--icount-shift` | virtual ns per instruction | no timeout; changes what the guest's own clock reads |

The guest timeout is the easiest to miss: it is written into the SYSTEM hive at
staging time, not passed at run time, so re-staging is required to change it.

It binds on packers that **wait**, not packers that **compute**. With
`icount sleep=on` the guest clock advances at real speed while the vCPU idles, so a
sleeping sample burns guest seconds while an executing one does not. telock's
payload B hit it at 2,598,959 executed blocks; obsidium reached 22,178,578 blocks
under the same 300s without coming close.

## Packers needing non-default parameters

| packer | parameter | default | needed | evidence |
|---|---|---|---|---|
| **telock 0.98** | `LABEL_HOST_IDLE` | 120 | **900** | Every certified rep stopped within a few hundred blocks of a fixed instruction (1291552 / 1291510 / 1291806 / 1291396 and 1117661 / 1118065 / 1118084) and reported "no unpacking observed", eligible and complete. It pauses deterministically and the 120s boundary cut it off mid-pause. |
| **telock 0.98** | guest timeout | 300 | **3600** | Payload B reached 2598959 blocks and 15 layers, then `maximum_30_minute_timeout`. Payload A finishes inside 300s; B is a slower binary. |
| **hyperion 2.3.1** | `LABEL_HOST_TIMEOUT` | 1200 | **45000** | Its stub brute-forces its own AES key before decrypting anything: `keyspace_loop` in `Src/Payloads/Aes/32/decryptexecutable.asm`, keyspace `key_space^key_length` = 4^6 = 4096. Adversarial review recovered this sample's key offline at index 452, i.e. **trial 453**, verified by checking every earlier candidate fails and that the plaintext re-encrypts to the ciphertext. At the measured throughput of 16 trials in 1200s that is ~34000s. 18000s would reach roughly trial 240 and fail. |
| **hxor_packer 0.1** | `LABEL_ICOUNT_SHIFT` | 2 | **0** | `runtimeDelay()` allows 550ms for a `Sleep(500)` measured with `GetTickCount`. Overshoot scales with virtual-ns per instruction. Mapping executed blocks onto the sample's symbols: at shift=2 `0x401afa` executes (detected, bails); at shift=0 `0x401b05` executes (passes) and `unpackFiles`/`LoadEXE` are entered. |
| **hxor_packer 0.1** | `LABEL_HOST_IDLE` | 120 | **900** | At shift=0 alone the run is truncated mid-`Sleep(500)` before the comparison is ever reached — neither branch appears in the trace. Both parameters are necessary; neither is sufficient. |
| **alushpacker 1.0.0** | `LABEL_HOST_IDLE` | 120 | **900** | Ran with the default and ended on the idle boundary at 58k–165k blocks having mapped its payload but not executed it. |
| **armadillo 252b2** | `LABEL_HOST_IDLE` | 120 | **900** | 11.4M executed blocks per rep at idle=900. |
| **obsidium 1.5.2.11** | `LABEL_HOST_IDLE` | 120 | **900** | 22.2M executed blocks per rep. |

## Settings that produced the current labels

| condition | idle | host timeout | guest timeout | icount shift | result |
|---|---:|---:|---:|---:|---|
| alushpacker 1.0.0 | 900 | 5400 | 300 | 2 | **TYPE_I**, 6/6 exact consensus |
| telock 0.98 | 900 | 9000 | 300 / 3600 | 2 | **TYPE_V-F**, 15 layers |
| armadillo 252b2 | 900 | 9000 | 300 | 2 | TYPE_IV (payload A) |
| obsidium 1.5.2.11 | 900 | 9000 | 300 | 2 | TYPE_VI-F (payload A) |
| hyperion 2.3.1 | 900 | 45000 | 3600 | 2 | running |
| hyperion 1.2 | 900 | 45000 | 3600 | 2 | running |

## Non-timeout environment fixes that were also required

Neither is a parameter, but both produced verdicts indistinguishable from a broken
packer:

- **VC++ redistributable** absent from the guest. Any MSVC-built stub importing
  `VCRUNTIME140.dll` failed import resolution before its entry point:
  `exec_events=0`, `no_execution_launch_failed`. alushpacker went from 0 to
  58k–165k blocks once installed. See `ops/qemu/install_guest_vcredist.sh`.
- **No standard handles.** `STARTUPINFO` was zeroed with no `STARTF_USESTDHANDLES`
  and `bInheritHandles=FALSE`, so every sample ran with no stdin/stdout/stderr.
  alushpacker mapped its payload and then hung in a CRT print, never reaching its
  payload entry. With real handles it types TYPE_I.

## Not pinned, deliberately

`host_timeout` and `host_idle_seconds` are NOT part of the backend identity. They
bound how long we watch, not how the guest behaves, and truncation is already
reported through `paper_termination_reason` and `bounded_observation`.
`icount_shift`, `icount_sleep`, `cpu_model` and `guest_smp` ARE pinned — they change
what the guest experiences, and hxor is the proof.
