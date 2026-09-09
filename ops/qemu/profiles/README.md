# Certified backend profiles

A profile is a named tracing configuration plus the stamp attesting that the
backend passed the channel fixture *under that configuration*.

It exists because the identity used to pin only the binaries. Tracing parameters
were environment variables, invisible to certification, so two runs whose guests
behaved differently could both claim the same stamp.

hxor_packer is the case that forced this. It unpacks only at `icount shift=0`: at
shift=2 each instruction advances the guest clock by 4ns instead of 1ns, which
pushes its `Sleep(500)`/`GetTickCount` comparison past its own 550ms allowance, so
it takes the evasion path and never calls `unpackFiles`. A shift=0 result is a
different measurement from the shift=2 results the rest of the corpus carries, and
nothing recorded that.

## What is pinned

Binaries: `qemu_sha256`, `plugin_sha256`, `launcher_sha256`, `fixture_sha256`,
`ntdll_sha256`, `profile_header_sha256`, `kernel_profile_guid_age`.

Tracing parameters that change what the guest experiences: `icount_shift`,
`icount_sleep`, `cpu_model`, `guest_smp`.

NOT pinned: `host_timeout` and `host_idle_seconds`. They bound how long we watch,
not how the guest behaves. A short window can truncate a recording, but the
completion boundary already reports that (`paper_termination_reason`), and
`bounded_observation` already marks a Type as a lower bound.

## Using a profile

    LABEL_PROFILE=slow-timer uv run python ops/qemu/run_condition_matrix.py <cfg>

`run_trace.py` writes the full identity into each run's `meta.json` and lists any
`backend_identity_mismatches`. A run whose parameters differ from its stamp is
`paper_label_eligible: false` — it cannot borrow another configuration's
certification.

## Profiles

| name | icount | certification | for |
|---|---|---|---|
| `default` | shift=2, sleep=on | single_process | the 100 existing labels |
| `slow-timer` | **shift=0**, sleep=on | single_process | packers whose timing checks fire at shift=2 (hxor_packer) |
| `cross-process` | shift=2, sleep=on | **full** | process-hollowing packers (hxor_packer's RunPE) |

`cross-process` is NOT yet certified: the full fixture fails with
`file_io_pointer_failures: 6` and a missing `file_read` event. Until it passes,
hollowing packers correctly classify `UNRESOLVED_UNCERTIFIED_CROSS_PROCESS`.

hxor_packer needs `slow-timer` AND `cross-process` together — a fourth profile
once the cross-process fixture passes.
