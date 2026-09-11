# hXOR timing, Xen observability, and published unpacking evidence

## RESOLVED (2026-09-11): hxor_packer 0.1 is TYPE_I

`hxor_packer 0.1` gates every unpacking path on an execution-delay check
(`unpacker/src/antiDefense.cpp:runtimeDelay`, `unpacker/main.cpp:11`):

```c
count = GetTickCount(); Sleep(500); count2 = GetTickCount();
if ((count2 - count) > 550) { detected = 1; return 1; }   /* skip unpackFiles */
```

The measured delta was recovered from guest memory by logging `NtWriteFile`
payloads (`paper_trace.c`, plugin arg `file_io_payload=N`), which prints the
sample's own diagnostic line. Measured values:

| icount configuration | offset (ms) | gate |
|---|---|---|
| shift=2, sleep=on  | 578, 672, 734 | detected |
| shift=1, sleep=off | 593 | detected |
| shift=1, sleep=on  | 609 | detected |
| shift=0, sleep=off, smp=1 | 609 | detected |
| **shift=0, sleep=off, smp=2** | **515, 532, 547, 562, 578, 594, 609, 656** | **clears at ~25%** |

At `shift=0, sleep=off` the distribution straddles the sample's own 550 ms
threshold with roughly 140 ms of spread. Runs below 550 unpack; runs above do not.
This is a property of the sample's check meeting our floor, not a harness defect:
under icount, virtual time advances with retired instructions, so plugin overhead
adds none, and `shift=0` (1 ns/instruction) is the fastest machine icount can model.

**Label.** Six reps under the certified `slow-timer` profile produced one
observation of unpacking (offset 532) and five refusals. Per Ugarte Sec V-C the
non-observing reps abstain — they are failed measurements, not competing labels —
so `packer-types finalize` emitted `TYPE_I` with status
`empirical_max_observed_complexity`.

**Observed topology in the passing rep** (`hxor_child_exec.py`):

```
pid 2884  root_marker            the stub
pid 3264  remote_write_target    the hollowed child
pid 3280  job_descendant         a child the payload itself spawned
cross-process write to a page the TARGET later executes: phys=0xe5b78000 va=0x400000
```

That is `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` → `VirtualAllocEx(RWX)`
→ `WriteProcessMemory(ImageBase)` → `SetThreadContext` → `ResumeThread`
(`unpacker/src/loadEXE.cpp`), observed as a write→execute transition on a guest
**physical** page.

**Open question for review:** the classifier returned `TYPE_I` for a structurally
cross-process RunPE hollow (`processes=2`, `layers=2`, `forward_transitions=1`).
Whether a hollow belongs in Type I is a question about how the classifier weighs
the `cross_process_memory` dimension, not about this run.

**Anti-VM transparency is NOT required for hxor.** With the timing gate cleared,
`InSandboxie()` and `InVMware()` both pass on the plain `qemu64` profile — the
sample prints `Nothing was detected!`. `--transparent` changes nothing here.

## Operational requirements

- `slow-timer` profile = `icount shift=0, sleep=off, cpu qemu64, smp 2`, full mode.
- `--host-idle-seconds >= 1800` (we use 2700). At `shift=0` a guest `Sleep(500)`
  needs ~500M retired instructions and produces **no monitored execution**, so a
  600 s idle window kills the run inside the sleep (exec ~9-10k, no `file_write`).
- Expect ~25% of reps to clear the gate. Budget reps accordingly; one suffices.

---

## Prior research notes (superseded where they conflict with the section above)

The strongest path within the existing evidence requirements is to retain QEMU TCG and determine whether the excess interval occurs before timer expiry, during interrupt delivery, or after the thread becomes ready. A controlled launcher-priority experiment and a verified guest timer-resolution experiment are reasonable next interventions. Neither has a documented guarantee of moving this particular sample below the threshold. Xen with sparse introspection is a realistic way to test whether the original executable unpacks at ordinary execution speed, but stock DRAKVUF does not provide the current oracle's every-write trace.

The attempts log establishes that the sample reaches `runtimeDelay`, measures `GetTickCount(); Sleep(500); GetTickCount()`, and rejects a delta greater than 550 ms. The recovered deltas are 672 and 578 ms with shift=2/sleep=on, and 593 ms with shift=1/sleep=off. These are treated as measured facts. The older shift=0 success claims in repository documentation are superseded by that log. Changing icount shift, disabling icount sleep, reducing SMP to one, changing arguments, and patching the executable are not proposed as solutions.

The rankings below are engineering judgments based on the cited mechanisms, not measured success probabilities. No new sample execution or backend certification was performed for this report.

**What the numbers reveal**

| Measured delta | Nearby multiple of 15.625 ms | Extra ticks beyond 500 ms | Approximate ticks to remove to pass |
|---|---:|---:|---:|
| 578 ms | 37 × 15.625 = 578.125 ms | 5 | 2 |
| 593 ms | 38 × 15.625 = 593.750 ms | 6 | 3 |
| 672 ms | 43 × 15.625 = 671.875 ms | 11 | 8 |

Endpoint truncation can make the difference of integer millisecond readings differ from the rounded duration. Thus the table is consistent with a 64 Hz tick lattice; it is not proof of the actual clock source. At that lattice, 35 ticks are 546.875 ms and 36 ticks are 562.5 ms. The fastest measured run is only 28 ms over the gate, but needs approximately 31.25 ms removed to reach the next passing lattice point.

Microsoft documents a typical 10–16 ms resolution for `GetTickCount`. That quantization can explain the lattice, but ordinary endpoint quantization cannot by itself explain five to eleven additional ticks. A substantial interval is being spent waiting, handling interrupts, scheduling, or doing work between the readings. A few observations do not establish a lower tail below 550 ms, and do not separate those mechanisms. [Microsoft, GetTickCount][gtc]

**Q1: timer resolution, delivery, and a clock that looks native**

`Sleep` expiration makes a thread ready; it does not guarantee immediate execution. The second reading therefore measures more than the requested wait. In particular, delay between the first reading and entry to the kernel wait, and between becoming ready and the second reading, both count. Microsoft explicitly documents this scheduling distinction and recommends timer-resolution requests to improve wait accuracy. [Microsoft, Sleep][sleep]

`GetTickCount` normally reads Windows-maintained shared time data. QEMU supplies emulated counters and timer interrupts; the guest kernel maintains `KUSER_SHARED_DATA`. Its documented fields include `TickCount`, `TickCountMultiplier`, and `InterruptTime`. The exact implementation used by this WOW64 sample should be disassembled and pinned rather than inferred from a generic Windows version. A syscall-only hook need not observe a shared-page read. [Microsoft, KUSER_SHARED_DATA][shared]; [Check Point, Anti-Debug: Timing][checkpoint]

The log's practical conclusion about plugin overhead is useful but its strongest wording needs qualification. Fixed icount does not charge host callback execution as guest instructions, and QEMU explicitly distinguishes icount from cycle-accurate simulation. However, an unrecorded run still has device activity, scheduling and asynchronous inputs. Identical hashes do not prove identical event order. Consequently, the claim that an unplugged plugin *must* yield exactly the same delta is stronger than the documentation supports. The supported conclusion is that callback cost is not directly added to a fixed-icount instruction clock. [QEMU, TCG Instruction Counting][icount]; [QEMU, Execution Record/Replay][replay]

The following diagnostic design separates the plausible causes without editing the sample. These are proposed measurements, not reported experimental results.

| Candidate cause | Measurement that distinguishes it | Interpretation |
|---|---|---|
| Shared tick quantization | Pair shared-page tick reads with QPC or precise interrupt-time reads in a companion fixture | Fine time advances normally while tick readings remain stepped. |
| Delay before the wait is armed | Timestamp the first sample tick read and entry to `NtDelayExecution` | The excess begins before Windows starts waiting. |
| Timer rounding or coalescing | Capture requested interval, effective due time, programmed timer comparator, and timer-service time | A later programmed deadline differs from late delivery of an already-due interrupt. |
| DPC/ISR latency | Correlate timer interrupt entry and return with DPC/ISR durations | The clock interrupt arrives, but high-priority kernel work delays wakeup or scheduling. |
| Ready-thread scheduling delay | Record the target thread's ready event and context-switch-in | The wait expired promptly but the target did not get CPU time. |
| QEMU timer delivery or interrupt acceptance | Log scheduled device deadline, callback time, pending interrupt, and guest ISR entry in QEMU virtual time | Distinguishes late callback from pending interrupts blocked by guest interrupt state or priority. |
| Clock disagreement | Compare QEMU virtual elapsed time, raw guest counter readings, and shared-data advancement | Shared time racing ahead of the underlying virtual interval indicates a different problem from slow scheduling. |

Windows Performance Recorder/Analyzer can supply context-switch and DPC/ISR evidence. Microsoft's CPU analysis documentation explains why ordinary sampled CPU traces alone are inadequate for short interrupts. Capture the narrow interval and correlate the actual thread, rather than substituting system-wide utilization for wakeup latency. Under strict backend-only diagnostics, collect equivalent kernel events through the existing external tracer. [Microsoft, CPU Analysis][wpa]

A companion timer probe should test `Sleep(500)` repeatedly using the same architecture, launch conditions and process priority as the sample. Record `GetTickCount`, `QueryPerformanceCounter`, and available precise interrupt-time APIs around each wait. Compare the probe with and without its own resolution request, then compare an otherwise identical probe launched by a separate process holding that request. This tests both whether resolution helps and whether the effect crosses the process boundary. Buffer diagnostic results and recover them through the existing write-payload channel. The probe is diagnostic; only execution of the unchanged corpus sample can produce its label.

QPC is a comparison clock, not independent ground truth under emulation: it can share an underlying virtual time source. Precise interrupt-time APIs also have Windows-version and implementation dependencies. Microsoft documents which interrupt-time APIs are affected by timer resolution. [Microsoft, Interrupt Time][interrupttime]

**Which guest timer changes are worth testing**

1. **Launcher-controlled priority, if ready latency is present.** Create the original target suspended, assign `ABOVE_NORMAL_PRIORITY_CLASS` or, in a separate profile, `HIGH_PRIORITY_CLASS`, then resume it under full tracing. This is an environment/launcher change; it does not require inserting a call into the target. Microsoft documents that high-priority-class threads preempt ordinary-priority threads. The hypothesis is specifically that the current run loses time after becoming ready. Priority cannot fix a late timer interrupt or time spent at DPC/ISR level. Pin the policy in the launcher/profile identity. [Microsoft, SetPriorityClass][priority]

2. **A timer-resolution request whose effect on the unmodified child is demonstrated.** On Windows before version 2004, `timeBeginPeriod` requests affect the global setting. Starting with Windows 10 2004, a process that does not make the request is not guaranteed higher resolution. Therefore adding the call to the launcher is not sufficient evidence that hXOR benefits. A driver-level request or an OS-policy experiment is a separate environment change requiring its own validation, not an assumed substitute. [Microsoft, timeBeginPeriod][period]

3. **A quieter, reproducible guest starting state.** If competing services account for the ready interval or interrupt load, establish a snapshot with that identified activity absent and keep it fixed. This preserves tracing but changes the experimental environment. Avoid guessing which service matters from the total host slowdown. Treat snapshot, guest build, power/timer policy and launch state as parts of the backend contract.

4. **One timer-device or dynamic-tick change at a time, guided by the captured timer source.** `disabledynamictick`, `useplatformtick`, and `useplatformclock` are different controls. Microsoft's BCD documentation identifies them as debugging controls; `useplatformclock` concerns the performance-counter source, and is not a command to make ordinary waits precise. Exposing HPET does not prove Windows uses it for the wait. Removing HPET can cause a different HAL choice, which must be observed rather than assumed. [Microsoft, BCDEdit /set][bcd]

Bruce Dawson's original Windows 10 experiments provide an especially useful warning: a global resolution query and observed interrupt frequency can change while another process's `Sleep` behavior remains close to its old cadence. That is why reading `NtQueryTimerResolution` or ClockRes alone is not a sufficient success criterion. Increasing interrupt frequency can also increase work in a TCG guest, so the net direction is not guaranteed. [Dawson, Windows Timer Resolution: The Great Rule Change][dawson]

There is also a concrete local limit on the LAPIC-deadline suggestion. The available QEMU source tree identifies itself as 11.0.90. In `target/i386/cpu.c`, the TCG system-emulation feature mask excludes `CPUID_EXT_TSC_DEADLINE_TIMER`; the code allows it only as a kernel-only feature for user-mode emulation. Consequently, adding a newer CPU name or a CPUID bit is not an implementation of deadline-timer support for this system backend. The source tree's correspondence to the pinned executable still needs verification before using this as a binary-level assertion. [Local CPU feature mask](../empirical_results/qemu_runtime/qemu-src/target/i386/cpu.c)

**What QEMU mailing-list evidence actually establishes**

Paolo Bonzini's March 2017 patch, “icount: process QEMU_CLOCK_VIRTUAL timers in vCPU thread,” describes an expensive vCPU/I/O-thread rendezvous and a latent timing race. The change runs virtual timers in the vCPU thread. This is a relevant precedent for measuring callback and interrupt delivery, but it is an old fix, not a new switch to apply blindly. The local source already calls `qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)` from the icount path. [QEMU development discussion][bonzini]; [local icount implementation](../empirical_results/qemu_runtime/qemu-src/accel/tcg/tcg-accel-ops-icount.c)

Ulrich Obergfell's May 2011 HPET driftfix proposal explicitly distinguishes delayed callbacks from interrupt coalescing and tracks unaccounted clock periods. It proposes reinjecting additional interrupts over later intervals. This is evidence that these failure modes exist and can be measured separately. It is not evidence that the proposal is present in this backend or that reinjection makes hXOR's delta smaller. [QEMU HPET driftfix proposal][hpetpatch]

QEMU's documented `-rtc ... driftfix=slew` addresses missed RTC interrupts and Windows ACPI-HAL drift. It does not generally control every Windows timer. The launcher already uses `clock=vm`, so that is not an untried fix. Blind catch-up is especially questionable when the symptom is a measured interval that is too large; determine which clock is late relative to which other clock first. [QEMU command-line documentation source][rtc]

**Published ways to hide instrumentation time**

Ether (CCS 2008, Xen) describes controlling TSC, APIC/PIT timers and periodic interrupts using a privileged logical time model that removes analyzer overhead. This is the historical comparison most directly relevant to a backend that must control several clock sources. It is a design precedent, not evidence that ordinary Xen automatically supplies the same behavior. [Dinaburg et al., Ether, §4.5][ether]

SPIDER (ACSAC 2013, KVM) measures time spent in the hypervisor and approximates VM-entry/exit cost, then uses the VMCS TSC offset to hide it. Its evaluation also makes the cost of breakpoint hits central to overhead. This is a concrete TSC compensation implementation; it does not establish that Windows shared tick data and sleep deadlines are automatically corrected along with TSC. [Deng et al., SPIDER, §4.6 and §6][spider]

BluePill (TIFS 2020, Intel Pin) accumulates requested waits and presents coordinated time-query results, explicitly discussing combinations of `RDTSC` and `GetTickCount`. Its strategy can conceal DBI overhead, but the authors do not claim generality against external or indirect clocks. Porting that approach into a system backend would mean declaring an explicit environment-time substitution policy. It is not ordinary observational tracing. [D'Elia et al., On the Dissection of Evasive Malware, §IV-A][bluepill]

nEther (EuroSec 2011) is a necessary qualification to Ether's claims: the authors found that the released implementation's simplistic fake-TSC behavior differed from the proposed overhead accounting and could be detected. A design paper, released code and a certified backend must be assessed separately. [Pék et al., nEther, §4.3.1][nether]

For this corpus, a deterministic backend time model can in principle retain every write and execution event. However, its admission requires a declared clock contract and recertification: hashes alone establish identity, not that substituted time is an acceptable environment. Uniformly slowing all clocks while allowing Windows to express `Sleep(500)` in those same units does not simply turn that wait into 400 measured milliseconds. Subtracting a fixed offset from both tick readings also cancels. Updating only TSC misses a direct shared-tick read; freezing all guest clocks throughout the sleep can prevent expiration. A sample-address-specific return-value clamp would merely bake the desired gate outcome into the environment and would not demonstrate native timing. None of those shortcuts is recommended.

**Q2: what Xen and DRAKVUF preserve**

Xen HVM runs ordinary guest instructions on hardware. DRAKVUF uses selected traps and altp2m views rather than translating and instrumenting every guest basic block. The altp2m design permits per-vCPU views and shadow mappings for breakpoints, reducing races that otherwise arise when temporarily restoring permissions or instructions. This protects breakpoint visibility; it does not remove the time spent handling events. [DRAKVUF, Xen altp2m][altp2m]

The original DRAKVUF paper explicitly puts time skew outside its scope and refers to Ether for TSC countermeasures. Current sandbox documentation describes `delaymon` as observing `NtDelayExecution`, not as a guarantee of sleep/time normalization, and warns that enabling many plugins affects performance. I found no documented stock DRAKVUF guarantee that `RDTSC` and Windows `GetTickCount` checks are neutralized together. [Lengyel et al., DRAKVUF, §2][drakpaper]; [DRAKVUF Sandbox basic usage][drakusage]

“Who Watches the Watcher?” (DFRWS 2018), coauthored by Lengyel, supplies empirical counterevidence to blanket introspection transparency: it demonstrates detecting atypical hypervisor activity using timing, thread racing and cache effects. That does not predict failure of hXOR's comparatively loose 50 ms allowance. It establishes that agentless tracing and invisibility to time measurements are different claims. [Tuzel et al., Who Watches the Watcher?][watcher]

Xen also has relevant documented time controls. In the inspected 4.19 documentation, default TSC mode executes reads natively when monotonicity can be guaranteed. The default virtual-timer policy is `no_delay_for_missed_ticks`, which keeps guest time tracking wall time while delivering missed interrupts. `delay_for_missed_ticks` instead advances a vCPU's time stepwise with missed interrupt delivery. These policies are useful comparison cases, but are not deterministic replay and do not promise sub-550 ms waits. Xen's `viridian` synthetic timers can give Windows ticks consistent with an enlightened time source; this is a performance/clock-consistency mechanism rather than concealment of introspection. [Xen xl.cfg, Guest Virtual Time Controls and HVM enlightenments][xenconfig]

**The write-to-execute evidence gap**

Stock `codemon` discovers pages through `MmAccessFault`, arranges execution traps, then alternates execution and write traps to avoid dumping an unchanged page repeatedly. Its write-fault logging includes GFN, CR3 and physical-address information. It therefore has real physical-frame information, but it does not log each store between the first write and subsequent execution. Its page discovery and process filtering also need auditing for the first remote-write-to-execute transition in a newly hollowed child. [DRAKVUF codemon source][codemon]

LibVMI memory events expose guest frame number, page offset, access type and, when valid, guest virtual address. The event is not itself a complete store record with byte length and data. Such a record requires additional decoding and observation. The identity relevant to guest aliasing is the guest physical frame, not the host machine frame backing an altp2m shadow. [LibVMI events.h][events]

| Xen observation method | What it can establish | What the current oracle still lacks |
|---|---|---|
| API/syscall traps and memory dumps | Process creation, remote-write requests, resumed child, recovered payload | Complete stores, actual execution of each written byte, and frame lifetime/alias history |
| GFN-based alternating W/X traps | A monitored frame was written and later fetched for execution | Intermediate writes and writers; write lengths/values; byte overlap within the page |
| Intel PT plus versioned code images | Detailed control-flow reconstruction | A full data-write log and automatic physical identity for every memory access |
| Continuously armed per-write EPT traps plus step/emulation and X tracking | Potential route to detailed physical write and execute evidence | Substantial implementation, race handling and validation; near-native timing cannot be assumed |

Intel's libipt documentation describes execution-flow decoding using supplied memory images and address-space/context information. A control-flow trace cannot alone recover arbitrary store operands or all versions of self-modifying data. DRAKVUF Sandbox documents an experimental `ipt` plus `codemon` workflow, which improves execution evidence but does not fill the every-store gap. [Intel, libipt decoding guide][libipt]; [DRAKVUF Sandbox, Intel Processor Trace workflow, chapter 10][iptworkflow]

A replacement oracle must distinguish “some write somewhere in a 4 KiB page followed by execution elsewhere in that page” from overlapping written/executed bytes. It also needs successful-write evidence rather than an attempted fault, kernel copies into another process, shared mappings, copy-on-write, remapping, frame reuse, and concurrent vCPUs. A page-level transition can be useful positive evidence without being a drop-in equivalent of the present trace.

For every-write monitoring, removing write permission means intercepting each relevant access, allowing or emulating it, and restoring the trap. The trap cost is paid repeatedly. Per-vCPU views help control races, but do not remove the exit/handler cost or solve store decoding. REP/string operations, multi-page accesses and another vCPU writing during observation require explicit treatment. SPIDER's data-watchpoint design documents the permission-change/single-step/rearm sequence; its sparse-instrumentation performance measurements must not be extrapolated to every system-wide write. [SPIDER, §4.5][spider]

**Is moving this one sample realistic?**

Yes, as a diagnostic and payload-recovery path. Use a supported Intel VT-x/EPT host, a fixed Windows guest and profiles, and a minimal plugin set. First establish the original stdout delta and whether the gate passes. Then add remote-write and child-execution observation and remeasure with that exact configuration. Passing with monitoring absent or with a lighter configuration does not validate the final tracing configuration. DRAKVUF's documented hardware requirements make this a deployment project, not a QEMU command-line change. [DRAKVUF project documentation][drakhome]

For a certified label under the existing every-write contract, moving requires a new trace producer and certification, not just running `codemon`. Pin Xen, CPU/microcode assumptions, LibVMI, DRAKVUF/plugins, guest image and symbols, timer policy, topology and launch policy. Ordinary hardware execution will retain scheduler and external-event nondeterminism. If certification requires replay-equivalent execution, the inspected stock Xen/DRAKVUF workflow does not establish that property. If certification instead validates event fidelity across bounded variation, a new Xen backend may be admissible after that validation. This distinction follows from the stated corpus contract; no existing QEMU certificate transfers.

**Q3: published evidence for hXOR itself**

| Source | Concrete evidence | Environment and limitation |
|---|---|---|
| akuafif's original repository | Identifies the 2012 student project, Huffman/XOR packing, and execution from memory in a child | Describes implementation and normal usage; no certified analysis trace or timer profile. |
| Packing Box configuration | Includes hXOR and compression/encryption variants, invokes the packer via Wine, marks tool status `ok` | Establishes a packing recipe. It does not establish successful runtime unpacking under Wine or a sandbox. |
| SECUINFRA/Unprotect YARA rule | Identifies the Afif 2012 banner and anti-analysis strings; says the rule was validated across packing modes | Detection-rule validation, not execution of the unpack path. |
| Cyber-Detect's Gorille writeup | Reports recovering `hostname.exe` and Akira payloads from Hxor-packed files | Does not identify stub hash, gate outcome, or a bare-metal/VMware/Xen/QEMU/Pin trace; discusses internal extractors and dynamic capabilities separately. |
| Peltomaa's 2025 thesis | Uses Windows 10, VirtualBox and FLARE-VM for a YARA teaching environment; reproduces the hXOR rule in appendix 2 | A named analysis environment, but no evidence that the original hXOR stub passes its delay check there. |

These findings are supported respectively by the [original repository][hxor], [Packing Box configuration][packingbox], [Unprotect rule][yara], [Gorille writeup][gorille], and [Peltomaa thesis][thesis]. The Gorille article is a useful positive payload-recovery result. Its description of these analyses as cheaper than dynamic analysis prevents treating it as proof of native stub execution. The packing recipe's `status: ok` must likewise not be converted into an unpacking-success claim.

Searches for hXOR/hXOR-Packer, akuafif/Afif, unpacking, traces, datasets, evaluation, theses and the named execution environments did not identify a paper reporting this exact stub as either successfully unpacked or evading a specified sandbox. This is a bounded negative finding, not proof that no such publication exists. Dataset inclusion alone provides neither result. No source found documents a universal launch default that makes these student packers pass anti-analysis checks.

For the original hXOR implementation, the attempts log supplies the concrete conditions: pass the timing gate and then the Sandboxie/VMware checks. The project says its unpacker requires no runtime input. A quiet hardware-virtualized Windows environment without the specific checked artifacts is therefore a reasonable baseline experiment, but success and the later RunPE path remain observations to obtain. There is no published basis here for changing arguments or substituting a different build. [Original repository][hxor]

**Ranking the available paths**

| Practical order for this corpus | Option | Prospect of passing the timing gate | Observability and certification cost |
|---:|---|---|---|
| 1 | Measure ready latency; test launcher priority and an identified quieter guest state | Plausible if scheduling accounts for at least two ticks in the shortest run | Full tracing retained; changed launch/environment policy needs a new identity and validation. |
| 2 | Verify timer-resolution effect on the unchanged child, then test it | Conditional; potentially helpful, but granularity alone is insufficient to explain current excess | Full tracing retained; OS-build scope and request mechanism must be pinned. |
| 3 | Fix a measured QEMU timer-delivery defect or change the demonstrated timer path | Potentially strong if a concrete delay is found; speculative before measurement | Full tracing can remain; QEMU/device/profile changes require recertification. |
| 4 | Additional repetitions of an already certified configuration | Unknown; no passing observation or established passing tail yet | No event-channel loss or backend change; potentially high host cost. |
| 5 | Xen HVM with sparse DRAKVUF observation | Best practical expectation of ordinary-speed execution, conditional on host and trap load | Every-write evidence is lost; useful diagnostic, insufficient for the present oracle by itself. |
| 6 | Xen with a new continuous write-trapping oracle | Unknown once full observation is enabled | Potential fidelity, substantial engineering and race/decoding validation; no near-native guarantee. |
| Separate policy decision | Deterministic, coordinated virtual-time substitution in QEMU | Could make this simple gate pass by construction | Structural trace channels can remain, but clock semantics change; identity certification alone does not establish admissibility. |

Ranked only by likelihood of satisfying this single comparison, an explicitly designed synthetic time policy comes first by construction, followed by lightly monitored hardware virtualization. Neither is the least disruptive route to a valid label. Ranked by preservation of the current event contract, existing certified repetitions come first, followed by validated TCG environment/timer changes, then a newly engineered Xen oracle; stock sparse DRAKVUF loses the most of the required store evidence. There is insufficient evidence to give a probability or a firm ordering among the unmeasured timer and scheduling interventions.

**Maximum-observed aggregation and concrete next steps**

The local `empirical_types/finalize.py` implements a fallback named `empirical_max_observed_complexity`, with `PACKER_MAX_OBSERVED_MIN_PAYLOADS` defaulting to 1. Unresolved classifications do not compete with resolved observations. The fallback runs when exact consensus did not produce a label; it is not an unconditional maximum replacing an already successful consensus. Resolved observations must pass its completion/trace checks; bounded observations require explicit opt-in. This confirms the open angle in the log, subject to the independent certified-backend eligibility requirements. [Local finalizer](../empirical_types/finalize.py)

The immediate experimental sequence should be: capture the narrow timer/wakeup timeline with full tracing; use a companion fixture to verify resolution propagation and quantify ready latency; test the intervention supported by those observations; recertify the resulting identity; then rerun the original samples and let the labeller classify actual traces. If the TCG path remains unresolved, perform the small Xen timing experiment before investing in an every-write Xen implementation. Keep all passing and failing repetitions and their deltas; a lower-tail pass is positive evidence only when its trace qualifies.

**Sources**

1. Microsoft. [GetTickCount documentation][gtc].
2. Microsoft. [Sleep documentation][sleep].
3. Microsoft. [KUSER_SHARED_DATA documentation][shared].
4. Check Point Research. [Anti-Debug: Timing][checkpoint].
5. QEMU Project. [TCG Instruction Counting][icount]; [Execution Record/Replay][replay].
6. Microsoft. [CPU Analysis][wpa]; [Interrupt Time][interrupttime].
7. Microsoft. [SetPriorityClass][priority]; [timeBeginPeriod][period]; [BCDEdit /set][bcd].
8. Bruce Dawson. [Windows Timer Resolution: The Great Rule Change][dawson], 2020, with later updates.
9. Paolo Bonzini. [icount: process QEMU_CLOCK_VIRTUAL timers in vCPU thread][bonzini], March 2017.
10. Ulrich Obergfell. [HPET driftfix proposal][hpetpatch], May 2011.
11. QEMU Project. [RTC and icount option documentation source][rtc].
12. Artem Dinaburg et al. [Ether: Malware Analysis via Hardware Virtualization Extensions][ether], CCS 2008.
13. Zhui Deng et al. [SPIDER][spider], ACSAC 2013.
14. Daniele Cono D'Elia et al. [On the Dissection of Evasive Malware][bluepill], TIFS 2020.
15. Gábor Pék et al. [nEther][nether], EuroSec 2011.
16. Tamas K. Lengyel et al. [DRAKVUF paper][drakpaper], ACSAC 2014; full text hosted as a patent-proceeding exhibit.
17. DRAKVUF Project. [Xen altp2m][altp2m]; [project documentation][drakhome]; [codemon source][codemon].
18. CERT Polska. [DRAKVUF Sandbox basic usage][drakusage]; [Intel PT workflow][iptworkflow].
19. Tomasz Tuzel et al. [Who Watches the Watcher?][watcher], DFRWS 2018.
20. Xen Project. [xl.cfg 4.19 documentation][xenconfig].
21. LibVMI Project. [Memory-event interfaces][events].
22. Intel. [Decoding Intel Processor Trace using libipt][libipt].
23. akuafif. [hXOR-Packer repository][hxor], describing the 2012 project.
24. Packing Box. [Packer configuration][packingbox].
25. Marius Genheimer / SECUINFRA Falcon Team. [hXOR YARA rule via Unprotect][yara], January 2024.
26. Cyber-Detect. [Packers detection: A key challenge in analyzing and combating malware][gorille].
27. Petri Peltomaa. [Suitability of the YARA Tool as Part of a Malware Analysis Course][thesis], 2025.
28. Local source and supplied evidence: attempts log in the research request; `empirical_types/finalize.py`; `ops/qemu/run_trace.py`; QEMU source under `empirical_results/qemu_runtime/qemu-src`. Local source inspection does not attest the running binary's source correspondence.

[gtc]: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
[sleep]: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
[shared]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
[checkpoint]: https://anti-debug.checkpoint.com/techniques/timing.html
[icount]: https://www.qemu.org/docs/master/devel/tcg-icount.html
[replay]: https://www.qemu.org/docs/master/devel/replay.html
[wpa]: https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis
[interrupttime]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time
[priority]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass
[period]: https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod
[bcd]: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
[dawson]: https://randomascii.wordpress.com/2020/10/04/windows-timer-resolution-the-great-rule-change/
[bonzini]: https://lists.gnu.org/archive/html/qemu-devel/2017-03/msg00703.html
[hpetpatch]: https://www.mail-archive.com/qemu-devel%40nongnu.org/msg64717.html
[rtc]: https://qemu.googlesource.com/qemu/+/4fc3cdde40f977ee8deecf988eea7acfa373117a/qemu-options.hx
[ether]: https://ether.gtisc.gatech.edu/ether_ccs_2008.pdf
[spider]: https://www.cs.purdue.edu/homes/dxu/pubs/ACSAC13.pdf
[bluepill]: https://s2lab.cs.ucl.ac.uk/downloads/tifs20.pdf
[nether]: https://static.crysys.hu/v1/publications/files/PekBB11eurosec
[drakpaper]: https://ptacts.uspto.gov/ptacts/public-informations/petitions/1556015/download-documents?artifactId=LTb6Bu2xqrmeZRM-lfMp4xewZU7dFBzxsAV023_nccW-Fm_UiYe4Ies
[altp2m]: https://github.com/tklengyel/drakvuf/wiki/Xen-altp2m
[drakhome]: https://drakvuf.com/
[codemon]: https://raw.githubusercontent.com/tklengyel/drakvuf/main/src/plugins/codemon/codemon.cpp
[drakusage]: https://drakvuf-sandbox.readthedocs.io/en/stable/usage/basic_usage.html
[iptworkflow]: https://drakvuf-sandbox.readthedocs.io/_/downloads/en/latest/pdf/
[watcher]: https://www.researchgate.net/publication/345646485_Who_watches_the_watcher_Detecting_hypervisor_introspection_from_unprivileged_guests
[xenconfig]: https://xenbits.xen.org/docs/4.19-testing/man/xl.cfg.5.html
[events]: https://raw.githubusercontent.com/libvmi/libvmi/master/libvmi/events.h
[libipt]: https://github.com/intel/libipt/blob/master/doc/howto_libipt.md
[hxor]: https://github.com/akuafif/hXOR-Packer
[packingbox]: https://github.com/packing-box/docker-packing-box/blob/main/src/conf/packers.yml
[yara]: https://unprotect.it/detection-rule/detect-executables-packed-with-hxor-packer/
[gorille]: https://www.cyber-detect.com/en/packers-detection-a-key-challenge-in-analyzing-and-combating-malware/
[thesis]: https://www.theseus.fi/bitstream/handle/10024/901608/Peltomaa_Petri.pdf?isAllowed=y&sequence=2
