# Benign packer relabel, November 2026

All conditions re-traced on the certified backend (det QEMU, plugin 9b51dab0, snap_redist guest with VC++/DirectX runtimes, 100M sample / 20e9 guest bound) and classified with the corrected paper rule (commit 27c9a51).

Conditions: 118. Labels: TYPE_0 1, TYPE_I 79, TYPE_II 10, TYPE_III 4, TYPE_IV 14, TYPE_V-F 1, TYPE_VI-F 3, none 6.

## Label changes against the previous committed labels (16)

| Condition | Previous | Now | Status |
|---|---|---|---|
| acprotect_std_Standard__installer | TYPE_I | TYPE_IV | empirical_exact_trace_consensus |
| amber_v2.0_2.0 | TYPE_IV | TYPE_I | empirical_exact_trace_consensus |
| amber_v3.0_3.0 | — | TYPE_II | empirical_exact_trace_consensus |
| amber_v3.1_3.1 | — | TYPE_II | empirical_exact_trace_consensus |
| asm_guard_2.9.4 | TYPE_VI-F | TYPE_IV | empirical_exact_trace_consensus |
| enigma_protector_v7.80_7.80_build_20250205 | TYPE_IV | TYPE_II | empirical_exact_trace_consensus |
| jdpack_v1.00_1.00 | TYPE_III | TYPE_I | empirical_exact_trace_consensus |
| obsidium_v1.5.2_1.5.2.11 | — | TYPE_IV | empirical_exact_trace_consensus |
| pelock_v2.40_2.40 | TYPE_VI-F | TYPE_IV | empirical_exact_trace_consensus |
| petite_v2.4_2.4 | TYPE_III | TYPE_IV | empirical_exact_trace_consensus |
| pezor_3.3.0 | — | TYPE_I | empirical_exact_trace_consensus |
| telock_v0.98_0.98 | — | TYPE_IV | empirical_exact_trace_consensus |
| winupack_0.39 | TYPE_V-F | TYPE_III | empirical_exact_trace_consensus |
| yoda_protector_v1.01.2_1.01.2 | TYPE_IV | TYPE_I | empirical_exact_trace_consensus |
| yoda_protector_v1.03.3_1.03.3 | TYPE_IV | TYPE_VI-F | empirical_exact_trace_consensus |
| zprotect_1.4.2.0 | TYPE_VI-F | TYPE_IV | empirical_exact_trace_consensus |

## VM arm for unresolved conditions (3)

| Condition | VM-arm outcome | VM-arm Type | Evasion suspected |
|---|---|---|---|
| astral_pe_1.6.0.0 | — | — | False |
| kkrunchy_v0.23a2_0.23_alpha_2 | — | — | False |
| molebox_4.6000 | — | — | False |
