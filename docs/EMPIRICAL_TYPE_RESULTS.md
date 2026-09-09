# Empirical Packer-Type Results — Complete Corpus

Every packer family+version in the NAS corpus, accounted for. Types are Ugarte et al. I–VI assigned **empirically** from real dynamic traces (see [AUTOMATIC_LABELING.md](AUTOMATIC_LABELING.md)). Generated from `manifest/empirical_types_*.yaml` — the final labels — so this document always matches the manifests rather than any one sweep. The `Rule` column records which labelling rule produced each Type, so the strongest evidence class stays distinguishable from the weaker ones.

Unlike [EMPIRICAL_TYPE_LABELS.md](EMPIRICAL_TYPE_LABELS.md), which lists only successful labels, this document also states **why** each unresolved condition is unresolved, so no condition is silently missing.

## Summary

- Corpus: **107** packer family+versions
- Empirically typed: **100**
- Unresolved: **5**

| Type | Conditions |
|---|---|
| **TYPE_0** | 1 |
| **TYPE_I** | 71 |
| **TYPE_II** | 7 |
| **TYPE_III** | 5 |
| **TYPE_IV** | 10 |
| **TYPE_V-F** | 1 |
| **TYPE_VI-B** | 1 |
| **TYPE_VI-F** | 4 |

### Why the unresolved are unresolved

| Root cause | Conditions | Meaning |
|---|---|---|
| UNCLASSIFIED | 3 |  |
| INFRASTRUCTURE | 2 | infrastructure — trace truncated/timed out (retryable) |

A `SAMPLE_NOT_PACKED` verdict is a **corpus** problem, not a classifier one: the payload runs as an ordinary unpacked binary, so there is no unpacking to observe. `INFRASTRUCTURE` is retryable and says nothing about the packer. Only `METHODOLOGY_LIMIT` reflects a genuine boundary of the runtime write→execute model.

## Empirically typed conditions

| Packer family | Version | Test case | Empirical Type | Runs | Rule |
|---|---|---|---|---|---|
| UPX | 3.95 | UPX_V395_001_DEFAULT | **TYPE_I** | 6 | exact |
| acprotect_std_Standard__installer | ? | . | **TYPE_I** | 6 | exact |
| alienyze_protector | 1.4 | . | **TYPE_IV** | 6 | max-observed |
| amber | 2.0 | AMBER_V2_002_REFLECTIVE | **TYPE_IV** | 6 | max-observed |
| amber | 3.1 | AMBER_001_DEFAULT_BUILD | **TYPE_II** | 6 | exact |
| asm_guard | 2.9.4 | . | **TYPE_VI-F** | 6 | max-observed |
| astral_pe | 1.6.0.0 | ASTRAL_001_DEFAULT_MUTATION | **TYPE_0** | 6 | mutator |
| beroexepacker | 1.00.2017.01.27 | BEP_001_DEFAULT | **TYPE_I** | 6 | exact |
| enigma_protector | 7.80_build_20250205 | ENIGMA_001_DEFAULT | **TYPE_IV** | 6 | max-observed |
| eronona | 1.0 | ERONONA_001_DEFAULT | **TYPE_I** | 6 | exact |
| exe32pack | 1.42 | EXE32PACK_001_DEFAULT | **TYPE_IV** | 6 | exact |
| fsg | 1.3 | FSG_V13_001_DEFAULT | **TYPE_I** | 6 | max-observed |
| hackupx | 1.00 | HACKUPX_001_MUTATE | **TYPE_I** | 6 | exact |
| jdpack | 1.00 | . | **TYPE_III** | 6 | exact |
| kkrunchy | 0.23_alpha | KKRUNCHY_001_DEFAULT | **TYPE_II** | 6 | exact |
| kkrunchy | 0.23_alpha_2 | KKRUNCHY_V023A2_001_DEFAULT | **TYPE_II** | 6 | family-inference |
| mew | 1.1_SE | . | **TYPE_I** | 6 | exact |
| molebox | 4.6000 | MOLEBOX_001_DEFAULT | **TYPE_VI-F** | 6 | max-observed |
| mpress | 1.27 | MPRESS_V127_001_DEFAULT | **TYPE_II** | 6 | exact |
| mpress | 2.19 | MPRESS_001_DEFAULT | **TYPE_II** | 6 | exact |
| npack | 1.1.300.2006 | . | **TYPE_I** | 6 | exact |
| nspack | 3.7 | . | **TYPE_IV** | 6 | exact |
| packman | 1.0 | . | **TYPE_I** | 6 | exact |
| pe_diminisher | 0.1 | . | **TYPE_I** | 6 | exact |
| pelock | 2.40 | . | **TYPE_VI-F** | 6 | exact |
| pepacker | 1.0 | PEPACKER_001_DEFAULT | **TYPE_I** | 6 | exact |
| petite | 2.2 | PETITE_V22_001_DEFAULT | **TYPE_III** | 6 | exact |
| petite | 2.3 | PETITE_V23_001_DEFAULT | **TYPE_III** | 6 | exact |
| petite | 2.4 | PETITE_001_DEFAULT | **TYPE_III** | 6 | exact |
| pezor | 3.3.0 | PEZOR_001_DEFAULT_32 | **TYPE_I** | 6 | exact |
| rlpack | 1.21_Basic | . | **TYPE_I** | 6 | exact |
| shrinker | 3.4_Demo | . | **TYPE_III** | 6 | exact |
| telock | 0.98 | . | **TYPE_VI-B** | 3 | max-observed |
| themida | 3.2.4.34 | . | **TYPE_I** | 6 | max-observed |
| upack | 0.399__Brute | UPACK_001_DEFAULT | **TYPE_IV** | 6 | exact |
| upx | 0.60 | UPX_V060_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.61 | UPX_V061_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.62 | UPX_V062_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.70 | UPX_V070_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.71 | UPX_V071_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.72 | UPX_V072_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.762b | UPX_V762BETA_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.763b | UPX_V763BETA_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.80 | UPX_V080_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.81 | UPX_V081_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.82 | UPX_V082_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.83 | UPX_V083_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.84 | UPX_V084_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.896b | UPX_V896BETA_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.90 | UPX_V090_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.92 | UPX_V092_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.93 | UPX_V093_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.94 | UPX_V094_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.99 | UPX_V099_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.991 | UPX_V0991_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.992 | UPX_V0992_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 0.993 | UPX_V0993_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.00 | UPX_V100_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.01 | UPX_V101_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.02 | UPX_V102_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.03 | UPX_V103_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.04 | UPX_V104_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.05 | UPX_V105_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.06 | UPX_V106_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.07 | UPX_V107_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.08 | UPX_V108_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.20 | UPX_V120_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.21 | UPX_V121_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 1.22 | UPX_V122_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 3.96 | UPX_V396_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.0.0 | UPX_V400_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.0.1 | UPX_V401_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.0.2 | UPX_V402_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.1.0 | UPX_V410_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.2.0 | UPX_V420_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.2.1 | UPX_V421_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.2.2 | UPX_V422_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.2.3 | UPX_V423_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 4.2.4 | UPX_V424_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 5.0.0 | UPX_V500_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 5.0.1 | UPX_V501_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 5.0.2 | UPX_V502_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 5.1.0 | UPX_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx | 5.1.1 | UPX_V511_001_DEFAULT | **TYPE_I** | 6 | exact |
| upx_scrambler | 3.0.4 | . | **TYPE_I** | 6 | exact |
| upx_scrambler | 306_unknown | . | **TYPE_I** | 6 | exact |
| upx_scrambler_rc103_unknown | ? | . | **TYPE_I** | 6 | exact |
| upx_scrambler_rc105_unknown | ? | . | **TYPE_I** | 6 | exact |
| upx_scrambler_rc1_RC1 | ? | . | **TYPE_I** | 6 | exact |
| upx_scrambler_rc1b10_RC1b10 | ? | . | **TYPE_I** | 6 | exact |
| winupack | 0.39 | . | **TYPE_V-F** | 6 | max-observed |
| xcomp | 0.97 | XCOMP_001_DEFAULT | **TYPE_I** | 6 | exact |
| yoda_crypter | 1.2 | . | **TYPE_II** | 6 | exact |
| yoda_crypter | 1.3 | . | **TYPE_II** | 6 | max-observed |
| yoda_protector | 1.0 | . | **TYPE_I** | 6 | exact |
| yoda_protector | 1.01.2 | . | **TYPE_IV** | 6 | family-inference |
| yoda_protector | 1.02 | . | **TYPE_IV** | 6 | exact |
| yoda_protector | 1.03.2 | . | **TYPE_IV** | 6 | family-inference |
| yoda_protector | 1.03.3 | . | **TYPE_IV** | 6 | family-inference |
| zprotect | 1.4.2.0 | . | **TYPE_VI-F** | 6 | max-observed |

## Unresolved conditions (with root cause)

| Packer family | Version | Root cause | Detail |
|---|---|---|---|
| alushpacker | 1.0.0 | UNCLASSIFIED | 2 distinct payloads x 3 reps, certified backend (plugin 50a5aa94...): every run exec_events=0 with paper_termination_reason=no_execution_launch_failed, sample_started=false and ... |
| hxor_packer | 0.1 | UNCLASSIFIED | — |
| hyperion | 1.2 | UNCLASSIFIED | — |
| armadillo | 252b2 | INFRASTRUCTURE | 0/6 runs hit the host timeout, 3 had an incomplete trace, 3 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| obsidium | 1.5.2.11 | INFRASTRUCTURE | 1/6 runs hit the host timeout, 1 had an incomplete trace, 1 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |

## Reproducing

```bash
ops/qemu/cert_retry_loop.sh                  # certify the backend
LABEL_CONDITIONS=3 LABEL_JOBS=6 \
  python3 ops/qemu/label_all.py              # sweep the whole corpus
python3 ops/qemu/investigate_unresolved.py   # root-cause the unresolved
python3 ops/qemu/build_final_report.py       # regenerate this document
```
