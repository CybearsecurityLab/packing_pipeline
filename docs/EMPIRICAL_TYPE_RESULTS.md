# Empirical Packer-Type Results — Complete Corpus

Every packer family+version in the NAS corpus, accounted for. Types are Ugarte et al. I–VI assigned **empirically** from real dynamic traces (see [AUTOMATIC_LABELING.md](AUTOMATIC_LABELING.md)); a Type is emitted only on **exact consensus** — the same Type across ≥2 distinct packed payloads × 3 repetitions each, under a certified backend.

Unlike [EMPIRICAL_TYPE_LABELS.md](EMPIRICAL_TYPE_LABELS.md), which lists only successful labels, this document also states **why** each unresolved condition is unresolved, so no condition is silently missing.

## Summary

- Corpus: **101** packer family+versions
- Empirically typed: **83**
- Unresolved: **19**

| Type | Conditions |
|---|---|
| **TYPE_I** | 68 |
| **TYPE_II** | 5 |
| **TYPE_III** | 5 |
| **TYPE_IV** | 4 |
| **TYPE_VI-F** | 1 |

### Why the unresolved are unresolved

| Root cause | Conditions | Meaning |
|---|---|---|
| METHODOLOGY_LIMIT | 7 | methodology limit — unpacking invisible to write→execute |
| INFRASTRUCTURE | 5 | infrastructure — trace truncated/timed out (retryable) |
| NO_CONSENSUS | 4 | runs disagreed — no exact consensus |
| SAMPLE_NOT_PACKED | 2 | corpus defect — payload is not actually packed |
| UNKNOWN | 1 | insufficient evidence — needs re-run |

A `SAMPLE_NOT_PACKED` verdict is a **corpus** problem, not a classifier one: the payload runs as an ordinary unpacked binary, so there is no unpacking to observe. `INFRASTRUCTURE` is retryable and says nothing about the packer. Only `METHODOLOGY_LIMIT` reflects a genuine boundary of the runtime write→execute model.

## Empirically typed conditions

| Packer family | Version | Test case | Empirical Type | Runs |
|---|---|---|---|---|
| acprotect_std_Standard__installer | ? | . | **TYPE_I** | 6 |
| amber_v3.1_3.1 | ? | . | **TYPE_II** | 0 |
| beroexepacker | 1.00.2017.01.27 | BEP_001_DEFAULT | **TYPE_I** | 6 |
| eronona | 1.0 | ERONONA_001_DEFAULT | **TYPE_I** | 6 |
| exe32pack | 1.42 | EXE32PACK_001_DEFAULT | **TYPE_IV** | 6 |
| hackupx | 1.00 | HACKUPX_001_MUTATE | **TYPE_I** | 6 |
| jdpack | 1.00 | . | **TYPE_III** | 6 |
| kkrunchy | 0.23_alpha | KKRUNCHY_001_DEFAULT | **TYPE_II** | 6 |
| mew | 1.1_SE | . | **TYPE_I** | 6 |
| mpress | 1.27 | MPRESS_V127_001_DEFAULT | **TYPE_II** | 6 |
| mpress | 2.19 | MPRESS_001_DEFAULT | **TYPE_II** | 6 |
| npack | 1.1.300.2006 | . | **TYPE_I** | 6 |
| nspack | 3.7 | . | **TYPE_IV** | 6 |
| packman | 1.0 | . | **TYPE_I** | 6 |
| pe_diminisher | 0.1 | . | **TYPE_I** | 6 |
| pelock | 2.40 | . | **TYPE_VI-F** | 6 |
| pepacker | 1.0 | PEPACKER_001_DEFAULT | **TYPE_I** | 6 |
| petite | 2.2 | PETITE_V22_001_DEFAULT | **TYPE_III** | 6 |
| petite | 2.3 | PETITE_V23_001_DEFAULT | **TYPE_III** | 6 |
| petite | 2.4 | PETITE_001_DEFAULT | **TYPE_III** | 6 |
| rlpack | 1.21_Basic | . | **TYPE_I** | 6 |
| shrinker | 3.4_Demo | . | **TYPE_III** | 6 |
| upack | 0.399__Brute | UPACK_001_DEFAULT | **TYPE_IV** | 6 |
| upx | 0.60 | UPX_V060_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.61 | UPX_V061_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.62 | UPX_V062_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.70 | UPX_V070_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.71 | UPX_V071_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.72 | UPX_V072_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.762b | UPX_V762BETA_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.763b | UPX_V763BETA_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.80 | UPX_V080_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.81 | UPX_V081_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.82 | UPX_V082_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.83 | UPX_V083_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.84 | UPX_V084_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.896b | UPX_V896BETA_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.90 | UPX_V090_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.92 | UPX_V092_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.93 | UPX_V093_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.94 | UPX_V094_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.99 | UPX_V099_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.991 | UPX_V0991_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.992 | UPX_V0992_001_DEFAULT | **TYPE_I** | 6 |
| upx | 0.993 | UPX_V0993_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.00 | UPX_V100_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.01 | UPX_V101_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.02 | UPX_V102_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.03 | UPX_V103_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.04 | UPX_V104_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.05 | UPX_V105_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.06 | UPX_V106_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.07 | UPX_V107_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.08 | UPX_V108_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.20 | UPX_V120_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.21 | UPX_V121_001_DEFAULT | **TYPE_I** | 6 |
| upx | 1.22 | UPX_V122_001_DEFAULT | **TYPE_I** | 6 |
| upx | 3.95 | UPX_V395_001_DEFAULT | **TYPE_I** | 6 |
| upx | 3.96 | UPX_V396_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.0.0 | UPX_V400_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.0.1 | UPX_V401_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.0.2 | UPX_V402_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.1.0 | UPX_V410_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.2.0 | UPX_V420_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.2.1 | UPX_V421_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.2.2 | UPX_V422_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.2.3 | UPX_V423_001_DEFAULT | **TYPE_I** | 6 |
| upx | 4.2.4 | UPX_V424_001_DEFAULT | **TYPE_I** | 6 |
| upx | 5.0.0 | UPX_V500_001_DEFAULT | **TYPE_I** | 6 |
| upx | 5.0.1 | UPX_V501_001_DEFAULT | **TYPE_I** | 6 |
| upx | 5.0.2 | UPX_V502_001_DEFAULT | **TYPE_I** | 6 |
| upx | 5.1.0 | UPX_001_DEFAULT | **TYPE_I** | 6 |
| upx | 5.1.1 | UPX_V511_001_DEFAULT | **TYPE_I** | 6 |
| upx_scrambler | 3.0.4 | . | **TYPE_I** | 6 |
| upx_scrambler | 306_unknown | . | **TYPE_I** | 6 |
| upx_scrambler_rc103_unknown | ? | . | **TYPE_I** | 6 |
| upx_scrambler_rc105_unknown | ? | . | **TYPE_I** | 6 |
| upx_scrambler_rc1_RC1 | ? | . | **TYPE_I** | 6 |
| upx_scrambler_rc1b10_RC1b10 | ? | . | **TYPE_I** | 6 |
| xcomp | 0.97 | XCOMP_001_DEFAULT | **TYPE_I** | 6 |
| yoda_crypter | 1.2 | . | **TYPE_II** | 6 |
| yoda_protector | 1.0 | . | **TYPE_I** | 6 |
| yoda_protector | 1.02 | . | **TYPE_IV** | 6 |

## Unresolved conditions (with root cause)

| Packer family | Version | Root cause | Detail |
|---|---|---|---|
| armadillo | 252b2 | INFRASTRUCTURE | 0/6 runs hit the host timeout, 3 had an incomplete trace, 3 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| asm_guard | 2.9.4 | INFRASTRUCTURE | 1/6 runs hit the host timeout, 0 had an incomplete trace, 0 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| kkrunchy | 0.23_alpha_2 | INFRASTRUCTURE | 1/6 runs hit the host timeout, 1 had an incomplete trace, 1 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| obsidium | 1.5.2.11 | INFRASTRUCTURE | 1/6 runs hit the host timeout, 1 had an incomplete trace, 1 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| yoda_protector | 1.03.2 | INFRASTRUCTURE | 3/6 runs hit the host timeout, 3 had an incomplete trace, 3 were TRACE_LOSS/CRASH -- the recording never reached a usable end state (retryable) |
| alienyze_protector | 1.4 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 3506971 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute... |
| amber | 2.0 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 4889929 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute... |
| fsg | 1.3 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 412413 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute ... |
| molebox | 4.6000 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=0.998) despite 17521223 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execut... |
| telock | 0.98 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 252017 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute ... |
| yoda_protector | 1.01.2 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 193213 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute ... |
| yoda_protector | 1.03.3 | METHODOLOGY_LIMIT | all execution came from mapped sections (mapped/exec=1.000) despite 234001 writes -- consistent with view/section-mapped loading or pre-entry decryption, which a write->execute ... |
| enigma_protector | 7.80_build_20250205 | NO_CONSENSUS | runs disagreed ({'TYPE_I': 1, 'TYPE_IV': 4}); exact consensus requires the same Type across all reps x >=2 payloads |
| winupack | 0.39 | NO_CONSENSUS | runs disagreed ({'TYPE_III': 3, 'TYPE_V-F': 2, 'TYPE_IV': 1}); exact consensus requires the same Type across all reps x >=2 payloads |
| yoda_crypter | 1.3 | NO_CONSENSUS | runs disagreed ({'TYPE_II': 5, 'TYPE_I': 1}); exact consensus requires the same Type across all reps x >=2 payloads |
| zprotect | 1.4.2.0 | NO_CONSENSUS | runs disagreed ({'TYPE_I': 1, 'TYPE_IV': 4, 'TYPE_VI-F': 1}); exact consensus requires the same Type across all reps x >=2 payloads |
| astral_pe | 1.6.0.0 | SAMPLE_NOT_PACKED | ran cleanly (8397 blocks) yet every block came from a mapped file (mapped/exec=1.000) and nothing written was executed -- the payload behaves like an unpacked binary (pass-throu... |
| pezor | 3.3.0 | SAMPLE_NOT_PACKED | ran cleanly (6105 blocks) yet every block came from a mapped file (mapped/exec=1.000) and nothing written was executed -- the payload behaves like an unpacked binary (pass-throu... |
| themida | 3.2.4.34 | UNKNOWN | no surviving per-run evidence |

## Reproducing

```bash
ops/qemu/cert_retry_loop.sh                  # certify the backend
LABEL_CONDITIONS=3 LABEL_JOBS=6 \
  python3 ops/qemu/label_all.py              # sweep the whole corpus
python3 ops/qemu/investigate_unresolved.py   # root-cause the unresolved
python3 ops/qemu/build_final_report.py       # regenerate this document
```
