# Falcon-512: native Keccak rows plus word tables (L3c)

Date: 2026-10-23. No push. Work in progress. The requested end-to-end L3c candidate is not yet completed: L3b's word-table work remains a prototype and its retained Boolean frontend failed the stop screen. Therefore no Keccak-rows-plus-word-tables ABAB measurement or complete application soundness claim is reported.

## Measured comparison

| System | Wallet s | Peak RSS | Proof bytes | Verify ms | Rows | Committed words |
|---|---:|---:|---:|---:|---:|---:|
| Falcon bit-level | 11.900435 | 27,653,008 KiB | 390,176 | 10.862502 | 10,115,187 | 205,520,896 |
| Keccak rows | 5.877517 | 14,054,560 KiB | 364,760 | 10.492314 | 6,077,055 | 102,760,448 |
| Keccak rows + word tables | not run | not run | not run | not run | not run | not run |
| leanVM Falcon | 0.494 to 1.02 s | see L5 receipt | 231,358 to 323,622 | 14.25 to 14.82 | cycles-based | cycles-based |

The first two rows are L4b's three-round ABAB medians from `hometurf-12t.jsonl`, using the matched canonical claim. Keccak rows use 16 native permutations. leanVM values are the supplied L5 rate-check range.

## L3c native-Keccak row census

Receipt `ht-L3c-census.jsonl`, generated on CPUs 24-35 with both thread knobs set to 12. The observation hook uses the same fixed output-dependency trimming as L4b; synthetic zero witness values do not influence row selection. Counts are native arithmetic rows, not Boolean rows. Bounds are now marked separately from conversions in the unchanged Falcon relation.

| Part | Native arithmetic rows |
|---|---:|
| inputs | 21,056 |
| statement digest SHAKE256(pk || m) | 40,125 |
| HashToPoint SHAKE256 | 43,425 |
| HashToPoint sample tests | 21,420 |
| HashToPoint compaction | 263,836 |
| h < q and s1 range | 34,304 |
| s2 and c - s1 as values mod q | 69,632 |
| NTT(s2) | 1,348,822 |
| NTT(h) | 1,369,033 |
| NTT(c - s1) | 1,333,908 |
| pointwise products and quotient checks | 1,022,405 |
| validity | 21,501 |
| norm | 476,385 |
| encoding length and validity | 10,690 |
| public output and padding | 1 |
| **Total lowering** | **6,076,543** |
| Canonical application claim overhead (L4b total minus lowering) | 512 |
| **Matched L4b total** | **6,077,055** |

The three NTTs total 4,051,763 rows; with products they total 5,074,168 (83.50% of lowering). The 16 native permutations retain 83,550 arithmetic glue rows across the two SHAKE stages. Hash-reduction witness words are separate from arithmetic row counts. No combined-candidate time projection is justified by proportional row scaling alone.

## Word-table implementation and soundness boundary

The candidate shared relation is LOGIC8 (65,536 rows), ADD8 (131,072), and MUL8 (65,536), for 262,144 rows. Sparse multiplicity reduction, direct-gather query binding, and schedule-digest tests exist in L3b. The standalone verifier tests reject wrong carry/sum/product, wrong tag, out-of-range operands, duplicate ordering, altered multiplicity, and forged coordinate claims. These are prototype reduction tests. They do not prove that Falcon PCS openings bind every lookup coordinate to the arithmetic witness, and no complete application-level verifier rejection suite was run.

L3b's retained-frontend stop result was 7.741669 s wallet, 13,806,324 KiB RSS, 361,464 proof bytes, 6.840737 ms verify, 6,199,575 rows, and 102,760,448 committed words. It omitted NTT/product/lookup checks and was explicitly an incomplete Falcon relaxation. L3b stopped before ABAB and fresh-input runs. This does not trigger the L3c stop rule: native Keccak removes its retained Boolean SHAKE bottleneck.

## Frozen surface

The candidate relation is frozen at the three byte tables above. The second hash is Keccak-f[1600]; protocol/PCS/claim hashes remain BLAKE2s. The table schedule and its digest must be bound into the final application transcript. No production lowering, application configuration, or parity claim is frozen. Inputs remain decoded Falcon coefficients; compressed byte parsing is absent.

## Pending work

Native Keccak rows materially reduce the measured Falcon workload. Adding word tables was not brought to a sound, complete application proof or measured ABAB result yet. The approximately two-hour binding attempt has not elapsed. The reusable `word_lowering` module now implements byte logic, addition, multiplication, carry propagation, multi-byte multiplication, bounds, and modular remainder through the same fixed tables. Its multi-byte product and mod-12289 remainder now pass the end-to-end joint PCS test (`ht-L3c-word-lowering-tests.log`, 1 passed). The three L3b word modules have been selectively ported from a014924a/ac5469c7 because blanket cherry-picking replaces or conflicts with L4k frontend files. `cargo check -p format_recursion` passes. Joint PCS query binding now passes `ht-L3c-joint-binding-tests.log`: an honest proof verifies; wrong carry/sum/tag, out-of-range operands, altered multiplicity, and a valid table tuple unbound to the arithmetic witness are rejected by the verifier. The mixed Keccak/BLAKE bridge tests also pass (`ht-L3c-keccak-binding-tests.log`). These tests validate components, not a complete Falcon word lowering. Falcon integer word lowering and performance remain pending.

## Generality checks requested by coordinator

After the Falcon result, run SHA-256 1 KiB and the BLAKE2s shielded spend with the exact same tables and lowering rules, no application tuning or table-size changes. Each requires three-round ABAB medians on CPUs 24-35 and the same verifier rejection gates. Baseline references supplied: SHA-256 1.72 s / 3.7 GiB versus leanVM 0.31 s; shielded small lookups 0.095 s, hash rows 0.24-0.29 s, leanVM 0.151 s. These are reference values, not new L3c measurements. Both checks remain pending. Existing L3 controls in `hometurf-12t.jsonl` include SHA-256 1 KiB small lookups at 3.140499 s / 7,071,516 KiB / 361,992 bytes / 6.975354 ms, and bit-level SHA-256 at 1.724930 s / 3,857,188 KiB / 322,940 bytes. These are prior control receipts, not L3c measurements or results for the shared byte tables. They cannot establish the requested same-table generality.

The total experimental permanent surface is R1CS/CCS arithmetic plus BLAKE2s compression rows plus Keccak-f[1600] rows plus LOGIC8/ADD8/MUL8 plus the lookup argument (sparse integer product bus, direct gather sumcheck, joint PCS opening). Fixed table rows total 262,144, six coordinates each (1,572,864 scalar entries if fully materialized). The sparse verifier currently generates only addressed tuples; the complete table is not committed afresh for each application. BLAKE2s uses 2^14 Boolean slots and 256 packed F64 words per compression; Keccak uses 2^16 Boolean slots and 1,024 packed F64 words per permutation. Padding and connectors add costs beyond those per-instance sizes. R1CS/CCS formal/spec surface counts remain to be audited.

## Word-lowered Falcon integer census

The reusable byte lowering was applied to the decoded Falcon fixture for the integer relation. Receipt `ht-L3c-word-relation-census.jsonl` reports **3,448,578 arithmetic rows** and **1,512,703 shared-table queries**, with every arithmetic row satisfied by the honest fixture. Per stage: bounds **7,680**, modular conversion **233,984**, each 512-point NTT **1,012,989** (three total), pointwise products **105,472**, and norm **56,331**. The independent NTT test confirms all 512 outputs against direct modular evaluation. The native-Keccak-only census had 1,369,033 rows per NTT, 1,022,405 product rows, and 476,385 norm rows. This is a component census: SHAKE, sample rejection/compaction, encoding, and complete application claim construction are not included.

## Projection status and exact missing work

The completed census and lowering component establish the fixed relation and its PCS binding, but the requested combined Falcon number is still unmeasured. The missing work is integrating the word-lowered integer relation with Falcon's existing SHAKE native rows, sample rejection/compaction, encoding budget, and complete application claim, followed by query schedule construction for every lookup coordinate and a fresh witness/proof path. The current test exercises byte arithmetic and one modular remainder, not the 512-point Falcon NTT or its 16-permutation application. Therefore no wallet, RSS, proof-size, verify-time, or committed-word projection is reported for Keccak rows plus word tables.
