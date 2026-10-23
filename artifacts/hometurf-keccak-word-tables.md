# Falcon-512: native Keccak rows plus word tables (L3c)

Date: 2026-10-23. No push. The decoded Falcon candidate now proves and verifies with native Keccak rows plus the unchanged byte tables. The three-round paired measurement is negative for speed, proof size and verifier latency. Application attack coverage and the two generality ABAB checks remain incomplete; no formal soundness or leanVM parity claim is made.

## Measured comparison

Three-round L3c ABAB on CPUs 24-35, six fresh processes per variant, fixture seed 0. Wallet includes witness rebuild, proof and bincode encoding, setup excluded. Whole-process RSS is each child's Linux wait4 high-water mark, including setup. Independent verification includes decoding. Raw evidence and frozen binary SHA256 hashes: `hometurf-L3c/abab/{metadata.json,samples.jsonl,summary.json}`. L4b's original bit-level and Keccak receipts remain unchanged in the shared JSONL.

| System | Wallet s | Peak RSS KiB | Proof bytes | Verify ms | Arithmetic rows | Committed F64 words |
|---|---:|---:|---:|---:|---:|---:|
| Falcon bit-level (L4b reference) | 11.900435 | 27,653,008 | 390,176 | 10.862502 | 10,115,187 | 205,520,896 |
| Keccak rows (L3c paired control) | 7.591567 | 14,043,610 | 366,552 | 11.304248 | 6,077,055 | 102,760,448 |
| Keccak rows + word tables | 12.895256 | 10,958,816 | 3,130,472 | 2,659.397169 | 3,581,416 | 51,380,224 |
| leanVM Falcon (L5 reference) | 0.49-1.02 | see L5 | see L5 | see L5 | VM cycles, different unit | see L5 |

L4b's original Keccak median was 5.877517 s on CPUs 36-47; it is not substituted for the paired control. The paired fixture is seed 0, so its proof size differs from L4b's earlier fixture. Native Keccak permutation count is 16 in both paired variants. The candidate pads 1,515,869 queries to 2,097,152. The candidate commits half as many F64 words but takes 1.70x the paired wallet time, uses 8.54x the proof bytes, and takes approximately 235x the verifier time. Wallet samples are variable on this shared host; all twelve samples are retained. A brief shielded proof/verify diagnostic ran on the slice near the last round; these raw medians are reported with that limitation, not as isolated-host throughput.

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

## Implementation status

The complete decoded Falcon path now includes native SHAKE absorption and squeezing, public-key serialization, rejection sampling, compaction, three NTTs, pointwise equality, bounds, norm, encoding budget, and the canonical BLAKE2s claim. The benchmark independently checks the canonical claim against the original application identity and native SHAKE reference. Byte query coordinates map to existing arithmetic witness cells, and the direct-gather evaluation is split into committed-lane PCS openings whose weighted sum is checked by the verifier. No coordinate copy rows or modulus-specific tables are added. Table contents and the shared lowering methods are unchanged between Falcon and the shielded port. The frontend asserts the accepted signature relation, with the public valid byte equal to one.

Component evidence: `ht-L3c-joint-binding-tests.log`, `ht-L3c-keccak-binding-tests.log`, and `ht-L3c-word-ntt-tests.log`. Full Falcon ABAB proves and verifies twelve independent processes, including six candidate proofs. The application-specific malicious-witness suite is still pending; component rejection tests alone do not establish all Falcon integration cases.

## Generality checks requested by coordinator

After the Falcon result, run SHA-256 1 KiB and the BLAKE2s shielded spend with the exact same tables and lowering rules, no application tuning or table-size changes. Each requires three-round ABAB medians on CPUs 24-35 and the same verifier rejection gates. Baseline references supplied: SHA-256 1.72 s / 3.7 GiB versus leanVM 0.31 s; shielded small lookups 0.095 s, hash rows 0.24-0.29 s, leanVM 0.151 s. These are reference values, not new L3c measurements. Both checks remain pending. Existing L3 controls in `hometurf-12t.jsonl` include SHA-256 1 KiB small lookups at 3.140499 s / 7,071,516 KiB / 361,992 bytes / 6.975354 ms, and bit-level SHA-256 at 1.724930 s / 3,857,188 KiB / 322,940 bytes. These are prior control receipts, not L3c measurements or results for the shared byte tables. They cannot establish the requested same-table generality.

The total experimental permanent surface is R1CS/CCS arithmetic plus BLAKE2s compression rows plus Keccak-f[1600] rows plus LOGIC8/ADD8/MUL8 plus the lookup argument (sparse integer product bus, direct gather sumcheck, joint PCS opening). Fixed table rows total 262,144, six coordinates each (1,572,864 scalar entries if fully materialized). The sparse verifier currently generates only addressed tuples; the complete table is not committed afresh for each application. BLAKE2s uses 2^14 Boolean slots and 256 packed F64 words per compression; Keccak uses 2^16 Boolean slots and 1,024 packed F64 words per permutation. Padding and connectors add costs beyond those per-instance sizes. R1CS/CCS formal/spec surface counts remain to be audited.

## Word-lowered Falcon integer census

The reusable byte lowering was applied to the decoded Falcon fixture for the integer relation. Receipt `ht-L3c-word-relation-census.jsonl` reports **3,448,578 arithmetic rows** and **1,512,703 shared-table queries**, with every arithmetic row satisfied by the honest fixture. Per stage: bounds **7,680**, modular conversion **233,984**, each 512-point NTT **1,012,989** (three total), pointwise products **105,472**, and norm **56,331**. The independent NTT test confirms all 512 outputs against direct modular evaluation. The native-Keccak-only census had 1,369,033 rows per NTT, 1,022,405 product rows, and 476,385 norm rows. This is a component census: SHAKE, sample rejection/compaction, encoding, and complete application claim construction are not included.

## Remaining gates

The combined application census and measured ABAB now supersede the projection fallback. Remaining: verifier-facing full-application attacks for carry, sum, product, tag, out-of-range operand, multiplicity and Keccak output; same-table SHA-256 1 KiB and shielded spend ABAB; final source and frozen-surface audit. The previously committed component-only report is historical and is superseded by this status.

## Full application lowering and first proof diagnostic

The application now includes native SHAKE absorption/squeezing, public-key serialization, sample rejection and logarithmic compaction, the word-lowered integer relation, norm and encoding budget, and the canonical BLAKE2s claim. Its arithmetic census is **3,581,416 rows**, **1,515,869 queries**, and **16 Keccak permutations**. Compaction contributes 91,218 rows, SHAKE/serialization 25,679, and encoding 17,413. The honest fixture satisfies the arithmetic relation and its full joint proof verifies. Receipt `ht-L3c-word-application-proof2.jsonl` reports **10.276910635 s proof-only**, **3,130,472 proof bytes**, and **2,637.250417 ms same-process verification**, with 2.384461274 s setup. These are diagnostics: the timer excludes witness rebuild and bincode encoding, no independent-process verification or per-child RSS was captured, and no ABAB median is claimed. The initial attempted runner pointed both variants to the candidate binary and was interrupted; it is not usable paired evidence. Correct wallet instrumentation, independent canonical-claim validation, verifier-facing application attacks, frozen binaries and proper three-round ABAB remain required.

## Shielded same-table first diagnostic

The shielded port uses the same `word_lowering::Lowering` byte-range and addition operations, fixed LOGIC8/ADD8/MUL8 relation, and joint argument. Its first proof and independent verification succeed: 0.129484523 s wallet, 247,808 proof bytes, 31.388703 ms verify, 16,930 arithmetic rows, 3,540 queries, 458,752 committed F64 words, 106 BLAKE2s compressions. This bridge currently requires one unused Keccak anchor, padded to its minimum batch, which is included in these costs. Receipts `ht-L3c-shielded-{proof,verify}.jsonl` are single samples, not ABAB results. No 2^18 table is materialized or recommitted per application.
