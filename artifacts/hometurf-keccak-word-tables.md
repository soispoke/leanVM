# Native Keccak rows plus fixed word tables: Falcon and generality (L3c)

Date: 2026-10-23. Local lane, no push. The complete decoded Falcon proof and both requested generality checks use the same fixed LOGIC8/ADD8/MUL8 tables and shared lowering rules. No table changes, size changes, application-specific tables or per-application tuning were introduced. The result is negative for Falcon and SHA-256 speed. Shielded spend avoids the old 5x small-circuit regression, but is slower than small lookups and has higher verifier latency. These are prototype implementation measurements, not a formal soundness or leanVM parity claim.

## Measured comparison

Three-round L3c ABAB on CPUs 24-35, six fresh processes per variant, fixture seed 0. Wallet includes witness rebuild, proof and bincode encoding, setup excluded. Whole-process RSS is each child's Linux wait4 high-water mark, including setup. Independent verification includes decoding. Raw evidence and frozen binary SHA256 hashes: `hometurf-L3c/abab/{metadata.json,samples.jsonl,summary.json}`. L4b's original bit-level and Keccak receipts remain unchanged in the shared JSONL.

| System | Wallet s | Peak RSS KiB | Proof bytes | Verify ms | Arithmetic rows | Committed F64 words |
|---|---:|---:|---:|---:|---:|---:|
| Falcon bit-level (L4b reference) | 11.900435 | 27,653,008 | 390,176 | 10.862502 | 10,115,187 | 205,520,896 |
| Keccak rows (L3c paired control) | 7.591567 | 14,043,610 | 366,552 | 11.304248 | 6,077,055 | 102,760,448 |
| Keccak rows + word tables | 12.895256 | 10,958,816 | 3,130,472 | 2,659.397169 | 3,581,416 | 51,380,224 |
| leanVM Falcon (L5 reference) | 0.49-1.02 | see L5 | see L5 | see L5 | VM cycles, different unit | see L5 |

L4b's original Keccak median was 5.877517 s on CPUs 36-47; it is not substituted for the paired control. The paired fixture is seed 0, so its proof size differs from L4b's earlier fixture. Native Keccak permutation count is 16 in both paired variants. The candidate pads 1,515,869 queries to 2,097,152. The candidate commits half as many F64 words but takes 1.70x the paired wallet time, uses 8.54x the proof bytes, and takes approximately 235x the verifier time. Wallet samples are variable on this shared host; all twelve samples are retained. A brief shielded proof/verify diagnostic ran on the slice near the last round; these raw medians are reported with that limitation, not as isolated-host throughput.

## Same-table generality: SHA-256 1 KiB

Each comparison uses three rounds of ABAB, six fresh processes per variant, pinned to CPUs 24-35 with both thread counts set to 12. Wallet includes witness rebuild, proving and proof encoding, excluding setup. RSS is the whole child's wait4 high-water mark, including setup. Verification runs independently and includes decoding. Every SHA word proof checks the canonical digest independently. Raw samples, frozen binary SHA256 hashes and median summaries are in `hometurf-L3c/generality/`; the runner is `hometurf-L3c/run_generality.py`.

| Variant | Wallet s | Peak RSS KiB | Proof bytes | Verify ms | Arithmetic rows | Committed F64 words |
|---|---:|---:|---:|---:|---:|---:|
| Bit-level paired control | 1.532331485 | 3,611,066 | 328,480 | 10.522801 | 2,006,683 | 25,690,112 |
| Shared word tables | 4.538263633 | 5,013,296 | 3,672,552 | 233.294435 | 1,375,776 | 25,690,112 |

The candidate is 2.96x slower, uses 1.39x RSS, 11.18x proof bytes and 22.17x verification time despite fewer arithmetic rows. It issues 111,456 shared-table queries. SHA shifts use existing bit serialization; there are no SHA tables or new lowering rules. Input bytes are serialized into arithmetic witness cells. Both paired drivers include an unused Keccak anchor required by the mixed bridge and the common canonical envelope, included in measured costs. The supplied historical bit-level reference is 1.72 s / 3.7 GiB and leanVM is 0.31 s; neither is substituted for this fresh paired control.

## Same-table generality: BLAKE2s shielded spend

Two separate three-round ABAB comparisons use the same measurement protocol. The word candidate has 106 BLAKE2s compressions, 3,540 queries and one unused Keccak anchor, all included in costs.

| Comparison | Variant | Wallet s | Peak RSS KiB | Proof bytes | Verify ms | Rows | Committed F64 words |
|---|---|---:|---:|---:|---:|---:|---:|
| Small lookups | Small control | 0.078016361 | 217,496 | 250,280 | 5.606592 | 65,536 padded | 884,736 |
| Small lookups | Shared word tables | 0.099144220 | 154,744 | 247,808 | 16.147934 | 16,930 core | 458,752 |
| Hash rows only | Native control | 0.201423661 | 541,864 | 274,272 | 5.179025 | 148,272 core | 3,211,264 |
| Hash rows only | Shared word tables | 0.097464181 | 154,742 | 247,808 | 16.164649 | 16,930 core | 458,752 |

The fixed 2^18 table does not reproduce the old 16-bit-table 5x slowdown: wallet is 1.27x small lookups and 0.484x hash rows only. This is a limited success for small-circuit overhead, not a universal win: verification is approximately 2.88x and 3.12x slower, respectively. Row units differ for the small control (padded) and other variants (core); do not interpret their ratio as a lowering reduction. The full public table is not materialized or recommitted per application; the sparse argument uses addressed tuples. Supplied historical references remain 0.095 s with small lookups, 0.24-0.29 s with hash rows and leanVM 0.151 s.

## Total frozen permanent surface

The total experimental permanent surface includes all of the following, not just the byte tables:

| Component | Fixed specification and count |
|---|---|
| R1CS/CCS arithmetic base | Native degree-two equation `a*b+c=d` over F192, four role columns, three F64 limbs per value. No separately new CCS engine is claimed. |
| BLAKE2s compression rows | 10 rounds, 2^14 Boolean slots, 256 packed F64 words per compression. Protocol, PCS and canonical claim hashes remain BLAKE2s. |
| Keccak-f[1600] rows | 24 rounds, 38,400 chi products, 2^16 Boolean slots and 1,024 packed F64 words per permutation. |
| LOGIC8 | 65,536 rows. |
| ADD8 | 131,072 rows. |
| MUL8 | 65,536 rows. |
| Total shared byte relation | 262,144 (2^18) rows, six coordinates: 1,572,864 scalar entries if materialized, 12 MiB as u64 entries. |
| Lookup argument and binding | Sparse public sorted integer multiplicities on a product GKR bus; direct-gather degree-two sumcheck; transcript-bound schedule digest; lane-split joint WHIR openings binding queries to committed arithmetic cells. |

Padding, connectors and per-proof query vectors are additional measured costs. The verifier generates addressed table tuples, rather than committing the entire table per application. There is no additive LogUp, modulus-specific table, application-specific table or table-size adjustment. These are counted relation dimensions and implementation specifications, not a count of formal proof lines. No new formal security theorem for the combined system is claimed.

## Full application and rejection boundary

Falcon includes native SHAKE absorption/squeezing, public-key serialization, rejection sampling and compaction, three NTTs, pointwise equality, bounds, norm, encoding budget and canonical BLAKE2s claim. Inputs are decoded coefficients; compressed byte parsing is absent. The frontend asserts acceptance and public valid byte one. The benchmark checks the canonical claim against the original application identity and native SHAKE reference. Query coordinates refer to existing arithmetic witness cells without coordinate-copy rows. Direct gather splits the full-stack claim into committed-lane openings, including the omitted-zero-tail boundary.

The same full-proof verifier rejection harness passed all seven cases on each of Falcon, SHA-256 and shielded spend, bypassing prover membership prechecks. It attempts wrong carry, wrong sum, wrong product, wrong tag, out-of-range operand, altered multiplicity and wrong Keccak output. For applications without honest MUL8 queries it injects a malformed MUL8 query and first adjusts the honest reference multiplicity, so the product attack is exercised. Logs are `ht-L3c-application-attacks.log`, `ht-L3c-sha256-attacks.log` and `ht-L3c-shielded-attacks.log`. Component binding and NTT evidence remains in `ht-L3c-joint-binding-tests.log`, `ht-L3c-keccak-binding-tests.log` and `ht-L3c-word-ntt-tests.log`. Rejection tests are regression evidence, not a formal soundness proof.

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

## Full word-lowered Falcon census

The complete application has 3,581,416 arithmetic rows, 1,515,869 queries padded to 2,097,152 and 16 native Keccak permutations. Stage rows: inputs 4,608; SHAKE/serialization 25,679; sample/compaction 91,218; bounds 7,680; modular conversion 233,984; each of three NTTs 1,012,989; products 105,472; norm 56,331; encoding 17,413; claim 64. All 512 NTT outputs were independently checked against direct modular evaluation.

## Evidence and excluded diagnostics

Authoritative paired receipts are `hometurf-L3c/abab/{metadata.json,samples.jsonl,summary.json}` and `hometurf-L3c/generality/{metadata.json,samples.jsonl,sha256-summary.json,shielded-small-summary.json,shielded-native-summary.json}`. Runners retain distinct frozen binaries, CPU affinity, independent verification and per-child RSS. Build cores were 48-63 with four jobs. The shared metric ledger is `hometurf-12t.jsonl`.

Earlier proof-only single samples, cumulative-RSS attempts, and an interrupted runner pointing both variants at the candidate are excluded from final comparisons. L3b's incomplete relation, which omitted NTT/product/lookup checks, is also excluded. No measured wallet result is inferred from proportional row scaling. Falcon host interference near its final round is disclosed above; retain the raw distribution when interpreting medians.
