# Standard row-format comparison for the leanR1CS freeze

This is a measurement report for the L3 BLAKE2s shielded spend and the L4 native-hash first-level merge verifier. The source program, public layout, native BLAKE2s compression schedule, and hash ports are shared by all three formats. The shielded fixture is shielded_application::application_vm(leanvm_input(0)). The merge fixture is the L4 record_native_first circuit over two repeated valid BLAKE64 native-hash base certificates, with full child checks and statement binding; it is not a merge of shielded leaves. The source program digests are `0cf9660eabe7c6dcc47db321f4600909e0ec1470ae05e6e6c93fb8513db08dc8` (shielded) and `03e5b298f22c5f10e96e594defe819d7703bf0f1f6559d06e42f0bea49b33f4b` (merge), and are identical across A, B, and C for each circuit.

This report makes no soundness claims. The inherited PCS configuration targets 128 bits; this does not establish a 128-bit bound for the prototype composition. Arithmetic uses GF(2^192), PCS messages use GF(2^64), and the transcript is BLAKE2s. No new custom gates are introduced. Native BLAKE2s remains the existing separate Flock relation, as requested.

Worktree: P/ht-L2r, branch hometurf/L2r, based exactly on publish/research/r1cs-recursive-verifier tip 8ff8d878. Builds used Rust 1.99.1. All timed runs used 12 threads pinned to cores 12-23. Release builds used cores 48-63. Each timing cell is the median of three fresh processes, in the order A,B,C,C,B,A,A,B,C for each circuit. Wallet time includes fresh source-witness construction and proof generation, but excludes fixed setup and fixture preparation. RAM is the additional peak resident set above the post-setup baseline, measured after resetting Linux VmHWM via /proc/self/clear_refs=5. Total process peaks, which include fixture and key storage, are recorded separately below. Committed words are F64 words in the PCS stack. The proof byte count is the encoded proof, which is smaller than the committed witness.

## What was lowered

The native source rows contain 36,612 pure additions out of 148,272 shielded rows, a 24.6925% share. The merge source contains 146,472 pure additions out of 578,847 rows, a 25.3041% share. The source share is the comparable quantity. The B and C constraint counts additionally include explicit public-output and all 18 native hash-port materialization constraints.

Pure additions mean rows x*1+u=z or 1*y+u=z with both addends nonzero wire identifiers; copies and zero-product rows are excluded. Other linear definitions, including constant multiplies and copies, may also be substituted. The selected bounded affine expansion cap is eight terms. It eliminates only first-assignment definitions whose expanded affine form has at most eight source terms. Literal R1CS at cap zero and unbounded expansion are recorded in the census artifacts. The unbounded merge form reaches 159,908,836 B nonzeros and a 7,108-term row, so it is not a usable standard sparse representation.

A literal true-R1CS lowering, before affine substitution, gives 150,576 shielded constraints, nnz 337,427 / 150,576 / 41,958, and 150,899 F192 witness entries; merge gives 873,755 constraints, nnz 1,745,209 / 873,755 / 389,342, and 985,449 entries. The selected cap-eight policy removes 98,556 and 247,449 linear definitions. This is a standard linear-combination lowering, not a new gate or a change of program. Its final widest matrix rows have 11 and 17 nonzeros because a constraint can combine more than one bounded definition.

### Shielded spend

| format | constraints | nnz A | nnz B | nnz C | witness F192, padded | committed words | wallet s | additional RAM KiB | proof bytes | verify ms | matrix step |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| A, native fixed gate | 149,120 | 122,889 | 149,150 | 254,576 | 149,333, native layout | 3,211,264 | 0.2095 | 279,488 | 274,048 | 5.20 | native index opening: 71,025 rows, 3,202 compressions |
| B, sparse R1CS | 52,024 | 132,837 | 62,806 | 41,952 | 52,347, 65,536 | 229,376 | 0.0419 | 14,148 | 124,216 | 5.34 | direct matrix: 505,914 rows, 0 compressions, 1.73 ms |
| C, CCS configured as R1CS | 52,024 | 132,837 | 62,806 | 41,952 | 52,347, 65,536 | 229,376 | 0.0435 | 14,144 | 125,952 | 5.86 | direct matrix: 505,914 rows, 0 compressions, 1.79 ms |

The full A verifier lowering is 367,469 rows and 11,025 native BLAKE2s compressions. The B and C verify times include their direct sparse matrix evaluation. The matrix-only row count is a recording through the existing native compiler, including equality-basis construction and sparse accumulation, and excludes transcript, WHIR, and native hash work.

### First-level merge verifier

| format | constraints | nnz A | nnz B | nnz C | witness F192, padded | committed words | wallet s | additional RAM KiB | proof bytes | verify ms | matrix step |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| A, native fixed gate | 687,616 | 677,485 | 677,604 | 1,177,179 | 906,701, native layout | 16,777,216 | 1.3548 | 1,330,776 | 324,968 | 6.38 | native index opening: 78,581 rows, 3,508 compressions |
| B, sparse R1CS | 581,040 | 1,262,716 | 945,244 | 420,368 | 738,002, 1,048,576 | 8,388,608 | 0.9632 | 953,852 | 179,896 | 26.27 | direct matrix: 6,627,333 rows, 0 compressions, 11.87 ms |
| C, CCS configured as R1CS | 581,040 | 1,262,716 | 945,244 | 420,368 | 738,002, 1,048,576 | 8,388,608 | 0.9461 | 923,552 | 178,872 | 22.14 | direct matrix: 6,627,333 rows, 0 compressions, 11.92 ms |

The full A verifier lowering is 399,963 rows and 12,626 native BLAKE2s compressions. The A committed-word cells count only the joint private witness at inverse rate 4. A also has a separately committed fixed index at inverse rate 16, excluded from those cells: 1,048,576 F64 words for shielded and 4,194,304 for merge. B and C use one joint rate-4 WHIR witness commitment.

A constraints in the main tables are the bridge circuit rows before its public prefix and final power-of-two padding. Its arithmetic domain has 262,144 rows for shielded and 1,048,576 for merge, including public prefixes of 128 and 512 rows. The A nnz cells are only a literal R1CS shadow, x*y=z+u, over that full indexed domain: A does not store sparse A/B/C. The zero anchor contributes no nonzero and repeated C entries cancel. Its witness cells count named F192 variables before the prover expands the four wire columns into limb tables. B/C constraint domains pad to 65,536 and 1,048,576 rows, respectively. Their actual F192 witnesses include one, the public outputs, aligned hash ports, and retained source variables.

Total peak resident set medians were 533.2 / 146.8 / 146.8 MiB for shielded A/B/C and 2,129.0 / 1,366.0 / 1,330.7 MiB for merge A/B/C. Since key/fixture storage is resident before wallet timing, both total and incremental RAM are relevant; incremental allocation is not an isolated allocator measurement.

Fixed setup medians were 0.0704 / 0.1466 / 0.1482 s shielded A/B/C and 0.3245 / 1.3428 / 1.2441 s merge A/B/C. Setup includes sparse lowering, not only PCS index preparation. Fixture preparation is also excluded: approximately 0.017-0.019 s shielded and 0.359-0.366 s merge. A one-shot caller rebuilding the key must add these costs, and merge key construction reverses the prepared-wallet advantage. Fresh common-source witness construction inside wallet time was 0.0145 / 0.0108 / 0.0119 s shielded and 0.3546 / 0.3148 / 0.3087 s merge. The merge rebuild re-records and lowers the full child verification circuit. These definitions differ from prior proof-only merge screens.

Wallet ranges were A 0.201-0.234, B 0.0419-0.0441, C 0.0425-0.0456 s shielded and A 1.308-1.362, B 0.935-0.994, C 0.912-0.955 s merge. Merge B verify varied from 21.05 to 27.85 ms and C from 21.47 to 22.62 ms. Warm standalone matrix timings are diagnostic repeats after full verification, not exact subtractions from the colder total. C uses identical R1CS-specialized machinery; its timing and proof-size differences are transcript/domain and query-path effects, not a structural CCS advantage.

The exact selected B/C census is:

| circuit | public length | hash blocks | constraints | linear constraints | nnz A/B/C | witness F192 | padded witness |
|---|---:|---:|---:|---:|---|---:|---:|
| shielded | 5 | 106 | 52,024 | 10,072 | 132,837 / 62,806 / 41,952 | 52,347 | 65,536 |
| merge | 3 | 14,598 | 581,040 | 348,720 | 1,262,716 / 945,244 / 420,368 | 738,002 | 1,048,576 |

C is the standard R1CS-equivalent CCS instance, with matrices [A,B,C], sets S_1={A,B}, S_2={C}, coefficients [1,1] in characteristic two, degree two, t=3 and q=2. The prototype does not implement a general degree-3 CCS prover, so no degree-3 measurement is claimed.

## Spartan-style prototype and matrix cost

The counted words are message words before rate expansion, not codeword words or proof bytes. For B/C, let Z be padded F192 witness length and Q=256 times the padded native compression count. The joint stack has three Z-word limb columns, Q-aligned space, and Q hash words: q_offset=ceil(3Z/Q)*Q, committed=q_offset+Q. This gives 196,608+32,768 shielded and 4,194,304+4,194,304 merge. A instead stores the four native wire roles as limb columns and its hash stack, pruning only whole unused WHIR lanes. Fixed A index words are reported separately above. Direct B/C matrices are trusted fixed key data scanned by the verifier; they have no matrix PCS commitment or opening. Their CSR address/coefficient storage is included in RAM, not private committed words.

B uses a single WHIR commitment to the three F64 limb columns of the F192 witness plus the unchanged packed native-hash witness. The outer sumcheck proves (Az)(Bz)-Cz=0. A second degree-2 product sumcheck folds the three matrix evaluations into one witness evaluation. The verifier then evaluates sparse A, B and C directly at the two multilinear points, in O(nnz), and performs the existing public, native-hash reduction, ring switch, and joint opening checks. C uses the same algorithm with the CCS domain separator and explicit configuration above. The key digest binds matrices, dimensions, witness layout and rates; its label also binds public values and caller context. Public constants are folded only from the source's declared fixed public prefix, not inferred from private witness values. Public outputs and hash ports are explicitly constrained, and upper limbs of F64 ports are zero-checked in the joint opening. This is a format and cost prototype, not a soundness result.

The recorded direct evaluator costs 505,914 native rows for shielded and 6,627,333 for merge. It has no BLAKE2s compressions because it only evaluates the sparse matrices and equality bases. These are the costs that appear if this verifier is placed inside a recursive merge.

For comparison, the existing A verifier pays a logarithmic fixed-index opening, recorded above, rather than walking all sparse matrix entries. The A index-opening stage excludes globally emitted final equalities and unused-limb checks: 32,573 additional rows in the shielded full verifier and 33,631 in the merge full verifier. Even assigning all those shared final rows to the A index stage gives only 103,598 and 112,212 rows. B/C matrix recordings include their own final checks; their matrix step alone exceeds the entire A verifier in both cases. No full B/C recursive verifier or recursively generated B/C proof is claimed.

## Conditional SPARK or holographic estimate

A full SPARK implementation was outside this measurement. The layout reference is [Microsoft Spartan sparse_mlpoly.rs](https://github.com/microsoft/Spartan/blob/master/src/sparse_mlpoly.rs), fetched as raw source; a snapshot and SHA-256 are retained with the evidence. The structural estimate uses the fetched standard sparse-matrix layout: N is the next power of two above the largest matrix nnz, M is the maximum padded row or variable dimension, `comb_ops` has 15 logical vectors for three matrices and is padded to 16, `comb_mem` has two M-sized audit vectors, and dynamic dereferences have six F192 vectors, padded to eight in the original reference.

The conditional compact F64-word accounting assumes addresses and audit/read timestamps fit in F64, with each F192 coefficient represented by three F64 limbs. Fixed operation columns are regrouped as 21 F64 vectors rather than the original 16 padded field vectors; dynamic dereferences use 18 F64 limb vectors rather than 24 padded limb vectors. These are layout assumptions for the WHIR model, not changes to the constraint format:

| circuit | N | M | fixed index tables, 21N+2M | dynamic deref tables, 18N |
|---|---:|---:|---:|---:|
| shielded | 262,144 | 65,536 | 5,636,096 | 4,718,592 |
| merge | 2,097,152 | 1,048,576 | 46,137,344 | 37,748,736 |

The fixed table count is 12N F64 words for address/timestamp fields and 9N F64 words for the three coefficient columns, plus two M-sized audit vectors. The dynamic count is six F192 dereference columns. These are additional committed table words, before product/memory-check openings and protocol metadata. They are not added to the measured B/C committed-word cells.

I also measured synthetic WHIR commitment and one combined opening for these table shapes on cores 12-23. The medians were:

| circuit | component | words | commit s | opening s | verifier ms |
|---|---|---:|---:|---:|---:|
| shielded | fixed index tables | 5,636,096 | 0.0665 | 0.1885 | 1.72 |
| shielded | dynamic dereferences | 4,718,592 | 0.0610 | 0.1865 | 1.71 |
| merge | fixed index tables | 46,137,344 | 0.5183 | 1.2535 | 2.14 |
| merge | dynamic dereferences | 37,748,736 | 0.4287 | 1.1394 | 2.09 |

These synthetic runs are component measurements, not a complete SPARK proof. For this particular separate-stack layout, a calibrated wallet subtotal is T_B + T_fixed_open + T_deref_commit + T_deref_open: 0.04193 + 0.18849 + 0.06095 + 0.18648 = 0.47785 s shielded and 0.96316 + 1.25348 + 0.42870 + 1.13937 = 3.78471 s merge. Fixed-index commitment is preprocessing and is excluded. Full estimated time is this subtotal plus dereference construction, memory/product checks, and their extra openings. Those terms are unmeasured; the subtotal is neither a complete SPARK benchmark nor a lower bound on every optimized holographic architecture. The merge model has 83,886,080 additional F64 table words across fixed index and per-proof dereferences, of which 37,748,736 are newly committed each proof. The model does not count the fixed index as a fresh per-proof commitment. The original SPARK timestamp update assumes a prime-field +1 operation; characteristic two needs a different binding-safe timestamp or memory-check port. No drop-in soundness or security claim is made here.

The same synthetic opening verifiers were actually recorded through the existing native compiler. The shielded fixed/dereference openings require 146,758 / 147,235 rows and 6,450 / 6,394 compressions. Merge requires 175,119 / 175,661 rows and 7,733 / 7,685 compressions. Thus these two PCS components alone total 293,993 rows and 12,844 compressions shielded, or 350,780 rows and 15,418 compressions merge. They do not include the B/C outer and inner sumchecks, native application-hash proof, witness opening, or SPARK memory/product checks. A joint opening may change those costs; the estimate measures a specific separate-stack architecture.

The original reference pads field vectors to powers of two. Retaining that uniform padding and three F64 limbs per field value, without the compact-address assumption, would cost 48N+6M fixed and 24N dynamic words: 12,976,128 / 6,291,456 shielded and 106,954,752 / 50,331,648 merge. The compact model is already the more favorable estimate.

## Freeze decision

For shielded spend, B and C reach prover storage and wallet-time parity with A by a wide margin, and independent verifier time is close. They do not reach recursive parity with A under direct matrix evaluation: the recorded matrix step is 505,914 rows versus 71,025 rows for A’s index opening. The direct B/C formats are useful if prover footprint is the freeze objective, but they are not a recursive replacement for A yet.

For the first-level merge, B and C halve committed words and reduce wallet time by roughly 29%, while their independent verifier time is roughly 3 to 4 times A. The direct matrix step is 6.63M rows versus 78,581 rows for A’s index opening. They do not reach recursive parity. The conditional SPARK route removes the O(nnz) verifier walk only by committing tens of millions of additional table words, and its complete merge cost was not measured.

The measurements support keeping A as the current recursive backend and keeping standard sparse R1CS/CCS as candidates for a later holographic measurement. They do not support freezing the direct sparse evaluator into the recursive format. The exact items held fixed for this comparison are the two source program digests and public layouts; F192 and the existing WHIR/BLAKE2s transcript; A’s fixed native gate `z=x*y+u`; B’s sparse CSR A, B and C matrices and witness ordering; C’s R1CS-equivalent configuration [A,B,C], {{A,B},{C}}, coefficients [1,1], degree two; the bounded affine expansion policy with cap eight; explicit public and 18-port materialization; power-of-two padding; native BLAKE2s rows unchanged; and the rate-4 joint witness commitment. The cap is a lowering policy, not a custom gate. A general degree-3 CCS prover, SPARK memory checks, and any holographic optimization remain unfrozen.

Release validation passed all 90 format_recursion library tests. The focused lowering and B/C proof tests passed again after the final metadata changes. Every timed independent verifier accepted its proof and rejected changed public output and an altered proof scalar. These checks are regression evidence, not a security argument.

Artifacts include the source census, pinned raw JSON, provenance, recorded matrix traces, synthetic SPARK component runs, and the 90-test regression log under `artifacts/row-format/`. The pinned A/B/C implementation and harness are committed locally at `55ef6a877d73e9314bee9233075a617f0b266b63`; the conditional PCS calibration code is at `2a214f5eba883b6037ec03c86b28225bfb9beb00`. No push was performed.

## Reproduction

From P/ht-L2r, use the Rust 1.99.1 toolchain and the shared target directory:

```sh
taskset -c 48-63 env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=../target-ht-L2r cargo build --release -p format_recursion --example row_prover --example row_formats --example sparse_pcs_model
python3 artifacts/row-format/run_pinned.py
python3 artifacts/row-format/run_components.py
python3 artifacts/row-format/summarize.py
```

The runners set both thread knobs and pin each fresh measurement process to 12-23. The matrix recorder can be reproduced with row_prover CASE B matrix-record PROOF_PATH 8 after producing a proof. Census sweeps use the row_formats example. Raw JSON retains fixture/setup times, total and incremental RSS, all stage counts, and the source digests. The two provenance files contain the exact measured binary hashes and source commits. The normalized metrics are also appended to P/artifacts/hometurf-12t.jsonl under flock.
