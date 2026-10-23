# Deferred R1CS matrix claims: first-level measurement

Deferring sparse A/B/C evaluations removes the direct evaluator's recursive bottleneck in this prototype. At 12 threads on cores 12-23, the same-app sparse-R1CS merge takes **0.752 s**, versus **1.245 s** with direct matrix evaluation and the same sparse outer backend. It has **533,813 native rows**, **8,388,608 committed F64 words**, and **888 bytes** of carried claims in its statement. Shielded wallets remain about **0.042 s**. Shielded plus the existing merge-circuit app is feasible: **1.232 s**, **580,280 native rows**, the same committed words, and **1,968 carried bytes**. These are measurements, not estimates or soundness claims.

The preceding [row-format report](hometurf-row-format-comparison.md) was committed at `e430c6f9`. The implementation here is committed at `23333d62f8d418876b91dad22ff624b331739e8b` on `hometurf/L2r`, worktree P/ht-L2r. This report supersedes that report's direct-evaluator performance verdict for the measured first-level deferred path. It does not establish a general recursive construction or justify a security freeze.

## Implementation and scope

The adapter follows leanVM's `doc/leanvm/body/e-recursion.tex`, “The matrix reduction” and “The root”, and `crates/leanvm_core/src/rec/tree/reduce/matrix.rs` in P/leanvm-riscv. The original module has private types and a closed Flock circuit enumeration, so it is adapted rather than called through a new public API. The shared field, equality tables, parallel pool, BLAKE2s transcript, native hash relation, recorder, and WHIR implementation are reused. The sparse path extends the two-matrix reduction to three matrices A/B/C; no new custom gate or lookup is introduced. C is only the standard degree-two R1CS-equivalent CCS configuration from the preceding report, not a general degree-three CCS implementation.

The child proof sends its three matrix evaluations after Spartan's inner sumcheck. They are absorbed by its transcript before the public/hash reductions and joint opening. `verify_deferred(..., false)` replays the outer and inner sumchecks, their terminal identities, public values, native BLAKE2s reduction, ring switching, and the joint WHIR opening, and returns the matrix claim. It does not evaluate A/B/C. Ordinary `verify()` still settles them directly. The wallet still computes the values needed to construct its proof, but supplies no matrix commitment, SPARK proof, or matrix opening.

Each carried claim contains the trusted fixed application key, a row point, a column point, and the three matrix values. The application key binds the sparse matrices, dimensions, layout, rates, and R1CS/CCS configuration. The first-level circuit checks each supplied child identity against its selected trusted application. The ordered child-statement digest binds each application key and public vector; child and outer transcripts also bind caller context. The folding transcript binds that digest, the number of inputs, and every input's identity, dimensions, points, and matrix values before sampling its batching challenge. The outer public statement contains the digest and all resulting carried claims, so neither values nor app identities are unauthenticated side data.

With challenge theta, input i contributes theta^(3i) times [A_i(r_i,c_i) + theta B_i(r_i,c_i) + theta^2 C_i(r_i,c_i)]. One degree-two row sumcheck and one degree-two column sumcheck batch both children and all registered apps. Their terminal check uses equality weights evaluated in rows and outputs one row/column point with three values per distinct app. Different shapes share the maximum round counts; short polynomials repeat across unused coordinates and their weights are zero-extended, with the corresponding lift factors checked in rows. Both children in the same-app case use the same circuit with different witnesses and public statements, not duplicate proofs.

The root's `Generator` holds compiled source instruction descriptors, fixed constants, bounded affine definitions, and wire mappings. It constructs row/column equality weights and walks these instructions to accumulate all three evaluations together. It never constructs or stores CSR A/B/C. The regression compares generator results against CSR for both real source circuits; the root settlement path itself uses the generator. This is a compiled circuit walk with O(circuit size) metadata and padded equality arrays, not a constant-space streaming compiler. Generator compilation is trusted preprocessing and excluded from settlement time.

**Remaining limitation:** the native wallet and fold prover still use the existing CSR setup to produce sumcheck messages. The benchmark process constructs and retains these setups. Only recursive verification and root settlement avoid matrix traversal/storage through CSR. This is not an end-to-end demonstration that no process ever builds matrices. Porting the fold prover's row/column products to forward/backward source walks remains work. The measured wrapper covers first-level nodes; a reusable arbitrary-depth node wrapper and tree-wide app registry were not implemented or measured.

## Measurement method

Release builds used Rust 1.99.1 on cores 48-63. Each final measurement is a fresh process pinned to cores 12-23 with `LEANVM_NUM_THREADS=12`. Seven cases ran in forward, reverse, forward order, three repetitions each, sequentially after the regression suite finished. Cells below are medians; raw order and binary hashes are in [provenance.json](row-format/deferred/provenance.json). Exploratory runs, some overlapping tests on other cores, are retained separately and excluded from the tables.

Wallet time includes fresh source-witness construction, proving, and serialization, excluding fixed setup. Merge time includes native child transcript checks, native matrix-fold proving, verifier recording/witness work, outer proving, and serialization. The native prechecks are redundant with the checks replayed in rows, but their time is included. There is no host acceptance shortcut replacing those row checks. Setup, canonical circuit construction, leaf proof generation, and root verification are excluded from merge time. Root time includes verifying the outer proof and settling every deferred matrix claim. It excludes trusted generator compilation and fixture construction. Timers are not assumed comparable to historical proof-only screens.

The shielded source digest is `0cf9660eabe7c6dcc47db321f4600909e0ec1470ae05e6e6c93fb8513db08dc8`. The second app is the preceding report's L4 first-level verifier circuit, digest `03e5b298f22c5f10e96e594defe819d7703bf0f1f6559d06e42f0bea49b33f4b`, which verifies two valid native-hash BLAKE64 base certificates. It is proved as an independent app here, not used as a claim about an already-recursed shielded subtree.

## Shielded plus shielded

In the table, child format B is sparse R1CS, child format C is R1CS-equivalent CCS. Outer B uses the matching sparse/CCS configuration; outer A uses the existing fixed gate. “Rows” counts the native verifier trace before the outer format lowering. “Compressions” counts its unchanged native BLAKE2s compressions.

| child format / matrix handling / outer | wallet s, left / right | merge s (range) | native rows | compressions | committed words | proof bytes | carried bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| B / direct / A | 0.0433 / 0.0364 | 1.945 (1.920-2.182) | 1,450,017 | 9,991 | 29,360,128 | 330,440 | 0 |
| B / carried / A | 0.0433 / 0.0371 | 1.103 (1.101-1.170) | 533,813 | 10,120 | 16,777,216 | 324,648 | 888 |
| B / direct / B | 0.0438 / 0.0373 | 1.245 (1.240-1.339) | 1,450,017 | 9,991 | 12,582,912 | 184,512 | 0 |
| **B / carried / B** | **0.0427 / 0.0421** | **0.752 (0.746-0.774)** | **533,813** | **10,120** | **8,388,608** | **179,520** | **888** |
| C / carried / B | 0.0415 / 0.0378 | 0.755 (0.741-0.798) | 533,813 | 10,120 | 8,388,608 | 178,944 | 888 |

Each shielded wallet commits 229,376 F64 words; B child proofs are 126,376 and 125,960 bytes. The proof sizes differ from the old direct-only report because the protocol label changed and matrix values now ride the transcript. No old B/C proof bytes are reused here. The same-app sparse merge lowers to 566,915 R1CS constraints and 679,332 F192 witness entries, both padded to 2^20. Native trace rows and final R1CS constraints are different census quantities because hash ports and public outputs are explicitly materialized.

The controlled comparisons show two effects. Deferral alone, retaining outer A, reduces 1.945 s to 1.103 s. With outer B held fixed, deferral reduces 1.245 s to 0.752 s, a 1.66x speedup, and removes one third of committed words. Full trace rows fall by 916,204, or 63.2%, with 129 additional native hash compressions for claim binding and the reduction transcript.

The supplied historical fixed-gate references are 0.209 s wallet and 1.22-1.27 s merge. The former agrees with the preceding report's 0.2095 s median. P/artifacts/hometurf-L4.md records 736,150 merge rows, 21,990 compressions, and 25,165,824 committed words for the historical shielded fixed-gate merge. Against that reference, the carried B/B prototype uses one third of the committed words and has a lower measured merge time. A fresh three-process run of the unchanged `shielded_native merge` example in this session instead measured **1.598 / 1.691 / 1.782 s**, with the same 21,990-compression shape and 317,064-byte proof. Those fresh controls were run after the main comparison, not interleaved. The supplied historical merge range was therefore not reproduced in this session; the new merge's timer includes recording, and no claim of a tightly paired speedup against the historical A times is made. Even the historical faster reference remains above the measured carried prototype.

## Shielded plus merge-circuit app

| child format / outer | shielded wallet s | merge-app wallet s | merge s (range) | native rows | compressions | committed words | proof bytes | carried bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B / B | 0.0423 | 1.0035 | 1.232 (1.221-1.234) | 580,280 | 12,075 | 8,388,608 | 179,296 | 1,968 |
| C / B | 0.0408 | 0.9544 | 1.245 (1.176-1.297) | 580,280 | 12,075 | 8,388,608 | 179,552 | 1,968 |

The second app's wallet commits 8,388,608 words. Its B/C proof bytes are 179,008 / 179,968. Fresh witness construction takes 0.330 / 0.316 s within its wallet time. The mixed outer circuit lowers to 585,972 R1CS constraints and 717,048 F192 witness entries, each padded to 2^20. Two distinct apps therefore fit in the same outer commitment size as one app at this shape; this is a padding result, not a guarantee for every additional app. A direct mixed evaluator and a fixed-gate mixed baseline were not measured. Comparing this mixed time to the historical homogeneous A merge is only a scale comparison, not parity evidence for identical workloads.

The mixed B merge spends 459 ms proving the matrix reduction, versus 23.4 ms same-app. The current implementation uses explicit maximum-dimension folding tables and serial sparse row folds inside the native prover; the merge-app matrices are much larger. Prover generator walks and shorter-table handling are plausible next measurements, with no speedup assumed here.

## Root settlement and resource accounting

| case / child format / outer | outer proof verify ms | outer proof's own matrix settlement ms | shielded settlement ms | second app settlement ms | complete root ms |
|---|---:|---:|---:|---:|---:|
| same / B / A, direct | 5.83 | included in A index opening | none | none | 5.83 |
| same / B / A, carried | 5.94 | included in A index opening | 2.42 | none | 8.41 |
| same / B / B, direct | 4.44 | 35.21 | none | none | 39.51 |
| same / B / B, carried | 4.13 | 18.32 | 2.16 | none | 24.56 |
| same / C / B, carried | 4.24 | 17.91 | 2.07 | none | 24.08 |
| mixed / B / B, carried | 4.10 | 18.03 | 2.11 | 18.98 | 43.29 |
| mixed / C / B, carried | 4.14 | 20.20 | 2.06 | 19.16 | 45.51 |

The complete root cell is the median of each run's total, so it need not equal the sum of independently rounded stage medians. Every sparse outer proof leaves its own fresh A/B/C claim, in addition to the child-app claims in its public statement. The root settles that claim too; omitting it would understate root cost. Thus same-app sparse root verification walks two circuit identities, and mixed sparse root verification walks three. The compiled shielded and merge-app generators have 52,024 and 581,040 R1CS instructions respectively. Each evaluates A/B/C together once at the folded points, independent of the number of same-app input claims.

Committed words count the WHIR message before inverse-rate-four expansion, not proof bytes or codeword words. For sparse B/C, Z is the padded F192 witness length and Q is 256 times the padded native compression count. The commitment contains three Z-word F64 limb columns, alignment to Q, and Q native-hash witness words: ceil(3Z/Q)*Q + Q. Here the shielded wallet has Z=65,536 and Q=32,768, giving 229,376 words. Both carried outer circuits have Z=1,048,576 and Q=4,194,304, giving 8,388,608 words. The direct B outer has Z=2,097,152 and the same Q, giving 12,582,912 words. No matrices, multiplicity columns, matrix-index commitment, or separate lookup tables are committed on this path. The fold proof is consumed as outer private witness and its checked outputs are public, so its wires are already included in the outer commitment census; its bytes are not added again as a separate commitment. Outer A also has a fixed index commitment, excluded from the private witness word figures as in the preceding report: 4,194,304 F64 words for carried outer A and 8,388,608 for direct outer A.

The native fold proof is 1,624 bytes same-app and 2,080 bytes mixed. This is 64 or 80 transmitted F192 sumcheck coefficients, plus three or six matrix values and 16 bytes of proof-container lengths. The same-app matrix reduction itself records 42,859 input-binding rows and 30 compressions, 240 row-phase rows and 48 compressions, and 449 column-phase rows and 51 compressions. The mixed counts are 47,491 / 33, 300 / 60, and 561 / 66. Whole-trace counts in the main tables also include both child verifiers and the compiler's final equalities/unused-limb checks. Direct matrix stage attribution is not identical to the old standalone matrix recorder, so the full matched trace difference is the appropriate comparison.

A claim's public-field representation is 24*(2 + row_log + col_log + 3) bytes: two F192 slots encode a 32-byte app hash, followed by points and A/B/C values. Shielded has 16+16 point coordinates, giving 888 bytes; the second app has 20+20, giving 1,080 bytes. Their mixed total is 1,968. Compact hash packing would give 872 and 1,064 bytes, but the measured statement uses 888 and 1,080. The ordered aggregate digest is another two public F192 slots, 48 encoded bytes carrying a 32-byte hash, excluded from “carried bytes”. Including it gives 936-byte same-app and 2,016-byte mixed public output vectors. Lengths and app ordering are fixed by the trusted node schema. The sparse outer verifier's own fresh claim has 1,080 public-field bytes if later transported to another node; it is derived during verification and is not duplicated in this node's output vector.

Median additional peak RAM above prepared setup is 961.7 MiB same-app B/B carried, 1,263.4 MiB B/B direct, 1,313.9 MiB B/A carried, and 2,344.7 MiB B/A direct. Total process peaks are 1,518.9 / 2,476.0 / 2,251.2 / 4,163.7 MiB respectively. Mixed B/B carried uses 954.4 MiB additional and 1,723.9 MiB total. Linux VmHWM was reset before timing; these process measurements include retained allocator/key state and are not isolated allocation counts. Some mixed shielded-wallet additional-RAM deltas are zero because allocator pages retained from preparing the larger fixture already cover that wallet's peak. They do not mean zero wallet memory use.

Prepared outer setup medians are 1.713 s same-app B/B carried, 4.320 s B/B direct, 0.521 s B/A carried, 1.339 s B/A direct, and 1.957 s mixed B/B carried. Rebuilding fixed setup for each merge would substantially change these latency comparisons.

## Validation and verdict

All 93 format_recursion library tests passed in release mode. After adding the known-app identity swap check, the focused first-level test passed again. Tests and measured harness checks reject a changed fresh matrix claim, a changed folded value, an altered child proof, an unknown child identity, swapped known identities, a root claim with a wrong app key, a root claim with a wrong matrix value, and modifications of the outer public statement's carried value or app identity. Generator evaluation matches CSR on both real source circuits, and every timed proof was verified and its generator claims settled. The first-level fixed-outer test checks the composed root function; sparse measured runs check outer verification followed by all generator settlements. These are regression checks, not a soundness argument.

For shielded, this measurement changes the row-format decision: standard sparse R1CS with deferred claims reaches and exceeds the supplied fixed-gate wallet and first-level merge performance references. Direct evaluation is no longer necessary inside merge rows, and a SPARK commitment is not needed for this measured first-level fixed-app route. Native root work increases to about 24.6 ms for sparse outer B, compared with about 5.8 ms for the direct fixed outer. Keeping outer A while carrying child claims gives 1.103 s merge and 8.41 ms root, a useful measured intermediate choice.

For shielded plus merge-app, the scheme works with one carried claim per distinct app and unchanged committed words at this padding boundary. It does not establish mixed-workload parity against A because that matched mixed control was not run. Its 1.232 s merge is dominated in part by the native CSR folding prover, and root work is 43.3 ms. R1CS-equivalent CCS has the same rows and words and similar timing; it supplies no structural advantage in this experiment. Arbitrary-depth recursion, a generator-based native fold prover, a lean root key with no retained prover CSR setup, and a protocol/security review remain outside this measurement.

Reproduce from P/ht-L2r, with Rust 1.99.1 on PATH:

```sh
taskset -c 48-63 env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=../target-ht-L2r cargo build --release -p format_recursion --example deferred_merge --example shielded_native
taskset -c 48-63 env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=../target-ht-L2r cargo test --release -p format_recursion --lib
python3 artifacts/row-format/deferred/run.py
python3 artifacts/row-format/deferred/summarize.py
```

The runner pins each measurement to 12-23 and records three sequential repetitions. Raw JSON, source/binary provenance, full regression log, final rejection log, stage census, medians, and exploratory evidence are under [artifacts/row-format/deferred](row-format/deferred/). Changes are committed locally; no push was performed.
