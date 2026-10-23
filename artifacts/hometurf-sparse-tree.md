# Sparse carried-claims tree, work in progress

The latest depth-2 mixed node merge is **1.022 s** (same-app **1.041 s**), above the one-second target. The first-level true sparse-R1CS mixed merge has reached a three-process median of **0.975 s** for independently proved shielded plus the merge-circuit application. Shielded plus a new depth-16 BLAKE2s Merkle membership application takes **0.752 s**. A reusable wrapper and depth-2 mixed tree are now implemented and measured, but the node median remains slightly above one second and outer claim settlement remains above 10 ms. These are prototype measurements and regression checks, not a security claim.

## Implementation

The native matrix-fold prover now uses forward source instruction walks and transpose source walks through bounded affine definitions. Its generated path only reads keys and shape metadata from prover setups; it does not read CSR rows or entries. Tables are sized to each application. Short repeated polynomials and zero-extended weights are folded using algebraic lift factors after their native dimensions end. The column phase combines A/B/C linearly before sumcheck and re-evaluates the three terminal values using the source generator. The existing four-field multiplication kernel batches sumcheck products and generator settlement. The row verifier, child checks, folding challenge transcript and carried-claim format are unchanged.

A regression compares both forward and transpose generator products with CSR on shielded and the merge-circuit application. A separate test compares the complete reduction proof bytes from generated and CSR prover paths. The wallet and outer Spartan prover still use CSR. Trusted generator compilation is excluded from timings; this is not an end-to-end matrix-free prover.

## First-level measurements

All table cells are medians of three fresh processes, 12 threads on cores 12-23 with both RAYON_NUM_THREADS and LEANVM_NUM_THREADS set to 12. Cases run same/mixed, mixed/same, same/mixed; the Merkle group substitutes Merkle for mixed. Setup and leaf proof generation are excluded from merge, while native child checks, matrix-fold proof construction, recording, outer proving and serialization are included. Every timed proof verified and all carried claims settled. Root acceptance includes native outer verification, its own matrix claim and every carried application claim.

| Candidate | Same merge s | Mixed shielded + merge-app s | Mixed fold ms |
|---|---:|---:|---:|
| Parallel CSR from preceding turn | 0.814 | 1.352 | 478 |
| Per-app tables plus parallel CSR | 0.832 | 1.150 | 309 |
| Generator, initial shared outer fold regression | 0.898 | 1.175 | 272 |
| Generator, shared outer fold restored, paired | 0.770 | 1.068 | 254 |
| Combined column polynomials | 0.791 | 1.054 | 206 |
| Batched field kernels | **0.716** | **0.975** | **223** |

Outer proving varies across groups, so the last table row's full-merge improvement is not solely attributable to fold kernels. The sub-second result is a measured median with modest headroom, not a latency guarantee. The three final mixed merge times are retained verbatim in `ht-L2r/artifacts/sparse-tree/simd-mixed-{1,2,3}.json`.

## Paired same-app regression check

A fresh detached bc1f691a baseline binary was built with the same toolchain and dependencies, on cores 48-63. Same-app ABABAB initially measured **0.822 s baseline vs 0.922 s generator**. Stage timing traced the regression to outer proving, **0.717 vs 0.827 s**, rather than matrix folding. The previous parallel `Matrix::fold_rows` edit affected the shared outer Spartan prover and allocated dense temporary buffers. Restoring that shared routine while leaving the carried fold on generator walks removed the regression.

The corrected ABABAB, interleaved across same/mixed cases in alternating case order, measured **0.760 s baseline vs 0.770 s generator** same-app; outer proving was **0.668 vs 0.662 s**. The ~10 ms difference is comparable to run variation, with no residual outer-stage regression. Mixed measured **1.238 s baseline vs 1.068 s generator**, with folding **459 vs 254 ms**. The supplied historical 0.752 s same-app result is close to this freshly paired 0.760 s baseline.

## Second real application

The new application proves membership of a private 32-byte leaf under a depth-16 BLAKE2s binary Merkle root, with 16 Boolean path selectors and 16 private 32-byte siblings. The root is the four-word public output. It uses the existing native compression relation and sparse R1CS lowering. Test input seeds change witnesses without changing the graph. An independent native BLAKE2s computation reproduces its root; native verifier checks reject a changed public root and a tampered proof. This is a new workload, not a matched leanVM parity comparison.

Shielded plus Merkle uses distinct circuits and independent fresh wallet proofs. In the same/Merkle alternating group, same-app merge is **0.732 s** and mixed merge is **0.752 s**, with **516,284 native rows**, **8,388,608 committed words**, **180,160 proof bytes**, and **1,584 carried-claim bytes**. Median wallet times are **0.0409 s shielded** and **0.00989 s Merkle**. Complete mixed root acceptance is **22.54 ms**, including **16.44 ms** for the outer matrix claim.

The large-app mixed case retains **580,280 native rows**, **8,388,608 committed words**, **179,296 proof bytes**, and **1,968 carried bytes**. Its final outer settlement is **18.54 ms**, the merge-app settlement **18.25 ms**, and shielded settlement **2.03 ms**. These exceed the requested 10 ms target for larger applications.

## Evidence and remaining work

Local code commits: `35e3a407` per-app tables, `3ca7f43f` generator fold and shared outer regression fix, `4091a3b8` batched kernels. No push was performed. Raw results, binary hashes, paired orders, generator comparisons, regression logs and summaries are under `ht-L2r/artifacts/sparse-tree`. `summarize.py` appends per-process rows to `P/artifacts/hometurf-12t.jsonl` and writes `summary.json`. The measurements are grouped exploratory comparisons; do not treat separate groups as paired controls.

The node implementation and subsequent measurements below supersede this first-level-only state. Remaining requirements are a robust sub-second node median, larger-application settlement at or below 10 ms, and complete root timing by identity count.

## Reusable node and depth-2 tree

The committed `row_format::tree` module supplies an app-independent node schema. Its key fixes the wrapper logic and four slot shapes. The proof binds child kind, ordered child statement digests, active-slot bits, application identities, and carried claims as runtime data. Application identities are not constants in the node circuit. Each child proof is replayed through the full sparse verifier before its carried slots and fresh outer claim enter the fold. The node fold retains one claim per active application slot, including each child wrapper identity. The node proof creates its own fresh matrix claim, which the next parent folds into a wrapper slot or the root settles. The root registry binds each active slot to a trusted application generator and checks all claims.

A depth-2 mixed run succeeded: two first-level nodes, each built from independently proved shielded and Merkle children, were merged as node plus node using the same node key. The reuse check passed and all active claims settled. Three-process alternating medians after digest binding and compact generator addressing were **1.006 s mixed** and **1.014 s same-app**, with **634,272 rows**, **8,388,608 words**, **180,064 mixed proof bytes**, and **2,664 carried bytes**. Complete mixed root acceptance was **34.77 ms**, including **14.15 ms** for the node’s own claim and application settlements of approximately **1.5 ms shielded**, **0.2 ms Merkle**, and **13.6 ms first-wrapper matrix**. A later compact-kernel pairing measured **1.008 s mixed** versus **1.053 s** for a linear settlement variant; compact is retained. The first run before digest binding was 1.117 s and 898,928 rows, so the ordered child digest reduced the node circuit materially.

The node verifier rejection probes bypass native prover prechecks and reject: a false carried evaluation, substituted app key, omitted claim, duplicated claim, wrong child kind, swapped children, tampered child proof, tampered node proof, malformed statement length, and a changed active claim. Full release library tests passed (94 tests before the node example probes; the row-format subset passed after node changes). These checks demonstrate those tested rejection behaviors only.

The depth-2 node is near but above the requested one-second interval. The full mixed-tree verdict is therefore **not yet under 1 s**. First-level mixed shielded plus merge-app is sub-second at 0.975 s, and shielded plus the independent Merkle app is 0.752 s. The remaining gap is outer proving, about 0.67 s at depth 2, plus roughly 0.24 s node folding and child replay. Root settlement also remains above 10 ms for the first-wrapper and node matrices. The four slots currently accommodate two real application shapes plus the first-wrapper and node-wrapper identities. They do not support a third real application simultaneously. The fixed schema was tested with a shielded-only subset and shielded plus Merkle; the identical node key across those workloads is recorded in raw JSON. Root count means all distinct identities, including wrapper identities, and the complete fresh-process 1/2/3-identity timing table remains to be assembled.


## Final group in this continuation

The final group uses the compact generator, four independent fresh wallet proofs per process, and all direct verifier probes. Binary SHA256 and the exact alternating order are in `ht-L2r/artifacts/sparse-tree/node-provenance.json`. Three fresh processes per case, same/mixed then mixed/same then same/mixed, measured **1.022 s mixed** and **1.041 s same-app**, with **253 ms** and **248 ms** in the fold prover. Shape remains **634,272 native rows**, **8,388,608 committed F64 words**, **180,064 mixed proof bytes / 179,488 same-app proof bytes**, and **2,664 mixed / 1,968 same-app active carried bytes**. The fixed public statement is **3,912 bytes**, including inactive padded slots, active flags, kind and digest; active carried bytes exclude these schema fields. No claim is hidden from the node public statement when inactive; an inactive slot must be canonically zero. Root checks bind every active slot to a trusted generator and its role.

| Root workload | Distinct matrix identities | Complete acceptance ms |
|---|---:|---:|
| Shielded wallet only | 1 | 4.83 |
| First-level shielded + shielded | 2 (shielded, first wrapper) | 19.84 |
| First-level shielded + Merkle | 3 (shielded, Merkle, first wrapper) | 20.41 |
| Depth-2 shielded tree | 3 (shielded, first wrapper, node wrapper) | 33.28 |
| Depth-2 shielded + Merkle tree | 4 (shielded, Merkle, first wrapper, node wrapper) | 34.71 |

Identity count alone does not determine cost: the two three-identity rows contain different circuits. Each timer includes checking the outer proof and settling its fresh matrix claim plus all active carried claims, excluding trusted setup and generator compilation. The larger wrapper settlements remain around 14-15 ms each, so the requested per-identity target is not met even where the total divided by identity count is below 10 ms. The one-, two-, and three-identity root cases are now measured; a third real application is not supported simultaneously by this four-slot tree schema.

The later node-key reuse regression proves another composition with the same node setup and an active node-wrapper slot; it uses two different node proofs built from reordered first-level children, and shares leaves between those nodes. It is a reuse test, not an independent eight-leaf benchmark. The reported depth-2 timings use four independent fresh leaves and two different first-level child proofs.

Direct rejection probes include replacing an omitted slot with canonical inactive zero data, removing a slot structurally, and duplicating an entire same-shape wrapper claim. These go to row replay or native root verification, bypassing the node prover's admission code. They do not establish a general soundness theorem. Changes are committed locally on `hometurf/L2r`; no push was performed. The full goal remains active: obtain a repeatable sub-second node median and bring the large wrapper settlements to 10 ms or less. The fixed-shape, two-real-application scope should be reviewed before claiming general mixed-workload recursion.

## Settlement continuation: generated weights and shared bindings

The selected candidate factors row equality weights into low/high tables, accumulates unreduced field products across row blocks, and computes column equality weights on demand during source evaluation. It no longer materializes a padded column equality table for native root settlement. Trusted generator compilation shares identical canonical source bindings (mixed first wrapper 476,118 bindings, node 596,044). Native coefficient multiplication uses exact base-field paths where applicable. Fold row and column weights are built with their scalar seed, avoiding a second full scaling pass; sumcheck accumulates unreduced products before reducing. These changes preserve the node key, rows, words and protocol.

All numbers below are medians of three fresh processes on cores 12-23, 12 threads, alternating same/mixed then mixed/same then same/mixed. The selected binary hashes and exact order are in `artifacts/sparse-tree/settlement-provenance.json`. Raw receipts and intermediate exploratory groups are preserved; independent groups are not paired comparisons.

| Selected weighted-column candidate | Same | Mixed shielded + Merkle |
|---|---:|---:|
| Node merge s | 1.0922 | 1.0269 |
| Matrix fold ms | 255.19 | 221.07 |
| Outer prover s | 0.7347 | 0.7198 |
| Rows | 634,272 | 634,272 |
| Committed F64 words | 8,388,608 | 8,388,608 |
| Proof bytes | 179,488 | 180,064 |
| Active carried bytes | 1,968 | 2,664 |
| Own node settlement ms | 7.42 | 8.07 |
| First-wrapper settlement ms | 7.61 | 8.17 |
| Shielded settlement ms | 0.69 | 0.77 |
| Merkle settlement ms | — | 0.17 |
| Complete depth-2 root ms | 19.81 | 23.23 |

| Root workload | Distinct matrix identities, including wrappers | Complete acceptance ms |
|---|---:|---:|
| Shielded wallet | 1 | 3.97 |
| First-level shielded + shielded | 2 | 10.94 |
| First-level shielded + Merkle | 3 | 11.31 |
| Depth-2 shielded | 3 | 19.81 |
| Depth-2 mixed | 4 | 23.23 |

Root acceptance includes the native outer verifier, fresh own matrix claim and every active carried claim. Individual per-identity settlement medians are now below 10 ms, including both wrapper identities. This is a median result, not a worst-case guarantee: noisy individual samples exceeded 10 ms. The fixed schema still supports two real applications plus two wrapper shapes; no third real application or unrestricted-depth identity deduplication is claimed.

A fresh paired ABABAB check against the detached `bc1f691a` baseline binary measured same-app **1.2461 s baseline versus 1.1655 s candidate**, outer **1.1285 versus 1.0515 s**. There is no same-app regression in this paired group. Mixed shielded + merge-app measured **1.8361 versus 1.8309 s**, with matrix folding **485.67 versus 248.02 ms**. Outer proving was **1.2319 versus 1.4762 s** in this mixed group; high host variation prevents attributing the full-merge difference to the fold optimization. Earlier paired 0.760/0.770 s evidence and the shared-outer fix remain documented above. These slower absolute readings must not replace or be compared unpaired with historical 0.752 s.

The intermediate on-demand group measured node same/mixed **1.0451/1.0101 s**, own settlement **9.72/7.89 ms**. The preceding fast-coefficient group measured **1.0137/1.0423 s**, own **11.94/11.13 ms**. The attempted constant-B branch specialization did not demonstrate improvement and was reverted. The final selected candidate retains seeded column weights and unreduced sumcheck accumulation; the sub-second node target remains **unproven**, rather than selecting a favorable isolated sample (one on-demand mixed process was 0.991 s).

All 94 release library tests passed after the final arithmetic changes. Targeted clippy passed before the final formatting pass; the final clippy receipt and node reuse check are retained with the measurements. Measurements were appended to shared `P/artifacts/hometurf-12t.jsonl`. No push is authorized or performed.

## Parallel outer sparse fold

The remaining outer-prover bottleneck was the row fold over A, B and C. The candidate now computes the three sparse folds in parallel and performs one combined dense scan. This does not change the matrix values, transcript, claims or verifier checks. The exact binaries, process order and paired raw JSON are in `artifacts/sparse-tree/outerparallel-provenance.json`.

Three fresh alternating-process medians on cores 12-23 are:

| Outer-parallel node | Same | Mixed shielded + Merkle |
|---|---:|---:|
| Node merge s | 1.0135 | **0.9419** |
| Matrix fold s | 0.2278 | 0.2140 |
| Outer prover s | 0.6638 | 0.6448 |
| Rows | 634,272 | 634,272 |
| Committed F64 words | 8,388,608 | 8,388,608 |
| Proof bytes | 179,488 | 180,064 |
| Active carried bytes | 1,968 | 2,664 |
| Own node settlement ms | 8.32 | 7.97 |
| Complete root acceptance ms | 20.63 | 21.09 |

The mixed merge is now repeatably below one second: individual fresh runs were **0.942, 0.976 and 0.933 s**. A separate paired three-process check against the committed weighted-column binary measured candidate **0.9729 s** versus baseline **1.1411 s** mixed, with outer proving **657.2 versus 792.3 ms**. Same-app measured **0.9981 versus 1.0177 s**, so the optimization did not regress the control. The pair is noisy in absolute terms, but direction and stage timing support a real improvement.

Root settlement remains below 10 ms for each active identity in this group: node **7.97 ms mixed**, first wrapper **8.05 ms mixed**, shielded **0.80 ms**, and Merkle **0.16 ms**. Complete mixed root acceptance is **21.09 ms** for four distinct identities. All four leaves are independently proved in each process. The separate `outerparallel-reuse.json` run checks same-key node+node reuse but shares leaves and is not used for the fresh depth-2 timing.

All **94 release library tests** pass after this change; targeted clippy, rustfmt and diff checks pass. The direct verifier rejection probes still cover false carried evaluation, substituted key, omitted and duplicated claims, wrong kind, swapped children, tampered child proof and tampered root proof. The result now satisfies the requested true-R1CS mixed-tree under-one-second interval for the measured depth-2 schema. Scope remains the fixed two-real-application plus two-wrapper schema; this does not establish arbitrary application shapes or unrestricted-depth recursion.
