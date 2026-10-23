# Sparse carried-claims tree, work in progress

The first-level true sparse-R1CS mixed merge has reached a three-process median of **0.975 s** for independently proved shielded plus the merge-circuit application. Shielded plus a new depth-16 BLAKE2s Merkle membership application takes **0.752 s**. A complete mixed tree has not been established: the reusable app-independent node wrapper and depth-2 measurement remain outstanding, and outer claim settlement remains above 10 ms. These are prototype measurements and regression checks, not a security claim.

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

Remaining requirements: implement one reusable node wrapper whose key does not depend on application identities or contents; fold carried claims and child outer claims across levels; prove and measure a depth-2 mixed tree; target verifiers directly with all requested rejection mutations, including omission, duplication, wrong kind and child swap; optimize settlement and measure complete root acceptance by distinct application count. Current tests do not establish those unimplemented requirements. Verdict for the full mixed-tree question: **not yet established**, despite sub-second first-level mixed results.
