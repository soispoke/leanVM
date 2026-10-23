# Client proving loop: native limb transposition

Single samples in two opposite-order full-length pairs and one small-client pair; no medians or statistical confidence claim. Same chain length, seed, 32 prover threads, Yukon wrapper and verification; external host work is not controlled. The branch at f7464bda is the control. Profile harness is identical in all six runs.

Profile first: 16,384 tagged BLAKE2s steps, 12,910,464 stored arithmetic rows and a 2^24 native evaluation domain. The control spends 181 ms compiling the witness, 1.54 s building the arithmetic witness, 3.35 s in the joint commitment, 2.01 s in arithmetic reduction, 2.01 s in the joint opening, and 806 ms in the index opening. These are rounded tracing spans; do not add nested spans together. Hash-input packing still determines much of the row geometry; this candidate changes scheduling, not that geometry.

Candidate: `stack_columns` previously exposed only one task per limb column (12 populated columns). Split each into 4,096-word tasks that remain inside a column. Reserved capacity, zero padding, limb order, field values and all circuit/verifier relations stay the same.

| Pair | Control proof ms | Candidate proof ms | Control arithmetic witness ms | Candidate arithmetic witness ms |
|---|---:|---:|---:|---:|
| full-control-t1 / full-chunk4096-t1 | 10323.297 | 9263.288 | 1540.00 | 1190.00 |
| full-control-t2 / full-chunk4096-t2 | 11727.664 | 8551.936 | 1420.00 | 1200.00 |
| small-control-t1 / small-chunk4096-t1 | 51.688 | 51.939 | 5.19 | 5.94 |

All six proofs verify. Every pair has identical proof size and deterministic BLAKE2s digest, index key, circuit shape, statement, trace-node count and hash-compression count. Full-length proof size is 386,192 bytes; small proof size is 207,320 bytes. Peak process RSS is about 34.4 GB for all full-length runs.

The full-length total-time changes are -10.27% and -27.08%; unrelated stages move substantially too. These are noisy development observations, not a stable speedup estimate. Arithmetic witness construction improves in both full-length pairs. The small sample is 0.49% slower overall. No application-matrix or recursive-tree speedup is inferred from the chain client screen. The seven-workload matrix remains the separate f7464bda integration result.

Edit check: `application-client-chunk-edit-check-t1` failed compilation on a Rust borrow conflict. The corrected `-t2` passed `native_arithmetic::tests::compact_preparation_and_reduction_preserve_every_limb_claim_and_transcript`. No rejection check was removed.

Raw results and gzip-compressed logs retain their original hashes under `receipts/`; original paths, hashes, shapes, keys, digests and stage data are recorded in `summary.json`. `chunk4096.patch` preserves the screened source change. Final source adds only an explanatory comment beyond this patch.

Final verdict: retain the 4,096-word transposition tasks. Formatting, all-target release Clippy with `-D warnings`, and release tests (79 format_recursion, 43 rec_aggregation, 5 ignored, plus doc tests) pass in `application-client-chunk-{fmt,clippy,release}-gate-t1`, with unchanged sources. `git diff --check` passes. No security, Ethereum acceptance or zero knowledge claim.
