# Flock baseline with BLAKE2s

The BLAKE2s adaptation of Succinct Flock completes the full recursive tower and verifies its serialized root against a separately generated verification key. Three repeated trials passed. Setup and the implementation's native self-checks dominate its measured cost.

This uses [Succinct Flock](https://github.com/succinctlabs/flock/tree/b684b1258e4b1f202bec24afd660ace851b09e5e), adapted at source `554435d5`. It retains Flock's Ligerito PCS, F128/F256 fields, recursive tower and residual checks. The chain, Merkle commitments and transcript use BLAKE2s; circuit and registry identifiers retain BLAKE3.

## Measured baseline

Eight sequential segments of 256 hash steps, folded into one root. Each step hashes a 64-byte state with BLAKE2s-256 and zero extends its digest to 64 bytes. Each trial creates 15 proofs, including the steady recursive spine.

| Metric | Median of three trials |
| --- | ---: |
| Final recursive stage, online preparation + proving + inline self-checks | 13.392 s |
| Proving component within that stage | 1.893 s |
| Full serialized-root verification, including residual discharge | 10.337 s |
| Complete tower creation, including shape setup and builder checks | 209.422 s |
| Complete serialized root bundle | 414,354 bytes |
| Core proof within that bundle | 321,150 bytes |

The final online stage ranges from 13.366 to 14.050 s. Its native replica checks take a median 11.426 s, including 6.668 s of accumulator self-discharge. Reporting only the 1.893 s proving component would omit most of the work. Root shape setup takes another 50.131 s. These direct wall timers have different boundaries; phase medians should not be added as an exact total.

The trials run in one process with a shared immutable verification key, generated separately from a six-leaf reference tower in 142.402 s. They retain each trial's shape setup and all checks, with no excluded warmup. Tables and memory pools can remain warm. Total process time is 837.666 s; maximum process RSS is 7.714 GiB. Hardware is the same shared Xeon Gold 6230R used for the native/leanVM series, with 16 workers on CPUs 0-15 and Rust 1.99.1. The 32 GiB sampled guard and 40 GiB global reserve passed.

## Comparison scope

The [matched native/leanVM results](PRIVATE.md#latest-repeated-comparison) prove tagged 32-byte chains and a balanced statement tree, with 16 steps per leaf. This Flock baseline proves a sequential 64-byte-state chain with 256 steps per segment. They also use different PCS implementations. These numbers establish a working Flock baseline; dividing their times would not give a matched speedup.

This is a literal port with avoidable overhead, including a second transcript compression on absorb rows whose high digest is unused. It does not establish the performance limit of Flock or BLAKE2s recursion.

## Validation and parameters

All 45 trial proof stages completed. Every serialized root passed the standalone consumer verifier; all three endpoints match an independent Python BLAKE2s calculation. Each trial rejected nine encoding, statement, public-input, commitment and leaf-size mutations, 27 rejections in total. The feature library suite passed 63 tests; the final default library suite passed 63 tests, with 24 ignored in each configuration. The final feature build and package library/example Clippy passed. Nine Python record-validation controls passed.

The port uses the upstream Chain128 profile adapted to BLAKE2s, with the unchanged embedded Fast/Slim query and grinding schedules. Additional transcript constraints require an m30 envelope, 63 lanes and capacity 2^15 per slot. It uses RS zerocheck; AG is unsupported. A transcript step obtains 64 real output bytes from two domain-separated BLAKE2s compression calls, rather than using zero compatibility outputs as challenges.

The port, compression duplex, concrete PCS and Rust implementation have no new formal security certificate. The earlier quotient/R1CS Lean theorems do not certify them. These are local implementation results, not an official recursion.fast score or a zero-knowledge claim.

## Evidence and reproduction

The [evidence record](../evidence/2026-10-22-flock-blake2s-baseline/README.md) contains the patch against pinned upstream, all 396 source hashes, exact build/runtime provenance, failed attempts, raw logs and independently checked summaries. The patch was applied to a fresh upstream source archive and reproduced all 396 files exactly.
