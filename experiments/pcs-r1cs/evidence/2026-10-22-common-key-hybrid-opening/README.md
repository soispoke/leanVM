# Common-key hybrid joint opening

Retained hybrid weights and lazy witness folding for joint opening.

The control is the accepted factored-index implementation at a77bfd85. These are chain16 local fixtures, not shielded transfers or new matched leanVM/Flock comparisons. Prover execution changes; keys, circuit shapes, security settings, verifier, transcript order and proof encoding are unchanged.

## Mechanism and checks

The opener keeps ring-switch and strided weights dense only over the aligned ring support. Point claims are grouped by their equality-table prefix and within-lane offset, with batching powers accumulated in lane coefficients. Small point supports stay small rather than becoming padded full-lane tables. Strided claims outside the ring support use the previous dense path.

The first sumcheck rounds fold only the dense support and its corresponding witness. Once that support reaches one lane, each newly encountered partner is folded directly from the original base-field witness using the same challenge prefix. These partner groups are disjoint. The resulting witness includes every committed lane, including lanes with zero initial weight, since those lanes contribute cross terms after challenges. Point messages and dense-support messages are added before each unchanged transcript challenge. Both weight families merge into the original WHIR state after the lane rounds.

The dense-reference regression compares the complete Proof object, including scalars and Merkle phases, at rates 1 and 4. It covers full and truncated lane sets, single-lane and multi-lane dense supports, nonzero support offsets, overlapping point supports, missing partner lanes and zero tails. The basis test independently reconstructs combined weights from point/strided definitions and compares every field element. All 44 PCS tests pass, with one pre-existing ignored test, and all 77 native release tests pass, including adversarial composition checks.

## Two-leaf screen

Three alternating fresh-process pairs. Positive paired reductions mean faster; percentages are medians of paired ratios, not ratios of independent medians.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.473 | 7.430 | +0.13% | 2/3 |
| All creation | 4.576 | 4.384 | +3.18% | 3/3 |
| Root creation | 1.337 | 1.266 | +5.91% | 3/3 |

## Independent eight-leaf confirmation

Seven fresh alternating pairs, each process creating and locally verifying all 15 certificates. Total includes setup, every creation, explicit verification, reporting/serialization and wrong-root/height rejection. Creation includes recording, child prechecks, witness preparation and proving. Timed jobs are serial.

| Measure | Control median | Candidate median | Paired reduction | Wins | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| Whole process (s) | 24.105 | 23.302 | +2.22% | 7/7 | [+1.77, +3.43]% |
| All creation (s) | 21.035 | 20.171 | +3.07% | 7/7 | [+1.45, +4.22]% |
| Root creation (s) | 1.357 | 1.294 | +5.51% | 7/7 | [+0.78, +5.88]% |
| Setup (s) | 2.685 | 2.757 | -2.00% | 3/7 | [-3.08, +4.21]% |
| Sampled peak RSS (GiB) | 8.037 | 6.892 | +14.24% | 7/7 | [+14.17, +14.35]% |

Decision: retain. At least 3% paired median improvement in total or creation, at least 6/7 target wins, positive bootstrap 95% lower bound, no companion regression over 1%, exact keys/shapes/statements/proof geometry.

Every key, shape, independently recomputed statement and per-position certificate length, scalar count and Merkle phase count matches both variants and the published common-key baseline. The two diagnostic tracing processes are excluded from timing medians and included in the provenance/geometry audit.

## Provenance and limits

Yukon was checked against upstream and pinned in an isolated checkout at 77d22d1cf5796fa7ec8d94bfe675967afd680c80. Its benchmark runner is unchanged, SHA256 ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. The offline advisor correctly withheld isolated utility because the input profile was warm-cache evidence. Selection was a research hypothesis, and direct paired runs determine retention.

The control reuses the exact frozen executable from factor-release-build, with normalized Rust/Cargo source hashes checked against control-v4 and the executable hash matched to the accepted factor measurement. Rust 1.99.1, native CPU plus pclmulqdq flags, 32 workers, CPUs 0-63, four Cargo jobs. Build/test budget 96 GiB, benchmark budget 16 GiB, host reserve 40 GiB. This Xeon Gold 6230R host is shared. RSS is sampled process-group memory, not cgroup isolation.

Clippy with tests/examples and warnings denied, formatting and strict rustdoc pass. No platform-specific source changed. An initial compile failed on Rust borrow errors and its receipt is preserved; the corrected differential test and full suites pass. Formatting receipts report a mutation because cargo fmt changed source bytes. No timed observation was excluded. An initial control-reuse helper used a wrong JSON key and stopped before copying; the corrected helper verified 239 source files. No interrupted old PGO job was restarted.

A post-measurement attempt to correct a comment and strengthen test-only coverage failed the binary identity gate: its fresh release executable differed. That publication attempt was rejected. The exact measured source bytes were restored and checked against the measured source manifest, then rebuilt. The publication build matches the frozen benchmark executable exactly. The strengthened test passed before restoration, but publication retains the exact measured implementation and tests. The archive preserves both build receipts and the explicit hash comparison.

The archive retains source and binary hashes, exact commands and tool identities, raw stdout/stderr, predeclared acceptance criteria, candidate patch, check failures and build/check receipts. The audit binds every measured process to its exact build and frozen binary and rejects overlapping recorded intervals. Executables and compiler caches are excluded. Run python3 verify-archive.py here to check archive member hashes without extraction.

Reproduce through current Yukon: build closed_tree with the recorded Rust flags, then run frozen control/candidate executables at --depth 1 --chain 16 and --depth 3 --chain 16 in the recorded alternating order using fresh output paths. This is conditional bounded-height implementation closure; the formal composition/security proof and official recursion.fast integration remain open. The optimization goal remains active.
