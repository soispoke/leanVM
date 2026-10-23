# Common-key padding-witness template

Rejected padding witness memoization under the frozen rule; accepted Rust sources restored.

The control is the accepted hybrid opener at f23eddd9. The prior AVX2 candidate is absent. Each fixture uses chain16 with two or eight leaves, creating and locally verifying every node in the binary tree. These are local research fixtures, not matched new leanVM/Flock benchmarks or shielded-transfer measurements.

Unused BLAKE2s slots contain the same valid compression instance, including its pinned constant wire. The generator previously rebuilt each padding instance and transposed each padding group. It now synthesizes one eight-block group and its lincheck stripe once per invocation, then streams those exact bytes to fully padded groups. Mixed groups retain the original per-instance path. Every witness byte, commitment, reduction, verifier, transcript order, key and proof encoding is preserved.

The generic reference test reconstructs every output word and every stripe byte independently, covering all 0–32 live-block counts, zero/nonzero/no padding, and block widths64/512/16384 bits. A BLAKE2s differential compares all four output buffers against explicitly materialized real padding blocks for every 0–32 live count. A full materialized input has no template path. Full release validation passes71 Flock,77 native recursion and44 PCS tests (one existing ignore), Clippy with tests/examples and warnings denied, formatting and PCS/native rustdoc. No architecture-specific source changes. The inherited broader Flock rustdoc link failure is documented in the preceding AVX2 experiment.

## Three-pair two-leaf screen

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.286 | 7.391 | +1.41% | 2/3 |
| All proof creation | 4.314 | 4.340 | -0.73% | 1/3 |
| Root creation | 1.251 | 1.244 | -0.60% | 1/3 |

Retention requires at least3% paired median improvement in total or creation, at least6/7 independent target wins, positive bootstrap95 lower bound, no companion total/creation regression over1%, and exact keys/shapes/statements/proof geometry. Every timed observation is retained. Paired reductions are medians of per-pair ratios, which need not equal a ratio of medians.

The audit independently reconstructs all leaf and aggregate statements, checks every key and shape plus per-position certificate byte/scalar/Merkle-phase counts against the published common-key baseline, binds each process to its source manifest and frozen build, and rejects overlapping timed intervals. The exact measured source bytes are retained on acceptance; rejected source changes are restored after archiving the patch.

Yukon advanced during the preceding phase. This phase pins the latest checked upstream ca3f535; its benchmark runner is unchanged (SHA256 ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e). The added read-only process observation tool is used before/after the measurements for context, with no scheduling authority or speedup claim. The first generic check preceded the upgrade; the stronger two-test check and every full gate/timed process use ca3f535.

Rust1.99.1, native CPU plus pclmulqdq,32 workers,CPUs0–63,four Cargo jobs. Build/test budget96GiB, benchmark budget16GiB, host reserve40GiB. The Xeon Gold6230R host is shared; RSS is sampled process-group memory, not cgroup isolation. The existing frozen control is reused only after its build/source/binary identity is checked.

The archive preserves exact commands, raw logs, source and binary hashes, frozen-control provenance, candidate patch, predeclared plan, checks and all timing receipts. Run python3 verify-archive.py to verify member hashes without extraction. Formal composition/security proof and official recursion.fast integration remain open. The optimization goal remains active.
