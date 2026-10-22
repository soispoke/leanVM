# Common-key factored index opening

Retained the existing WHIR factored-lane opening path for the native circuit index.

The control is the accepted four-element kernel at a7b0cfa8. This optimization changes prover execution only: circuit/index construction, common setup key, verifier, transcript order, security profiles and serialized proof format are unchanged. These are chain16 local fixtures, not shielded transfers or new matched leanVM/Flock comparisons.

## What changed

The four index claims share one multilinear point and cover four aligned columns. The old opener constructs their combined dense F192 weight. The new path splits the shared equality point into a block table and lane selectors, combines the same batching powers into lane coefficients and calls the existing recursive_prover_with_lane_weights API. At the measured index shape, the dense weight alone is 192 MiB; the factored block table is 3 MiB plus tiny lane/selector vectors. The lane prover also avoids materializing the initial dense-weight folds. This allocation comparison is structural, not a claim about the process peak RSS.

The fast path checks all four claim offsets, dimensions and shared points before sampling any transcript challenge. Other layouts use the original opener. It draws exactly the same batching challenge and target, and the unchanged verifier consumes the same protocol. A differential regression test compares the complete Proof object, including Merkle phases, with the dense reference at rates 1 and 4. Reordered claims exercise the fallback and still produce the exact dense proof. All 77 native release tests pass, including composition and adversarial rejection tests.

## Two-leaf screen

Three alternating fresh-process pairs, three locally verified certificates per process. Positive paired reductions mean faster; paired ratios differ from ratios of independent medians.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.796 | 7.397 | +6.59% | 3/3 |
| All creation | 4.754 | 4.469 | +5.98% | 3/3 |
| Root creation | 1.334 | 1.267 | +5.00% | 3/3 |

## Independent eight-leaf confirmation

Seven new alternating pairs, 15 locally verified certificates per process. Total includes common setup, every leaf and internal creation, explicit verification, serialization/reporting and wrong-root/height rejection. Creation includes recording, child prechecks, witness preparation and proving. Timed jobs are serial.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| Whole process | 23.844 | 23.111 | +3.28% | 6/7 | [+2.70, +4.08]% |
| All creation | 20.799 | 20.015 | +3.73% | 7/7 | [+3.38, +4.40]% |
| Root creation | 1.347 | 1.305 | +1.70% | 6/7 | [+1.36, +5.42]% |
| Setup | 2.729 | 2.700 | +1.65% | 5/7 | [-0.70, +2.14]% |

Decision: retain. Retention requires at least 3% paired median reduction in total or all creation, at least 6/7 target wins, a positive paired bootstrap 95% interval and no companion regression over 1%. Every key, shape, independently recomputed statement and per-position certificate length, scalar count and Merkle phase count matches both variants and the published common-key baseline.

## Validation and provenance

Final targeted Clippy with tests/examples and warnings denied, formatting and strict rustdoc pass. No platform-specific source changed, so the prior kernel feature checks remain applicable. Native and exact-proof differential tests cover the new call path.

Yukon was refreshed and pinned at b6b976274674363634110423c9a85a1652c70bb3 for this phase. Runner SHA256 remains ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. The control reuses the exact frozen, validated quad-release-build executable from the previous accepted phase; normalized Rust/Cargo source hashes match the clean control-v3 worktree, and its executable hash matches the archived build/measurement binding. No redundant control build is included as a performance result. Rust 1.99.1, native CPU plus pclmulqdq flags, 32 workers, CPUs 0-63 and four Cargo jobs. Build/test budget 96 GiB, benchmark budget 16 GiB and host reserve 40 GiB. The shared Xeon Gold 6230R host is not a dedicated benchmark machine. RSS is sampled process-group memory, not cgroup isolation.

The archive retains exact commands, source and binary hashes, build/check receipts, all timed stdout/stderr, the source patch and predeclared retention plan. Its audit binds every timed run to the exact corresponding build source and frozen binary and rejects overlapping admitted intervals. The formatting mutation receipt is false because cargo fmt intentionally changed source hashes. No timed run is excluded in this phase.

Reproduce with the recorded Rust flags and current Yukon: build closed_tree, then run frozen controls/candidates at --depth 1 --chain 16 and --depth 3 --chain 16 in the archived alternating order, using fresh output paths. Run python3 verify-archive.py here to validate archive members and hashes without extraction. Executable binaries and compiler caches are excluded. The long-running performance goal remains active; formal native composition security and official recursion.fast integration remain open.
