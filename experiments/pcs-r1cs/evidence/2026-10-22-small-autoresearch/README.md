# Small-tree autoresearch: retain 32 workers for larger small trees

On this shared Xeon Gold 6230R host, 32 workers improve four- and eight-leaf native recursion relative to 16 workers. The independently validated eight-leaf result improves every one of nine paired trials: the median paired reduction is 20.1% for root preparation plus proving and 11.7% for whole-process time. Both configurations use exactly the same frozen prover binary, statement, parameters and CPU affinity. This is a host-specific operating-point improvement using twice as many workers, not an algorithmic or protocol speedup.

## Retained result

Each leaf has 256 tagged BLAKE2s steps. Trials alternate fresh processes after one excluded warmup per configuration and workload. Both configurations may run on CPUs 0-63; only `LEANVM_NUM_THREADS` changes. Reported times are medians; reduction percentages are medians of the paired reductions, which need not equal the ratio of the two medians.

| Leaves | Pairs | Root, 16 workers (s) | Root, 32 workers (s) | Paired root reduction | Total, 16 workers (s) | Total, 32 workers (s) | Decision |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 2 | 3 | 1.302 | 1.272 | 1.6% | 2.555 | 2.645 | Keep 16 workers |
| 4 | 3 | 1.024 | 0.831 | 18.9% | 5.593 | 5.188 | 32-worker supporting check |
| 8 | 9 | 1.015 | 0.809 | 20.1% | 10.958 | 9.611 | Retain 32 workers |

The two-leaf root difference is inconclusive and its total time regresses in two of three pairs, so 32 workers is not retained for that case. The four-leaf result is a three-pair supporting check: every pair improves root and total time. The primary retention decision uses nine new eight-leaf pairs, separate from the initial worker-count screen.

| Eight-leaf validation detail | 16 workers | 32 workers |
| --- | ---: | ---: |
| Root proving alone, median (s) | 0.945 | 0.738 |
| Complete root proof (bytes) | 317,608 | 317,608 |
| Maximum process RSS (GiB) | 4.692 | 4.822 |
| Root wins for 32 workers | | 9 / 9 |
| Whole-process wins for 32 workers | | 9 / 9 |

The paired bootstrap median 95% intervals are 18.9-22.9% for root preparation plus proving and 11.46-13.37% for whole-process reduction. This is a descriptive paired bootstrap on nine shared-host trials, not a cross-machine guarantee. Every corresponding proof length and all recorded circuit geometry match, including leaf and intermediate proofs, not only the root. The retained validation contains 36 tree processes including warmups and 380 locally verified proofs with independently recomputed statement digests.

Root creation includes symbolic preparation and native proving, excluding key setup and child proving. Whole-process time includes per-level setup, every proof, verification and negative checks. Validation uses a copy of the existing recorder with exit polling reduced from 0.5 s to 0.01 s. Its only other change fixes the original checkout path after moving the recorder; [run-original.py](run-original.py) and [run-precise.py](run-precise.py) retain both versions. Both worker configurations use the same recorder. The Yukon outer wrapper remains the resource and source-hash guard.

## Rejected experiments

| Idea | Workload | Repeats | Paired root reduction | Root wins | Decision |
| --- | --- | ---: | ---: | ---: | --- |
| Wordwise projections and fewer trace-hash allocations | 8 leaves, 16 steps | 9 pairs | 1.6% | 5 / 9 | Reject |
| Direct parallel stack initialization, removing overwritten zero-fill | 4 leaves, 256 steps | 7 pairs | 1.8% | 5 / 7 | Reject |
| Fewer workers | 4 leaves, 256 steps | 3 each | Slower | | Reject 4 and 8 workers |
| More workers beyond the winning point | 4 leaves, 256 steps | 3 each | Total slower | | Reject 64 workers |

The wordwise candidate improves root preparation alone by 16.2% in the paired median, but does not produce a robust gain in root preparation plus proving or whole-tree time. Its root interval includes slowdowns. The stack candidate has a misleading 6.521/6.022 s gap between whole-process medians; its median paired process reduction is only 0.084%, below the predeclared 3% threshold. Neither source change is applied to the branch. Their patches, checks and complete trials remain in this evidence directory.

The 4/8/16-worker screen uses CPUs 0-15 and takes 13.028/8.018/6.018 s, respectively. The separate 16/32/64-worker screen uses CPUs 0-63 for every setting and takes 6.013/5.513/8.570 s. These are coarse whole-process medians with the original recorder. The screen selected 32 workers for independent validation; it is not substituted for that validation.

A mathematically zero first zerocheck message was considered and rejected before implementation. The diagnostic profile puts the entire native zerocheck at about 22 ms, roughly 2% of root proving; its end-to-end ceiling was too low. Larger measured costs were the initial commitment and joint PCS opening. [stack-profile](stack-profile) is diagnostic evidence, separate from matched timings. [small-protocol.md](small-protocol.md) records the staged decisions and retention criteria.

## Checks and provenance

The accepted profile changes no Rust source, verifier, circuit, setup, security parameter or proof format. Baseline executable SHA256 is `6f45d0259d44c1daae02148388b33624da775be5f1ebe329824a3777514f918b`, built at `cb88d52698be5ef640d4d15d1dd5e6caa553c70e`. Native source remains the published witness-schedule source. [trace-freeze.json](trace-freeze.json) and every worker plan bind the exact binary; receipts bind source hashes, thread settings, affinity, raw logs and guard outcomes.

Both discarded source candidates passed 74 native release library tests, release builds, all-target Clippy for `format_recursion` and `rec_aggregation` with warnings denied, and final formatting checks. The trace candidate reuses its final unchanged-source test receipts from the preceding work phase and has a fresh current-stack build. The stack candidate has fresh final tests and checks. Intermediate formatting failures are retained rather than hidden. [trace-rejected.patch](trace-rejected.patch) and [stack-rejected.patch](stack-rejected.patch) reproduce the discarded edits.

All 96 timed tree processes in this research batch, including warmups, are retained and independently validated. Their 960 proof records all report successful local verification. The diagnostic profile is one additional process. [audit-workers.py](audit-workers.py) checks raw guard-log hashes, independent statements, source-commit/binary identity, common environments except worker count, every shape and every proof length. [audit-series.py](audit-series.py) audits the discarded source candidates. [workers-audit.json](workers-audit.json) contains exact medians, paired trials and intervals. The existing Python evidence-validator suite is also rerun through Yukon before publication.

Yukon matched upstream at phase start: `578a2f8e21c59c8904525f966d6a9368d3c16d40`. [tooling.json](tooling.json) and [bench-research-used.py](bench-research-used.py) retain the exact tooling revision and unchanged runner hash. Rust 1.99.1 uses `-C target-cpu=native -C target-feature=+pclmulqdq`. No Lean source or accelerator changed. The tooling is the experiment pipeline, not the source of the prover speedup.

## Reproduce and limits

Build the witness-schedule source with the flags above. For the retained eight-leaf setting, run `private_tree --depth 3 --chain 256` with `LEANVM_NUM_THREADS=32`, and repeat with 16 workers as the control. Pin both runs to CPUs 0-63 through Yukon, preserve 40 GiB of host memory reserve, allow 8 GiB per process, alternate order, and exclude a warmup per setting. Use depth 2 for the four-leaf supporting case; keep 16 workers for the two-leaf case. The archived measurement scripts retain exact schedules and original absolute paths; replay on another machine requires path adaptation and a new binary hash.

This result makes no new comparison with leanVM or Flock and does not extrapolate to 16,384-step leaves, 256-leaf trees or another CPU. The [partial full-length checkpoint](../2026-10-22-full-recursion/README.md) preserves the earlier available results. Separate keys per recursion level, general recursive closure, a small protocol specification and a formal proof of the new composition remain open. [MANIFEST.json](MANIFEST.json) hashes all evidence files except itself.
