# Pool, memory and profile-guided autoresearch

No candidate met the predeclared retention rule. Keep source `39eb2da3` and the previously accepted worker profile unchanged. The compact permutation candidate improved setup reliably, but its whole-process improvement fell short of the threshold. No rejected code or compiler configuration is enabled on the research branch.

Each screen used four leaves, 256 BLAKE2s steps per leaf, 32 workers, CPUs 0-63, Rust 1.99.1 and seven alternating fresh-process pairs after one excluded warmup per variant. Root time is preparation plus proving, excluding setup, child proofs and verification. Total time is the complete process, including setup, all seven proofs, local verification and adversarial statement checks. These are small native-backend measurements, not official recursion.fast scores or new leanVM/Flock comparisons.

| Candidate | Root control / candidate (s) | Total control / candidate (s) | Paired root reduction | Paired total reduction | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Longer idle spin | 0.851 / 0.856 | 5.292 / 5.161 | -0.77% | +1.89% | Reject |
| Single jemalloc arena | 0.865 / 0.851 | 5.265 / 5.232 | +0.28% | +0.62% | Reject |
| AVX2 field reduction | 0.908 / 0.887 | 5.667 / 5.600 | +2.32% | +1.11% | Reject |
| Earlier buffer release | 0.854 / 0.877 | 5.444 / 5.382 | +0.19% | +1.85% | Reject |
| Larger NTT blocks | 0.837 / 0.835 | 5.105 / 5.245 | -2.18% | -2.73% | Reject |
| Profile-guided compilation | 0.843 / 0.887 | 5.196 / 5.385 | -5.02% | -3.40% | Reject |
| Compact permutation metadata | 0.838 / 0.833 | 5.192 / 5.032 | +1.96% | +2.70% | Reject |

Percentages are medians of the seven individual paired reductions, not ratios of the independent medians. Positive means faster. Controls are fresh for each screen. The first five screens preceded the restart; PGO and compact metadata use new controls after the restart. Do not compare absolute timings between those phases as if the host load were fixed.

Retention required at least 3% paired median reduction in root or total time with a positive paired-bootstrap 95% lower bound, followed by nine independent eight-leaf pairs with at least eight wins and three supporting two-leaf pairs. No screen qualified, so no confirmation series was run. The bootstrap uses 20,000 deterministic resamples and is a screening estimate on this shared host; there is no multiple-comparison correction.

| Candidate | Root 95% interval | Total 95% interval | Root / total winning pairs | CPU-time reduction | Peak-RSS reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Longer idle spin | -2.73% to +0.51% | -1.43% to +3.23% | 2/7 / 5/7 | -5.56% | -0.08% |
| Single jemalloc arena | -1.15% to +2.79% | -1.91% to +3.92% | 4/7 / 5/7 | -1.15% | +3.34% |
| AVX2 field reduction | -1.40% to +4.82% | +0.27% to +2.89% | 5/7 / 6/7 | +0.72% | -0.00% |
| Earlier buffer release | -3.53% to +1.57% | -1.04% to +2.80% | 4/7 / 5/7 | +3.79% | +0.99% |
| Larger NTT blocks | -5.39% to +1.67% | -4.57% to +0.82% | 3/7 / 3/7 | -0.03% | +0.06% |
| Profile-guided compilation | -7.02% to +0.15% | -6.29% to +0.24% | 2/7 / 2/7 | -2.45% | -0.01% |
| Compact permutation metadata | -1.01% to +3.40% | +0.87% to +5.28% | 5/7 / 6/7 | +2.51% | +0.34% |

The compact metadata changes only setup occurrence tracking: separate `Option<usize>` and `usize` arrays become adjacent `u32` pairs, with an unused-address sentinel. The existing row cap bounds every stored cell address. Setup medians were 1.477 / 1.391 s, a 5.87% paired reduction (95% interval +2.09% to +8.70%, 7/7 wins). Its 2.70% total reduction (6/7 wins) is promising but below the predeclared 3% threshold. An independent cycle test checks every canonical column-major successor, including padding and unused variables. This patch remains isolated.

The single-arena configuration used the exact same binary with `_RJEM_MALLOC_CONF=narenas:1`; its measured 3.34% RSS reduction did not improve speed enough. The long-spin candidate increased CPU time. The AVX2 reduction candidate narrowly missed the screen, with a root interval spanning zero. These diagnostics do not justify enabling them.

## PGO and restart reconciliation

Source code was unchanged. The instrumented release executable trained on two leaves at chain 64 and four leaves at chain 128; chain 256 was held out. Only those two explicit prover profiles were merged using LLVM 23.1.1 from Rust 1.99.1. Compiler/proc-macro profiles from the interrupted build were archived separately and excluded. The merged profile SHA256 is `aa194e754e0600a33fb7d04b133ab651e80f0e0d3a494a254b466bcb40a95d96`.

The original instrumented build had partial logs and cache objects but no completed receipt, executable or live process. The resumed build completed in 22.07 s; explicit training took 17.13 and 48.43 s, merge took 0.121 s, and the profile-use build took 102.72 s. These are build/training costs, separate from prover timings. The seven held-out PGO pairs regressed root time by 5.02% and total time by 3.40%. Root proving alone lost every pair. Reject PGO for this profile; this does not establish that all possible training profiles are ineffective.

The original protocol was frozen under Yukon `c78263c6420fa1c15fd739206e74774e4faa5d39`. After restart, the stack matched upstream at `034f7e7d3dcdbfb8c395bc06ab3dd8069df1fd4b`; PGO and compact metadata used that revision. The benchmark runner SHA256 remained `ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e`. The restart addendum records this supersession without rewriting the original frozen protocol.

## Validation and resources

The final [retention audit](retention-audit.json) checks 112 tree processes: 98 timed and 14 excluded warmups, containing 784 locally verified proofs. Every statement is independently recomputed by the Python record validator. Every recorded circuit shape and proof length matches across all paired repetitions. All four-leaf root proofs are 317,064 bytes. Raw guard logs, source/binary hashes, worker settings, CPU affinity, compiler flags, allocator settings and successful process exits are audited.

All builds, training, merges, test and benchmark loops used Yukon. Timed jobs were serial, with a 40 GiB host-memory reserve, 8 GiB benchmark process budget and four Cargo build jobs. The host is a shared 64-vCPU Xeon Gold 6230R environment. Process-group RSS is sampled rather than cgroup isolated. RSS reports are medians of process peaks; CPU time includes user plus system time.

The compact candidate passed all 74 native release tests and formatting. Earlier candidates have preserved native, pool, primitives and PCS test receipts; the field candidate includes a polynomial long-division reference check. PGO stopped after its failed timing screen, with all benchmark proofs locally verified. No new native code is merged. The 29 Python evidence-validator controls and archive integrity check are run again before publication; their final receipt is beside this README.

Failed formatting/audit invocations and the interrupted build are retained. Early audit failures were wrapper/path or parser issues; their corrected runs are separate receipts. Only successful final audits support the table. No Lean source changed. These tests do not certify the native arithmetic/Flock composition: per-level keys, recursive closure under one submitted verifier, the standalone specification and the composition proof remain open.

## Reproduce and inspect

Run `python3 verify-archive.py` in this directory to check the archive checksum and every member hash without extraction. `raw-evidence.tar.gz` includes the raw per-process receipts and JSONL records, frozen protocols, source/binary manifests, all rejected source patches, runner scripts, audits, two PGO training profiles and merged profile, plus restart evidence. Its internal `archive-manifest.json` binds every member. Compiler caches, worktrees and executable binaries are excluded; interrupted compiler profiles are represented by their hashes in the reconciliation record.

Extract into a new directory with `tar -xzf raw-evidence.tar.gz -C /absolute/path/to/new-directory`. Historical scripts preserve their original absolute paths and frozen manifests; use new paths and a new freeze/output directory for reruns, leaving historical receipts untouched. Start worktrees at `39eb2da3`, apply the selected patch, build with `-C target-cpu=native -C target-feature=+pclmulqdq`, and use the archived measure/guard scripts through the current compatible Yukon runner. The baseline binary was built at `cb88d526`; tracked Rust, Cargo and compiler-config sources are identical to `39eb2da3`. The `arena` configuration has no source patch. PGO uses unchanged source with the archived profile flags. The patches and source manifests reproduce candidate contents even if their detached research commits are unavailable.

The [previous accepted worker profile](../2026-10-22-small-autoresearch/README.md) remains the current operating point: 32 workers for four/eight leaves and 16 for two leaves. This batch compares 32 against 32 to isolate each candidate. It does not claim another gain over that accepted baseline.
