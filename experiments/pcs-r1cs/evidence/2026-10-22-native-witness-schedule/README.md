# Reusing the native witness computation schedule

Recording the helper-value schedule once during setup reduces root preparation + proving time by **7-13%** against the previous native implementation. The eight-leaf root takes **1.016 s**, versus leanVM's **1.075 s**, in seven matched trials. At four leaves the candidate remains about 4% slower than leanVM. These are local implementation measurements, not an architectural ranking or official recursion.fast score.

## Repeated results

All backends prove the same tagged BLAKE2s tree, using their own child proofs. Each workload has rotating fresh-process trials after one excluded warmup per backend. Rust 1.99.1, 16 workers on CPUs 0-15, Intel Xeon Gold 6230R, shared Linux host. Times are medians in seconds.

| Leaves / aggregation levels | Steps per leaf | Trials per backend | Previous native root | New native root | Time reduction | leanVM root |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 / 1 | 16 | 3 | 1.060 | 0.987 | 7.0% | 1.195 |
| 4 / 2 | 16 | 3 | 1.313 | 1.203 | 8.3% | 1.156 |
| 8 / 3 | 16 | 7 | 1.163 | 1.016 | 12.6% | 1.075 |
| 8 / 3 | 256 | 3 | 1.149 | 1.012 | 11.9% | 1.094 |

Root creation includes recording, fresh helper-value evaluation, witness preparation and proving. It excludes setup, child proving and final verification. The reduction is `1 - new median / previous median`. Every adjacent baseline/candidate pair improves. At eight 16-step leaves, the native range is 1.002-1.084 s and the VM range is 1.032-1.177 s. All seven adjacent VM pairs favor native, but some differences are below 1%; the median paired reduction versus VM is 3.25%, compared with 5.47% from the ratio of medians. These overlapping shared-host ranges do not establish general parity or dominance.

The 256-step run repeats the improvement on longer leaves. It remains much smaller than the historical 16,384-step leaf workload. Complete values, paired reductions, memory and ranges are in [audit.json](audit.json) and the four `schedule-depth*/summary.json` files.

### Other costs, eight leaves and 16 steps per leaf

| Metric | Previous native | New native | leanVM |
| --- | ---: | ---: | ---: |
| Root proving alone (s) | 1.087 | 0.946 | 0.988 |
| Full root verification in Rust (ms) | 6.05 | 6.20 | 18.63 |
| Complete root proof (bytes) | 317,512 | 317,512 | 324,064 |
| Whole process, median (s) | 10.02 | 9.03 | 9.53 |
| Sum of per-level setup, median (s) | 2.07 | 2.09 | 1.13 |
| Maximum process RSS (GiB) | 5.04 | 4.90 | 3.52 |

Whole-process time includes setup, all proofs, verification and negative checks, with up to about 0.5 s of completion-poll delay. It is an approximate whole-run measure. Setup now records a schedule; its cost is reported rather than hidden by the root timer. Retaining the schedule can increase memory: maximum two-leaf RSS is 2.92/3.02 GiB for previous/new native. The eight-leaf native process still uses more memory than the VM comparison. Every benchmark stays below the 32 GiB process budget and retains at least 40 GiB system memory headroom.

The verifier algorithm is unchanged; the small native verification-time difference is not an algorithmic improvement. The VM wrapper forwards authenticated deferred records across level programs and discharges them at the root. Its growing verification cost is not an inherent cost of upstream leanVM's fixed-program recursion.

## What changed

The compiler used to rebuild circuit rows, variable mappings and hash connectors for each witness. Setup now records a straight-line computation schedule for helper values. Each proof evaluates that schedule on fresh witness values. All program operations, equality checks, public-output positions and constant values are still checked for identity before evaluation. Public values must match the caller's statement, and the complete arithmetic and hash arguments are still proved.

The schedule stores public constants and variable identities, rather than private witness values or cached proofs. BLAKE2s compressions are recomputed from fresh inputs. Circuit rows, variable IDs, connectors, public inputs, security parameters and verifier code remain unchanged. Every corresponding baseline/candidate benchmark has identical circuit geometry and proof lengths. The original compiler remains available as the differential reference. Diagnostic profiles show root witness compilation falling from about 183 ms to 42 ms; these profiles are separate from the repeated timing results.

## Source and validation

Candidate source: `cb88d52698be5ef640d4d15d1dd5e6caa553c70e`, parent `8a8e8adaeecccdf89ada2c9c7ac4ace39ab8f5a5`. Previous native binary source: `f50dd22cc994596dd48695ac49c5e3f9b2aef1ae`. VM reference: `bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47`. [candidate.patch](candidate.patch), [freeze.json](freeze.json) and [REVIEW.md](REVIEW.md) retain the exact change, source/binary hashes and review. The baseline source differs from the candidate's parent only in reporting/evidence files.

All **73 native release library tests** passed, including every-helper-value differential checks for hashing, field arithmetic, projections, Frobenius and malformed intermediate values. The leaf test checks complete serialized proof equality against reference lowering. Final release build and all-target Clippy for `format_recursion` and `rec_aggregation` passed with warnings denied. All **29 Python evidence-validator tests** passed. All **60 complete tree processes**, including warmups, passed local verification and independent Python BLAKE2s statement checks. The [audit](audit.py) rechecks summaries, warmups, guard/log hashes and source/binary freezes. Final test/build/Clippy source hashes match the measured freeze.

This is a prover optimization with runtime and source-review evidence. No Lean source changed. Existing quotient and structured-R1CS theorems do not certify this native composition, concrete PCS or Rust implementation. Separate trusted keys per level, recursive closure under one submitted verifier and zero knowledge remain unresolved.

## Reproduction and provenance

Build each source revision in a fresh Cargo target directory with Rust 1.99.1 and `RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'`. Use `cargo build --locked --release -p rec_aggregation --example private_tree` for the native sources and the `chain_tree_vm` example for the VM source. Set `LEANVM_NUM_THREADS=16`. Run `private_tree --depth 3 --chain 16`, or the VM with the same flags plus `--log-inv-rate 1`, through [run.py](../../recursion/run.py) and memguard. The depth/chain/trial combinations are in the table above. Substitute new executable paths and record their hashes when replaying on another machine.

[measure.py](measure.py) retains the exact rotating schedules. [run-command.py](run-command.py) records admission, CPU affinity, source hashes and time/memory limits. These scripts and [audit.py](audit.py) refer to the original absolute workspace paths. Replaying them requires restoring those workspaces or adapting the paths; executables and build caches are not committed. `edit-schedule.py` is an intermediate development script; the committed source and `candidate.patch` are authoritative.

Yukon matched upstream at phase start, revision `e9857575725d6e20d18c07bc540edcfba298152e`. The shared clean checkout advanced to **`58b0915ae37a851bcd770734b1a397274fc83d22` before measured trials**, and all benchmark receipts record that revision. The archived [benchmark runner](bench-research-used.py) is byte-identical across both revisions, SHA256 `ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e`. [tooling-advance.json](tooling-advance.json) records the change. The initial audit rejected its stale tooling-pin assertion; the corrected audit checks both the measured pin and exact runner hash. Original receipts remain unchanged. Yukon records development work; it is not itself a Rust prover speedup, and no Lean accelerator was used. [MANIFEST.json](MANIFEST.json) hashes every evidence file except itself.
