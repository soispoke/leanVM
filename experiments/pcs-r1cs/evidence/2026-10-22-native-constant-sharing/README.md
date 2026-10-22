# Sharing public constants in native recursion

Sharing duplicate public constants reduces root preparation + proving time by **18% at four leaves and 27% at eight leaves** in this repeated series. The two-leaf change is within timing noise. The eight-leaf candidate takes 1.183 s versus leanVM's 1.091 s, about 8.5% longer. These are local implementation measurements, not an architectural ranking or official recursion.fast score.

## Repeated results

Each workload uses three fresh-process trials per backend, rotating execution order, after one excluded warmup per backend. All backends prove the same tagged BLAKE2s statements, each using its own child proofs. Rust 1.99.1, 16 workers, CPUs 0-15, Intel Xeon Gold 6230R, shared host. Times below are medians in seconds.

| Leaves / aggregation levels | Hash steps per leaf | Previous native root | New native root | Time reduction | leanVM root |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 / 1 | 16 | 1.112 | 1.101 | 1.0% | 1.300 |
| 4 / 2 | 16 | 1.709 | 1.395 | 18.3% | 1.228 |
| 8 / 3 | 16 | 1.629 | 1.183 | 27.3% | 1.091 |
| 8 / 3 | 256 | 1.602 | 1.163 | 27.4% | 1.100 |

Root creation includes recording, lowering, witness preparation and proving. It excludes setup, child proving and final verification. Every complete tree is also built and verified; setup and intermediate work remain in the raw records. The reduction is `1 - new median / previous median`. The paired reductions, ranges and exact values are in [audit.json](audit.json) and the four `summary.json` files.

At two leaves the adjacent changes are +3.0%, -10.6% and +1.2% time reductions, so there is no clear gain. Every four-leaf pair improves by 16.5-21.7%, and every eight-leaf pair with 16 steps improves by 24.3-27.5%. The 256-step run independently repeats the deeper-root improvement, while remaining much smaller than the earlier 16,384-step leaf workload.

### Other costs, eight leaves and 16 steps per leaf

| Metric | Previous native | New native | leanVM |
| --- | ---: | ---: | ---: |
| Root proving alone (s) | 1.565 | 1.101 | 1.002 |
| Full root verification in Rust (ms) | 6.08 | 6.82 | 18.90 |
| Complete root proof (bytes) | 336,152 | 317,512 | 324,064 |
| Whole process (s) | 12.03 | 10.03 | 9.53 |
| Maximum process RSS (GiB) | 7.64 | 5.04 | 3.53 |

These measurements do not improve every metric: native root verification is slightly slower in this series. Whole-process time includes setup, all proofs, verification and negative checks, with up to about 0.5 s of completion-poll delay. It is not a precise proving-only timer. Peak RSS is a process high-water mark. Every run stayed below the 32 GiB budget and retained at least 40 GiB system memory headroom.

The VM comparison wrapper forwards authenticated deferred records across level programs and checks all of them at the root. Its increasing verification time does not represent an inherent cost of upstream leanVM's fixed-program recursion.

## What changed

The recorder used to emit a fresh node for every occurrence of the same public constant. The compiler then added equality rows binding the duplicates. A small cache now reuses the original constant node, keyed by all three field limbs. Private inputs retain separate identities, even when their values happen to match. The cache resets whenever the active trace changes.

| Native arithmetic level | Previous actual / padded rows | New actual / padded rows |
| --- | ---: | ---: |
| 1 | 769,536 / 1,048,576 | 720,384 / 1,048,576 |
| 2 | 1,079,296 / 2,097,152 | 1,013,760 / 1,048,576 |
| 3 | 1,110,016 / 2,097,152 | 1,044,480 / 1,048,576 |

The largest gain comes from halving the padded arithmetic table at levels two and three. This is shape dependent: the new level-three circuit is only 4,096 rows below the next threshold. A different workload or future verifier change can lose that benefit. Native field rows are not VM cycles or Boolean-format rows.

## Source, checks and scope

Previous measured source: `f1b6626fc546956085f4512d8210f715e6dd256b`, with the same Rust/configuration/formal sources as the published `7591db25` checkpoint. Candidate: `f50dd22cc994596dd48695ac49c5e3f9b2aef1ae`. VM reference: `bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47`. [constants.patch](constants.patch), [source audit](source-audit.json), [source and binary freeze](constants-freeze.json), and [source review](REVIEW.md) retain the exact change and its checks.

All 72 native release library tests passed, including malformed connector proofs, fixed-program binding, private-input independence and constant-cache lifecycle tests. All-target release Clippy passed for `format_recursion` and `rec_aggregation` with warnings denied. All 29 Python evidence-validator tests passed. All 48 complete tree processes in the new series, including warmups, passed local verification and independent Python BLAKE2s statement checks. [audit.py](audit.py) recomputed every retained summary, checked guard/log hashes and rechecked both source/binary freezes.

The verifier source, hash functions, transcript domains, opening profiles, security parameters and Lean sources are unchanged. The recorder emits different circuits, so setup keys change. Runtime tests and source review are the evidence for this translation change; there is no new Lean equivalence theorem. Existing quotient and structured-R1CS theorems do not certify this native composition, concrete PCS or Rust implementation. Separate trusted keys per level, recursive closure under one submitted verifier and zero knowledge remain unresolved.

A separate preprocessing experiment, `63e390ad`, passed 71 release tests and Clippy but improved median root creation only 0.38%, with mixed paired results. It was not promoted. Its patch, freeze, checks and complete measurements are retained under `rejected-preprocessing.patch`, `preprocessing-*`. Initial failed tool invocations and superseded checks are also preserved; final validation uses `constants-tests-v2`, `constants-build-v2` and `constants-clippy`.

## Reproduction and evidence

Build the source revisions above using the pinned Rust toolchain and `RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'`. Use `cargo build --release -p rec_aggregation --example private_tree` for the candidate and previous native sources, and the `chain_tree_vm` example for the VM. Set `LEANVM_NUM_THREADS=16`. Run `private_tree --depth 3 --chain 16`, or the VM with the same flags plus `--log-inv-rate 1`, through [run.py](../../recursion/run.py) and memguard. Substitute your executable paths and preserve new hashes when replaying the archived schedules on another machine.

[measure-constants.py](measure-constants.py) freezes the initial eight-leaf schedule. [measure-constants-more.py](measure-constants-more.py) accepts depth and optional chain length for the other workloads. [run-compiler-command.py](run-compiler-command.py) applies Yukon admission, affinity, source hashing and time/memory limits. Paths refer to the original research workspace; executables and build caches are not committed.

Yukon was clean and equal to upstream at `e9857575725d6e20d18c07bc540edcfba298152e`. The exact [benchmark runner](bench-research-used.py) is archived. It accelerates and records development; it is not itself a Rust prover speedup, and no Lean accelerator was used in this phase. [MANIFEST.json](MANIFEST.json) hashes every evidence file except itself.
