# Native arithmetic and private hash batching

The latest native candidate matches leanVM on the measured two-child parent, but remains slower on deeper trees. It verifies faster in Rust and has larger proofs. These local implementation measurements use the same tagged hash-chain statement, with a separate trusted circuit and key at each level.

A separate [Succinct Flock baseline adapted to BLAKE2s](FLOCK_BASELINE.md) is now measured. It uses a different sequential chain workload and is not a matched speed comparison.

## Construction

The outer proof combines native GF(2^192) arithmetic constraints, Flock's batched BLAKE2s argument and WHIR openings. A shared committed connector table binds the arithmetic verifier and hash argument to the same inputs and outputs. Hash messages and intermediate chaining values stay in the witness; the proof contains no separate request table. This is not a zero-knowledge claim.

Each parent checks both complete child verifiers and hashes their ordered statement digests. This backend extends the original Boolean full-adder format. Its native field rows are neither Boolean rows nor VM cycles.

## Latest repeated comparison

Source `f1b6626f`, 16 workers, CPUs 0-15 and 16 hash steps per leaf. Trials alternate execution order and exclude one warmup process per backend and workload. Times include root preparation and proving; setup and child proving are separate. Each backend verifies its own child proofs. Full verification and proof size include auxiliary records.

| Leaves / aggregation levels | Trials | Native root creation (s) | leanVM root creation (s) | Native / leanVM verification (ms) | Native / leanVM proof (decimal KB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 / 1 | 7 | 1.042 | 1.097 | 5.61 / 11.51 | 325.4 / 284.4 |
| 4 / 2 | 3 | 1.700 | 1.097 | 5.89 / 15.46 | 338.3 / 318.4 |
| 8 / 3 | 3 | 1.581 | 1.100 | 6.34 / 18.78 | 336.2 / 324.1 |

The two-child ranges are 1.006-1.080 s for native and 1.051-1.234 s for leanVM. All seven adjacent pairs favor native. At four and eight leaves, native root creation is about 55% and 44% slower, respectively. Whole-tree process times, memory, raw records and limitations are in the [repeat series](../evidence/2026-10-22-native-matched-repeats/README.md). The prior diagnostic candidate was separately repeated: 1.231 s versus leanVM's 1.081 s, confirming its remaining gap.

The new work fuses multiply-add constraints, batches fourteen range words per hash block, packs three connector words into a native row, shares evaluation weights, caches immutable compiler analysis and prepares the compact joint witness directly. All 70 native release tests, all-target Clippy, the three matched VM wrapper tests, upstream two-to-one recursion, the 20 Python record-validator controls and formatting passed. The source and axiom scope below is unchanged. These shallow results do not establish general parity or architectural dominance.

The following sections retain earlier measurements at their original source revisions.

## Improvement over the original native prototype

Three alternating baseline/candidate pairs use four 16-step leaves and two binary aggregation levels, with 16 workers pinned to CPUs 0-15. The original binary is built from `eb8985ce`; the candidate is built from `d87e4322`. Both prove the same statements. [Validated records](../evidence/2026-10-22-private-index4-performance/optimization.json), [paired gains](../evidence/2026-10-22-private-index4-performance/paired-gains.json) and the [frozen schedule](../evidence/2026-10-22-private-index4-performance/measure.py) retain every trial.

| Metric | Original | Checkpoint `d87e4322` |
| --- | ---: | ---: |
| Whole process, median (s) | 16.05 | 8.03 |
| Peak process RSS, maximum (GiB) | 15.58 | 7.45 |
| Root proving, median (s) | 3.923 | 1.902 |
| Total root proof (decimal KB) | 634.1 | 338.9 |

The median paired process speedup is 2.00x. Process time includes setup, leaf proofs, verification and negative checks, plus up to about 0.5 s of completion polling delay. It is an approximate whole-run measure, not a precise proving-only timer.

The changes prune authenticated zero lanes, reuse evaluation weights, prepare witnesses in parallel, avoid redundant limb decomposition and compact the joint witness stack. Public constant folding only uses values explicitly pinned by circuit constraints. The joint commitment uses code rate 1/4; the fixed index uses 1/16. These select existing production WHIR parameters targeting 128-bit round-by-round soundness, with the rates bound into the transcript. This parameter target is not a formal security theorem for the full native composition.

## Earlier matched comparison with leanVM

Two child proofs to one parent, 16 chain steps per leaf. Medians of three rotated trials on the same deterministic fixture, 16 workers and CPU affinity 0-15. Each backend verifies its own child proofs, so proof formats and verifier work differ. Setup is excluded from parent creation and reported in the raw records. All auxiliary records count in proof size and full verification.

| Implementation and WHIR profile | Parent preparation + proving (s) | Full Rust verification (ms) | Total root proof (decimal KB) |
| --- | ---: | ---: | ---: |
| Native, joint 1/4 and index 1/16 | 2.127 | 5.76 | 337.1 |
| leanVM, rate 1/2 (default) | 1.058 | 11.43 | 284.4 |
| leanVM, rate 1/4 | 1.137 | 11.04 | 196.4 |

The [validated comparison](../evidence/2026-10-22-private-index4-performance/matched-depth1.json) includes prover-only timing, ranges, peak memory and source/binary provenance. The earlier [request-table bridge](NATIVE.md) is a different implementation and workload.

### Three aggregation levels

Eight 16-step leaves, 15 proofs per process, three rotated trials per implementation:

| Implementation and WHIR profile | Root preparation + proving (s) | Full Rust root verification (ms) | Total root proof (decimal KB) |
| --- | ---: | ---: | ---: |
| Native, joint 1/4 and index 1/16 | 1.843 | 6.22 | 338.7 |
| leanVM, rate 1/2 (default) | 1.041 | 18.65 | 324.1 |
| leanVM, rate 1/4 | 0.944 | 19.03 | 203.1 |

The [VM wrapper](VM_TREE.md) forwards authenticated deferred claims because its program changes at each level. The root discharges all seven records at depth three. This is a diagnostic wrapper, not upstream leanVM's same-program fixed-point construction; its growing verification cost is not an inherent VM cost. [Validated deeper records](../evidence/2026-10-22-private-index4-performance/matched-depth3.json).

## Earlier full-length leaves

One process proves eight distinct 16,384-step hash chains, four parents, two grandparents and a root. All 15 proofs verify. This uses the challenge benchmark's leaf length, with eight leaves rather than 256. It is not a matched full-length comparison with leanVM.

| Stage | Proofs | Padded native rows | Proving per proof (s) | Rust verification (ms) | Total proof (decimal KB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Leaf | 8 | 16,777,216 | 10.285 | 6.59 | 386.0 |
| First parent | 4 | 4,194,304 | 3.095 | 6.20 | 361.7 |
| Second parent | 2 | 2,097,152 | 1.782 | 5.99 | 337.6 |
| Root | 1 | 2,097,152 | 1.669 | 6.15 | 337.0 |

Times are medians across distinct proofs at a level in one process; the root has one sample. Whole process time is 114.84 s and peak RSS is 38.86 GiB. [Independent statement and record validation](../evidence/2026-10-22-private-index4-performance/full-summary.json), [raw records](../evidence/2026-10-22-private-index4-performance/full-0/stdout.jsonl) and [process receipt](../evidence/2026-10-22-private-index4-performance/full-0/result.json) preserve the measurement. The original full-length run was 152.37 s at 52.59 GiB; those separate single runs do not establish a paired speedup.

### Opening-profile tradeoff

The preceding index-rate-1/8 profile is retained in [its own complete series](../evidence/2026-10-22-private-index3-performance/). Its full-length run used 113.82 s and 34.94 GiB, with a 3.069 s root and 382,800-byte proof. Rate 1/16 uses 114.84 s and 38.86 GiB, with a 1.669 s root and 336,984-byte proof. These are separate single runs. The root's padded native rows fall from 2^22 to 2^21, but the larger index encoding increases memory and does not improve the measured whole-tree time. This checkpoint selects rate 1/16 for full-length recursive root cost; rate 1/8 remains a useful lighter profile for shallow trees.

## Earlier measurement and validation

Measurements ran on a shared Intel Xeon Gold 6230R host, with carry-less multiplication enabled, Rust 1.99.1, 16 workers and CPU affinity 0-15. Each proof has one timed sample. The latest repeated series excludes one warmup process per backend and workload; the earlier series did not. Repeated trials use fresh processes and the same deterministic statements. Native proving includes trace lowering, backend witness preparation and proof generation. Parent preparation includes symbolic child-verifier recording. Preprocessing is separate. These are Rust timings, not the challenge's compiled Lean verifier or official score.

The earlier `d87e4322` source passed 60 release native library tests, including actual malformed connector proofs covering all 18 slots and three limbs, and all-target Clippy. The matched VM wrapper passed its three targeted tests, including a real depth-two tree and adversarial deferred-record controls; upstream two-to-one recursion passed. The independent Python record validators passed 20 controls. Formatting passed. Earlier tests and failed experiments remain under [the lane records](../evidence/2026-10-22-perf-lanes/). Full-length jobs use an 80 GiB sampled process guard and preserve 40 GiB global memory headroom; this is admission and monitoring, not hard isolation.

Yukon tooling was checked against upstream at `8e19ffca`. It supplies source-bound development checks, not a measured acceleration of the cryptographic prover. No Lean source changed in this optimization phase. At the final audit, upstream and local Yukon had advanced to `e155c298`; its Lean audit hardening does not change the benchmark runner used here. The measurement-phase tooling pin remains unchanged.

## Formal and challenge scope

The original quotient and structured-R1CS Lean theorems do not certify this native arithmetic/Flock composition, compiler, private bridge, concrete PCS or Rust implementation. No new numerical security bound or zero-knowledge property is asserted here.

The [pinned recursion.fast relation](https://github.com/scaraven/recursion.fast/blob/15e4ae5eaba6a65211668c6e0f55f9fea1d9050d/RecursionFast/Contract/Relation.lean) requires nodes to verify children with the same submitted verifier. It does not require literally one circuit shape or key. A verifier could authenticate several shapes and keys. Our per-level externally supplied setups have not yet established recursive closure under one submitted verifier. Fixed-shape recursion is one possible construction, not a challenge requirement.

The tagged proof-system oracle adapter, concrete PCS/composition knowledge soundness, perfect completeness and executable extractor certificate also remain open. This is not an official recursion.fast entry. The pinned challenge uses Lean 4.34.1; these runs do not exercise its Lean verifier or official harness.

Upstream status checked on 22 October at `scaraven/recursion.fast` revision `921bdbd`: v3 is frozen, the implementation moved to `v3/contract-archive`, and `main` is an ideation skeleton. These experiments retain their historical `15e4ae5` relation pin. The submissions repository still points to that pin and its setup guidance is stale. See the current [design record](https://github.com/scaraven/recursion.fast/tree/921bdbdefe561f2352ea321c1b0533b774722229/docs) for the archived design's lessons and unresolved problems.

## Reproduce

```bash
export RUSTUP_TOOLCHAIN=1.99.1
export CARGO_TARGET_DIR=/absolute/path/to/target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
export LEANVM_NUM_THREADS=16
cargo build --locked --release -p rec_aggregation --example private_tree --example chain_tree_vm
taskset -c 0-15 python3 experiments/pcs-r1cs/recursion/run.py \
  --out /absolute/path/to/new-evidence --budget-gib 80 -- \
  "$CARGO_TARGET_DIR/release/examples/private_tree" --depth 3 --chain 16384
python3 experiments/pcs-r1cs/recursion/summarize_private.py /absolute/path/to/new-evidence
```

Use the frozen schedule and config beside the measurements to repeat the alternating baseline and VM series. Never label an older executable with the current source revision.
