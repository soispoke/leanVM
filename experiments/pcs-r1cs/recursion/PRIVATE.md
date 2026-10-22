# Private hash binding and repeated recursion

Three successive 2→1 recursion levels now pass on eight fresh 16,384-step hash chains. The root takes 3.82 seconds to prove and 8.70 milliseconds to verify, with a 635,072-byte total proof. These are single-run development measurements on a shared host, with a separate preprocessed key at each level.

This is a local recursion prototype. It proves native field arithmetic and batches BLAKE2s with Flock. The hash messages and intermediate chaining values stay in the proof witness; the serialized proof contains no separate request table. This is not a zero-knowledge claim.

## Construction

The outer proof combines a native GF(2^192) arithmetic argument with Flock's batched BLAKE2s argument. Child-verifier arithmetic becomes multiply-add rows; child-verifier hashes become compression requests in the batch. A shared committed connector table and WHIR openings bind both arguments to the same hash inputs and outputs. The recursive circuit checks both child verifiers, then hashes their ordered statements to obtain its own statement.

This changes the arithmetic backend and adds hash-binding machinery beyond the original Boolean full-adder format. The reported native row count therefore cannot be compared directly with that format's rows or leanVM cycles.

## What is checked

Leaves prove the tagged hash-chain statement in the pinned recursion.fast relation. A parent records both complete child verifiers, including native arithmetic, Flock, connector equality and WHIR openings, then hashes the two child statements in order. The verification keys are fixed by trusted preprocessing. Every level currently has its own circuit and key. These runs cover hash chains, not Falcon or shielded-transfer recursion.

Proofs are serialized with fixed-integer bincode, capped at 1 MiB, and parsed with trailing bytes rejected. All serialized auxiliary data is included in the reported proof size.

## Measurements

The [full-size leaf run](../evidence/2026-10-22-private-tree-full-depth3/summary.json) proves eight independent 16,384-step hash chains, four parents, two grandparents and one root. All 15 proofs verify. Each parent also rejects a changed statement. This uses the challenge's benchmark leaf length, with eight leaves rather than its required 256.

| Stage | Proofs | Padded native rows | Proving per proof | Rust verification | Total proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Leaf | 8 | 16,777,216 | 13.32 s | 9.46 ms | 694,200–696,536 |
| First parent level | 4 | 4,194,304 | 3.95 s | 8.63 ms | 632,032–634,464 |
| Second parent level | 2 | 4,194,304 | 3.82 s | 9.59 ms | 633,208–635,168 |
| Root | 1 | 4,194,304 | 3.82 s | 8.70 ms | 635,072 |

Times are medians across the distinct proofs at that level in one process, not repeated trials. The root has one sample. The complete process took **152.37 seconds** and peaked at **52.59 GiB RSS**, including preprocessing and symbolic verifier recording. The shared host exposes an Intel Xeon Gold 6230R and carry-less multiplication; 16 workers were used without CPU pinning. Rows are native GF(2^192) multiply-add constraints, not Boolean full-adder rows or VM cycles. [Raw records](../evidence/2026-10-22-private-tree-full-depth3/stdout.jsonl), [process receipt](../evidence/2026-10-22-private-tree-full-depth3/result.json) and [supplementary environment](../evidence/2026-10-22-private-tree-full-depth3/environment.json) retain the scope and provenance.

An earlier [four-leaf run](../evidence/2026-10-22-private-tree-full-leaves/summary.json) independently completed two recursion levels at the same leaf length: 101.22 s total, 52.49 GiB peak, and a 5.11 s root. The [small-leaf development run](../evidence/2026-10-22-private-tree-depth3-batched/summary.json) completed three levels with 16 steps per leaf: 37.08 s total and 15.62 GiB peak. Differences in shared-host timings between these runs are not measured optimization gains.

Per-proof proving includes private-trace compilation, backend witness preparation and proving. It excludes circuit preprocessing and symbolic child-verifier recording. Verification includes proof-cap serialization. `Plan::measure_quiet` takes one measured sample without a warmup. Process wall time includes the complete run. These are Rust timings, not the challenge's compiled Lean verifier or official score.

The index resource cap was raised from 2^22 to 2^24 padded native rows, with private compiler allocation limits at 2^25. Four columns of cell addresses still fit in u32; the resulting native/index/bridge WHIR dimensions stay inside the existing tested production parameter range. Actual sizes remain checked before building an index, and long runs use a 64 GiB process guard plus a 40 GiB global memory reserve. This capacity change is not a new security proof.

### Development history

The [first capacity run](../evidence/2026-10-22-private-tree-depth1-dev/stdout.jsonl) failed before producing a recursive proof: the compiler estimated about 50 million rows. [Aligned word routing](../evidence/2026-10-22-private-tree-depth1-limbs/stdout.jsonl) reduced the estimate to about 10 million. Batching unused 64-bit range checks as valid private hash compressions brought the parent within capacity. These extra compressions use the existing Flock circuit; partial-word range checks still use Boolean constraints.

The [initial full-leaf attempt](../evidence/2026-10-22-private-tree-chain16384-capacity/stdout.jsonl) was rejected under the former limits. It is retained as a capacity failure, not a completed tree. All failed runs remain available with their source and binary hashes.

## Formal and challenge scope

The new arithmetic argument, private bridge and compiler have Rust tests and engineering reviews. The original quotient and structured-R1CS Lean theorems do not certify this new composition. No numerical security bound is asserted for it here.

This is not a recursion.fast entry: one closed fixed-shape verifier, the tagged proof-system oracle adapter, concrete PCS/composition security, perfect completeness and the executable extractor certificate remain unfinished. Exact statement encodings alone do not discharge these obligations. The [pinned challenge contract](https://github.com/scaraven/recursion.fast/tree/15e4ae5eaba6a65211668c6e0f55f9fea1d9050d) uses Lean 4.34.1; this run does not exercise its compiled Lean verifier or official harness.

Closing recursion requires more than equal padded row counts. Leaf and node metadata, public-input positions, hash-block profiles and opening shapes must agree. Both authorized keys must be pinned externally and propagated unchanged; embedding a node's own key as a circuit constant would create a circular setup requirement. This design remains unimplemented. There is no matched repeated-recursion leanVM benchmark yet.

## Reproduce

```bash
export RUSTUP_TOOLCHAIN=1.99.1
export CARGO_TARGET_DIR=/absolute/path/to/target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
export LEANVM_NUM_THREADS=16
cargo build --locked --release -p rec_aggregation --example private_tree
python3 experiments/pcs-r1cs/recursion/run.py \
  --out /absolute/path/to/new-evidence --budget-gib 64 -- \
  "$CARGO_TARGET_DIR/release/examples/private_tree" --depth 3 --chain 16384
python3 experiments/pcs-r1cs/recursion/summarize_private.py /absolute/path/to/new-evidence
```

Use [the matched single-level leanVM comparison](NATIVE.md) for the earlier measurements. They use a different bridge that discloses its request table, and must not be presented as timings for this private bridge. Yukon tooling was checked against upstream at revision `dec7b98`; it supplies development checks, not a cryptographic speed or security result.
