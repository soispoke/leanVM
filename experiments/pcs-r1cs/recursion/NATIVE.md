# Native-field recursion prototype versus leanVM

The follow-up [private hash bridge and repeated-recursion work](PRIVATE.md) has separate evidence and limits. The measurements below describe the original bridge that discloses its request table.

The new prototype produces a verified outer certificate for a complete quotient child verifier, including all three WHIR openings. It proves field arithmetic and batches BLAKE2s through Flock, without executing a VM guest. **It has not demonstrated repeated self-recursion.**

At eight children, median proving takes **6.63 s versus 7.26 s for leanVM**, but complete verification takes **1.19 s versus 7 ms** and total proof size is **15.79 MB versus 0.236 MB**. Peak process memory is **8.09 GiB versus 19.35 GiB**. On this workload, avoiding the VM reduces memory and produces comparable proving times, while exposing a much larger verification payload. It does not establish a better recursion system.

## What to compare

Use proving time, verification time and total proof size including auxiliary data. Track circuit rows and VM instructions as diagnostics; they are different units. For a recursion challenge, also measure verification inside the next proof and require two successive recursion levels. Native verification alone does not establish practical recursion.

The [matched results](../evidence/2026-10-22-native-vm-checked/TABLE.md) compare 1, 2, 4 and 8 independent proofs of the same small application. Every child has 4,096 padded rows, private 64-bit inputs, and public sum and XOR outputs. Both paths receive identical child proof bytes, use BLAKE2s, verify the quotient PIOP and all three openings, and produce the same ordered public claim. The runner checks proof fingerprints and public claims across paths.

These experiments measure one outer aggregation level. They do not measure Falcon or shielded-transfer recursion, and do not establish equal proving cost for arbitrary statements or larger child proofs.

## What changed

The earlier full-adder implementation could not fit even after removing hashes. This experiment changes the arithmetic backend: a row checks `z = x*y + u` over the native extension field. A table zerocheck enforces rows, a permutation product argument enforces copy wiring, and WHIR opens the committed witness and index. Public pins bind constants, expected outputs and the values derived from disclosed hash requests. Frobenius operations use constrained squaring chains.

Flock proves each requested BLAKE2s compression. The adapter binds messages, counters, flags, chaining values and outputs to that proof. Larger request sets are partitioned into deterministic bounded batches. Native projection checks connect the public request bytes to the arithmetic argument; the arithmetic witness is not transmitted as a separate value array or replayed by the verifier.

The implementation reuses `leanvm_core::gkr` as a library primitive. This is additional shared proof machinery and a different field gate, beyond the original Boolean full-adder format and its small generator decoder. It should not be described as proving the original format efficiently merely by optimizing its implementation.

## Limits that matter

- The certificate discloses the hash request table and intermediate chaining advice. Its total serialized size includes both, as well as the arithmetic and hash proofs. The table grows with the number of children.
- The verifier walks the fixed program to derive public projections and hashes public I/O to seed the arguments. This work is linear in that data. The new verifier has not been compiled and proved as its own child, so its cost and size under repeated recursion remain unmeasured.
- There is no zero-knowledge claim. Absence of a separate arithmetic witness array does not hide values exposed in hash requests.
- The new arithmetic argument and composition have tests, not a Lean soundness or implementation proof. The published quotient and structured-R1CS theorem files are unchanged. Their numerical soundness bound must not be asserted for this new composition without a proof.

## Relation to recursion.fast

The [current recursion.fast design](https://github.com/scaraven/recursion.fast/blob/059812f72502004a91e7b12a3ba6e1d57f8b0611/docs/DESIGN-v3.md#6-scoring-whole-tree-wall-time-on-the-reference-machine) ranks whole-tree prover wall time: 256 hash-chain leaves and 255 binary aggregation nodes. Root-step latency is reported separately. The submitted verifier checks both leaves and its own child proofs. Submissions can change the PCS and verifier, subject to the Lean knowledge-soundness, completeness and extractor obligations. Proof size, verifier time and memory are admission limits, not separate scores. The current defaults include a 1 MiB proof cap, a 2 s root-verification cap and 96 GB tree memory. The repository is experimental; its README says the contract stage has landed and later baseline and harness stages remain.

This prototype is not a recursion.fast entry. Its current serialized certificates exceed the size cap, its recursive fixed point is unimplemented, and its new composition does not have the required formal certificate. These measurements identify engineering tradeoffs; they do not establish challenge eligibility.

## Reproduce

Use Rust 1.99.1 for the recorded run and a Linux x86 host exposing `pclmulqdq`. The shared host used 16 workers for each backend. Source and binary hashes, CPU model, kernel, admission checks, memory and raw samples accompany the results. The run has one warmup and five measured samples per backend and batch size. Other missions were active, so small timing differences should not be treated as an architectural ranking.

```bash
export RUSTUP_TOOLCHAIN=1.99.1
export CARGO_TARGET_DIR=/absolute/path/to/fresh-target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
cargo build --locked --release -p rec_aggregation --example recursion_comparison
python3 experiments/pcs-r1cs/recursion/compare.py \
  --binary "$CARGO_TARGET_DIR/release/examples/recursion_comparison" \
  --out /absolute/path/to/new-evidence --samples 5
cargo test --release -p format_recursion --lib
cargo test --release -p rec_aggregation --example recursion_comparison
cargo clippy --release -p format_recursion -p rec_aggregation --all-targets -- -D warnings
cargo fmt --all --check
python3 experiments/pcs-r1cs/recursion/test_compare.py
```

The runner refuses an existing output directory, uses memguard admission, stops its own experiment below 40 GiB available memory, rejects missing samples and differing child proofs, and preserves failed runs. Proving excludes shared child proof generation. Setup and preparation are reported separately; aggregate totals include preparation, proving and verification. Memory is peak RSS over the whole process, including setup and negative checks.

The [first development series](../evidence/2026-10-22-native-vm-comparison/) predates the cleaned code and strengthened fingerprint checks. It is retained as development evidence. The final checked series above is the reference for sharing. The [first successful single-child development run](../evidence/2026-10-22-native-arithmetic-dev/) also excluded chaining advice from its hash-proof component size; its component sizes must not be presented as the total proof size.
