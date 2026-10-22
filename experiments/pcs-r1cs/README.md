# leanPCS and structured leanR1CS

This research branch compares where an application's quotient PIOP is checked. **leanPCS** checks it in the EVM and aggregates its PCS openings. **leanR1CS** checks it inside the aggregate; the application contract emits a claim. Both use leanVM's recursive prover and WHIR opening verification.

**Measured result:** with Keccak for PCS and native BLAKE2s for R1CS, aggregate proving cost is comparable on seven statements, batches of 1/2/4/8, and recursive trees. R1CS uses much less application-check execution gas. Compact generator descriptions cover all nine circuits in 0.9-16.1 kB per app. This does not establish a universal winner; the largest circuits still exceed this quotient prover's implementation limit.

Those recursive trees use leanVM's recursive verifier and Flock hash support. The [separate full-adder recursion experiment](recursion/README.md) exceeded the quotient backend's capacity. A [new native-field prototype](recursion/NATIVE.md) produces verified outer certificates by changing the arithmetic backend and binding Flock hash batches. Its matched comparison with leanVM reports complete proof size, verification time and memory. A [private-bridge follow-up](recursion/PRIVATE.md) completes three aggregation levels over eight full-length hash chains, using separate keys per level. The latest [witness-schedule experiment](evidence/2026-10-22-native-witness-schedule/README.md) cuts native root preparation + proving time by another 7-13%. The eight-leaf root takes 1.016 s versus leanVM's 1.075 s in seven matched trials, with 317,512/324,064-byte proofs and 6.20/18.63 ms Rust verification. At four leaves native remains about 4% slower. These local measurements use separate keys per level; the VM comparison wrapper forwards deferred records. The [common-key closure prototype](recursion/CLOSED.md) now tests leaves, repeated self-composition and mixed-height composition under one fixed key, with [small-tree measurements and evidence](evidence/2026-10-22-common-key-closure/README.md). This is conditional implementation closure, with a bounded public height; official recursion.fast integration and a formal soundness proof of the new native composition remain open.

Start with the [full Linux measurements](evidence/2026-10-22-full/README.md), [compact descriptions](format/compact/README.md), and [formal scope](../../formal/quotient/README.md). This is a research prototype, not an audited implementation or a protocol recommendation.

The [Succinct Flock baseline adapted to BLAKE2s](recursion/FLOCK_BASELINE.md) also completes three repeated recursive towers. Its sequential chain workload differs from the matched native/leanVM tree, so its times are reported separately.

## What the comparison measures

The optimized PCS path uses a Keccak application transcript. The optimized R1CS path uses leanVM's native BLAKE2s transcript; its client proof bytes therefore differ. They keep the same application circuit, inputs, field, quotient relation and opening protocol. The [hash decision](HASH-DECISION.md) explains this protocol choice. The R1CS Keccak control retains the identical client proof used by PCS, at a higher aggregate cost.

The current run measures seven supported statements individually, membership batches of 1, 2, 4 and 8, and two levels of recursion with 2 x 2 and 4 x 4 applications. The [raw evidence](evidence/2026-10-22-full/) includes all proving stages, verification, cycles, proof sizes, gas, memory and unsupported configurations. ECDSA and Poseidon circuits exist, but exceed the quotient implementation's row limit. The separate packed backend has different assurance and privacy properties and is reported separately.

For membership, the prototype application-contract execution costs 10,971 gas for PCS and 61 for R1CS, about 180 times less. This excludes transaction/calldata costs, application state, circuit publication/registration and native claim coverage. PCS assumes the proposed 10-gas `FIELD_MUL` opcode. It is not a 180-fold reduction in total transaction gas.

## What is proved

The [Lean formalization](../../formal/quotient/QuotientSecurity/R1CS.lean) proves that the structured R1CS rows are equivalent to the quotient gate, including uniqueness of their auxiliary wires, and transfers the original ideal-model soundness bound `(Q + 3) / 2^128`. The [Boolean circuit formalization](../../formal/quotient/QuotientSecurity/Described.lean) covers the full-adder relation under its wiring, size and public-encoding hypotheses. The [format build](evidence/2026-10-21-format/LEAN.md) and [later circuit-statement build](evidence/2026-10-21-described/LEAN.md) retain the checked proof provenance. Their theorem files match the saved source hashes; the later record also matches the current root module.

These theorems do not verify the Rust implementation, concrete PCS, transcript hash instantiation, recursive verifier, application algorithms, circuit builders or generator decoder. Passing tests and reproducing a circuit's rows are useful implementation evidence, not a formal proof of these links. The [packed backend](../../crates/packed_format/) has no Lean soundness proof and is not zero knowledge. The underlying recursive VM proofs are also not zero knowledge; application privacy composition is outside this experiment.

The new full run found and fixed a Falcon builder bug: two helpers shared a carry-conversion cache but disagreed on the conversion row's sum output. The fix shares the canonical conversion row. A regression tests both cache insertion orders on both bit inputs; Falcon valid, invalid, boundary and known-answer tests pass. Its compact description was regenerated and compared against the corrected circuit. Earlier Falcon results should be read with this correction.

## Reproduce

The recorded Linux runs use Rust 1.99.1; the compiler version is saved with their evidence. On an x86 host exposing `pclmulqdq`, use a fresh Cargo target directory and explicitly enable the feature. An old `target-cpu=native` cache can retain software arithmetic after a VM CPU configuration changes.

```sh
export PATH="$PWD/experiments/pcs-r1cs:$PATH"
export CARGO_TARGET_DIR=/absolute/path/to/fresh-target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
cargo build --locked --release -p rec_aggregation -p circuit_suite -p packed_format --examples
python3 experiments/pcs-r1cs/full_run.py \
  --binary-dir "$CARGO_TARGET_DIR/release/examples" \
  --out /absolute/path/to/new-evidence
python3 experiments/pcs-r1cs/summarize_full.py /absolute/path/to/new-evidence
```

The runner uses 16 threads on CPUs 0-15, three measured rounds, and one warmup per paired process. It alternates interface order, independently verifies proofs, checks tampering, records binary/source hashes and rejects missing samples. Tree runs have no explicit warmup. It requires Linux and `memguard` admission; the command above uses the bundled equivalent of the recorded host's 200 GiB admission helper. A watchdog stops only the current benchmark process group if available memory falls below 40 GiB. Interrupted or failed outputs are preserved for review.

```sh
cargo test --locked --release -p circuit_suite -p packed_format
cargo clippy --locked --release -p rec_aggregation -p circuit_suite -p packed_format --all-targets -- -D warnings
python3 -m unittest discover -s experiments/pcs-r1cs -p 'test*.py'
```

## Other code and earlier results

- [Track A optimization challenge](challenge/README.md): candidate provers are checked by a frozen reference verifier.
- [Recursive trees](../../crates/rec_aggregation/src/aggregation/tree.rs): roots verify leaf aggregate proofs and bind their ordered public inputs.
- [Keccak instruction experiment](KECCAK-INSTRUCTION.md): follow-on integration work; not part of the optimized BLAKE2s comparison.
- Historical [review run](evidence/2026-10-20-review/README.md), [cycle measurements](evidence/2026-10-20-arch/README.md), and [tree results](evidence/2026-10-21-trees/README.md). The old VM configuration lacked carry-less multiplication; those timings are not current hardware baselines.

These measurements can establish the cost of these implementations. They cannot establish that either interface is strictly better for every application, backend or security requirement. Prime-field-heavy circuits expose the cost of this Boolean representation; the PCS interface itself does not require that representation.
