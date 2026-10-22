# A verifier in the generic circuit format

**Latest:** the [common-key construction](CLOSED.md) uses one setup and circuit for leaves, repeated node composition and mixed child heights. The [four-element encoder optimization](../evidence/2026-10-22-common-key-quad-reduction/README.md) reduces eight-leaf whole-process time by 3.52% against the previously accepted two-element kernel across seven independent pairs, with unchanged key, circuit shape and certificate sizes. This is conditional implementation closure with a bounded height; formal native composition security and official recursion.fast integration remain open.

**Earlier finite-tree results:** the [private native-field prototype](PRIVATE.md) reuses its witness computation schedule, reducing root preparation + proving time by another 7-13%. The eight-leaf root takes 1.016 s versus leanVM's 1.075 s in seven matched trials; at four leaves it remains about 4% slower. Complete proofs are 317,512/324,064 bytes and full Rust verification is 6.20/18.63 ms. The [matched evidence](../evidence/2026-10-22-native-witness-schedule/README.md) reports setup, memory, timing ranges and all 60 tree processes. These earlier shared-host runs use separate trusted circuits and keys per level. The common-key result above establishes tested implementation closure; a formal composition proof remains open. The results below preserve the original full-adder experiments.

The [Succinct Flock baseline adapted to BLAKE2s](FLOCK_BASELINE.md) completes three repeated towers with independent consumer verification. Its workload and timing boundaries differ from the matched native/leanVM series.

## Earlier full-adder backend

**Result: the direct implementation exceeds the current quotient backend's capacity. No recursive outer proof was produced.** This experiment removes leanVM from the verifier being compiled, rather than reusing its recursive verifier or hash instruction.

The child is a small circuit with 4,096 padded rows, two private 64-bit inputs, and public sum and XOR outputs. Its proof uses the existing quotient protocol, BLAKE2s transcript and all three WHIR openings. The compiler records the verifier as field operations and hashes, then lowers those operations into the existing full-adder format. Child proof contents and statement are inputs; the child circuit commitment and protocol parameters are fixed. Dynamic query bits control both the authenticated Merkle paths and the opening equations. No hash result is accepted as an unchecked hint.

## Measured outcome

| Check | Result |
| --- | --- |
| Complete recorded verifier | Accepts two independently generated valid proofs |
| Program independence | Identical operations and constants for both proofs |
| Deliberate corruptions | 18 rejected by the recorded verifier |
| BLAKE2s hash calls | 10,324 |
| BLAKE2s compressions | 17,795, including long leaf hashes |
| Dynamic field multiplications | 78,891, with squares and constant multiplications counted separately |
| Boolean lowering | Exceeded 8,388,608 rows inside the first opening verifier |
| Rows at the stop | 8,399,399; this is a partial count, not the complete circuit size |
| Outer proof and proving time | Unavailable: the complete circuit did not fit |

Hash counts include statement hashing, transcript operations, grinding, opening seeds, Merkle leaves and paths. Fixed domain and circuit seed digests are precomputed. The recorded implementation uses independent Merkle paths and does not optimize shared paths across queries. These counts describe this implementation, not a lower bound on recursion.

The original lowering used six base-field products for variable field multiplication. The latest implementation uses five-point interpolation with Karatsuba inside each base-field product, and linear maps for squares, constant products and Frobenius. Primitive tests compare the Boolean gadgets against native field arithmetic and BLAKE2s across block boundaries, including changed-input rejection. The complete verifier was executed at the recorded-operation level; it was not fully lowered, evaluated as a complete Boolean circuit, or proved. No new Lean theorem or implementation correspondence proof is claimed.

## What this changes in the comparison

The earlier recursion timings remain measurements of leanVM recursion, where Flock supplies specialized BLAKE2s machinery. They do not demonstrate efficient recursion using only this generic full-adder format.

The result supports investigating a shared hash argument with explicit binding to the circuit's requests. It does not show that hash batching alone is enough: the verifier also performs substantial field arithmetic. A successful design must measure the hash argument, its binding checks, the remaining arithmetic, and the outer proof together. It would be additional shared proving and verification machinery beyond the small circuit-description decoder.

## Follow-up: a working hash batch, with arithmetic still over capacity

**The Flock hash adapter passes its tests, but standalone recursion still does not fit.** It proves all 17,795 compressions requested by the complete verifier trace in one Flock batch, without leanVM. A native checker validates the remaining trace operations. The values are disclosed; this checker is not a succinct recursive proof and is not zero knowledge.

| Diagnostic, three fresh child proofs | Result |
| --- | --- |
| Complete trace with Flock hash proof and native arithmetic replay | All three accepted |
| Corruptions of each complete certificate | 15 rejected per run, including a forged hash that arithmetic replay alone accepts |
| Hash batch plus replay certificate construction, median | 739 ms |
| Native certificate verification, median | 244 ms |
| Encoded Flock proof plus intermediate chaining values | 508,176 to 511,184 bytes |
| Disclosed trace values, excluding framing | 11,469,336 bytes |
| Optimistic main circuit with hashes removed | Exceeded 8,388,608 rows at node 1,014 of 477,889 |
| Rows at that stop | 8,413,267, including 7,952,984 for variable field multiplication |
| Complete recursive outer proof | Not produced |

These are shared-host component diagnostics, not recursive proving times or a comparison with leanPCS. Construction includes extracting requests, native arithmetic replay, context binding, Flock witness generation, commitment, reduction and opening. It excludes child proving, trace recording, Boolean lowering and negative tests. Verification includes replay, context binding and the Flock verifier. There is no warmup series. The final run used 16 workers, peaked at 1.48 GiB RSS and retained over 207 GiB available system memory.

### What binds the hashes

The adapter expands each hash into RFC 7693 compression requests. The message, byte counter, final-block and last-node flags, initial chaining value, every intermediate chaining value and the final digest are all bound. The verifier derives each block's chaining input from the preceding output, resets to the parameterized IV at each message boundary, and enforces padding. It does not trust prover-provided hash outputs or recompute each requested hash.

After the public request table and the Flock witness commitment have entered the transcript, a random multilinear point selects an evaluation across compression instances. Eighteen packed-word claims cover every compression's public inputs and outputs, including padded instances. The existing mixed WHIR opening discharges these claims together with Flock's reduction claim against the same committed witness. The verifier also rejects unconsumed proof data. A mutation fixture demonstrates that a valid Flock proof of unrelated hashes is accepted without these binding claims and rejected with them.

The surrounding native replay checks every non-hash operation against a trusted fixed trace program and checks the caller's expected statement digest. Three different child proofs have the same program and constants. This is a transparent prototype of the adapter's interface: public I/O and program digests are hashed natively to seed the transcript. Neither those seeding hashes nor the replay checker have been recursively proved. A compact circuit-to-coprocessor binding remains to be implemented for a recursive proof.

### What remains

Removing every hash constraint still leaves the main verifier circuit over capacity inside the first opening verifier. Variable field multiplication accounts for about 95% of rows in this partial compilation. This identifies another implementation bottleneck; it is not a count of the whole circuit or a lower bound on alternative designs. The capacity diagnostic also omits circuit-to-coprocessor binding costs, so it is deliberately optimistic and never returns a purported valid circuit to the prover.

Practical standalone recursion requires addressing the remaining field arithmetic and proving its binding to the shared hash requests, then measuring a complete outer proof. The new adapter is tested Rust code. No Lean proof was added for it or for this composition; the published quotient and structured-R1CS theorems remain unchanged and do not establish the soundness of this new implementation. In particular, the random evaluation used for I/O binding is an additional probabilistic check, so the original numerical bound must not be asserted for the combined experiment without a composition proof.

### Evidence and reproduction

The [checked follow-up evidence](../evidence/2026-10-22-hash-batching-checked/stdout.jsonl) records all three runs and the capacity failure. Its [execution record](../evidence/2026-10-22-hash-batching-checked/result.json), validation logs, source hashes and source patch preserve the environment and implementation. The earlier development run remains in `2026-10-22-hash-batching`.

```bash
export CARGO_TARGET_DIR=/absolute/path/to/fresh-linux-target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
cargo build --release -p format_recursion --example batched
LEANVM_NUM_THREADS=16 python3 experiments/pcs-r1cs/recursion/run.py \
  --out /absolute/path/to/new-evidence --budget-gib 32 -- \
  "$CARGO_TARGET_DIR/release/examples/batched" --repeat 3
cargo test --release -p format_recursion --lib
cargo clippy --release -p format_recursion --all-targets -- -D warnings
```

The eleven unit tests cover arithmetic replay, field and hash gadgets, zero-prefix Merkle lanes, public I/O layout, all packed I/O columns including padding, message lengths at block boundaries, adversarial public requests, malformed proofs, and the unbound-proof mutation fixture.

### Small arithmetic optimizations

A further [checked run](../evidence/2026-10-22-arithmetic-opt/stdout.jsonl) keeps the same format, protocol and high-level verifier. Binary linear maps now share short XOR expressions between output bits. For the representative dense constant in the gadget profile, this reduces a constant multiplication from 17,168 to 7,232 rows. Tests compare the optimized maps to native field arithmetic on every binary basis vector. Multiplication cutoff trials confirmed that the existing four-bit cutoff used the fewest rows of the five tested choices, so it was retained. Common-expression interning removed about 1% of dynamic products in a development trace and increased recording overhead; it was not retained.

The outcome is unchanged: with hashes omitted, compilation reaches node 1,029 before exceeding the row limit at 8,413,912 rows. Variable products consume 8,122,960 of those rows, about 97%. This is a partial compilation, not a measurement of the full circuit's size. Three fresh hash-batch certificates still verify and reject all 45 complete-certificate corruptions. The original recorded-verifier regression also passes all 18 corruptions and retains the same high-level operation counts. All thirteen unit tests, all-target Clippy and formatting pass. No complete recursive proof is produced.

The latest evidence preserves construction and native verification timings, but they remain component diagnostics. The optimized linear maps affect Boolean circuit compilation, not the transparent hash-batch certificate's proving algorithm. The earlier hash-batch timing table should not be interpreted as a before/after speed comparison for this optimization.

### Five-product field multiplication

The [next checked run](../evidence/2026-10-22-five-product/batched/stdout.jsonl) reduces a fully variable field multiplication from **28,298 to 24,544 full-adder rows, 13.3% fewer**. This is a circuit-size result, not an end-to-end proving-time speedup. The field, circuit format, transcript, verifier equations and backend limit are unchanged.

The implementation evaluates the two quadratic field elements at 0, 1, x, x + 1 and infinity, multiplies these five pairs in the base field, and interpolates before reducing modulo y³ + y + 1. Multiplication and division by x and x + 1 are fixed binary linear maps. They introduce no advice or new proof protocol. The previous six-product implementation remains as a test reference. The four-bit Karatsuba cutoff remains best among the five tested cutoffs.

All 36,864 binary basis pairs agree with native field multiplication. Tests also cover zero, one, all-one operands, randomized dense inputs, and every basis vector for the fixed linear maps. All fifteen unit tests, all-target Clippy and formatting pass. These are implementation checks; no new Lean implementation-equivalence proof is claimed.

Three fresh hash-batch certificates pass with all 45 corruptions rejected, and the complete recorded-verifier regression still rejects its 18 corruptions. With all hashes and circuit-to-coprocessor binding omitted, compilation now reaches node 1,585 instead of 1,029 before exceeding the same 8,388,608-row limit. It stops at 8,395,870 rows, still inside the first opening verifier. These are partial compilations at different stopping points, not complete circuit sizes or a recursion speed comparison. The direct compilation with hashes also remains over capacity. **No complete recursive outer proof is produced.**

The [execution record](../evidence/2026-10-22-five-product/batched/result.json), [test log](../evidence/2026-10-22-five-product/tests.log), [direct regression](../evidence/2026-10-22-five-product/direct-regression/stdout.jsonl), source hashes and patch preserve the result. The hash-batch run peaked below 1.5 GiB RSS and retained over 200 GiB available system memory. Its component timings do not measure this arithmetic optimization: the transparent replay uses native field arithmetic, not the Boolean circuit.

## Evidence and reproduction

The [final diagnostic](../evidence/2026-10-22-recursion-checked/stdout.jsonl) and [execution record](../evidence/2026-10-22-recursion-checked/result.json) preserve the capacity failure explicitly. Earlier development diagnostics are retained in the adjacent `2026-10-22-recursion-trace`, `2026-10-22-recursion-capacity` and `2026-10-22-recursion` directories. Review added explicit checks for the omitted zero lanes restored in raw opening paths; the final recorded verifier includes those checks. The final diagnostic used less than 1 GiB process RSS and retained over 190 GiB available system memory. Source hashes, a patch against the published baseline and validation logs accompany the final record.

```bash
export CARGO_TARGET_DIR=/absolute/path/to/fresh-linux-target
export RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq'
cargo build --release -p format_recursion --example recursive
LEANVM_NUM_THREADS=16 python3 experiments/pcs-r1cs/recursion/run.py \
  --out /absolute/path/to/new-evidence --budget-gib 16 -- \
  "$CARGO_TARGET_DIR/release/examples/recursive" --row-limit 8388608
cargo test --release -p format_recursion --lib
cargo clippy --release -p format_recursion --all-targets -- -D warnings
```

The runner preserves outputs, checks admission before starting, and stops its own process group below 40 GiB available system memory. A successful diagnostic exit with a capacity record is not a successful recursive proof. Higher `--row-limit` values permit further compilation for research; they do not increase the quotient prover's supported size.
