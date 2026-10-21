# Matched PCS and structured R1CS experiment

This branch is a reproducible research comparison based on `leanEthereum/leanVM` commit `651453c6839de98566c18e94d058507c9ff8920b` (`PCS-openings-aggregation`). It retains the same application, client proof, field, quotient PIOP, WHIR openings and outer proof system on both sides. The measured difference is where the application PIOP is verified.

* **PCS:** execution runs the upstream EVM PIOP and emits opening claims. One aggregate verifies all three opening proofs, covering all four claims.
* **Structured R1CS:** the aggregate additionally verifies the PIOP, including its Keccak transcript, and binds the registered application identity and public inputs. Execution emits that app claim.
* **Structured R1CS on the VM transcript (`r1cs-vm`):** the same, with the PIOP's random oracle instantiated by the VM's BLAKE2s chain instead of Keccak-256. Only the aggregate reads this transcript, so it uses the hash native to the aggregate. Client proofs then differ from the PCS path's; see [the decision](HASH-DECISION.md).

The workload is knowledge of a BLAKE2s preimage and a depth-32 Merkle path, not a complete shielded-pool transaction. The structured R1CS description lowers exactly to the existing full-adder gate and copy constraints. It is not a general sparse-matrix compiler. Registration trusts the compiler that associates the versioned application description with the fixed wiring commitment and authenticated aggregate program.

## Layout

| File | Purpose |
| --- | --- |
| `crates/rec_aggregation/examples/comparison.rs` | Single-application paired experiment |
| `crates/rec_aggregation/examples/batch.rs` | Several distinct applications in one aggregate |
| `crates/rec_aggregation/examples/standalone_opening.rs` | Opening-boundary regression harness |
| `crates/rec_aggregation/examples/comparison_support/` | Shared opening verifier adapter, R1CS relation, PIOP graph generator and Keccak gadget |
| `experiments/pcs-r1cs/run.py` | Locked builds, guarded measurements, provenance and complete sample-matrix validation |
| `experiments/pcs-r1cs/test_runner.py` | Regressions for incomplete, duplicated or invalid measurements |

The EVM recorder and recursive generator consume the same generic `quotient::reduce` operation graph. The opening adapter extracts the existing recursion helpers and supplies the standalone opening's exact configuration, transcript seed and terminal weight. Source rewrites that insert application-claim bindings require an exact single marker; a changed marker fails generation. No protocol parameter, security setting or backend capacity limit is relaxed.

## Reproduce

Use release mode; the compiler is not intended for debug execution. `Cargo.lock` is committed. The workspace builds for the host CPU. On this Mac, the runner requires `~/.local/bin/memguard`, waits for admission before each heavy job and keeps the existing 100 GB machine limit. It fixes eight performance workers, leaving upstream's efficiency-worker behavior intact. Do not run multiple proving drivers concurrently without accounting for their combined memory.

```sh
python3 -m unittest discover -s experiments/pcs-r1cs -p 'test_*.py'
python3 experiments/pcs-r1cs/run.py --output /absolute/path/to/a/new/result-directory
```

The default is three processes, one warmup and three measured paired samples per process, at fan-in one and two. For a faster validation run use `--processes 1 --samples 1`. Every output directory must be new, including after a failed run. Metadata is written before execution and records failure explicitly. The runner checks that every requested pair exists, timings are finite and nonnegative, client/admission measurements match, totals agree with their stages, and sources remain unchanged. Raw logs and samples are retained.

For a manual capacity probe, after a successful memory admission:

```sh
LEANVM_NUM_THREADS=8 cargo run --locked --release -p rec_aggregation --example batch -- --fan-in 4 --samples 0
```

An unsupported committed witness size produces a `kind: capacity`, `status: unsupported` record, never a successful sample or zero proving time. Other proving errors fail the process. Native and Python verifiers accept committed sizes through 2^30 (`pcs::MAX_MU`); the WHIR profile stays 128-bit there, and the recursion guest keeps its 2^28 window. A recursive tree of aggregates is not implemented here. `--dry-run` reports the exact committed shape a batch would need without proving it, and `--pcs` or `--oracle blake2s` select the interfaces.

## Validation and interpretation

Tests cover R1CS gate elimination, tampered auxiliary variables, malformed dimensions and permutations, wrong public inputs, independent Keccak vectors across sponge block boundaries, opening/PIOP mutations, noncanonical field limbs, public-input substitution, and batch order/count/duplicate substitution. `cargo clippy --locked --release -p rec_aggregation --all-targets -- -D warnings` checks the actual examples, rather than only a subset that could hide broken helper targets. The experiment also retains the upstream native verifiers as differential checks.

The EVM is upstream revm with the proposed ten-gas `FIELD_MUL` instruction. R1CS execution does not require that opcode. Both paths use a native prototype dependency-frame coverage adapter. Its CPU cost is measured; no production opcode gas is invented for it. The R1CS EVM contract only emits a claim, so its execution gas is not the cost of a real application transaction.

The Keccak circuit is the bit-level floor for this instruction set, not a native Keccak opcode (see below). The results do not establish an unavoidable R1CS cost or an architecture-wide winner. General R1CS compilation, compact onchain circuit publication, production registry/coverage semantics, larger recursive trees, ordinary application state and block execution proving remain outside this prototype. The underlying VM proofs are not zero knowledge; application privacy composition has not been independently audited here.

The original measurements and detailed accounting are preserved in the [research record](https://github.com/soispoke/hardness/blob/5c377d0bcf47b02f2208098b5f3d517016a540c8/prototypes/leanccs-pcs-comparison/baselines/pcs-openings/recursion/COMPARISON.md). They belong to that source revision. Validation and measurements of this cleaned branch are recorded separately rather than silently relabeling those historical results.

## Optimization round

[`comparison_support/keccak.rs`](../../crates/rec_aggregation/examples/comparison_support/keccak.rs) emits Keccak-f[1600] as one shared straight-line function: the state lives in frame cells, constants only flip a wire's polarity, and repeated subterms are shared. A round costs the theta parity network (two XORs a bit) and chi (one AND and about two XORs a bit), which is the floor when every state bit is a machine word and `XOR` and `MUL` are separate instructions. Bit binding uses Horner evaluation per 64-bit limb, avoiding a constant load per bit. Correctness is proved, not sampled: one generated round agrees with an independent FIPS 202 round on every input of Hamming weight at most two, and both are polynomials of degree at most two over GF(2), so they are equal everywhere. Further tests read the emitted source text back against the reference permutation, derive the round constants and rotation offsets from the specification, and run the compiled guest against `sha3` at every transcript length. Deliberately wrong theta and chi indices both fail.

The Keccak circuit removes 572,000 heap accesses per application and cuts the R1CS path's extra cycles over PCS from 2.01M to 1.39M. The VM transcript removes nearly all of the rest. Per application, from the [Arch runs](evidence/2026-10-20-arch/README.md) (counts are exact; that VM lacks `pclmulqdq`, so its wall times are not representative):

| Per application | PCS | R1CS, VM transcript | R1CS, Keccak |
| --- | ---: | ---: | ---: |
| Aggregate VM cycles | 797,207 | 797,964 | 2,189,442 |
| Committed size, one / four / eight applications | 2^24.88 / 2^26.88 / 2^27.88 | 2^24.88 / 2^26.88 / 2^27.88 | 2^26.24 / 2^28.23 / 2^29.23 |
| Application execution gas | 10,971 | 61 | 61 |

The [Track A challenge](challenge/README.md) freezes everything but the prover: the candidate build only runs the timed aggregate, and the frozen baseline build makes the hidden workload and the client proofs and verifies the result. Its pilot is recorded in the [Arch evidence](evidence/2026-10-20-arch/README.md).

## Trees, a native Keccak circuit and real-hardware kits

[`aggregation::tree`](../../crates/rec_aggregation/src/aggregation/tree.rs) proves a root over proofs of any leaf program: it runs the recursion guest's own `verify_sub` on each leaf, batches their deferred claims with `aggregate_claims`, and publishes a statement over the leaf program's seed, the ordered leaf public inputs and the batched claim, which verification recomputes against the leaf bytecode. The deferred-claim code now takes a bytecode table as a parameter; the upstream guest's path is unchanged (`aggregate_two_to_one` and `leaf_claim_matches_the_general_path` pass). The `tree` example proves leaves of matched applications and a root over them, and checks that reordered, changed, dropped or forged leaves, a moved claim and a foreign leaf program are rejected. Leaves must stay within the recursion guest's 2^22 to 2^28 window, so a leaf holds up to eight PCS or BLAKE2s R1CS applications and two Keccak R1CS ones. On Arch ([evidence](evidence/2026-10-21-trees/README.md)) a root verifies each leaf in about 260,000 cycles, and 4 × 4 trees cost the same for PCS and the BLAKE2s R1CS path: 1.04M root cycles at 2^25.08 committed.

[`flock::keccak`](../../crates/flock/src/keccak.rs) is the circuit a native Keccak instruction would prove; [the design note](KECCAK-INSTRUCTION.md) gives its tests, cost and the integration still needed. [`bench/`](bench/README.md) holds the Pixel 7 client-proving driver, the static Android build and the Mac command lines.

## Published-branch evidence

The [review validation record](evidence/2026-10-20-review/README.md) retains fresh measurements, exact source/environment provenance and regression logs for the cleaned code. Fixed public seeds generate benchmark fixtures, not production secrets.

## Formal assurance

The structured gate lowering and its ideal-model soundness theorem are in [`formal/quotient/QuotientSecurity/R1CS.lean`](../../formal/quotient/QuotientSecurity/R1CS.lean). The six row equations are equivalent to the shared quotient gate, and the five eliminated auxiliary wires are uniquely determined. The theorem preserves the original copy and packed public word constraints and the original `(Q + 3) / 2^128` soundness bound. See the [formal scope](../../formal/quotient/README.md#structured-r1cs-comparison) for the distinction between packed word equations and the diagnostic checker's individual bit anchors, and for the implementation and concrete circuit obligations that remain outside the proof. Benchmark and adversarial tests are not formal verification of either complete pipeline.
