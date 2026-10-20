# Matched PCS and structured R1CS experiment

This branch is a reproducible research comparison based on `leanEthereum/leanVM` commit `651453c6839de98566c18e94d058507c9ff8920b` (`PCS-openings-aggregation`). It retains the same application, client proof, field, quotient PIOP, WHIR openings and outer proof system on both sides. The measured difference is where the application PIOP is verified.

* **PCS:** execution runs the upstream EVM PIOP and emits opening claims. One aggregate verifies all three opening proofs, covering all four claims.
* **Structured R1CS:** the aggregate additionally verifies the PIOP, including its Keccak transcript, and binds the registered application identity and public inputs. Execution emits that app claim.

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

An unsupported committed witness size produces a `kind: capacity`, `status: unsupported` record, never a successful sample or zero proving time. Other proving errors fail the process. The pinned backend accepts committed witness log sizes only through 28. A larger recursive tree is not implemented here.

## Validation and interpretation

Tests cover R1CS gate elimination, tampered auxiliary variables, malformed dimensions and permutations, wrong public inputs, independent Keccak vectors across sponge block boundaries, opening/PIOP mutations, noncanonical field limbs, public-input substitution, and batch order/count/duplicate substitution. `cargo clippy --locked --release -p rec_aggregation --all-targets -- -D warnings` checks the actual examples, rather than only a subset that could hide broken helper targets. The experiment also retains the upstream native verifiers as differential checks.

The EVM is upstream revm with the proposed ten-gas `FIELD_MUL` instruction. R1CS execution does not require that opcode. Both paths use a native prototype dependency-frame coverage adapter. Its CPU cost is measured; no production opcode gas is invented for it. The R1CS EVM contract only emits a claim, so its execution gas is not the cost of a real application transaction.

The Keccak gadget is a constrained bit-level implementation, not a demonstrated state-of-the-art arithmetization. The results do not establish an unavoidable R1CS cost or an architecture-wide winner. General R1CS compilation, compact onchain circuit publication, production registry/coverage semantics, larger recursive trees, ordinary application state and block execution proving remain outside this prototype. The underlying VM proofs are not zero knowledge; application privacy composition has not been independently audited here.

The original measurements and detailed accounting are preserved in the [research record](https://github.com/soispoke/hardness/blob/5c377d0bcf47b02f2208098b5f3d517016a540c8/prototypes/leanccs-pcs-comparison/baselines/pcs-openings/recursion/COMPARISON.md). They belong to that source revision. Validation and measurements of this cleaned branch are recorded separately rather than silently relabeling those historical results.
