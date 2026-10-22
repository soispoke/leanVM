# A verifier in the generic circuit format

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

The lowering uses Karatsuba polynomial multiplication for variable field products and linear maps for squares, constant products and Frobenius. Primitive tests compare the Boolean gadgets against native field arithmetic and BLAKE2s across block boundaries, including changed-input rejection. The complete verifier was executed at the recorded-operation level; it was not fully lowered, evaluated as a complete Boolean circuit, or proved. No new Lean theorem or implementation correspondence proof is claimed.

## What this changes in the comparison

The earlier recursion timings remain measurements of leanVM recursion, where Flock supplies specialized BLAKE2s machinery. They do not demonstrate efficient recursion using only this generic full-adder format.

The result supports investigating a shared hash argument with explicit binding to the circuit's requests. It does not show that hash batching alone is enough: the verifier also performs substantial field arithmetic. A successful design must measure the hash argument, its binding checks, the remaining arithmetic, and the outer proof together. It would be additional shared proving and verification machinery beyond the small circuit-description decoder.

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
