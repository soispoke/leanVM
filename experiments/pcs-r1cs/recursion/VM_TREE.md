# Matched tagged hash-chain VM tree

`cargo run --release -p rec_aggregation --example chain_tree_vm -- --depth 3 --chain 16`

This benchmark uses the same leaf starts and exact tagged chain, leaf and ordered
node hashes as `private_tree`. Each parent runs upstream `verify_sub` on both
actual VM child proofs. It reuses upstream witness extraction and deferred-claim
sumchecks. It does not replace child verification with a native success hint.

## Different wrapper

Every level has an authorized program/key. A VM child verifier defers evaluations
of fixed bytecode and Flock matrices. Because different levels have different
bytecodes, a parent authenticates the child's outstanding records in the child
public hash and forwards those records into its own public hash. The root checks
every record against its authorized program. Fresh child-verifier claims are
batched with pinned, valid zero-point claims on the current child program.

This is not the upstream same-program fixed-point construction. The number of
records is 1, 3 and 7 at depths 1, 2 and 3. It is a diagnostic comparison with
growing metadata, not evidence about the best possible leanVM recursion.
Serialized proof size includes all records, including their values. Root
verification includes serialization for the 1 MiB cap and all deferred checks.

## Timing

- Setup includes compilation, bytecode preprocessing and fixed zero-point claims.
- Parent preparation includes child verification, canonical hint extraction,
  deferred batching and public-statement construction.
- Proving measures `cpu::prove`, including VM execution and backend witness
  generation. Parent preparation is reported separately, matching native symbolic
  recording outside the native proof timer. Compare preparation plus proving if
  evaluating the full parent creation cost.
- Leaf proving includes program cloning and installation of its two start cells.
- Verification includes every final deferred polynomial evaluation.
- Each proof is timed once. There is no warmup or repeated-trial median.
- `base_cycles` and `padded_cycles` are VM instructions, not native field rows.

`--shape` executes one leaf and compiles all requested levels without proving.
The straightforward tagged-byte packing currently decomposes digest cells into
bits. A 16-step leaf executes 31,381 VM instructions and 17 BLAKE compressions.
Do not interpret its cost as a lower bound for an optimized VM implementation.

The tagged statement adapter is exact. The proof-system transcript still uses
existing untagged BLAKE2s. No new Lean certificate, numerical security bound,
zero-knowledge claim, closed fixed-shape recursion or official challenge result
is established here.

## Explicit WHIR rate

`--log-inv-rate 1` is now the default, matching the upstream production/test
profile (`LOG_INV_RATE_0 = TEST_LOG_INV_RATE = 1`). The first development runs
hardcoded `2`; they can be reproduced with `--log-inv-rate 2`. The parameter
propagates through every level and appears in the JSON output.

Both values use the same production Johnson/OOD configuration analysis targeting
128-bit round-by-round soundness, with 17-bit query grinding. They correspond to
rate 1/2 and rate 1/4; neither is a reduced-security test profile. Upstream's
`production_profile_is_128_bit_johnson_with_query_grinding` checks all allowed
rates1–4 through committed log-size30. Higher redundancy trades more encoding work for fewer queries; its effect on
total proving time must be measured. Compare configurations
at the same security target and state which one was used. A numeric rate match
alone does not prove that the whole protocols have equal security.

The wrapper tests also construct one actual depth-two VM tree and reuse its root
proof to reject changed points/values, missing/truncated/extra records, reordered
individually valid records, a freshly recomputed valid replacement record, proof
and public-input mutations, truncated serialization, and substitution of a
foreign same-sized leaf key with correctly recomputed affected records. The valid
record controls reach the root proof/public-hash binding rather than failing only
a polynomial check. These are implementation controls, not a formal security
certificate.
