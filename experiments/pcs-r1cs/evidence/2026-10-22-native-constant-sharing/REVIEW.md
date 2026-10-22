# Constant-sharing source review

Candidate `f50dd22cc994596dd48695ac49c5e3f9b2aef1ae` differs from the published `7591db25` checkpoint only in `crates/format_recursion/src/trace.rs`. The frozen baseline's Rust sources and configuration match that checkpoint. The rejected preprocessing experiment is separate and is not included.

The recorder shares only `Op::Constant` nodes, keyed by all three limbs of GF(2^192). It never interns private inputs or hash outputs, and the hash map is not iterated when generating a program. Therefore randomized map iteration does not influence node order. Equal private values still produce distinct node identities.

Before this change, the compiler constrained each repeated constant node to the first canonical constant with an equality row. Sharing the first constant node removes those redundant variables and equality rows. Existing arithmetic simplification of identical nodes agrees with characteristic-two arithmetic. No verifier equation, hash function, transcript domain, opening profile or security parameter was edited. The generated circuits and setup keys do change.

The three active-trace lifecycle paths are `start`, `take` and `Trace::bind_batch`. Each clears the constant cache. A dedicated test installs a detached trace while an unrelated cache is active; this caught a missing reset during development before the final build and measurements. Trace concatenation shifts existing identities and does not consult the active cache.

Final release tests cover constant identity and lifecycle, independence from private input values, fixed-program structure and output binding, constrained helper wires, malformed connector proofs and existing recursive verification. All 72 native tests and all-target Clippy passed. Every benchmark proof is locally verified, and the retained validator independently recomputes the tagged BLAKE2s statements.

This is a source review and runtime validation, not a Lean equivalence proof or a cryptographic audit. The existing quotient/R1CS theorems do not certify this native recursive composition. Separate trusted keys per level, lack of a single recursively closed verifier and the existing non-zero-knowledge scope remain unchanged.
