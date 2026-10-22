# Fresh witness schedule review

Candidate `cb88d526` changes only the private trace compiler and the proving/setup methods in `private_recursion.rs`. The circuit's rows, variable allocation order, public inputs, connector table, cryptographic parameters and verifier implementation remain unchanged.

The compiler records how it computed every auxiliary value during trusted setup. A scalar instruction appends a constant, sum, multiply-add, limb, bit or compression-output word. A compression instruction recomputes BLAKE2s from the specified fresh source words. Fixed hash prefixes remain fixed; retained terminal blocks and fallback typing compressions preserve their original order. The schedule stores public constants and variable identities, rather than private witness values or cached proofs.

Every call checks complete program identity, including operations, equality checks, output positions and public constant values, before evaluating the schedule. It allocates new value/compression vectors and checks all public values against the caller's statement. The existing bridge and argument verifier still check the same complete circuit and compression relation. Schedule construction occurs once inside trusted setup; the schedule is private and is not deserialized from a prover.

Differential tests compare every helper field element, compression and public value with the original lowering route across private inputs, malformed intermediate values, extension-field arithmetic, Frobenius, aligned and unaligned projections, fixed hash prefixes, empty hashes and fallback range typing. Existing malformed-program tests also exercise the new entry point. The leaf proof test compares the complete serialized proof byte for byte with the reference compiler's output.

This is a prover optimization. The original lowering route remains available as the reference. Setup, full-tree process time and memory are reported separately so gains cannot be inferred solely from moving work outside the root timer. The retained schedule consumes memory; measurements determine that cost.

These source and runtime checks add no formal Rust implementation or cryptographic composition theorem. The existing native recursion prototype still has separate trusted keys per level, no established closure under one submitted verifier, and no zero-knowledge claim.
