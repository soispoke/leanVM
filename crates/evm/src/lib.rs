//! `flock::membership`'s verifier as an EVM contract, and the EVM it runs on: revm with one more instruction,
//! `FIELD_MUL`, a product in `GF(2^192)`.
//!
//! The contract is not written by hand. [`contract::contract`] runs the Rust verifier (`membership::reduce`) on a
//! scalar type that records every operation, and compiles the recorded graph: the two cannot disagree on what is
//! computed. A field element is the low 192 bits of a word, limb 0 lowest; addition is `XOR`.
//!
//! Calldata is `y`, `root` (the statement, 32 bytes each), the witness commitment as its two 16-byte big-endian
//! scalars, then the proof's scalars, 24 big-endian bytes each. The contract returns the commitment's two scalars
//! and the two claims, each a point then a value, one word a scalar. It reverts on a malformed or degenerate proof.
//!
//! [`quotient`] is the same for `flock::quotient`, whose proof is two commitments and five scalars.

mod codegen;
pub mod contract;
pub mod machine;
pub mod quotient;
pub mod record;
