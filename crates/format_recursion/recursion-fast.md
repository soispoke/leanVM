# recursion.fast relation adapter

This module implements the statement byte layouts at submissions contract pin `15e4ae5eaba6a65211668c6e0f55f9fea1d9050d`. Its source of truth is `RecursionFast/Contract/Relation.lean` at that revision, read through `git show`. It is an adapter and circuit test fixture, not a completed challenge submission or a Lean security certificate.

## Exact statement

| Operation | Bytes hashed with BLAKE2s-256 |
| --- | --- |
| One chain step | `0x43 || digest[32]` |
| Leaf statement | `0x4c || chain_end[32] || n.to_le_bytes()[8]` |
| Node statement | `0x4e || left_digest[32] || right_digest[32]` |
| Instantiated oracle query | `0x52 || query` |

The chain starts at the private 32-byte value and applies exactly `n` steps. A zero-length chain leaves the start unchanged. The relation allows `n <= 2^20`. The native adapter rejects larger lengths before hashing. Child proofs are capped at `2^20` bytes, matching the contract's instantiated verifier wrapper.

`LeafCircuit::build(n, row_limit)` uses existing `Ckt` BLAKE2s primitives and fixes `n` when building the index. Its only private inputs are the start's 256 bits. The public format is the contract's 32-byte statement digest followed by 32 zero bytes, fitting the existing quotient circuit's 64-byte public statement. The caller must bind this exact statement and this fixed circuit/index in any proof backend. The caller must not accept a prover-selected circuit index without separate authorization.

Construction checks the row budget after each hash and checks the final padded size. It may construct one hash beyond the requested budget before returning `RowLimit`; it never builds the whole remaining chain after exceeding that budget. The circuit adapter supports at most `2^29` padded rows to retain bounded cell addresses. This resource limit does not change the challenge's mathematical chain bound or prove completeness for all allowed lengths on this backend.

`expected_leaf` calculates the digest natively without evaluating the circuit. Tests compare both paths to independently generated Python `hashlib.blake2s` vectors. They cover lengths zero, one, two, and sixteen; changed start, length, public digest, and zero padding; malformed resource bounds; and ordered node digest inputs.

## Node scope

`node_digest` is a composable circuit gadget for the ordered child digest hash. It must be combined with two actual child-verifier circuits to become a recursive node circuit. Computing the digest alone proves no claim about child proofs.

The native `node_relation` helper implements the full node relation by checking its digest and invoking a supplied child verifier on each exact digest/proof pair, after enforcing both proof caps. This callback is an explicit dependency, not a trusted acceptance shortcut. Unit tests use a simple recognizer to check adapter plumbing; they do not certify any SNARK verifier.

## Formal and challenge status

The inspected submissions repository pins `15e4ae5`, while the separate core checkout is at `059812f72502004a91e7b12a3ba6e1d57f8b0611`. Both use Lean 4.34.1. Their relation encodings agree, but their security definitions differ: the pin uses Boolean good/bad knowledge states, while the newer core uses a potential and a bounded log length. A theorem proved against one is not silently a theorem against the other. This module does not change the pin.

The previous ideal-commitment quotient soundness theorem does not establish concrete PCS security, exact compiled verifier correctness, perfect completeness for every oracle, or the challenge's executable extractor image obligation. The native arithmetic/Flock argument is also a separate experimental composition. No `Certificate` or `CertificateR` for that argument is asserted here.

The local submissions tree has no ranked records, and its README says the full v3 harness and intake remain pending. This adapter is useful for developing an entry and running local checks; its tests are not an official challenge evaluation.
