# Dense joint-stack layout

The opt-in `keccak-route-qfirst` layout places the native witness q first when its public region is at least one z coefficient region. Three z coefficient regions follow at `z_offset=q_words`; q remains contiguous at offset zero. Other shapes retain the previous layout. Padding is rounded to the existing WHIR common-row granularity. No witness, equation, opening, query or grinding parameter is omitted.

Prover, native verifier and recursive verifier translate every z and port opening by the same public offset. q claims retain their dedicated offset. The setup key adds a versioned domain, z offset and committed size only when this layout is selected, preserving legacy keys otherwise. This is a physical permutation and removal of unused padding, not a change to the R1CS relation or native Keccak relation.

The 65-test package passes, including proof-stream mutation, false public input, invalid witness, substituted keys and false carried claims. Additional direct verifier tests change z/q offsets while keeping the original setup key and proof; both reject. These tests support implementation consistency, not a formal soundness proof. Core verification excludes external decoding and does not establish the full admission gate.
