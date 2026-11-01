# Structured Keccak and structural zero absorption

Keccak-f[1600], Ethereum padding, 128-bit settings, query counts, grinding, leaf rate 1/4, and recursion rate 1/2 remain unchanged. Application generators and public statements are unchanged.

The existing optimized Flock reduction is relabeled by the same bijection on R1CS rows and columns. The 25 input and 25 output word ports remain first, and the constant is pinned at bit 3200. All 24 chi rounds and every output constraint remain. Empty rows still force zero padding. The block remains 2^16 bits. Leaf and tree envelopes advance to versions 16 and 12 to distinguish the new circuit layout.

Recursive sponge XORs fold only structural zero wires or identical wire IDs. A witnessed value equal to zero never triggers this folding. Thus the omitted casts and additions implement algebraic identities; every sponge preimage, padding bit and permutation remains the same. No Merkle tree or query distribution changes.

Regression evidence includes native permutation equivalence, the relabeling transpose check, and a direct unchecked Flock-reduction test that submits a false output in each of the 25 lanes and verifies rejection. Wrong transcript labels and proof-stream mutations are rejected. Frozen candidate wallet and root screens reject wrong paths, altered outputs, substituted identities, and tampered proofs. The combined experimental core suite passed 210 tests. These are regression tests, not a proof of soundness or a new security claim.

Matched ABAB x3 on CPUs 36-47, six samples per variant and workload, is recorded in the external experiment directory artifacts/opt-O3/zero-abab. Detailed receipts and limitations are in artifacts/opt-O3.md in the shared experiment root. No challenge eligibility is claimed: timing and admission targets remain unmet.
