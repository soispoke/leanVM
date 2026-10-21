# A native Keccak instruction

**Status.** The proving circuit exists and is proved correct: [`flock::keccak`](../../crates/flock/src/keccak.rs) is Keccak-f[1600] as one flock R1CS block, and flock's circuit-agnostic lincheck proves and verifies batches of permutations against it. The instruction is not yet wired into the VM. That integration changes leanVM's arithmetization and all three of its verifiers, so it is soundness-critical work for a separate, reviewed change.

## Why it matters

With the Keccak transcript, the R1CS aggregate spends about 199,000 VM cycles and 6.9 million committed words per permutation, seven permutations per application ([Arch runs](evidence/2026-10-20-arch/README.md)). A flock block commits 2^16 bits, 1,024 words, per permutation: about 6,700 times less, plus one instruction row and its memory traffic. The R1CS path could then share the PCS path's Keccak client proof again at roughly the cost of the BLAKE2s variant. Per byte hashed, the block costs 1.9 times a BLAKE2s compression (2^16 bits per 136-byte block against 2^14 per 64-byte one).

## The circuit

flock proves `(A z)_i · (B z)_i = z_i` for every slot of a block. Keccak's only nonlinear step is chi, so the block has the constant wire, the 1,600 input bits, one product per state bit per round (38,400), and the 1,600 output bits pinned as wires the bus can read: 41,601 of 65,536 slots. The round states between are linear forms that cascade through all 24 rounds, as `BLAKE2s`'s lanes do, so the dense matrices are never built. A forward walk evaluates `A w` and `B w` by running the round structure over the field, and the fold runs its transpose backwards. Each product depends only on earlier slots, so the satisfying witness for an input is unique and its output is the permutation.

| Test | What it establishes |
| --- | --- |
| `block_round_is_exactly_the_reference_round` | One block round equals an independent FIPS 202 round on every input: both have degree at most two over GF(2), and they agree on all 1,280,801 inputs of weight at most two |
| `witness_satisfies_exactly_the_permutation` | Honest witnesses satisfy every slot and output the permutation; a flipped product, output or padding bit breaks a slot |
| `fold_is_the_transpose_of_the_walk` | `⟨Aᵀe + α Bᵀe, w⟩ = eᵀ(Aw) + α eᵀ(Bw)` for random `e`, `w`, `α` |
| `lincheck_roundtrip_over_permutations` | flock's lincheck proves and verifies eight permutations with these walks and rejects a wrong claim |
| `reference_matches_known_answers` | The reference sponge gives the published Keccak-256 of `""` and `"abc"` |

A wrong theta rotation and a wrong transpose index were each injected and caught.

## What integration needs

1. **ISA and compiler.** An instruction `KECCAK(in, out)` over 25 consecutive 64-bit lane cells each way, executed natively, and a zkDSL intrinsic beside `blake2s`.
2. **Table and bus.** A Keccak table whose rows read and write those 50 cells through the memory bus, sized by the number of permutations, as `BLAKE2S_TABLE` is.
3. **Commitment.** The packed block witness committed as a column of the one stacked witness, with lane values bound to block slots by point-evaluation equality, as `hash_flock` binds `q_flock`.
4. **Native prover and verifier.** Witness and `(a, b)` generation for the zerocheck, a Keccak reduction beside `Blake2sSetup`, and its claims routed through ring switching into the shared opening.
5. **Python verifier.** The same reduction, with the matrix evaluation done by the walks.
6. **Recursion guest.** In-circuit verification of the Keccak table's zerocheck and lincheck, including the walk-based matrix evaluation or a deferred claim on the block's matrices that the outer verifier recomputes, as it does for `BLAKE2s` today.

Items 3, 4 and 6 carry the soundness risk. Each needs negative tests on the table, the bus and the binding of lane values to block slots, and review before measurements count. That makes it Track B work under the challenge's own rule.
