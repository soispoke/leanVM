# Transcript hash for the R1CS path

**Decision.** The R1CS path's application PIOP uses the VM's BLAKE2s chain (`quotient::Oracle::Blake2s`, interface `r1cs-vm`). The PCS path keeps Keccak-256. The Keccak R1CS variant stays as a control that shares the PCS path's client proof byte for byte.

**Why.** The transcript hash should be native to the machine that verifies the PIOP. In the PCS path that machine is the EVM, where Keccak-256 is an opcode. In the R1CS path the EVM never reads the transcript: its contract only emits the application's claim, and the aggregate verifies the PIOP inside leanVM, where BLAKE2s is an opcode and Keccak is a 1600-bit circuit. Keccak was used on both paths only so they could share one client proof. That isolates where the PIOP is verified, but it charges the R1CS path for a hash its verifier never needs.

**Measured effect.** RESULTS_PLACEHOLDER

**Security.** The formal soundness theorem (`Instance.soundness`, `Instance.r1cs_soundness`, bound `(Q + 3) / 2^128`) is stated with the hash as a random oracle on the absorbed transcript, so it applies to either instantiation unchanged. The BLAKE2s chain adds no primitive to the trust base: leanVM already relies on BLAKE2s for its own transcript, its Merkle commitments and its opcode, whose compression the VM proves with flock's R1CS. Domain separation comes from the seed (a digest of `flock-quotient-vm-1` and the circuit, then of the statement) and from the chain's tags, which mark each absorbed block as an observation or a squeeze. The model's caveat that the oracle is this protocol's only applies equally to both hashes, each of which is used elsewhere in its system. Keccak's chaining value and BLAKE2s's are both 256 bits.

The guest mirrors the native chain with the upstream helpers (`obs`, `squeeze_state`, `challenge_from_state`), and pins each commitment root to its canonical 128-bit encoding, as the native decoder does. `oracles_do_not_cross` checks that each oracle verifies only its own proofs and that the seed binds the statement. The single-application run applies the full tampering suite to this variant.

**Not chosen.** An arithmetization-friendly hash (a Poseidon-style permutation over a binary field) would need a new VM opcode or circuit, a new cryptanalysis assumption, and EVM support it does not have. BLAKE2s already gives the VM a one-instruction hash with none of those costs. A native Keccak opcode, proven by flock like BLAKE2s, would let both paths share one client proof cheaply; it changes the VM's arithmetization and its recursive verifier, so it is Track B work.

**Consequences for the comparison and the challenge.** The two paths no longer share client proofs. Client proving changes negligibly, since the hash is a tiny part of native proving, and execution gas is unchanged, since neither EVM contract reads the R1CS transcript. The Track A challenge scores `pcs`, `r1cs-vm` and the `r1cs` control as separate interfaces with separate baselines.
