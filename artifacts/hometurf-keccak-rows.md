# L4k: Keccak-f[1600] native-row investigation

This lane was started from `020448f2` on `hometurf/L4k` (no push). The source already contains `crates/flock/src/keccak.rs`, a complete Keccak-f[1600] Flock circuit and reduction unit tests. That circuit is an application-level bit circuit; it is not wired into `format_recursion::private_bridge::PrivateBridge`, whose production bridge remains BLAKE2s-specific (`Blake2sSetup`, `Compression`, `blake2s_compress`). Consequently this lane did not claim a native Keccak production proof or change protocol hashing.

## Evidence available on this branch

The checked-in Keccak application circuit documents 1,003,539 Boolean rows for Keccak-256 of 1 KiB (eight permutations plus input/public rows), with a 2^20 padded shape. The Flock Keccak reduction uses one degree-two product per chi state bit per round: 38,400 nonlinear products per permutation; theta, rho, pi and iota are linear wiring. Its reduction tests cover honest permutation output and a changed output claim.

The existing automatic-trimming run for the Keccak 1 KiB application (commit `89401e868d330e177e807aa4c900e5c8fa263831`, 12 threads, recorded CPUs 0-11) is the only end-to-end measurement available in this checkout: wallet prove 1.496485141 s, peak RSS 4,266,580 KiB, proof 324,060 bytes, verify 9.269212 ms. The witness reports 2,050,353 trace nodes and 8,192 Boolean input rows; the selected shape is `log_rows=21`, `n_blocks=39`, `block_log=7`, `q_offset=25,165,824`, `stack_log=25`. This is a bit-level application circuit, not a native-row replacement, and therefore is not an ABAB native-vs-BLAKE comparison.

For comparison, the L4 BLAKE2s native bridge screen reports 14,598 compression rows, 578,847 pre-bridge arithmetic rows, 16,777,216 committed F64 words, 323,976-byte proof, and 0.655029074 s in its faster alternating candidate slot (the report explicitly says that screen was not a valid ABAB application measurement). The universal recursive node remains 63,426 BLAKE2s calls, 2,034,321 pre-bridge rows and 67,108,864 joint witness words.

## Cost model

At the circuit level, Keccak costs 38,400 chi products per permutation and eight permutations for 1 KiB. BLAKE2s compression rows in the existing bridge are one native Flock block each, with 16,384 packed witness slots per scheduled block. These units are not directly interchangeable: Keccak's product slots are 1-bit GF(2) relations, while the bridge's committed-word count includes padding, connectors and opening layout. No valid per-row prover-time ratio was measured here.

## Phase 2 and soundness status

Transcript, WHIR Merkle and claim hashing were left as BLAKE2s. MPT and Falcon/SHAKE native-row workloads were not implemented or measured in this lane. No merge timing under protocol Keccak is available; therefore the requested <1 s viability gate is unanswered. Existing Keccak Flock tests reject a wrong output claim, while the production bridge's existing verifier checks were untouched. There is no soundness claim for a native Keccak reduction.

## Verdict

Keccak as a native application hash has a plausible algebraic advantage (only chi is nonlinear), and the repository already has the circuit/reduction needed for a focused integration. This lane does not establish that it beats the BLAKE2s bridge: the required bridge adapter, MPT/Falcon measurements, protocol-hash phase, ABAB runs on CPUs 36-47, and adversarial verifier tests remain outstanding. The only defensible result is that the current Keccak bit-level circuit is expensive (1,003,539 rows for 1 KiB) and must not be presented as native-row evidence.
