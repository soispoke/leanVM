# L4k: Keccak-f[1600] native-row investigation

This lane was started from `020448f2` on `hometurf/L4k` (no push). The source already contains `crates/flock/src/keccak.rs`, a complete Keccak-f[1600] Flock circuit and reduction unit tests. That circuit is an application-level bit circuit; it is not wired into `format_recursion::private_bridge::PrivateBridge`, whose production bridge remains BLAKE2s-specific (`Blake2sSetup`, `Compression`, `blake2s_compress`). Consequently this lane did not claim a native Keccak production proof or change protocol hashing.

## Evidence available on this branch

The checked-in Keccak application circuit documents 1,003,539 Boolean rows for Keccak-256 of 1 KiB (eight permutations plus input/public rows), with a 2^20 padded shape. The Flock Keccak reduction uses one degree-two product per chi state bit per round: 38,400 nonlinear products per permutation; theta, rho, pi and iota are linear wiring. Its reduction tests cover honest permutation output and a changed output claim.

The existing automatic-trimming run for the Keccak 1 KiB application (commit `89401e868d330e177e807aa4c900e5c8fa263831`, 12 threads, recorded CPUs 0-11) is the only end-to-end measurement available in this checkout: wallet prove 1.496485141 s, peak RSS 4,266,580 KiB, proof 324,060 bytes, verify 9.269212 ms. The witness reports 2,050,353 trace nodes and 8,192 Boolean input rows; the selected shape is `log_rows=21` (2^21 padded arithmetic rows), `n_blocks=39`, `block_log=7`, `q_offset=25,165,824`, `stack_log=25`. This is a bit-level application circuit, not a native-row replacement, and therefore is not an ABAB native-vs-BLAKE comparison.

For comparison, the L4 BLAKE2s native bridge screen reports 14,598 compression rows, 578,847 pre-bridge arithmetic rows, 16,777,216 committed F64 words, 323,976-byte proof, and 0.655029074 s in its faster alternating candidate slot (the report explicitly says that screen was not a valid ABAB application measurement). The universal recursive node remains 63,426 BLAKE2s calls, 2,034,321 pre-bridge rows and 67,108,864 joint witness words.

## Cost model

At the circuit level, Keccak costs 38,400 chi products per permutation and eight permutations for 1 KiB. BLAKE2s compression rows in the existing bridge are one native Flock block each, with 256 packed F64 words per scheduled BLAKE2s block (2^14 Boolean slots / 64-bit packing). These units are not directly interchangeable: Keccak's product slots are 1-bit GF(2) relations, while the bridge's committed-word count includes padding, connectors and opening layout. No valid per-row prover-time ratio was measured here.

## Phase 2 and soundness status

Transcript, WHIR Merkle and claim hashing were left as BLAKE2s. MPT and Falcon/SHAKE native-row workloads were not implemented or measured in this lane. No merge timing under protocol Keccak is available; therefore the requested <1 s viability gate is unanswered. Existing Keccak Flock tests reject a wrong output claim, while the production bridge's existing verifier checks were untouched. There is no soundness claim for a native Keccak reduction.

## Verdict

Keccak as a native application hash has a plausible algebraic advantage (only chi is nonlinear), and the repository already has the circuit/reduction needed for a focused integration. This lane does not establish that it beats the BLAKE2s bridge: the required bridge adapter, MPT/Falcon measurements, protocol-hash phase, ABAB runs on CPUs 36-47, and adversarial verifier tests remain outstanding. The only defensible result is that the current Keccak bit-level circuit is expensive (1,003,539 rows for 1 KiB) and must not be presented as native-row evidence.

## ML-DSA-44 projection correction and operation census

The preceding published 97-permutation, 31M-row ML-DSA projection and its derived time/RAM/word estimates are withdrawn: they used an incorrect w1Encode width and omitted transforms. The earlier Falcon projection also mixed nibble-native and bit-level row units. None is measured evidence and none should be used for performance conclusions.

Pinned reference: RustCrypto/signatures `cf99f5ebe36954026fdc86d2a2b372e6c97d04fb`, ml-dsa/src/{sampling,verifying,param,lib}.rs, archived in P/artifacts/hometurf-L4k/ml-dsa-reference. Cold FIPS 204 ML-DSA-44 verification, 32-byte message and empty context:

| Operation | Permutations | Basis |
|---|---:|---|
| ExpandA (SHAKE128) | expected approximately 80 | 16 polynomials, 5 rate-168 output blocks each. Candidate acceptance q/2^23 = 0.9990235567; expected 256.250216 candidate triples (0.250216 rejected) per polynomial. More than 280 candidates can be needed; the five-block count is overwhelmingly likely, not a hard maximum. |
| tr = SHAKE256(pk,64) | 10 exact | floor(1312/136)+1 absorption permutations. |
| mu = SHAKE256(tr || Mprime,64) | 1 exact for this message/context | Mprime = 0x00 || len(ctx) || ctx || M; input 64+2+32 = 98 bytes. General count floor((66+len(ctx)+len(M))/136)+1. |
| SampleInBall(c_tilde,39) | expected approximately 1 | 8 sign bytes plus sum(i=217..255) 256/(i+1) = 42.221078 expected index bytes. Rare rejection tails may require further rate-136 blocks; expected-byte count is not an exact permutation bound. |
| challenge SHAKE256(mu || w1Encode,32) | 7 exact | gamma2=(q-1)/88, hence 44 high-bit values and 6 bits/coefficient; 4*256*6/8 = 768 encoded bytes. Input length 64+768=832; floor(832/136)+1=7. |
| Total | expected approximately 99 | 80+10+1+1+7; unbounded rejection tails must be handled in a real circuit. |

Cold modular work: 4 forward NTTs for z, 4 for 2^13*t1, 1 for the challenge c, and 4 inverse NTTs, all length 256 modulo 8380417. ExpandA already samples the NTT-domain matrix and requires no further transform. A*z uses 16 polynomial pointwise products (4096 scalar products); c*t1 adds 4 (1024 scalar products): 5120 scalar products total. Matrix accumulation uses 3072 scalar additions and final subtraction another 1024. UseHint/HighBits touches 1024 coefficients. Verification checks 1024 z coefficients against gamma1-beta=131072-78=130994 and checks hint encoding, ordering, boundaries and at most omega=80 ones; it does not perform a Falcon-style reconstructed-w norm test. RustCrypto caches ExpandA, tr and the four public-key NTTs when decoding a verifying key; the user-requested circuit includes these cold costs.

L3b Boolean calibration (distinct from nibble-native rows): mean Falcon 512-point NTT=(394109+398801+387974)/3=393628 Boolean rows; each has 2304 butterflies, versus 1024 for a 256-point transform (factor 4/9). A width-only linear estimate is 393628*(4/9)*(23/14) Boolean rows per 256-point transform; charging quadratic width gives 393628*(4/9)*(23/14)^2. Falcon pointwise stage is 342939/512=669.802734 Boolean rows per scalar product, scaled by (23/14)^2 for a 23-bit product. These are projections of one circuit implementation, not measured ML-DSA rows. Parser, sampling, hints, norm and packing costs must be added before a total projection is meaningful. Whole-process RAM and committed words depend on final power-of-two bridge layout; the previous simple proportional estimates did not establish them.

A real ML-DSA circuit and matched L5 fixture measurement now supersede the projection-only request. Projected wallet totals remain pending a complete, dimensionally consistent census.

## Native bridge integration update

Commit `bbdb8e6a` adds `flock::keccak::reduction::KeccakSetup` and a Keccak-specific private bridge. Commit `1ec50125` adds the whole-process measurement helper. The bridge binds all 25 input and 25 output lanes per permutation, places chi products in the packed witness, and reuses the existing zerocheck/lincheck/ring-switch and arithmetic opening machinery. Release tests pass for the six Flock Keccak tests and the malformed-proof bridge test (wrong output, wrong wiring, wrong digest, and tampered proof, all with prover prechecks bypassed).

The follow-up mixed opening adapter is present in the working tree and type-checks through the existing Keccak bridge test, but it has not yet received a production mixed BLAKE2s+Keccak application test or a valid Falcon/ML-DSA end-to-end certificate. The 1 KiB numbers above are therefore the verified Keccak-only application bridge measurement; they should not be interpreted as completed Falcon or ML-DSA measurements.
