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

## ML-DSA-44 and Falcon Keccak projection (requested; all numbers below are projections)

Reference algorithm: RustCrypto `ml-dsa` at commit `cf99f5ebe36954026fdc86d2a2b372e6c97d04fb` (source snapshot in `artifacts/hometurf-L4k/ml-dsa-reference`). For ML-DSA-44, FIPS 204 verification has `K=L=4`, `N=256`, `q=8,380,417`, `tau=39`, and a 1,312-byte encoded public key.

The expected Keccak-f[1600] count per verification is:

| FIPS 204 operation | Keccak-256 permutations | basis |
|---|---:|---|
| ExpandA, SHAKE128 | **80 fixed** | 16 polynomials × 5 168-byte SHAKE128 blocks; RustCrypto `rej_ntt_poly` squeezes 840 bytes per polynomial. The expected accepted 3-byte candidates are `256/(q/2^23)=256.39` per polynomial; rejection count is expected **0.39** per polynomial. |
| `tr = H(pk)` | **10** | 1,312-byte key plus SHAKE padding, `ceil((1312+1+1)/168)=8` if counting SHAKE128 rate, but SHAKE256's 136-byte rate gives **10**. |
| `mu = H(tr || M)` | **1 expected for a short message** | 64-byte `tr` plus a message ≤64 bytes fits one SHAKE256 absorption block. Longer messages add `ceil((64+|M|+2)/136)-1`. |
| SampleInBall | **1 expected** | 8 initial bytes plus an expected `Σ_{i=217}^{255}256/i ≈ 42.7` rejection-sampled index bytes; the RustCrypto loop uses a variable number of squeezes, but this total fits one 136-byte block overwhelmingly. |
| challenge hash over `w1Encode` | **5 expected** | ML-DSA-44 `w1Encode` is projected as 512 bytes (4 bits × 4 × 256 coefficients), plus 64-byte `mu`; SHAKE256 absorbs 576 bytes in 5 blocks. |

Thus the projected total is **97 Keccak permutations per ML-DSA-44 verification** (80 fixed + 10 + 1 + 1 + 5), with the `mu`, SampleInBall and message-length terms explicitly expected values. This is a projection of the FIPS/RustCrypto schedule, not an executed ML-DSA circuit.

For modular work, the projected verification has 4 forward NTTs for `z` (one per vector component), 4 inverse NTTs for `Az - c·t1` (one per output row), and 16 pointwise products for `A·z` (4×4). `c·t1` adds four pointwise products. UseHint/HighBits touches 4×256 coefficients; norm checks scan `z` (4×256) and the reconstructed `w` (4×256), with the exact bound comparisons depending on hint encoding. These counts follow the RustCrypto `raw_verify_mu` path (`z.ntt`, `c.ntt`, `A_hat*z_hat`, `c_hat*t1_2d_hat`, inverse NTT, `use_hint`, `encode_w1`).

Using L3b Stage 0 as the only measured calibration, Falcon's three NTT rows are 394,109 + 398,801 + 387,974 = **1,180,884 Boolean rows**, and pointwise/product checks are **342,939 rows**. A linear 23-bit/14-bit operand-width scale gives projected ML-DSA modular rows `(1,180,884 + 342,939) × (23/14) × (4 forward + 4 inverse + 16 A·z + 4 c·t1)/(3 NTT + Falcon's 512-point product baseline)`; because the denominator's product arity is not exported by L3b, I conservatively report the simpler directly count-scaled range **2.51–3.04 million projected Boolean rows** (lower end treats the 16 products as the Falcon-equivalent batch; upper end charges each of the 20 products separately). This uncertainty is material and is why these are projections.

### Projected wallet envelopes

The measured Falcon bit-level baseline is 13.4127 s, 27.5 GiB whole-process peak RSS, and 8,798,175 arithmetic rows. For the **all-bit-level ML-DSA-44 projection**, I scale the hash portion by the permutation ratio `97/16` (Falcon's 7 digest + 9 HashToPoint permutations) and the modular portion by the 23/14 operand ratio and the 8 NTT + 20 pointwise products versus Falcon's 3 NTT + product stage. This gives **~31.0 million projected rows**, **~47.2 s projected wallet time**, **~97.0 GiB projected peak RSS**, and **~1.27×10^8 projected committed words** (all linear-envelope estimates from the Falcon baseline; no proof bytes are claimed).

For the **Keccak-row ML-DSA-44 projection**, I replace the 97-permutation hash work by the measured native-row cost: 0.0281/8 = **3.51 ms projected per Keccak permutation**, versus Falcon's bit-level hash envelope 0.57 × 13.4127/16 = 0.478 s per permutation. The hash component projects to **0.34 s**, while the modular envelope remains **~2.51–3.04 million rows**. Combining the measured per-permutation time with the scaled modular fraction gives **~7.1–9.0 s projected wallet time**, **~14.6–18.5 GiB projected peak RSS**, and **~3.6–4.8 million projected committed words**. These values assume linear row/time/RSS scaling and retain all verifier checks; they are not measurements.

### Falcon with Keccak rows

L3b reports SHAKE as 4,892,898 rows, **56.88%** of the 8,798,175-row bit-level core. The measured native Keccak permutation cost ratio is `(0.0281/8)/(1.4965/8) = 0.0188` against the existing bit-level Keccak application. Replacing only SHAKE rows therefore projects **8,798,175 × (0.4312 + 0.5688×0.0188) = 3,892,000 rows**, **13.4127 × (0.4312 + 0.5688×0.0188) = 5.93 s**, **27.5 × (same factor) = 12.1 GiB RSS**, and **~3.9 million projected committed words**. The modular NTT/product relation, norm checks, decoding and all verifier checks remain unchanged. These are projected wallet numbers; no Falcon Keccak-row proof was implemented.
