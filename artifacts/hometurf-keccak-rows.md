# Native Keccak rows: measurements and protocol feasibility

Native Keccak-f[1600] is wired into the private bridge and produces real proofs. Application-level Keccak improves Keccak-256 1 KiB by 20.4x, MPT by 8.26x and Falcon SHAKE by 2.02x in the matched compiler. A real encoded-input ML-DSA-44 native-row circuit matches L5 and proves in 62.850 s; modular arithmetic remains expensive. The bit-level ML-DSA side uses the authorized census/projection fallback. No Keccak-protocol merge proof is claimed.

Branch `hometurf/L4k`; local commits only, no push. Timed processes use CPUs 36–47, `RAYON_NUM_THREADS=12`, `LEANVM_NUM_THREADS=12`; builds/tests use CPUs 48–63 and `CARGO_BUILD_JOBS=4`.

## Measured wallet and verifier results

| Workload / variant | Wallet s | Whole-process GiB | Proof bytes | Verify ms | Arithmetic rows | Committed F64 words |
|---|---:|---:|---:|---:|---:|---:|
| keccak / bits | 1.556004 | 3.475519 | 329,576 | 10.654344 | 2,042,663 | 25,690,112 |
| keccak / rows | 0.076184 | 0.203766 | 245,136 | 11.090992 | 54,410 | 851,968 |
| mpt / bits | 12.393910 | 26.917011 | 389,472 | 11.582972 | 16,579,748 | 205,520,896 |
| mpt / rows | 1.500369 | 3.408815 | 328,504 | 10.661277 | 1,223,960 | 25,690,112 |
| falcon / bits | 11.900435 | 26.371964 | 390,176 | 10.862502 | 10,115,187 | 205,520,896 |
| falcon / rows | 5.877517 | 13.403473 | 364,760 | 10.492314 | 6,077,055 | 102,760,448 |
| ML-DSA / native rows | 62.850237 | 106.983593 | 427,336 | 14.874831 | 63,472,024 | 822,083,584 |

Keccak, MPT and Falcon: three ABAB rounds, six fresh processes per variant, medians. ML-DSA: six fresh native processes, medians; no ABAB speedup claim because the bit-level proof was skipped under the memory fallback. Verify latency is one standalone fresh-process observation per variant. Wallet includes fresh fixture/witness, proof construction and bincode serialization, excluding setup. RSS is the entire child's wait4 high-water mark, including circuit construction and setup. Verification rebuilds independent preprocessing before the timer. Shared JSONL: `P/artifacts/hometurf-12t.jsonl`.

Padded arithmetic rows (bits/native): Keccak 2^21 / 2^16; MPT 2^24 / 2^21; Falcon 2^24 / 2^23; ML-DSA native 2^26. Native application permutations: Keccak 8, MPT 62, Falcon 16, ML-DSA 99. The bit-level versions perform the same permutations in Boolean gates; their native application count is zero.

Historical 1.496 s Keccak and 13.4 s Falcon timings are context, not paired denominators. Both paired variants use the same direct full-adder compiler, fixed output-dependency trimming and independent statement checks. This changes the Boolean-to-native row census from the historical trace compiler: Falcon is 10,115,187 rows here versus the historical 8,798,175. No checks were removed to align counts.

## Implementation and proof binding

`flock::keccak::reduction` supplies a packed batched zerocheck/lincheck reduction. Theta/rho/pi/iota are linear; chi has 38,400 product bits per permutation. Keccak's padded 2^16-bit circuit occupies 1,024 packed F64 witness words per permutation; BLAKE2s's 2^14-bit circuit occupies 256 per compression.

`PrivateBridge::new_mixed` and `native_hash::Builder::setup_mixed` bind BLAKE2s and all 25 input/output Keccak lanes to one arithmetic reduction, one joint commitment and one WHIR opening. Packed families occupy aligned disjoint regions and their claims are lifted into the common cube. `Ckt::enable_native_keccak` records permutation calls; `boolean_application::lower_with_keccak` packs their circuit inputs, invokes the native row and constrains bit unpacking. Ordinary Boolean finish rejects native placeholders, preventing dropped obligations. BLAKE-only setup rejects mixed use. Transcript, WHIR Merkle and canonical claim hashing remain BLAKE2s in these measurements.

Keccak/MPT/Falcon preserve the original canonical application claim: BLAKE2s(original Boolean application identity || reversed-byte 16-byte statement halves). The native variant computes identity from the original circuit. The bit-level control includes one fixed unused permutation anchor because the Keccak bridge requires a nonempty schedule; this is disclosed overhead. ML-DSA exposes L5's public digest and validity directly. Its public digest uses the Boolean BLAKE2s gadget on both sides.

Falcon retains the existing decoded-coefficient frontend, modular relation, compaction, norm/range and encoding-budget checks; it does not add a compressed-signature byte parser. Its 16 permutations are seven statement-digest SHAKE permutations and nine HashToPoint permutations. MPT retains the same RLP/path/reference checks. The earlier 26–30 ms Keccak raw-digest screen omitted the canonical claim envelope and is not the matched 76.184 ms result.

## Native hash-row cost

512 independent calls, three ABAB rounds/six processes each; every proof verifies. Median BLAKE2s batch 0.0343565635 s = 67.102663 us/compression. Median Keccak batch 0.1098827905 s = 214.614825 us/permutation. BLAKE2s rate 64 bytes gives 1.048479 us/byte; Keccak at SHAKE256 rate 136 gives 1.578050 us/byte, or at SHAKE128 rate 168 gives 1.277469 us/byte. These are amortized proof costs, not host hash timings or isolated reduction-kernel timings.

Total committed words: BLAKE2s 262,144 = 512/call = 8/byte; Keccak 1,048,576 = 2,048/call = 15.058824 per rate-136 byte or 12.190476 per rate-168 byte. These include connectors and PCS padding, unlike witness-only 256/1,024 words above. For a 64-byte protocol Merkle/chain preimage, both need one native call: the rate-136 per-byte advantage does not halve that call count.

## ML-DSA-44: FIPS 204 encoded-input circuit

The circuit parses pk1312, message32 and sig2420 bytes as private bits, decodes t1 and z, checks canonical sparse hints and z norms, recomputes ExpandA, tr, mu and SampleInBall, performs A*z-c*t1*2^13 via NTTs modulo 8380417, inverse NTT, UseHint/HighBits, w1Encode and challenge equality. It outputs validity and BLAKE2s(validity_u64_le || pk || message), exactly L5's statement. There is no host verification predicate in the circuit.

Fixture: RustCrypto `ml-dsa=0.1.1`, L5 `sign(0)`: seed [0x51;32] with first eight bytes zero, message [0x42;32], empty context, deterministic signing. `P/artifacts/hometurf-L4k/mldsa44-L5-fixture.json` contains all bytes. Public digest is `0fbdbdc8105b987a48e75e214bb7154fe98d3c493691b7419842c64374defcea`. Both circuit variants evaluate to this digest and validity 1. Native proofs verify. The six native proofs plus the initial screen are byte-identical, SHA256 `b35e8f96ce34ace5f0528ea0034d0294d2c622ca4e8d2affc6b2ab10d196b5e7`; separate verification covers that deterministic artifact.

Rejection loops have unbounded tails in FIPS. The measured fixed circuit budgets five SHAKE128 output blocks (840 bytes) per matrix polynomial and one SHAKE256 block (128 index bytes after signs) for SampleInBall. It explicitly checks completion and returns validity zero on exhaustion. `RejectionBudget`/`build_with_budget` permit larger fixed shapes and regenerated preprocessing. A validity-1 proof proves the completed FIPS path; the measured fixed budget is not complete for all possible valid FIPS inputs. No negligible-tail argument replaces the completion constraint.

### Permutation census

| Operation | Cold FIPS count | Arithmetic / expected-value basis |
|---|---:|---|
| ExpandA, SHAKE128 | expected approximately 80 | 16 polynomials; at least five 168-byte output blocks each. Acceptance q/2^23=0.999023556709; expected candidates=256/p=256.250213802 (0.250213802 rejections/polynomial). Probability more than 280 candidates are needed is about 1.39946e-40 per polynomial under the XOF model; count has unbounded tails. |
| tr=H(pk), SHAKE256 | 10 exact | floor(1312/136)+1; 64-byte output. |
| mu=H(tr || Mprime) | 1 exact here | Mprime=0x00 || len(ctx) || ctx || message; 64+2+32=98 bytes. General absorption count floor((66+ctx_bytes+message_bytes)/136)+1. |
| SampleInBall | expected approximately 1 | Eight sign bytes plus sum(i=217..255)256/(i+1)=42.221969 expected index bytes. Rare rejection tails can exceed a rate-136 block. |
| Challenge H(mu || w1Encode) | 7 exact | gamma2=(q-1)/88; w1 has 44 values, hence 6 bits/coefficient: 4*256*6/8=768 bytes. Input 64+768=832, so floor(832/136)+1=7. |
| Total cold FIPS | expected approximately 99 | 80+10+1+1+7. The measured fixed schedule has exactly 99 native calls, with completion guards. |

### Modular census and bit-level fallback

Nine forward 256-point NTTs (z4, t1*8192 four, c1) and four inverse NTTs, each 1024 butterflies, total 13,312 butterflies. Inverse scaling is included. ExpandA samples A directly in NTT domain. A*z is 4x4: 4096 scalar pointwise products, plus 1024 c*t1 products = 5120. Matrix accumulation has 3072 additions plus 1024 final subtractions. UseHint/HighBits processes 1024 coefficients. Norm checks require all 1024 z coefficients to satisfy abs(z)<131072-78=130994; sparse hint order/boundaries/trailing zeros and <=80 entries are checked. There is no Falcon-style reconstructed-w norm check. RustCrypto's cached key expansion is recomputed inside this cold circuit.

| Census | Bit-level Keccak | Native Keccak rows |
|---|---:|---:|
| Boolean full-adder frontend rows | 41,996,576 | 29,944,283 |
| Lowered arithmetic rows | 88,479,644 | 63,472,024 |
| Padded rows | 134,217,728 | 67,108,864 |
| Committed words (planned / proved) | 1,644,167,168 planned | 822,083,584 proved |
| Keccak permutations | 99 Boolean | 99 native |

Bit-level evaluation succeeded in 20.334643 whole-process s / 9,668,496 KiB (evaluation only, not proving). Its shape exceeds the bounded backend log26 cap. Doubling the native commitment projects roughly 125.700474 s / 213.967186 GiB; the initial-screen calibration was 144.231594 s / 213.949249 GiB. These are projected, not measured. Peak memory above about 200 GiB triggers the user's fallback: no bit-level proof, proof size or verify latency is claimed. Six native wallet samples: 63.335309594, 62.365164051, 61.582902022, 64.228073837, 61.845881241, 70.953303600. The initial 72.115797 s screen is excluded from the median.

L5's current matched inverse-rate-2 reference is 6.4366 s / 8,411,200 KiB; its SDK permutation screen is 5.412373 s (one sample). Inputs/digest match; R1CS includes serialization while L5's timer excludes it. Native R1CS remains about 9.8x slower than L5's matched reference. L5's updated Falcon reference is 0.5313 s, superseding historical 1.02 s context. No measured ML-DSA bit/native speedup ratio is asserted.

## Projection cross-check requested before the real circuit

L3b Stage-0 (`P/artifacts/hometurf-word-tables.md`) measures mean Falcon 512-point NTT=(394109+398801+387974)/3=393628 Boolean rows, with 2304 butterflies; a 256-point NTT has 1024 (factor 4/9). Width-linear projected cost=393628*(4/9)*(23/14)=287410.920635 Boolean rows, or width-quadratic=472175.083900. Projected product cost=(342939/512)*(23/14)^2=1807.783911 Boolean rows/scalar. Thirteen NTTs plus 5120 products project to 12,992,195.59–15,394,129.71 Boolean rows, before sampling/parser/canonical reduction/hints/digests/checks. Do not combine this Boolean subtotal with nibble-native rows.

The actual censuses supersede that incomplete subtotal. For the requested historical row-linear check, projected t=13.4*(R/8.8M) s and RAM=27.5*(R/8.8M) GiB:

| Conditional projection (all numbers projected) | Rows | Words | Wallet s | Whole-process GiB |
|---|---:|---:|---:|---:|
| ML-DSA bit-level | 88,479,644 | 1,644,167,168 | 134.730367 | 276.498888 |
| ML-DSA native Keccak | 63,472,024 | 822,083,584 | 96.650582 | 198.350075 |
| Falcon native Keccak, conditional 57% SHAKE premise | 3,892,820 | 51,380,224 | 5.765434 | 12.165063 |

Falcon model: residual rows=8.8M*0.43=3.784M. The whole matched Keccak envelope supplies an upper connector proxy 54410/8=6801.25 rows/call, giving R=3.784M+16*6801.25=3,892,820. Projected t=13.4*0.43+16*0.000214614825=5.765434 s; RAM=27.5*(R/8.8M)=12.165063 GiB. Layout projects 2^22 arithmetic height / 51,380,224 committed words. The measured Falcon layout is 2^23 / 102,760,448 words; implementation and padding differences limit the calibration. The supplied 57% premise spans a different census/compiler, so this conditional model is not an exact row prediction. Earlier published 97-permutation ML-DSA estimates are withdrawn; they had wrong w1Encode width and omitted transforms.

## Validation and limits

Six release Flock Keccak tests and two bridge tests pass, including mixed BLAKE2s+Keccak proof and ordinary-verifier rejection of changed wiring, wrong intermediate output, wrong digest and corrupted proof stream. Adversarial bridge proofs bypass host prechecks. Two compiler placeholder regressions pass. Full circuit suite: 78 passed / 4 ignored / 0 failed; doctest runner passes after explicit RUSTDOC path; all-target release clippy passes for Flock/circuit_suite/format_recursion. Modular tests cover all 255 twiddle constants and UseHint boundary cases.

ML-DSA unchecked forced-valid-claim proofs rejected so far: signature, message, key, z, hint (5/5). Each mutation is evaluated as invalid, then public variable values are overwritten with the original valid digest/validity; proof generation calls `prove_mixed_without_prechecks_for_tests`, and the ordinary verifier must reject. Required cases: signature, message, key, z out of range, hint. This is implementation evidence, not a formal soundness/security claim.

## Phase 2: protocol-hash feasibility

Application rows above retain BLAKE2s protocol hashing. A complete protocol substitution must also change the Fiat-Shamir chain/grinding, WHIR committer and verifier Merkle hashing, symbolic recursive verifier and claim hashing together, retaining application outputs/digests. Existing `FiatShamirState::keccak` is an EVM-oriented no-grinding mode; substituting it would omit required grinding checks. It is not used as a shortcut.

The conditional layout model in `protocol-projection.json` freezes the measured BLAKE merge trace and assumes one Keccak permutation for each BLAKE compression. It is not a re-recorded Keccak verifier census. Keccak needs 17 connector rows/slot versus six and four times packed witness words. For BLAKE64's 578,847 trace rows / 14,598 hashes, 16,384 slots: occupied rows project from 688,128 to 868,352, padded height stays 2^20, words project from 16,777,216 to 33,554,432 (2x). Scaling the supplied 0.88–0.97 s reference by words projects 1.76–1.94 s. For shielded's 736,150 rows / 21,990 hashes, 32,768 slots: occupied rows project from 950,272 to 1,310,720, padding 2^20 to 2^21, words 25,165,824 to 67,108,864 (2.667x); time projects 3.253–3.387 s from 1.22–1.27 s. All candidate numbers are projections, not measured merge costs; hash counts can change after the verifier is re-recorded.

Three-round ABAB native hash-batch screen (six fresh proofs per variant; every proof verifies):

| Calls | BLAKE2s s | Keccak s | BLAKE words | Keccak words |
|---|---:|---:|---:|---:|
| 16,384 | 0.605078 | 2.673029 | 8,388,608 | 33,554,432 |
| 32,768 | 0.956349 | 4.619456 | 16,777,216 | 67,108,864 |

These are native hash-batch proofs with BLAKE2s protocol hashing, not first-level merge proofs or a Keccak-protocol wallet. They measure the cost of the prospective hash-row payload at merge-sized slot counts. Raw receipts and binary metadata: `protocol-proxy-*`; summary: `protocol-proxy-summary.json`. They are diagnostic proxies, not formal runtime lower bounds. Nevertheless, 2.67 s at 16,384 calls and 4.62 s at 32,768 calls, together with the conditional layout model, do not support the required under-one-second merge. The feasibility decision is to retain BLAKE2s protocol hashing and the measured application-level Keccak rows. A complete protocol switch was not implemented or adopted; there is no actual Keccak-protocol wallet/merge timing. Completing that switch safely requires matching grinding, host Merkle, symbolic-verifier and claim-hash changes, not replacing the transcript with its no-grinding mode. The Phase 2 result is a negative feasibility screen, not a measured protocol regression.


## Reproduction

Phase-1 frozen source `3bf7091f937e25d55f171c4bc86be5c3b5f634e9`, binary SHA256 `cbadb0411155d194299afd8e843af29ae5d514d6a28557f82919626403dba8da`, raw `P/artifacts/hometurf-L4k/{keccak,mpt,falcon}-abab/`. ML-DSA frozen source `08305593`, binary SHA256 `14a95283564332164d5b17ef5961d40b9100609d185482ac03c81696f6e296a6`, raw `mldsa-native-r*`, `mldsa-native-verify.*`, `mldsa-bit-evaluate.*`, `mldsa-rejections.*`; frozen executable and metadata are alongside them. New `RejectionBudget` API retains the measured default topology. Harnesses are under `experiments/pcs-r1cs/`, and circuit implementation is `crates/circuit_suite/src/mldsa.rs`.

## Verdict

Keccak as a native application hash makes Keccak-256 decisively faster, brings MPT near the historical leanVM reference, and halves Falcon's paired commitment and wallet time. The real encoded ML-DSA circuit is measured and matches L5, but remains much slower and larger than leanVM; the bit-level comparison is a census/projection fallback. Keccak's larger native relation costs more than BLAKE2s per call and per byte in this implementation. The protocol-hash feasibility screen does not support a viable under-one-second merge, so BLAKE2s stays the protocol hash. No security claim or full switched-protocol benchmark is made.

Final source audit: release rebuild at `6cfbbee1` passes; the parameterized default circuit recount remains exactly 29,944,283 Boolean frontend rows and 99 native permutations (`P/artifacts/hometurf-L4k-final-default-census.log`). Latest mixed-bridge regressions pass both tests, including malformed-proof rejection without prover prechecks. No timed jobs remain running.
