# L4k native Keccak rows — measured progress, goal incomplete

Branch `hometurf/L4k`, based on `020448f2`. No push. Timings use CPUs 36–47, RAYON_NUM_THREADS=12 and LEANVM_NUM_THREADS=12; builds/tests use CPUs 48–63 and CARGO_BUILD_JOBS=4.

## Implemented bridge and soundness test scope

`flock::keccak::reduction` supplies packed witnesses and a batched zerocheck/lincheck reduction for Keccak-f[1600]. Each permutation has 38,400 chi product bits; theta, rho, pi and iota are linear. The padded circuit uses 2^16 Boolean slots and 1,024 packed F64 witness words per permutation, versus BLAKE2s's 2^14 slots and 256 packed words per compression. This is witness-only cost, before native connectors, minimum batch padding and PCS alignment.

`PrivateBridge::new_mixed` and `native_hash::Builder::setup_mixed` bind both BLAKE2s and Keccak I/O to one arithmetic reduction, one joint witness commitment and one joint WHIR opening. Their ring-switch claims are lifted into disjoint aligned portions of the common packed witness. Keccak binds all 25 input and 25 output lanes. Transcript, WHIR Merkle and claim hashes remain BLAKE2s.

Release evidence: six Flock Keccak tests pass; two Keccak bridge tests pass, including mixed BLAKE2s+Keccak proof and verifier rejection of changed Keccak/BLAKE wiring, wrong intermediate output, wrong digest and tampered proof. Malformed row tests bypass prover prechecks. Two native-placeholder compiler tests pass, including a guard that prevents ordinary Boolean finish from discarding native obligations. This is implementation test evidence, not a formal soundness or security claim.

## Falcon-512: measured three-round ABAB

Frozen source `3bf7091f937e25d55f171c4bc86be5c3b5f634e9`; executable SHA256 `cbadb0411155d194299afd8e843af29ae5d514d6a28557f82919626403dba8da`. Raw receipts: `P/artifacts/hometurf-L4k/falcon-abab/`; summary.json contains all six timing samples per variant. Keccak rows replace only the two SHAKE calls (seven statement-digest permutations and nine HashToPoint permutations); all modular relations, sampling/compaction, bounds, norm and encoding-budget checks retain the existing Falcon frontend. Inputs remain decoded coefficients, as in the baseline; this does not add a compressed Falcon byte parser.

Both variants use the same new direct Boolean/native compiler, trim solely by fixed output dependencies, and check the full 64-byte application statement against the independent fixture. Both also compute the original canonical claim: BLAKE2s(application identity || the existing reversed-16-byte statement-half serialization). The identity is derived from the original Boolean circuit even for the native-row variant. The bit-level control includes one fixed unused permutation anchor because this bridge requires a nonempty Keccak schedule. This compiler's bit-level row census differs from the historical trace compiler's 8,798,175 rows; the historical 13.4 s timing is context, not the paired denominator below.

| Metric | Bit-level SHAKE | Native Keccak rows |
|---|---:|---:|
| Wallet s (median) | 11.900435 | 5.877517 |
| Whole-process peak RSS KiB (median) | 27,653,008 | 14,054,560 |
| Proof bytes | 390,176 | 364,760 |
| Standalone verify ms (one process) | 10.862502 | 10.492314 |
| Arithmetic rows | 10,115,187 | 6,077,055 |
| Padded arithmetic rows | 16,777,216 | 8,388,608 |
| Committed F64 words | 205,520,896 | 102,760,448 |

Wallet includes fresh fixture/witness construction, proof and bincode encoding; setup is excluded. RSS is the complete child process high-water mark from wait4, including setup/fixture allocation. Proof verification runs in a separate process against independently reconstructed preprocessing. The shared JSONL contains these measured medians. Candidate permutations: 16; the baseline performs the same 16 permutations in Boolean gates.

## Keccak-256 1 KiB

Matched canonical-claim three-round ABAB, six fresh processes per variant, source/binary as above. Raw receipts: `P/artifacts/hometurf-L4k/keccak-abab/`. Eight application permutations in both variants.

| Metric | Bit-level Keccak | Native Keccak rows |
|---|---:|---:|
| Wallet s (median) | 1.556004 | 0.076184 |
| Whole-process peak RSS KiB (median) | 3,644,346 | 213,664 |
| Proof bytes | 329,576 | 245,136 |
| Standalone verify ms (one process) | 10.654344 | 11.090992 |
| Arithmetic rows | 2,042,663 | 54,410 |
| Padded arithmetic rows | 2,097,152 | 65,536 |
| Committed F64 words | 25,690,112 | 851,968 |

This is a 20.4x wallet improvement; the historical bit-level reference was 1.496 s. The earlier 26–30 ms raw-digest screen omitted the application-identity claim envelope and is not this matched comparison. Whole-application time divided by eight is an amortized cost, not an isolated permutation-reduction timing. The controlled BLAKE2s per-compression comparison remains pending.

## MPT: measured three-round ABAB

62 application permutations; six fresh processes per variant. Matched statement and canonical claim. Receipts: `P/artifacts/hometurf-L4k/mpt-abab/`.

| Metric | Bit-level | Native Keccak rows |
|---|---:|---:|
| Wallet s (median) | 12.393910 | 1.500369 |
| Whole-process peak RSS KiB (median) | 28,224,532 | 3,574,402 |
| Proof bytes | 389,472 | 328,504 |
| Standalone verify ms | 11.582972 | 10.661277 |
| Arithmetic rows | 16,579,748 | 1,223,960 |
| Padded rows | 16,777,216 | 2,097,152 |
| Committed words | 205,520,896 | 25,690,112 |

## Amortized native hash-row cost

Three ABAB rounds, 512 independent calls per fresh process; verification succeeds after every proof. Same pinned 12-thread slice. Median Keccak wallet 0.1098827905 s = 214.614825 us/permutation = 1.578050 us/SHAKE256-rate byte (136 bytes). Median BLAKE2s wallet 0.0343565635 s = 67.102663 us/compression = 1.048479 us/byte (64 bytes). Total committed words are 1,048,576 versus 262,144, or 2,048 versus 512 words/call and 15.058824 versus 8 words/rate-byte. This includes connector and PCS padding. Packed witness-only words remain 1,024 versus 256/call. SHAKE128 uses rate 168, making the corresponding Keccak cost 1.277469 us/rate-byte and 12.190476 total words/rate-byte. These are batch-amortized prover costs, not host hash timings. Receipts: `P/artifacts/hometurf-L4k/rowcost-*`.

## Remaining work and current verdict

Keccak replaces Falcon SHAKE work successfully and halves its padded commitment in the measured matched compiler. It remains slower than the supplied leanVM Falcon reference (~1.02 s). Matched canonical-claim Keccak-1KiB and MPT are complete. An encoded-input ML-DSA-44 circuit has been drafted and compiles; arithmetic and full-statement validation remain pending. No ML-DSA measurement is claimed. Phase 2 protocol hash/merge measurement remain pending. No under-1-second Keccak protocol-merge claim is established.

## ML-DSA-44 projection correction and operation census

The preceding published 97-permutation, 31M-row ML-DSA projection and its derived time/RAM/word estimates are withdrawn: they used an incorrect w1Encode width and omitted transforms. The earlier Falcon projection also mixed nibble-native and bit-level row units. None is measured evidence and none should be used for performance conclusions.

Pinned reference: RustCrypto/signatures `cf99f5ebe36954026fdc86d2a2b372e6c97d04fb`, ml-dsa/src/{sampling,verifying,param,lib}.rs, archived in P/artifacts/hometurf-L4k/ml-dsa-reference. Cold FIPS 204 ML-DSA-44 verification, 32-byte message and empty context:

| Operation | Permutations | Basis |
|---|---:|---|
| ExpandA (SHAKE128) | expected approximately 80 | 16 polynomials, 5 rate-168 output blocks each. Candidate acceptance q/2^23 = 0.9990235567; expected 256.250214 candidate triples (0.250214 rejected) per polynomial. More than 280 candidates can be needed; the five-block count is overwhelmingly likely, not a hard maximum. |
| tr = SHAKE256(pk,64) | 10 exact | floor(1312/136)+1 absorption permutations. |
| mu = SHAKE256(tr || Mprime,64) | 1 exact for this message/context | Mprime = 0x00 || len(ctx) || ctx || M; input 64+2+32 = 98 bytes. General count floor((66+len(ctx)+len(M))/136)+1. |
| SampleInBall(c_tilde,39) | expected approximately 1 | 8 sign bytes plus sum(i=217..255) 256/(i+1) = 42.221969 expected index bytes. Rare rejection tails may require further rate-136 blocks; expected-byte count is not an exact permutation bound. |
| challenge SHAKE256(mu || w1Encode,32) | 7 exact | gamma2=(q-1)/88, hence 44 high-bit values and 6 bits/coefficient; 4*256*6/8 = 768 encoded bytes. Input length 64+768=832; floor(832/136)+1=7. |
| Total | expected approximately 99 | 80+10+1+1+7; unbounded rejection tails must be handled in a real circuit. |

Cold modular work: 4 forward NTTs for z, 4 for 2^13*t1, 1 for the challenge c, and 4 inverse NTTs, all length 256 modulo 8380417. ExpandA already samples the NTT-domain matrix and requires no further transform. A*z uses 16 polynomial pointwise products (4096 scalar products); c*t1 adds 4 (1024 scalar products): 5120 scalar products total. Matrix accumulation uses 3072 scalar additions and final subtraction another 1024. UseHint/HighBits touches 1024 coefficients. Verification checks 1024 z coefficients against gamma1-beta=131072-78=130994 and checks hint encoding, ordering, boundaries and at most omega=80 ones; it does not perform a Falcon-style reconstructed-w norm test. RustCrypto caches ExpandA, tr and the four public-key NTTs when decoding a verifying key; the user-requested circuit includes these cold costs.

L3b Boolean calibration (distinct from nibble-native rows): mean Falcon 512-point NTT=(394109+398801+387974)/3=393628 Boolean rows; each has 2304 butterflies, versus 1024 for a 256-point transform (factor 4/9). A width-only linear estimate is 393628*(4/9)*(23/14) Boolean rows per 256-point transform; charging quadratic width gives 393628*(4/9)*(23/14)^2. Falcon pointwise stage is 342939/512=669.802734 Boolean rows per scalar product, scaled by (23/14)^2 for a 23-bit product. These are projections of one circuit implementation, not measured ML-DSA rows. Parser, sampling, hints, norm and packing costs must be added before a total projection is meaningful. Whole-process RAM and committed words depend on final power-of-two bridge layout; the previous simple proportional estimates did not establish them.

A real ML-DSA circuit and matched L5 fixture measurement now supersede the projection-only request. Projected wallet totals remain pending a complete, dimensionally consistent census.


L5 fixture parity: `P/artifacts/hometurf-L4k/mldsa44-L5-fixture.json`, generated with pinned ml-dsa=0.1.1, seed sign(0), 32 bytes 0x42. Public digest BLAKE2s(1u64_le || pk1312 || message32) = `0fbdbdc8105b987a48e75e214bb7154fe98d3c493691b7419842c64374defcea`. This is host fixture reproduction, not yet circuit evidence. The circuit family budgets ExpandA at 840 bytes/polynomial and SampleInBall at 128 index bytes, constraining successful completion; larger rejection tails require a larger circuit family instance. It must not be described as complete for every possible FIPS input at this fixed budget.

## ML-DSA-44 encoded-input circuit status and projection

The L5 fixture is reproduced exactly, and the verifier frontend parses the fixed FIPS 204 encodings (pk 1312 bytes, message 32 bytes, signature 2420 bytes), checks z/hint bounds, expands A, computes tr/mu/challenge, performs NTT and inverse NTT work, UseHint/HighBits, challenge equality, and a public digest. The native-row census on the deterministic L5 fixture completed before proof layout at **33,237,844 Boolean full-adder rows and 99 Keccak permutations** (ExpandA 80 expected, tr 10 exact, mu 1 exact, SampleInBall 1 expected, challenge 7 exact). The bit-level version was not measured: at least 38,400 Boolean rows per permutation gives a rough hash-only lower bound of 3.8M rows, while modular work dominates; a complete bit-level proof was not claimed.

This census is not a proof result: the current fixed rejection budgets cover the overwhelmingly likely ExpandA/SampleInBall paths, while FIPS 204's rejection loops have unbounded tails. No wallet time, RSS, proof bytes, verification time, or committed-word result is reported for ML-DSA until the fixed circuit is validated against the L5 digest and malformed-verifier cases. The native Keccak bridge itself is measured above. The earlier projection-only request is retained as the operation census: 9 forward and 4 inverse 256-point NTTs, 5120 scalar products, 1024 UseHint coefficients, and 1024 z norm checks. Falcon Stage-0 calibration gives 393628 Boolean rows per 512-point NTT (2304 butterflies), hence 393628*(4/9) = 174945.777778 projected Boolean rows for a 256-point NTT before 23-bit scaling; point products calibrate at 669.802734 Boolean rows/scalar before 23-bit scaling. These are projections, not measurements.

Full-circuit native witness evaluation succeeds on L5 sign(0), producing validity 1 and exactly the L5 public digest above. Before constant-twiddle optimization, the 33,237,844-row Boolean frontend lowers to 76,347,795 native arithmetic rows; padding gives 134,217,728 rows and a projected layout of 1,644,167,168 committed words. Evaluation alone took 17.883135 whole-process seconds and 7,820,176 KiB RSS; these are not wallet proving metrics. The configured backend cap is currently 2^24 rows, so no proof has been attempted at that layout. Constant arithmetic is being reduced before a measured proof attempt.

After reusing Falcon's signed-digit linear constant multiplication, the frontend is 29,944,283 Boolean full-adder rows. Full native evaluation still matches the L5 digest, with **63,472,024 arithmetic rows**, **67,108,864 padded rows**, **822,083,584 projected committed words**, and **99 permutations**. Evaluation process: 15.188467 s and 5,507,588 KiB; not a prover timing. The experimental arithmetic cap is raised from log24 to log26 (four address columns still fit u32) to permit this measured native proof attempt. This does not alter the verifier's constraints or public statement.
