# ML-DSA-44 verification on leanVM, lane L5

This experiment proves an ordinary RISC-V guest that parses standard FIPS 204 ML-DSA-44 public-key and signature encodings from advice and verifies one signature. There is no ML-DSA, SHAKE or Keccak VM instruction or precompile. RustCrypto `ml-dsa` 0.1.1 is built `no_std` with default features disabled; its software `shake` and `keccak` crates implement the FIPS 204 hashes. The host signs deterministically from seeded keys and checks the guest output. The proof system is not zero knowledge.

All 15 ML-DSA-44 ACVP internal-projection signature-verification vectors from NIST ACVP-Server commit 65370b8 pass. Native and interpreter tests reject a tampered signature, wrong message and wrong public key. The guest commits validity, the public key and the message, producing the expected public digest.

## Measurements

The initial L5 batch ran at `Rate::MIN`, which is leanVM inverse-rate log 1, or rate 1/2. The historical Falcon reference (1.022909148 s) and the matching leanR1CS convention use inverse-rate log 2 in leanVM, or rate 1/4. A second three-round ABAB batch was run at that matched rate. Builds used cores 48-63 and `CARGO_BUILD_JOBS=4`. The wallet time includes witness execution and proof construction, with setup excluded. Verification was timed in a fresh process. Six samples were collected in three ABAB rounds, and medians are shown.

| program | RISC-V cycles | wallet prove s | peak RSS KiB | proof bytes | verify ms |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44, rate 1/2 | 2,869,390 | 5.2978 | 6,412,100 | 373,846 | 16.124 |
| Falcon-512, rate 1/2 | 147,758 | 0.4942 | 446,566 | 323,622 | 14.821 |
| ML-DSA-44, rate 1/4 | 2,869,390 | 6.4366 | 8,411,200 | 270,606 | 14.808 |
| Falcon-512, rate 1/4 | 147,758 | 0.5313 | 587,794 | 231,358 | 14.248 |

Contention snapshots were taken before each timed round. No heavy benchmark process was present on cores 0-11; the shared sandbox service was the only persistent CPU activity visible there. Raw JSON lines are in `hometurf-12t.jsonl`, with `system: leanvm` and `lane: L5`.

## Cycle profile

The exact baseline ML-DSA cycle count is 2,869,390. A marked profile guest inserted 17 ordinary RISC-V marker instructions at phase boundaries; excluding those markers, the phase counts sum exactly to the measured total:

| phase | cycles | percent |
|---|---:|---:|
| ExpandA, SHAKE128 | 1,454,235 | 50.68% |
| NTTs and products | 768,306 | 26.78% |
| hint and norm checks | 193,787 | 6.75% |
| `tr` hash | 161,144 | 5.62% |
| challenge hash | 113,314 | 3.95% |
| decoding | 96,240 | 3.35% |
| `mu` hash | 18,861 | 0.66% |
| SampleInBall | 19,686 | 0.69% |
| I/O and remaining work | 43,817 | 1.53% |

The markers are ordinary guest instructions and are excluded from the totals. The VM instruction-class totals are ALU 58.0%, load 4.9%, store 2.6%, load-data 10.8%, store-data 10.1%, shifts 10.6%, multiply 2.2%, multiply-high 0.9%, and HASH 0.0%.


The ML-DSA public key is expanded from its encoded `rho,t1` in the guest on every run. No expanded matrix or NTT-domain key is supplied as advice.

## Reproduction and source

The implementation is in the `programs/mldsa` guest and host on local branch `hometurf/L5`, based on `a40a7fa6`. `programs/mldsa/host/examples/measure.rs` runs cycles, proving, verification, and PC profiling. `L5-paired-r*-*.log`, `L5-contention-round*.txt`, and `L5-medians.json` preserve the raw measurements. No push was performed.

## SDK permutation variant (single sample)

A vendored `shake` 0.1.0 wrapper replaces both `with_f1600` absorb/squeeze callbacks with the SDK `leanvm_guest::keccak::f1600`, preserving SHAKE padding and cursor logic. This variant passes interpreter output comparison and proof verification. At log inverse rate 2 (rate 1/4): 1,877,321 cycles, 5.412373103 s wallet prove, 6,522,856 KiB whole-process peak RSS, 258,638 proof bytes, and 14.786785 ms separate-process verify. This is a single sample, not the ABAB median. The raw logs are `L5-sdk-rate2.log` and `L5-sdk-contention.txt`. Generic Keccak therefore explains 992,069 cycles (34.6%) of the original guest cost. The verifier is built without allocation (`ml-dsa` default features disabled).

## Two-to-one merge

A same-program ML-DSA 2-to-1 first-level merge at leaf log inverse rate 2 and tree Rate::MIN completed in 0.395215517 s after 0.295618947 s setup, producing a 259,947-byte tree proof. The merged proof verified in the harness.

## Validation and limits

Local commit: `dc58826bb9601a1ef41bab4b6b3408778d219004` on `hometurf/L5`, clean worktree; nothing pushed. Release baseline and SDK-native tests each pass all three tests (15 ACVP vectors plus native and interpreter mutation tests). A pinned-nightly baseline rebuild matches the measured ELF byte for byte. The guest and host are allocator-free for ML-DSA verification; the proving process allocates normally. The wallet timer includes witness and proof construction, but excludes proof encoding; the historical lane-B timer included encoding, so it is not a controlled speedup comparison. The fresh ML-DSA/Falcon ABAB comparison uses identical timing boundaries and allocators.

Phase profiling was performed untimed on cores 48-63. The same-program merge is an exploratory single sample with two copies of the same leaf proof, not two distinct signed statements. It had no dedicated pre-run contention snapshot and is excluded from the controlled ABAB results. A mixed merge was not attempted: the fixed-pair prototype requires core changes beyond the pinned baseline, so integrating and auditing it was outside the quick optional check.
