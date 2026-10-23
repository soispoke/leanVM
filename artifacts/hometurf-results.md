# Native hash rows: hometurf evaluation

Native application BLAKE2s rows win the measured hash-chain, Merkle and leanXMSS wallet comparisons against RISC-V leanVM, and verify faster. They do not win the shielded wallet comparison: Boolean nonhash rules still dominate. Most R1CS transported proofs are larger. These are development single runs, not hardware-independent performance claims.

All L1 timed work uses CPUs 0-11, LEANVM_NUM_THREADS=12 and RAYON_NUM_THREADS=12. L2 uses CPUs 12-23. Builds/tests use CPUs 48-63 with CARGO_BUILD_JOBS=4. Wallet time includes witness generation, proof and encoding, excludes setup and signature generation. Verification includes decoding in a separate process. RAM is process peak RSS including setup; fixed keys must remain resident. R1CS and VM prove the same committed output digest. R1CS specializes length/depth/count into a fixed circuit key; VM reads them at runtime and binds its program identity. No zero-knowledge or Ethereum compatibility claim is established.

R1CS measurements come from `hometurf-L1-final/*-summary.json` and the final L1 entries in `hometurf-12t.jsonl`. L2 direct-instruction entries supersede its earlier streaming guest screens. The BLAKE VM rows are fresh L1 reruns of the existing L2 receipt binary; its SHA256 and declared source base are recorded in the JSONL. Gates are historical `integrator-reference12` receipts at 87151953: they hash private messages and include the prior application-claim wrapper, so they show the old implementation cost rather than an exact matched-output baseline. Other gate versions were not benchmarked. An unmeasured cell is not a prediction.

**blake2s-64b**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 26.0 | 70.6 | 193,880 | 4.79 |
| R1CS gates (historical) | 106.1 | 334.9 | 247,956 | 5.21 |
| RISC-V leanVM | 82.2 | 100.6 | 172,830 | 17.05 |

Wallet: R1CS is 3.16x faster.

**blake2s-1kib**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 35.5 | 69.7 | 194,336 | 6.09 |
| R1CS gates (historical) | 1307.4 | 3985.0 | 323,356 | 6.97 |
| RISC-V leanVM | 184.3 | 172.6 | 196,166 | 14.53 |

Wallet: R1CS is 5.19x faster.

**hashchain-16**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 27.9 | 70.9 | 193,824 | 4.16 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 75.9 | 96.1 | 170,358 | 12.72 |

Wallet: R1CS is 2.72x faster.

**hashchain-256**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 51.0 | 101.9 | 200,440 | 7.16 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 129.7 | 121.7 | 188,990 | 13.13 |

Wallet: R1CS is 2.55x faster.

**hashchain-4096**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 343.9 | 618.4 | 265,512 | 5.83 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 495.0 | 554.8 | 219,894 | 13.10 |

Wallet: R1CS is 1.44x faster.

**merkle-20**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 28.0 | 68.9 | 194,656 | 4.22 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 73.8 | 99.2 | 170,838 | 16.77 |

Wallet: R1CS is 2.63x faster.

**merkle-32**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 23.9 | 68.1 | 194,400 | 4.97 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 79.9 | 102.7 | 174,110 | 13.45 |

Wallet: R1CS is 3.34x faster.

**leanxmss**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 41.4 | 112.4 | 208,656 | 4.61 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 103.0 | 121.7 | 187,974 | 12.54 |

Wallet: R1CS is 2.48x faster.

**shielded**

| System | Wallet ms | RAM MiB | Proof bytes | Verify ms |
|---|---:|---:|---:|---:|
| R1CS native hash rows | 214.7 | 528.6 | 274,272 | 5.43 |
| R1CS gates (historical) | unmeasured | unmeasured | unmeasured | unmeasured |
| RISC-V leanVM | 150.8 | 189.9 | 197,990 | 12.79 |

Wallet: leanVM is 1.42x faster.

The brief cited earlier leanVM BLAKE times of 146 ms / 222 ms for 64 B / 1 KiB. The fresh same-slice reference-binary runs above are faster, so the verdict uses those fresh comparisons rather than the older figures.

**Scaling and units**

One native BLAKE2s compression uses a dedicated Flock block of 16,384 Boolean z slots, packed 64 per F64 word: 256 packed witness words per padded compression slot. The bridge adds six native arithmetic connector rows per slot. Its native table has four F192 columns, twelve populated F64 limb words per padded arithmetic row. Public anchors, alignment, at least 8,192 arithmetic rows and at least 128 compression slots add fixed overhead. Joint committed words exclude the separately committed fixed index and WHIR rate expansion. These units must not be confused with a transported proof byte or a VM cycle.

| Workload | Actual R1CS compressions | Padded slots | R1CS padded arithmetic rows | Joint words | Words/app compression | VM cycles | VM words | VM cycles/app compression | VM words/app compression |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| blake2s-64b | 2 | 128 | 8,192 | 131,072 | 131,072.0 | 1,178 | 360,992 | 1,178.0 | 360,992.0 |
| blake2s-1kib | 17 | 128 | 8,192 | 131,072 | 8,192.0 | 14,678 | 1,285,224 | 917.4 | 80,326.5 |
| hashchain-16 | 18 | 128 | 8,192 | 131,072 | 8,192.0 | 651 | 328,872 | 40.7 | 20,554.5 |
| hashchain-256 | 258 | 512 | 8,192 | 262,144 | 1,024.0 | 6,891 | 665,128 | 26.9 | 2,598.2 |
| hashchain-4096 | 4,098 | 8,192 | 65,536 | 4,194,304 | 1,024.0 | 106,731 | 6,164,008 | 26.1 | 1,504.9 |
| merkle-20 | 22 | 128 | 8,192 | 131,072 | 6,553.6 | 1,065 | 336,248 | 53.2 | 16,812.4 |
| merkle-32 | 34 | 128 | 8,192 | 131,072 | 4,096.0 | 1,563 | 366,200 | 48.8 | 11,443.8 |
| leanxmss | 341 | 512 | 16,384 | 393,216 | 2,730.7 | 2,178 | 624,584 | 15.1 | 4,337.4 |
| shielded | 106 | 128 | 262,144 | 3,211,264 | 30,583.5 | 5,957 | 1,330,872 | 56.7 | 12,675.0 |

The denominator is semantic application compressions; final committed-output hashing adds one compression for BLAKE/shielded and two for chain/Merkle/XMSS. XMSS additionally computes 294 candidate chain edges and selects the required 99, so R1CS executes 341 compression blocks versus VM 146. Its full target-sum encoding, pinned top bits, bounded leaf index, WOTS aggregation and all 32 Merkle levels are constrained. For chain 4096, the two public-output compressions push 4098 above the 4096-slot boundary, doubling its hash schedule to 8192 slots. Between chain256 and chain4096 the measured R1CS joint witness grows by 1024 words per added step; the VM grows by 26 cycles and approximately 1432 words per added step. These are slopes across these two padded instances, not asymptotic constants.

**Merge cost and limitations**

The old universal split node remains measured at 3.48 s, 67,108,864 joint words and 361,196 proof bytes. It records both base/node verifier kinds and all checks; the compression schedule is already minimally padded at 65,536 slots. L4 separated a base-only first level: 1.32 s and 25,165,824 words on old gate-based BLAKE64 certificates. With the new native-hash base statement, alternating old/native screens measured 1.306/0.882/1.375/0.968 s; native commits 16,777,216 words and sends 323,976 bytes. Both native passes are below 1 s, but this is a first-level screen and is not an implemented common-key recursive tree or mixed-application merge. The tree-only function is a shape census with unsatisfying placeholders and exposes no proving API.

L3 measured 1.631 s for the first merge of two distinct native shielded spends. LeanVM same-program first/tree merges remain about 0.33-0.40 s in L2 receipts, with different application fixtures clearly named there. This evidence does not establish R1CS aggregation parity or end-to-end mixed merges below one second. The shared-top Merkle screen was rejected: no padding threshold was crossed and timings were mixed; its verifier patch must not be presented as an accepted optimization.

The experimental shared-root lookup bridge now proves a multiplicity-aware product bus over fixed tables. It commits Boolean integer-count bits before the bus challenges and opens both count evaluations and all six query coordinates against the joint arithmetic/hash root. This is a prototype, excluded from the benchmark table. The wallet table uses the complete Boolean nonhash shielded rules and native compression bindings, not the lookup prototype. See `hometurf-L4.md` for measured and analytic recursion details, and `hometurf-statements.md` for exact fixtures.

**Soundness and release evidence**

Every compression input/output, counter and flag is connected to the arithmetic witness and the Flock relation in one joint commitment. Constants are trusted public anchors supplied by the verifier; exposing a value alone does not make untrusted caller-chosen constants sound. Chaining reuses output variable IDs. Tests cover wrong output digests, changed intermediate bindings, tampered paths, changed proof streams, altered XMSS path/tip/randomness/index, and forged arithmetic witnesses. Existing verifier malformed-binding tests bypass prover prechecks. No verifier check or PCS profile was weakened.

Release gates and push identity are recorded in `hometurf-gates.json` once complete. The implementation remains experimental engineering, with no new formal soundness theorem.
