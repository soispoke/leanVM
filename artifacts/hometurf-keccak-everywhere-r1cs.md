# Keccak everywhere in leanR1CS — L6

Status: paired measurements complete. Local branch only; no push performed. See the final validation results below.

**Verdict: Keccak everywhere does not fit the one-second merge interval in this implementation.** Final ABAB medians are **3.590 s** for the first mixed merge and **4.494 s** for the depth-2 mixed node, versus **0.744 s** and **1.002 s** for the current BLAKE2s controls (4.83× and 4.49×). Both Keccak levels commit four times as many words. First/node RSS rises from 1,534,932/1,907,404 KiB to 5,194,844/6,028,958 KiB. Proofs grow about 14%; complete root settlement rises from 13.01/22.38 ms to 27.22/43.61 ms. Wallet slowdowns range from 1.59× to 2.78× while Keccak wallet proofs are slightly smaller. The original unoptimized Keccak screens were 3.251/6.789 s, but those single runs are not paired timing denominators.

## Configuration and statements

`format_recursion/keccak-protocol` selects Ethereum Keccak-256 (rate 136 bytes, suffix 0x01/final 0x80), native Keccak-f[1600] rows, Keccak Fiat–Shamir hashing, PCS Merkle hashing, application identities and claims, matrix/source keys and recursive hashes. Grinding is retained, including nonce search, predicate and absorption. This does not select the existing EVM no-grinding transcript. Production security targets remain 128 bits, joint inverse rate 4, separate index inverse rate 16, and production query-count derivation. No security parameters were reduced.

BLAKE-only bridge constructors and mixed BLAKE schedules are rejected in this configuration. The sparse adapter has 50 input/output lane ports, Klog16, native Keccak reduction and zero-input native padding. There are no dummy BLAKE rows for typing. Default builds retain the BLAKE backend as the comparison control. Legacy BLAKE application/bridge fixtures run under that default configuration; their Keccak counterparts have separate native proof, compiler and sparse regression tests.

The shared statement specification is `artifacts/keccak-statements.md`. Shielded uses the same 2-in/2-out, depth-20 layouts with all application hashes (including fixture derivation) replaced. Its seed-20261024 digest is `599943d4ea06d97bbd20b602add63200e167a17a72d9775d91d33fa3eb72e4d3`, validity 1, and 56 application permutations. Merkle retains the original direction convention: bit 0 places the sibling left, bit 1 places the current node left. Its corrected seed-1 depth-16 root is `1357b0fe3e7707641fdc297b6e3b8810a9d98be16f1474446ce61974bb7d4327`; it uses 17 permutations including the leaf hash. The earlier opposite-direction exploratory Merkle result is withdrawn. Falcon-512, Keccak-1KiB and MPT statements are unchanged.

## Measurement method

All timed runs use `taskset -c 12-23 env RAYON_NUM_THREADS=12 LEANVM_NUM_THREADS=12`. Builds/tests use cores 48–63 and four build jobs. ABAB repeated three times means six samples per variant. Proofs are independently verified in a separate process for each wallet sample. RSS is whole-process `wait4` peak RSS, including setup, whereas wallet time excludes key setup and includes fresh witness generation and proving. Merge time includes child admission, claim folding, recording and outer proof generation; wrapper setup and existing child proofs are excluded. Complete root time includes native verification and settlement of every active carried claim plus the fresh wrapper claim, without setup. Binary hashes and exact commands are saved in provenance/receipts. JSON lines are appended to `artifacts/hometurf-12t.jsonl` with system r1cs, lane L6.

For wallet A/B, both variants prove the same native Keccak application. A uses BLAKE2s protocol/claim hashing; B uses Keccak protocol/claim hashing. Canonical envelopes therefore change intentionally. The Merkle raw-root wallet uses its original application root envelope, separate from the canonical identity envelope used for the other four workloads. Merge A uses the original BLAKE shielded/Merkle apps and BLAKE protocol; merge B uses their specified Keccak editions and Keccak protocol. Merge ratios consequently include the requested application hash substitution as well as protocol hashing.

## Wallet ABAB medians

Values in paired cells are A / B (BLAKE protocol / Keccak protocol). Application permutations exclude the envelope: B adds one native Keccak claim permutation for the four canonical-envelope workloads; A instead uses BLAKE claim compressions. Merkle has 17 total permutations and no extra canonical claim hash.

| Wallet | Prove s A / B | B/A | RSS KiB A / B | Proof bytes A / B | Verify ms A / B |
|---|---:|---:|---:|---:|---:|
| Shielded-Keccak | 0.507994 / 0.809183 | 1.593 | 982922 / 980804 | 293824 / 286896 | 11.271 / 11.019 |
| Merkle-Keccak | 0.032589 / 0.090470 | 2.776 | 76720 / 76674 | 194424 / 193824 | 10.560 / 10.334 |
| Falcon-512 | 6.067141 / 10.527342 | 1.735 | 14051056 / 14051744 | 364760 / 361720 | 11.326 / 12.087 |
| Keccak-1KiB | 0.078477 / 0.156304 | 1.992 | 213024 / 210792 | 245136 / 238992 | 11.507 / 11.099 |
| MPT | 1.541334 / 2.577743 | 1.672 | 3573670 / 3572454 | 328504 / 324072 | 10.674 / 10.789 |

| Wallet | Arithmetic rows A / B | Committed F64 words A / B | Application permutations |
|---|---:|---:|---:|
| shielded | 348049 / 348067 | 6422528 / 6422528 | 56 |
| merkle | 690 / 690 | 131072 / 131072 | 17 |
| falcon | 6077055 / 6077073 | 102760448 / 102760448 | 16 |
| keccak | 54410 / 54428 | 851968 / 802816 | 8 |
| mpt | 1223960 / 1223978 | 25690112 / 25690112 | 62 |

## Mixed merge ABAB medians

B includes the safe compiler optimization: algebraic zero/identical-add folding and permutation-prefix folding only when every input is pinned by the fixed key. Private zero-valued inputs are never treated as constants. Fresh-witness proof and wrong-output regressions cover this distinction. The preserved initial candidate remains available for the before/after screen.

| Level / variant | Merge s | RSS KiB | Proof bytes | Core verify ms | Complete root ms | Rows | Words | Native calls |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| first A | 0.743694 | 1534932 | 180160 | 4.288 | 13.006 | 516284 | 8388608 | 0 Keccak / 9620 BLAKE |
| first B | 3.590186 | 5194844 | 206192 | 10.004 | 27.219 | 999496 | 33554432 | 9808 Keccak / 0 BLAKE |
| node A | 1.001830 | 1907404 | 180064 | 4.169 | 22.380 | 634272 | 8388608 | 0 Keccak / 14263 BLAKE |
| node B | 4.494221 | 6028958 | 205552 | 9.107 | 43.607 | 1139668 | 33554432 | 14289 Keccak / 0 BLAKE |

## Optimization screens

- **Rate 136:** active in all Keccak results. For 64-byte Merkle pairs it still takes one call. Four 32-byte children fit in a 128-byte preimage and one call. This preserves Keccak-256 capacity; rate 168 was not substituted.
- **Arity and leaf packing:** the exact layout screen is `L6-lever-layout-screen.json`. For 65,536 leaves, arity 2 needs 16 path calls and 512 sibling bytes; arity 4 needs 8 calls and 768 sibling bytes; arity 16 returns to 16 calls and needs 1,920 sibling bytes. Leaves of 32/128/256/512/1024 bytes take 1/1/2/4/8 calls. These counts alone do not change PCS query semantics or prove a merge speedup. The isolated native relation screen tests arities 2/4 and 32/128-byte leaves, independent Keccak node digests, honest proofs and wrong-root rejection; receipts are under `L6-layout-screen/`.
- **Reduced transcript calls:** optional `keccak-batched-transcript` buffers full 24-byte scalars before a challenge and hashes state, scalar count, scalars and terminal role. Grinding flushes pending absorbs and uses the original nonce predicate/search and absorption. It is a separate protocol encoding, not enabled in the main ABAB B variant. Independent RustCrypto encoding/order checks and sparse host/recorder tests cover it. Timing screens are under `L6-followup/{first,node}-batched.*`.
- **Connector layout:** current dense bridge needs 17 rows per slot for 50 lanes; the BLAKE bridge needs 6 for 18 lanes. A direct six-row substitution would omit lanes and is not valid. Packed-limb binding would need a new connector reduction. The sparse path instead materializes 50 lane columns. The optimistic dense subtraction saves 180,224 rows at 16,384 slots or 360,448 at 32,768 slots, but does not reduce Keccak's packed q table (16,777,216 or 33,554,432 words). This is a metadata screen, not an implemented six-row Keccak prover. Explicit 22/22 wrapper padding also remains in the primary depth-2 run. It is not evidence of reusable node-on-node key closure.

### Measured lever results

| Screen | Merge/prove s | RSS KiB | Proof bytes | Verify/root ms | Rows | Words | Keccak permutations |
|---|---:|---:|---:|---:|---:|---:|---:|
| first batched transcript | 4.029661 | 5200184 | 206192 | 28.454 root | 997307 | 33554432 | 9103 |
| node batched transcript | 4.895078 | 5956116 | 205360 | 57.644 root | 1136904 | 33554432 | 13447 |
| isolated arity 2, leaf 32 B | 0.106608 | 74444 | 195752 | 8.174 verify | 786 | 131072 | 17 |
| isolated arity 4, leaf 32 B | 0.090160 | 76280 | 187224 | 8.086 verify | 682 | 114688 | 9 |
| isolated arity 2, leaf 128 B | 0.092947 | 79140 | 195808 | 8.006 verify | 786 | 131072 | 17 |
| isolated arity 4, leaf 128 B | 0.081318 | 74664 | 186056 | 7.812 verify | 682 | 114688 | 9 |

These lever timings are single screens, not ABAB medians. Batching reduced calls by 7.2%/5.9% at first/node but crossed no commitment-size boundary and demonstrated no timing improvement. Arity/packing prototypes are isolated relations; they are not a claim that changing the production PCS preserves its proof format, query semantics or security analysis. The six-row connector result is a layout/feasibility screen only; a packed-limb connector implementation and a reworked PCS arity remain future work. No screened variant demonstrated a merge below one second.

## Verification and limits

The native compiler covers lengths 0,1,64,135,136,137,272, fresh witnesses, exact-rate padding, wrong context, changed proof stream and changed Merkle path. A false permutation is proved through the no-precheck prover entry and rejected by the verifier. Sparse tests bind products, hash ports, public outputs, generator/matrix equality, carried values, application identities and zero padding. Complete tree root verification rejects false carried evaluations, substituted keys, omitted/duplicated claims, wrong child kind, swapped children and tampered child/root proofs. Claims are settled against trusted generators; rejecting only a prover admission API is not counted as verifier evidence.

The first and node wrappers share dimension bounds but can have different port/block layouts. This report establishes the measured depth-2 mixed composition, not arbitrary repeated node-key closure. It does not claim a new formal security proof, zero knowledge or EVM equivalence. The optional batching and arity/packing screens are distinct from the measured production-profile comparison.

Evidence: `L6-wallet-abab/`, `L6-merge-abab/`, `L6-followup/`, `L6-layout-screen/`, `L6-protocol-components.log`, `L6-final-{keccak,baseline,batched}-tests.log`, `L6-final-batched-fs-tests.log`, `L6-final-{baseline,keccak}-clippy.log`, `L6-final-batched-clippy.log`, `L6-fmt-check.log`. Earlier failed logs are retained as development history and are superseded only by successful final gates.
