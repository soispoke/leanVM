# Mixed-program leanVM merge: measured fixed-pair prototype

A real first-level proof verifies a shielded leaf and a leanXMSS leaf, binds their ordered program identities and outputs, and settles both program claims. At 12 threads on CPUs 12–23, ABAB mixed merges take **0.402600375 s and 0.423128566 s**, versus **0.423771346 s and 0.429967390 s** for shielded + shielded. Both commit **5,948,416 u64 words**. This is an implementation and measurement, not a time estimate.

Source: `hometurf/L2`, commit `5eeb620704f796355e0b0fc97fb53e05f88e8dd9`. Binary SHA-256: `0bfd9df3a6267b9719d24c8f51697f276e38650c132aa08d2610fc5620597178`. No push. Existing independent leaves are `hometurf-L2/shielded.proof` and `hometurf-L2/leanxmss.proof`; leaf log inverse rate 2, recursion log inverse rate 1. The same-program control repeats the shielded proof in both slots; the mixed proof uses one leaf from each different program.

## ABAB results

| Order | Case | merge2to1 s | Independent verify ms | Rows | Committed words | Proof bytes | Peak RSS KiB |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | A: shielded + shielded | 0.423771346 | 15.899078 | 112,776 | 5,948,416 | 259,915 | 510,912 |
| 2 | B: shielded + leanXMSS | 0.402600375 | 13.307521 | 110,511 | 5,948,416 | 260,043 | 518,168 |
| 3 | A: shielded + shielded | 0.429967390 | 12.181230 | 112,776 | 5,948,416 | 259,915 | 517,756 |
| 4 | B: shielded + leanXMSS | 0.423128566 | 14.399285 | 110,511 | 5,948,416 | 260,043 | 523,160 |

Mean merge: same-program 0.426869368 s; mixed 0.412864471 s. Mean independent verify: 14.040154 ms and 13.853403 ms. With two samples per case and different leaf shapes, these show no material mixed penalty in this experiment; they do not establish a speedup. Historical same-program 0.35–0.52 s is consistent with these fresh controls. The mixed proof adds 128 bytes relative to the shielded control.

Every timed process uses `taskset -c 12-23`, `LEANVM_NUM_THREADS=12`, `RAYON_NUM_THREADS=12`; the binary also initializes and asserts exactly 12 pool threads. Merge timing includes native input-proof validation, circuit witness generation, reduction, proof construction and encoding. Leaf preparation, ELF decoding and tree construction are outside it. The two same setups took 0.312662/0.293949 s; mixed setups took 0.250347/0.272293 s. RSS includes resident setup. Each root is decoded and checked in a separate fresh process, with verifier-key/tree construction excluded from the verify timer. Builds, tests and instrumented profiles use CPUs 48–63 and are outside the ABAB samples.

## What changed and how the identities are bound

`Tree::new_mixed([(program0, shape0), (program1, shape1)], arity, rate)` fixes two ordered program slots. Each child uses its own `ProofShape`, including its own program digest, leaf table heights and rate. Standard `Tree::new` behavior is retained.

The first-level digest hashes the ordered items `[digest0, output0, digest1, output1]`, under the existing first-level tag and item count. The tree transcript seed includes both program identities and shapes plus `mixed-fixed-pair-v1`. `prove_first_claims` and `verify_claims` additionally check explicit caller-supplied program digests against their slots and reject swapped or unknown identities. Program identities are bound through the statement digest and verifier key; they need not be copied as separate public statement fields.

Both programs' bytecode tables and RAM images are independently zero padded to a common block size and concatenated into two halves of a public dense polynomial. An extra top coordinate selects slot 0 or 1. Over the binary field, `T(x,z) = (1+z) T0_padded(x) + z T1_padded(x)`. Padding coordinates are appended after all original bytecode coordinates, preserving the tuple-coordinate layout. Each leaf's original bytecode Frobenius/twist relation and image weight/high-coordinate relation are checked before the claims enter the existing dense reduction. Its checked sumcheck batches both programs' claims to one evaluation of each stacked polynomial. The root verifier evaluates the actual stacked tables and settles those evaluations; higher nodes carry the same claims.

This settles two logical program claims. In this implementation bytecode/image polynomials are verifier-known public tables, not separately PCS-committed bytecode proofs. There is **no extra bytecode PCS opening** to count. The additional selector and shared dense reduction serve that binding role. Therefore this result does not measure Emile's additional-opening design for arbitrary runtime-selected programs.

All existing bus/table checks, Flock checks, WHIR/ring-switch checks, Merkle authentication, transcript checks, dense and matrix reductions, root claim settlement, leaf count and output ordering remain enabled. Native leaf validation is also retained; it does not replace the circuit verifier checks.

## Exact row and word census

Rows below are unpadded logical machine rows. Committed words include the common per-table power-of-two padding/floors. Per-row unpadded word weights, in `[EMUL, EXK, HASH, SPLIT, CAST, PUB]` order, are `[9,7,257,65,4,0]`; HASH's 256 packed witness words plus selector are counted once, with no second charge for its alias ports.

| Circuit | Rows | Unpadded witness words | Padding/floors | Committed words |
|---|---:|---:|---:|---:|
| Standard shielded + shielded | 112,776 | 3,498,408 | 2,450,008 | 5,948,416 |
| Stacked shielded + shielded control | 112,818 | 3,499,241 | 2,449,175 | 5,948,416 |
| Stacked shielded + leanXMSS | 110,511 | 3,393,252 | 2,555,164 | 5,948,416 |
| Standard leanXMSS + leanXMSS | 108,137 | 3,286,466 | 2,661,950 | 5,948,416 |

The representation control isolates **+42 rows and +833 unpadded words** for stacking plus explicit per-child digest binding: +35 EMUL, +2 HASH, +1 CAST, +4 PUB. Of this, the shared reduction adds 37 rows / 576 words; the remaining statement work adds 5 rows / 257 words. There is no padded committed-word increase. Mixed versus standard shielded changes total rows by −2,265 and unpadded words by −105,156 because its second leaf verifier is smaller; that difference is not the isolated mixed overhead.

| Mixed stage | Rows | Unpadded words |
|---|---:|---:|
| Shielded bus/table checks | 4,200 | 146,986 |
| Shielded deferred program binding | 975 | 8,658 |
| leanXMSS bus/table checks | 3,860 | 139,873 |
| leanXMSS deferred program binding | 948 | 8,415 |
| Shared dense + matrix reduction | 5,036 | 65,493 |

Thus the second program's claim including bus/table checks is **4,808 rows / 148,288 unpadded words**. The narrower deferred binding itself is **948 rows / 8,415 words**. Both children already require program/bus checks in a same-program merge, so this entire second-child amount is not incremental mixed overhead. The two mixed program/bus stages together are 303,932 words, 8.96% of the mixed circuit's unpadded words. Padding cannot be assigned uniquely to a program stage.

Mixed per-table rows are `[71458,21867,9874,527,6297,488]`, padded at log heights `[17,16,14,10,13,10]`. Exact per-stage row vectors are in `hometurf-mixed-census.json`; instrumented raw logs are in `hometurf-L2/mixed-profile-*.log`. Profile wall times are diagnostic only.

## Rejection and regression evidence

`cargo test --release -p leanvm --lib rec::tree`: **12 passed, 0 failed**, including the new mixed-program test. It proves/round-trips/verifies the heterogeneous first level and a parent over two mixed first-level proofs. Different leaf rates and image sizes exercise per-slot shape selection and padding.

The test rejects swapped/unknown caller identities, unknown prover identities, swapped foreign leaf proofs, wrong outputs and altered root statement words. It directly feeds a foreign program's raw proof to a row verifier with matching proof heights/rate, bypassing API digest guards, and observes failed checks. Independently corrupting each half of the stacked bytecode and image tables causes root deferred dense-claim settlement to fail. The real shielded + leanXMSS harness separately proves and verifies, rejects swapped/unknown identities and a tampered serialized root, and rejects swapped prover identities. See `mixed-tree-tests.log` and `mixed-reject.log`.

## Reproduction and scope

Build: `CARGO_TARGET_DIR=../target-leanvm-riscv cargo build --release -p leanvm-cli --bin mixed` using host toolchain 1.99.1 and build CPUs 48–63. From `leanvm-riscv`, `python3 artifacts/hometurf-mixed-abab.py` runs ABAB with fresh-process verification and appends normalized metrics under a file lock. The shared `P/artifacts/hometurf-12t.jsonl` includes `merge2to1_mixed_s`, committed words, rows, verify ms, bytes and RSS. Full samples and binary/source provenance are in `hometurf-mixed-measurements.json`. Raw proof files remain under `P/artifacts/hometurf-L2/`; text evidence is also committed under `leanvm-riscv/artifacts/hometurf-mixed/`.

The key fixes the ordered pair, both leaf shapes, tree arities and recursion rate; higher levels repeat that pair. Runtime arbitrary program selection, an allowlist registry, and mixed children from different tree keys are outside this prototype. Standard same-program trees keep their existing statement/transcript format; mixed trees have a distinct key domain.

## Frozen protocol surface

For this prototype, the following values and rules are frozen into the verifier key and transcript:

1. The ordered pair is exactly `(shielded, leanXMSS)`; slot 0 and slot 1 cannot be exchanged. A production deployment would replace this fixed pair with its approved program registry.
2. Each slot's 32-byte program digest, bytecode tuple width and height, image height, leaf proof rate and `ProofShape` are fixed. The mixed domain tag is `mixed-fixed-pair-v1`.
3. The first-level statement item order is exactly `program_digest_0, output_0, program_digest_1, output_1`; the first-level kind tag and item count remain the existing `Kind::First` values.
4. Bytecode and image tables are each padded with zeroes to the common maximum block, concatenated as slot 0 followed by slot 1, and selected by one final binary selector coordinate. Original tuple and image coordinates precede that selector.
5. The tree has binary first levels (`arity_0 = 2`), binary higher nodes (`arity = 2`) and recursion `Rate::MIN`; children retain their own leaf rates and shapes.
6. The verifier checks both explicit digest-slot equality and the circuit's program/bus, Flock, opening, Merkle, transcript, output/digest, dense-reduction and matrix-reduction relations. Any table mutation, swapped/unknown digest, foreign leaf, wrong output or malformed root is rejected.

Changing any item above requires a new verifier key/domain and fresh measurements. In particular, this frozen surface is not a commitment to arbitrary runtime-selected programs.

**Verdict:** heterogeneous first-level merging works for shielded + leanXMSS with every existing check retained. Its measured merge cost is about **0.413 s**, independent verification about **13.85 ms**, and padded commitments match the same-program baseline. The fixed-pair experiment supports modest mixed overhead for this architecture; a universal EIP-8288 program-opening design still needs its own implementation and measurements.
