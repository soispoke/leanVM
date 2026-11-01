# O1: native Keccak per-permutation optimization

In progress. Start 2026-10-23 approximately 23:31 UTC, deadline 2026-10-24 02:31 UTC. Worktree `opt-O1`, branch `opt/O1`, control `9e5f41c4`. No push. Timing slice 12-23, 12 threads; builds/tests 48-63, four jobs.

## Control

Fresh release binaries built from unmodified `9e5f41c4` with Rust 1.99.1, native CPU flags, Keccak protocol feature. Stored in `artifacts/opt-O1/control/`. SHA256: deferred_merge `9acf34fc0199451914a85c1f534c4691d6d05e29b56befd494fdee2686af4d19`; sparse_tree `c68ce6b4e6352a7a9b82246add33989508c65b01299376d19f2935fc1f3bc2be`.

Initial first-level screens: 3.565338 / 3.488746 s, 33,554,432 words, 999,496 rows, 206,192 proof bytes, 8.677 / 12.491 ms core verification, 25.731 / 25.134 ms root. These are preliminary screens, not accepted ABAB comparisons. Node screen: 4.469066 s, 33,554,432 words, 1,139,668 rows, 205,552 proof bytes, 9.972 ms core verification, 41.881 ms root. Three-sample baseline medians: first 3.577805 s and node 4.877695 s (baseline-driver.log).

## Structural census

The existing Flock Keccak relation already uses only 38,400 chi product bits plus constant, input and output bits (41,664 useful slots) per permutation. Theta/rho/pi/iota are linear forms, not committed intermediates. Klog16 rounds this to 65,536 Boolean slots, 1,024 packed F64 words. Simply committing chi only or folding round constants is already implemented and cannot be claimed as a new optimization.

The sparse first-level control has 1,727,231 F192 witness elements before power-of-two padding (zlog21). Its arithmetic limb table is 6,291,456 F64 words, but q alignment rounds its offset to 16,777,216 words, followed by 16,777,216 Keccak words. This is the origin of the 33,554,432 committed-word total. The 17 connector rows apply to the dense bridge; measured mixed merges use the sparse port-column backend with 50 lane ports. A dense six-row change would not directly optimize these mixed merges.

Stage diagnostic timing uses existing tracing spans and adds no prover timers. Values below are single diagnostic passes, not paired timing denominators. Full trace logs and extracted values are in `P/artifacts/opt-O1/trace/` and `census.json`.

| Stage | First s | Node s |
|---|---:|---:|
| Keccak witness | 0.590 | 0.445 |
| Joint commitment | 0.894 | 0.783 |
| Keccak reduction | 0.337 | 0.342 |
| Joint opening | 0.862 | 0.791 |
| Sparse matrix products | 0.0111 | 0.0170 |
| Outer R1CS sumcheck | 0.0220 | 0.0355 |
| Sparse matrix row folding | 0.0515 | 0.0766 |
| Inner matrix sumcheck | 0.0133 | 0.0238 |

Node uses padded zlog22 (12,582,912 arithmetic words), unlike the standalone first-level harness zlog21. Both controls nevertheless align q at 16,777,216 and commit 33,554,432 total words. Each sparse port family materializes 50 columns across 16,384 slots. The full traced node also proves two children before timing the final node; only the last prover span is used here.

## Stack packing candidate (pending matched timing)

Place q first and arithmetic limbs after it. This removes alignment holes while keeping every coordinate binding, all 50 ports and the same native Keccak relation. Offsets are mirrored in the recursive recorder. The power-of-two cube remains log25, but actual committed lanes can shrink. An earlier draft incorrectly rejected this based only on the cube size; that draft is superseded. Targeted honest, wrong-output, swapped-connector and tampered-proof tests passed; ABAB is pending.

## Accepted: aligned stack ordering

Implementation `ae3c0e07` (on top of diagnostic harness `bfb8c754`; report correction `448add27` is historical and superseded). Frozen binaries are `P/artifacts/opt-O1/layout`. Matched order ABAB repeated three times per workload, six samples per variant. All twelve first-level and twelve node receipts verified. Source implementation moves the unchanged q table to offset zero when it is at least as large as an arithmetic limb, then places the three arithmetic limbs after it. Native and recursive point, public and connector opening offsets move together.

| Workload / variant | Merge s | Words | Rows | Proof bytes | Core verify ms | Root ms |
|---|---:|---:|---:|---:|---:|---:|
| first A | 4.348033 | 33,554,432 | 999,496 | 206,192 | 9.202 | 30.831 |
| first B | 3.601539 | 23,068,672 | 1,001,295 | 186,992 | 8.878 | 20.604 |
| node A | 5.529166 | 33,554,432 | 1,139,668 | 205,552 | 9.707 | 48.333 |
| node B | 3.652452 | 29,360,128 | 1,141,250 | 198,800 | 9.242 | 32.452 |

First merge improves 17.2%, node improves 33.9% in this matched run. These control medians exceed the referee's earlier values and the lane's initial screens, so ratios are only claimed against this matched control. The q size and security settings are unchanged. The recursive opening circuit changes with the lane count, so permutation counts become 9,772 first and 14,361 node, versus 9,808 and 14,289 control. This is a consequence of packing, not a separate hash-count optimization.

Soundness note: relocation is an injective rearrangement of the same packed q words and three arithmetic limb tables. Every field evaluation, public binding and all 50 port equalities still refer to the same logical coordinates. All ring q offsets remain aligned and both verifiers derive the new offsets from setup. The setup key changes through its bound q offset. No query, rate, grinding, claim, hash relation or security parameter changes. This is regression evidence, not a new soundness proof.

Tests: `layout-rejection-tests.log` submits proofs built with a changed permutation input (therefore a false output relative to bound ports) and swapped permutation blocks, without admission/precheck rejection, and requires ordinary verifier rejection. It also rejects changed public output and proof-stream mutation. The Keccak-enabled 60-test format_recursion library gate passed after the layout plus witness-generator change (`keccak-lib-tests.log`), covering native/recorded verifiers, sponge boundaries, deferred claims and tree identities. Each timed node example additionally runs its direct verifier rejection probes.

## Packed witness candidate

Implementation `636f69d4`. Reuses the existing grouped packed-witness driver: eight blocks per worker scratch group, word-to-stripe transpose, streamed publication, and real zero-input padding permutations. No layout, transcript or relation change. The independent bit-circuit and full reduction test now includes three actual inputs plus five zero-input padding slots. All six Flock Keccak tests pass (`witness-tests.log`); the 60-test recursion gate also passes. Matched ABAB against the original control completed. First median is 2.682 s, node median is 3.125 s; words, rows and proof bytes match the aligned-layout candidate. The witness-only change was not separated from layout in this run, so the accepted combined result is reported as cumulative. Immutable binaries are in `P/artifacts/opt-O1/witness`.

## Host batch hashing candidate

AVX-512 eight-state Keccak-f[1600] for batches of independent protocol hashes. Scalar tail and non-AVX-512 fallback retained. Independent RustCrypto tests cover counts 1,7,8,9,16,17, lengths 1,32,64,135,136,137,271,272,1024 and zero-prefix states after 0,1,3 full blocks. Both protocol-hash reference tests passed (`simd-reference-tests.log`). Build succeeded and the reference tests passed. Matched ABAB3 against the original control is currently live in exec session 76506 (`simd-driver.log`); no acceptance or rejection is claimed until both workload medians exist. The previous report draft incorrectly described the invocation and is superseded. No transcript encoding or hash-output change is intended.

## Best cumulative result

The best verified combined stack-ordering plus packed-witness result is first-level 2.682 s and node 3.125 s, with 23,068,672 and 29,360,128 committed words, respectively. Both remain above the one-second target.

## Virtual zero padding prototype (not accepted)

The existing real padding permutations occupy nonzero q rows and prevent the arithmetic table from reusing their storage. Prototype: active permutations remain unchanged; all inactive q bits are defined as zero, and the lincheck pin polynomial is the public indicator of indices below `actual_blocks` instead of the all-ones polynomial. The verifier still checks the pin with the alpha-cubed batching term. Actual block count comes from the authenticated setup, never prover advice.

The packed q table is a virtual vector: read active words from committed storage and append zeros. Both ring-switch and q-port opening weights are restricted to that public prefix. This is essential because arithmetic limbs may occupy the same physical storage as the virtual q tail. The native verifier evaluates masked ring weights using a tensor-algebra prefix recurrence; the recursive recorder evaluates the equivalent Frobenius expansion with the same prefix restriction. Ordinary field/public claims continue opening the physical table. All active input/output port bindings remain.

The witness prover may allocate a padded virtual table for its reduction, but only active q words are copied into the physical commitment. Arithmetic limbs follow at the next aligned limb boundary. For the first-level layout at 9,772 permutations this puts q live words at 10,006,528 words, arithmetic at offset 10,485,760, and the three 2^21-word limbs end exactly at 16,777,216. This would cross the 2^24 boundary if the full recursive shape remains below it. Node dimensions remain larger. This is a feasibility calculation, not a measured win.

Checks so far: prefix MLE, prefix equality product and masked tensor ring weights match explicit Boolean sums; fused PCS weights with prefix connector claims match a dense oracle. Further tests target nonzero physical words overlapping the virtual q tail, a changed prefix bound, a false active claim, a tampered proof, wrong permutation output/wiring, and zero active pins. The protocol label changes from io64-v1 to zero-v2. No security claim is made from these tests beyond regression evidence. Full gates and ABAB are pending.

## O1b

Started 2026-10-24 00:37 UTC, deadline 02:31 UTC. Branch `opt/O1b`, worktree `opt-O1b`, control `c59adcb0` in separate fresh-build worktree `opt-O1b-control`. Timing remains cores 12-23; builds/tests cores 48-63, four jobs. Restored the saved virtual-zero prototype and its separately saved `stack_open/prefix.rs`; candidate remains unaccepted. The overlap opening test already targets changed prefix bounds, false prefix claims and proof mutation; an explicit assertion now confirms every overlapping physical tail word is nonzero. Active-pin tests and fresh control build are running. No timing or soundness acceptance is claimed.

### Accepted virtual-zero first-level win: d06885e4

Matched ABAB3 first medians: control 2.423625062 s, candidate 1.864678043 s (23.1% lower). Control/candidate: words 23,068,672/16,777,216; rows 1,001,295/1,008,071; bytes 186,992/197,920; core verify 9.1184265/10.223713 ms; root 18.410697/20.5349905 ms. Node ABAB still running in session 96466; its pending status is not a node acceptance. All 60 Keccak format_recursion library tests, both targeted active-pin reduction tests, all five PCS stack-open/prefix tests, Clippy lib/examples with warnings denied, formatting and diff checks pass. See O1b-*-tests.log and O1b-padding-clippy.log. Soundness invariant and rejection scope are committed in opt-O1b/artifacts/opt-O1b/virtual-zero.md. Immutable binaries/receipts: artifacts/opt-O1/O1b-padding and O1b-padding-abab.

A separate combination worktree opt-O1b-O2 contains d06885e4 plus O2 e9164faa, 41e98b89, 28387d02 and ba49591f, cherry-picked without conflicts (local combined head 7702441a). Its keccak-quad-cap build is live in session 64300. No combined acceptance yet.

Next joint-opening candidate uses nibble tables for the ring-switch binary-linear map, reducing lookup-table working-set size without changing weights or verifier checks. Targeted ring-switch tests queued in session 51988. No timing or acceptance yet.

Virtual-zero node ABAB3 is complete and rejected for node latency: 2.775733855 s control versus 3.001325217 s candidate (8.1% slower). Words stay 29,360,128; rows 1,141,250/1,163,322; proof bytes 198,800/199,888; core verify 8.9531475/10.4800005 ms; root 29.3742535/31.0391015 ms. The first-level acceptance remains valid, but d06885e4 must not be described as a universal node speedup.

Combined O1b+O2 ABAB is live in session 87645, receipts O1b-O2-abab. First completed: 2.644500664 s control and 1.582484251 s combined; words 23,068,672/12,582,912; rows 1,001,295/1,844,734; proof bytes 186,992/226,832; core verify 9.472992/9.951857 ms; root 20.0696405/20.4651385 ms. Full combined gate and node medians remain pending, so no combined acceptance yet. Nibble ring-switch candidate passes all 11 targeted tests; examples are still building in session 19132.

### O1b checkpoint at 01:00 UTC

Branch `opt/O1b`, local accepted commit `d06885e4`, no push. The virtual-zero padding candidate is accepted for first-level merges only after matched ABAB3 and all gates: first median 2.423625062 s control versus 1.864678043 s candidate, words 23,068,672 versus 16,777,216, rows 1,001,295 versus 1,008,071, proof bytes 186,992 versus 197,920, core verify 9.1184265 versus 10.223713 ms, root 18.410697 versus 20.5349905 ms. It is rejected as a standalone node optimization: node median 2.775733855 versus 3.001325217 s, words unchanged at 29,360,128, rows 1,141,250 versus 1,163,322, proof bytes 198,800 versus 199,888, core verify 8.9531475 versus 10.4800005 ms, root 29.3742535 versus 31.0391015 ms.

The accepted soundness note is `opt-O1b/artifacts/opt-O1b/virtual-zero.md`. It records public-prefix binding, virtual zero tail semantics, unchanged active port bindings and protocol parameters. Rejection tests cover nonzero physical words in the virtual tail, changed prefix bound, false active claim, tampered proof, wrong permutation output/wiring, public mutation and ordinary proof mutation. Prefix MLE/equality/ring weights match explicit Boolean oracles. The 60-test Keccak recursion gate, five PCS prefix tests, active reduction tests and Clippy with warnings denied passed.

Combined screen with O2 accepted commits, local combined head `7702441a` in worktree `opt-O1b-O2`, is accepted on this slice after ABAB3 and the combined 63-test gate. First median control/candidate 2.644500664/1.582484251 s, words 23,068,672/12,582,912, rows 1,001,295/1,844,734, proof bytes 186,992/226,832, core verify 9.472992/9.951857 ms, root 20.0696405/20.4651385 ms. Node median control/candidate 2.809805006/1.867597084 s, words 29,360,128/14,680,064, rows 1,141,250/1,805,759, proof bytes 198,800/234,000, core verify 9.5226865/10.144455 ms, root 31.600552/29.6280705 ms. Candidate permutations are 4,677 first and 7,521 node, versus 9,772 and 14,361 control. Receipts and frozen binaries are under `artifacts/opt-O1/O1b-O2` and `O1b-O2-abab`; O4 should integrate the source commits rather than these binaries.

Rejected or pending candidates: the standalone virtual-zero node result above is rejected on latency. A nibble-table ring-switch map candidate passed 11 ring-switch equivalence/tampering tests and was built, and is queued for matched ABAB; it is not accepted yet and remains in `artifacts/opt-O1/O1b-nibble`. No claim is made for its timing.

### O1b continuing at 01:05 UTC

The round remains active until 02:31 UTC. Combined result is accepted as above, and all 63 combined tests passed. The joint-opening nibble-only ABAB is live in session 33960, with first medians 2.2997777545 s control and 1.8920122855 s candidate; node samples remain pending. All 60 nibble recursion tests passed. This cumulative win against c59adcb0 does not isolate a nibble improvement over d06885e4, so do not accept nibble without an incremental matched comparison. Immutable nibble binaries and patch are under O1b-nibble.

Current uncommitted ring_switch.rs extends nibble lookup to a 64-state AVX-512BW byte-shuffle map, with scalar fallback. Initial 11 ring-switch tests passed (O1b-ring-simd-tests.log), but the dense equivalence test was expanded from 10 to 14 variables specifically to ensure vector batches execute while testing chunk sizes 17,65,256 and full width; that expanded gate is live in session 40382 (O1b-ring-simd-expanded-tests.log). Next: inspect it, build/freeze SIMD binaries, finish nibble ABAB, and screen SIMD without overlapping timed slice 12-23. No SIMD acceptance exists.

### O1b joint-opening experiments rejected at 01:15 UTC

Nibble-only map: ABAB3 first A/B 2.2997777545/1.8920122855 s, node 2.7382709235/2.8282989065 s. First rows/words/bytes match d06885e4, so the cumulative first win does not isolate a nibble benefit. Node regresses. All 11 ring-switch tests and 60 recursion tests passed, but the candidate is not accepted. Frozen binaries and exact patch: O1b-nibble.

AVX-512BW 64-state nibble shuffle map: ABAB3 first A/B 2.569500425/2.079878094 s, node 2.8627493925/3.0485348415 s. Words, rows and proof bytes match d06885e4. All 11 expanded ring-switch tests and 60 recursion tests passed. Rejected on node latency and lack of an isolated win over virtual padding. Exact patch/frozen binaries: O1b-ring-simd. Source ring_switch.rs is restored to accepted d06885e4.

Current uncommitted candidate targets Keccak witness construction: an eight-state AVX-512 generator inside the existing grouped driver, plus skipping declared zero tail stripes and entirely inactive virtual groups. A scalar grouped reference compares every packed z/a/b word and stripe for counts 0,1,7,8,9,17 under real and virtual padding. Tests for the final zero-tail version are queued in session 62656 (O1b-witness-simd-zero-tests.log). No acceptance or timing yet.

### O1b witness candidate rejected at 01:36 UTC

Eight-state AVX-512 witness construction, skipped zero-tail stripes and avoided clearing overwritten active words: all eight targeted Keccak tests, all 72 Flock library tests, all 60 Keccak recursion tests and Clippy passed. Scalar equality covers counts 0,1,7,8,9,17, partial groups and both real/virtual padding. Against c59adcb0, ABAB3 first A/B 2.37101614/1.8810343985 s and node 2.8570442695/2.8729298795 s. Rows/words/proof bytes match d06885e4, as expected. Against d06885e4 directly, ABAB3 first 1.862475982/1.809704456 s and node 2.90406101/2.965511276 s. Rejected as an additional combined optimization because node regresses, despite the small isolated first-level win. Full receipts: O1b-witness-simd-abab and O1b-witness-v-padding-abab. Exact patch, x86.rs and binaries: O1b-witness-simd. Main opt/O1b source restored to accepted d06885e4.

A separate inner-tail experiment in opt-O1b-inner-zero (base d06885e4) adds a rectangular ring mask: active outer prefix and used-word inner prefix per permutation. Native tensor recurrence matches explicit Boolean sums. Six PCS tests pass, including nonzero physical masked tails, changed outer/inner bounds, false active claims and proof tampering. Full recursion gate session 70143 and examples build 75524 are live. No timing or acceptance exists yet.

### O1b inner virtual tail result (2026-10-24 01:41 UTC)

Candidate `opt-O1b-inner-zero` (base d06885e4) adds a rectangular ring equality mask over Keccak's 651 used packed words per permutation. The six PCS tests and 60 recursion tests passed, including explicit Boolean recurrence checks and verifier rejection probes for altered outer and inner bounds, false active claims, nonzero masked tails, and proof mutation. Clippy passed and `git diff --check` is clean. Frozen binaries and patch are under `artifacts/opt-O1/O1b-inner-zero`; full control ABAB3 first medians were control 2.4728396065 s and candidate 1.8077456095 s, with words 23,068,672 to 16,777,216, rows 1,001,295 to 1,009,095, proof bytes 186,992 to 199,104, verification 9.079108 to 10.581905 ms, and root 20.3218045 to 21.157469 ms. This is not accepted yet because the candidate's node workload is still running and the candidate's source is uncommitted; it needs the node matched result and a soundness note before acceptance.

A separate unaccepted `opt-O1b-lazy-q` experiment skips the virtual q allocation when all ring slice values are precomputed. It is isolated and has not been timed or accepted.

At 01:46 UTC the inner-tail full-control ABAB3 completed: node A/B 2.7910411795/2.8326300955 s, words unchanged 29,360,128, rows 1,141,250/1,164,346, bytes 198,800/199,120, verify 10.2015825/10.651484 ms and root 29.4805435/30.523873 ms. It is not accepted as a standalone node improvement. An incremental ABAB3 against accepted d06885e4 is running to isolate the inner mask from the already-known outer-padding node regression. A soundness note is prepared in the candidate worktree at artifacts/opt-O1b/inner-virtual-zero.md. No push or integration was performed.

A second isolated prover-only candidate, opt/O1b-zero-reduction (base d06885e4), finds a conservative byte bound covering every nonzero a/b/c witness byte, skips round-one high chunks beyond it and skips bit-round blocks wholly beyond it. Physical bits are inspected, not trusted prover metadata; the verifier and transcript format are unchanged. Expanded existing naive-oracle tests exercise zero, one-bit, 511/512/513-bit, one-third and full active prefixes. The Flock test gate and examples build are live. No timing or acceptance yet.

### O1b inner-tail masking rejected at 01:52 UTC

Full incremental ABAB3 against d06885e4 rejects the candidate: first A/B 1.9209037725/1.9746678135 s, words 16777216/16777216, rows 1008071/1009095, bytes 197920/199104, verify 10.568324/11.120016999999999 ms, root 20.929527999999998/22.973559 ms. node A/B 2.973607986/3.0284121600000002 s, words 29360128/29360128, rows 1163322/1164346, bytes 199888/199120, verify 10.986324/10.448433000000001 ms, root 33.16386249999999/32.094207 ms. Both workloads regress incrementally despite green tests. Source remains isolated and uncommitted; exact patch, soundness note and frozen binaries are retained in O1b-inner-zero. This candidate is not for integration.

### O1b zero-reduction incremental rejection at 01:59 UTC

All 71 Flock tests and 60 Keccak recursion tests passed on the final candidate, together with Clippy and formatting. Existing naive-oracle tests now cover zero, one-bit, 511/512/513-bit, one-third and full prefixes; fused-table outputs start nonzero so skipped chunks must explicitly overwrite them. The verifier and relation are unchanged. Incremental ABAB3 against d06885e4: first A/B 2.006802207/1.964751899 s, words 16777216/16777216, rows 1008071/1008071, bytes 197920/197920, verify 10.5042835/10.5643025 ms, root 21.566812/21.374252499999997 ms. node A/B 3.1157315060000004/3.1662888569999996 s, words 29360128/29360128, rows 1163322/1163322, bytes 199888/199888, verify 11.646111/10.9554165 ms, root 33.718362/31.583509499999998 ms. Rejected as a combined-workload optimization because the node median regresses. A full original-control ABAB3 is running for the required candidate record. Source remains isolated and uncommitted, exact patch and frozen binaries are in O1b-zero-reduction.

The lazy-q candidate has passed 46 PCS tests (one manual report ignored), 60 recursion tests, Clippy and formatting. Its PCS overlap test compares the entire proof, including Merkle data, between precomputed slices and a fresh virtual-witness fold. It has not been timed yet. A clean O2 combination plus both prover-only candidates is frozen under O1b-O2-prover, with combined tests running; no acceptance is implied.

### O1b timing-overlap incident at 02:04 UTC

I mistakenly started the lazy-q incremental driver while zero-reduction original-control node measurements were live. Both were O1b jobs. I stopped only the two positively identified O1b Python drivers and their direct benchmark children, after checking /proc command lines; no unrelated processes were touched. All lazy-q samples and all node samples of O1b-zero-reduction-control-abab are invalidated, archived in directories ending overlap-invalid, and explicitly invalidated in the append-only JSONL. The clean zero-reduction run reuses only its completed nonoverlapping first receipts and reruns the entire node ABAB3 sequence under O1b-zero-reduction-control-clean-abab. Lazy-q will start only after that driver is confirmed terminal. No acceptance uses the invalidated samples.

### O1b zero-reduction clean original-control result at 02:08 UTC

first A/B 2.3412229865/1.7580064114999998 s; words 23068672/16777216; rows 1001295/1008071; bytes 186992/197920; verify 9.098231/10.233948999999999 ms; root 18.573770500000002/21.520140499999997 ms. node A/B 2.529482586/2.6371870705 s; words 29360128/29360128; rows 1141250/1163322; bytes 198800/199888; verify 8.77696/9.920975 ms; root 27.703168/28.940382 ms. This completes the full original-control candidate record with clean receipts. First receipts were reused from the unaffected first segment; all node samples were freshly rerun. Rejection remains based on the incremental node regression above. No source commit or push was made. The driver was confirmed exit 0 before starting O1b-lazy-q-clean-abab against d06885e4.

### O1b lazy-q allocation rejected at 02:15 UTC

Clean incremental ABAB3 against accepted d06885e4, first A/B 1.6804090729999999/1.7073849855 s, words 16777216/16777216, rows 1008071/1008071, bytes 197920/197920, verify 9.5497185/10.0336635 ms, root 20.228914/19.245058999999998 ms. Clean incremental ABAB3 against accepted d06885e4, node A/B 2.685446803/2.5709882385 s, words 29360128/29360128, rows 1163322/1163322, bytes 199888/199888, verify 9.808965/10.2216015 ms, root 27.212759/29.0304075 ms. The prover skips constructing virtual q only when all ring claims provide precomputed slice evaluations; a proof-equality PCS regression test covers the fallback. 46 PCS tests, 60 recursion tests, Clippy and formatting passed. Node improves, but first-level regresses, so the candidate is rejected as a combined optimization and remains uncommitted in opt-O1b-lazy-q.

### O1b second timing-overlap correction at 02:18 UTC

I started the pending O2-prover combination before the lazy-q original-control driver was terminal. I stopped only the identified new O2 driver and its child, then stopped only the identified lazy-q driver and its child so the entire node comparison can be rerun. No unrelated processes were touched. All O2-prover partial samples and all lazy-q original-control node samples are invalidated in JSONL; overlap-invalid archives preserve the evidence. Only unaffected first receipts are reused. The O1b measurement harness now takes an exclusive flock on artifacts/opt-O1/O1b-timing.lock before running, enforcing serialization mechanically for all subsequent O1b runs. No acceptance uses either overlap.

### O1b lazy-q clean original-control result at 02:22 UTC

first A/B 2.096867956/1.550969275 s; words 23068672/16777216; rows 1001295/1008071; bytes 186992/197920; verify 8.389987999999999/9.606685500000001 ms; root 17.600937000000002/19.356396 ms. node A/B 2.344683656/2.391654565 s; words 29360128/29360128; rows 1141250/1163322; bytes 198800/199888; verify 8.191288/9.653434 ms; root 23.7952765/26.8375175 ms. The full node sequence was rerun after the overlap; only unaffected first receipts were reused. Rejection remains based on the clean incremental first-level regression. The exclusive lock handed the slice to O1b-O2-prover-clean-abab only after the lazy-q driver exited.

### O1b O2-prover combination rejected at 02:27 UTC

Against accepted combined control 7702441a, first A/B 1.3047851074999999/1.3178869500000001 s; words 12582912/12582912; rows 1844734/1844734; bytes 226832/226832; verify 8.922806000000001/9.047907 ms; root 17.152452/17.401782 ms. Against accepted combined control 7702441a, node A/B 1.5408056344999999/1.4798493590000001 s; words 14680064/14680064; rows 1805759/1805759; bytes 234000/234000; verify 9.680399/9.1947775 ms; root 26.3785205/24.5684495 ms. ABAB3 passes verification for every sample, and all 63 recursion, 71 Flock, 46 PCS tests and Clippy passed. Node improves, but first-level regresses; the extra changes remain rejected as a combined optimization, isolated and uncommitted. The original-control run is pending and will not override this incremental rejection or run beyond 02:31 UTC. No additional accepted commit is claimed.

### O1b final handoff, deadline 2026-10-24 02:31 UTC

Accepted source remains d06885e4 for virtual-zero first-level padding, and combined head 7702441a for O1b plus accepted O2 commits e9164faa, 41e98b89, 28387d02 and ba49591f (local cherry-picks 6f56027a, c2952ac7, fd7fb971 and 7702441a). No further candidate is accepted. No push was performed. O4 integrates source commits. The existing opt-O1b-O2 foreign edits in sparse_tree.rs and verifier.rs were preserved; frozen binaries and the committed combined head identify the accepted result.

| Accepted scope | Control merge s | Candidate merge s | Candidate words | Rows | Proof bytes | Verify ms | Root ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Virtual zero, first only | 2.423625062 | 1.864678043 | 16777216 | 1008071 | 197920 | 10.223713 | 20.534990 |
| O1b + O2, first | 2.644500664 | 1.582484251 | 12582912 | 1844734 | 226832 | 9.951857 | 20.465139 |
| O1b + O2, node | 2.809805005 | 1.867597084 | 14680064 | 1805759 | 234000 | 10.144455 | 29.628070 |

Standalone virtual-zero node padding is rejected: 2.775733855 to 3.001325217 s. The accepted combined medians above are from their matched c59adcb0 control runs, not cross-run historical comparisons. Later accepted-O2 control samples were faster under different host conditions; they cannot be substituted into the earlier speedup ratios. The one-second merge goal has not been achieved, and sustained one-arrival-per-second cadence has not been demonstrated.

Rejected additions: nibble ring map, AVX-512 ring map, eight-state witness SIMD, inner virtual tail, zero-reduction skipping, lazy-q allocation, and both prover-only changes atop O2. Detailed matched medians, dimensions, proof bytes and verifier/root times are recorded above and in receipts. Inner-tail is a structural change with a prepared soundness note but no source commit because it regresses both workloads incrementally. All other late additions preserve the verifier and transcript. Zero-reduction improves standalone first slightly but regresses node; lazy-q and the extra O2-prover combination improve node but regress first. None is a universal merge improvement.

Evidence: accepted virtual-padding soundness note is committed at opt-O1b/artifacts/opt-O1b/virtual-zero.md. Its public-prefix pin and opening tests cover nonzero physical overlap, changed bound, false claim, mutated proof, wrong permutation output/wiring and public mutation. Accepted padding has 60 recursion tests, five PCS tests and active-pin tests; accepted O2 combination has 63 recursion tests. Late inner-tail has six PCS and 60 recursion tests; late zero-reduction has 71 Flock and 60 recursion tests; late lazy-q has 46 PCS and 60 recursion tests; late O2-prover combination has 71 Flock, 46 PCS and 63 recursion tests. All relevant Clippy and formatting checks passed. Each completed valid ABAB run has six successful verified samples per variant per workload on cores 12-23, using both thread variables at 12. O1b-receipt-audit.json records the receipt audit.

Frozen candidate executables, patches and SHA256 manifests are under artifacts/opt-O1/O1b-*. Source experiments remain isolated and uncommitted; main opt/O1b is clean at d06885e4 apart from the untracked measurement harness. Builds and tests used cores 48-63 with four Cargo jobs. Security parameters, rates, query counts and grinding were unchanged. Invalid overlap samples are archived in overlap-invalid directories and invalidated explicitly in the append-only hometurf-12t.jsonl; exclude them from all timing conclusions. The harness now enforces an exclusive O1b timing lock. Earlier process-interference incident and subsequent timing-overlap incidents are disclosed in this report and O1b-process-incident.md.

At the hard deadline 02:31 UTC the last original-control O2-prover driver was stopped by the deadline monitor, after recording 7 completed node samples; it has no valid node median and is not used for acceptance. The monitor verified the driver command before stopping it and stopped only its direct benchmark child. No O1b timing process remains live. All requested work is now handed off without a push.
