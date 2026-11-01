# O3 Keccak optimization

Started 2026-10-23 23:35 UTC; deadline 2026-10-24 02:35 UTC. Local branch opt/O3, control 146a0e94. No pushes authorized. Timing CPUs 36-47, 12 threads; builds/tests CPUs 48-63, four build jobs. Leaf rate 1/4 and recursion rate 1/2 are unchanged.

Control build started as PID 532125, target-opt-O3, log opt-O3/control-build.log. No timing results or accepted candidates yet. Generic CPU Keccak instruction and separate optimized Flock module confirmed in source. Census pending control build and measurement.

## Control and census

Frozen control built from 146a0e94 before source edits; binaries and guest hashes in opt-O3/bin/manifest.json. Three own-slice fresh processes per workload (preliminary baseline, candidate acceptance still requires matched ABAB x3). Exact L6 Falcon fixture used. Leaves 1/4, recursion 1/2. Raw receipts opt-O3/control; summary opt-O3/control-summary.json; individual scalar measurements appended to hometurf-12t.jsonl.

| Workload | Prove/merge s | Words | Bytes | Verify/root ms |
|---|---:|---:|---:|---:|
| shielded | 0.485456 | 5182376 | 215190 | 24.868 |
| Falcon exact L6 | 0.516744 | 6146232 | 220110 | 24.974 |
| same | 2.591940 | 26674176 | 307563 | 33.745 |
| mixed | 2.740467 | 26674176 | 308107 | 32.486 |
| node-mixed | 3.154618 | 26674176 | 307019 | 42.673 |

Shielded cycles 106245; Falcon cycles 125526. Direct recursion circuits have no guest cycles. Root timings settle carried claims. Control exceeds both 300000-byte merged proof and 20-ms admission caps.

Mixed stage census (diagnostic tracing, not a benchmark sample): Build witness 1.40 s (57.91%), Commit 207 ms (8.53%), bus 311 ms (12.84%), constraints 57.4 ms (2.37%), Flock reduction 149 ms (6.17%, zerocheck 132 ms, lincheck 16.9 ms), PCS open 294 ms (12.16%). Full merge timer 2.746361 s. Trace opt-O3/census-mixed.clean.log. The CPU instruction and recursive hash table both use the generic gate-list circuit. HASH has 9546 permutations, pads to 16384 rows, and alone uses 16777216 packed words (1024 per row). Other rows: EMUL 241013 (height 2^19), EXK 62282 (2^17), SPLIT 535 (2^10), CAST 510521 (2^20), PUB 575 (2^10). Merkle versus transcript count separation remains to be instrumented.

Structured candidate in progress: retain 50 contiguous bus ports and the constant at bit 3200; relabel the existing optimized Flock circuit's row and column coordinates identically. Products occupy word-aligned slots. This is a simultaneous permutation of R1CS rows/columns, with the same pinned Keccak input and output relation. All empty rows remain enforced. No hash, rate, query, grinding or security parameter changes. Tests and matched performance results pending; no accepted candidate yet.

First structured focused release test run: 3/3 passed, including native permutation equivalence and CPU tamper/substituted-program rejection. Additional port relabeling transpose test and explicit wrong-output rejection added. Candidate envelope versions bump leaf 15 to 16, tree 11 to 12, rejecting foreign layouts before decoding. Program identities remain unchanged because generator bytes and the execution relation remain unchanged.

Expanded structured release tests: Flock 6/6 and VM focused 3/3 passed (opt-O3/candidate-tests.log). This includes relabeling/transpose consistency and wrong output rejection. Host binary rebuild still running at 23:46 UTC. Merkle source review found shared top path prefixes already implemented through stratified query authentication; no claim of an unimplemented win is made. A further candidate is structural zero absorption in the recursive sponge: current xor_word emits casts for known zero lanes even on the first rate block.

23:50 UTC: structured candidate screening proves/roots all verify. Matched ABAB x3 is live. Next frozen candidate `zero` folds only structural zero wire identities in recursive sponge XORs (never witnessed zero values), preserving every hash input and permutation. A subsequent cast-cache candidate reuses a constrained CAST row only when all its given slot/wire IDs match exactly; no witness-dependent circuit folding. These remain provisional until matched timing and verifier rejection checks complete.

## Structured-only candidate: rejected standalone

Matched ABAB x3 complete, six samples per variant/workload on CPUs 36-47 (opt-O3/candidate-abab). Frozen executable hashes are in opt-O3/bin/manifest.json and source snapshot in opt-O3/structured-source.patch.

| Workload | Control s | Candidate s | Candidate bytes | Candidate verify/root ms |
|---|---:|---:|---:|---:|
| shielded | 0.559807 | 0.559939 | 215126 | 26.297 |
| falcon-l6 | 0.621320 | 0.618396 | 220174 | 27.670 |
| same | 3.323542 | 1.819305 | 308011 | 40.213 |
| mixed | 3.402548 | 1.956346 | 307627 | 38.239 |
| node-mixed | 3.595506 | 2.478250 | 307467 | 51.873 |

Words and cycles are unchanged from control. Same/mixed/node proving improves substantially, but the standalone candidate fails the merged proof-byte cap (307467 to 308011 bytes), admission remains over 20 ms, and node complete-root median regresses from 47.511 to 51.873 ms. Rejected as a standalone deliverable; retained only as an experimental component for combined candidates. No accepted commit yet. Verifier rejection receipts: opt-O3/candidate-rejections.json (7/7); Flock false-output unchecked-reduction test passes all 25 lanes and wrong transcript (opt-O3/false-output-tests.log).

## Accepted candidate: structured Keccak plus structural zero absorption

Commit `979226d1` is local on `opt/O3`; nothing was pushed. The candidate combines the optimized structured Keccak reduction with conservative zero/identity wire folding in recursive sponge XORs. Matched ABAB x3 medians on CPUs 36-47:

| Workload | Control s | Candidate s | Candidate words | Candidate bytes | Candidate verify/root ms |
|---|---:|---:|---:|---:|---:|
| shielded | 0.510027 | 0.512024 | 5182376 | 215126 | 26.103 |
| Falcon exact L6 | 0.545672 | 0.546158 | 6146232 | 220174 | 21.322 |
| same merge | 2.741448 | 1.343486 | 22217728 | 293067 | 33.857 |
| mixed merge | 2.897178 | 1.484246 | 22217728 | 292203 | 35.997 |
| node-mixed merge | 3.243896 | 1.777046 | 22217728 | 292523 | 37.728 |

The candidate is accepted as a matched local win for all merge metrics: 51% to 59% faster, 16.96% fewer committed words, and merged proofs now below 300,000 bytes. Wallet proving is statistically unchanged. Merge and root targets remain above 1 s and admission remains above 20 ms, so no eligibility claim is made. Core suite: 210/210. Flock focused suite: 7/7 including false output in all 25 lanes, wrong transcript and tampered reduction. Wallet and tree rejection screen: 7/7. Structural soundness note: `artifacts/O3/soundness-structured-zero.md`.

Timing limitation: the inherited wallet/root harness starts verification after proof decoding and excludes public tree setup. Reported verify/root values settle all active carried claims, but are not end-to-end external admission/root receipts including decoding. No admission or root eligibility claim follows from these numbers. A later harness update will record decoding-inclusive values separately. The original background control build attempt died without output; successful foreground exec session 11742 produced the frozen control. Its durable provenance is opt-O3/control-build-receipt.json; the empty control-build.log is not a successful-build receipt.

## Cast reuse: matched results, incremental acceptance pending

Only exact given slot/wire IDs reuse a CAST row. No witnessed-value folding is added. ABAB x3 against frozen control (opt-O3/cast-abab), six samples per variant:

| Workload | Control s | Candidate s | Bytes | Verify/root ms |
|---|---:|---:|---:|---:|
| shielded | 0.554279 | 0.585724 | 215126 | 29.516 |
| falcon-l6 | 0.600658 | 0.566358 | 220174 | 27.560 |
| same | 3.117354 | 1.527719 | 292427 | 33.989 |
| mixed | 3.290044 | 1.401354 | 291979 | 35.673 |
| node-mixed | 3.328225 | 1.746663 | 291307 | 38.505 |

Committed words unchanged at 22217728 for all three merges. Setup medians are 1.806/1.856/2.050 s. Incremental benefit versus accepted zero absorption is uncertain: table heights do not cross a padding boundary. No cast-cache commit has been accepted.

## Live checkpoint

Allocation-free packed Keccak witnesses pass 7/7 Flock tests (opt-O3/direct-witness-tests.log). Frozen direct binaries include cast reuse and census counters. Direct measurements/ABAB are live; parallel native deferred-matrix verification is frozen as variant parallel and queued after direct. Both still compare against the original control, all on 36-47. Parallel suites (leanvm/flock/fiat_shamir/pcs release library tests) are compiling/running. A separate harness-only build adds stats mode for a precise hash-category census and decoding-inclusive admission/root timers. No transcript batching or hash-arity change has been made yet. Protocol/rates/query/grinding config remains unchanged. Deadline is still 2026-10-24 02:35 UTC.

## Direct packed witness follow-up

Direct ABAB x3 completed (60 measurements, opt-O3/direct-abab). Same/mixed/node medians are 1.533488/1.507640/1.733697 s against original control 3.333035/3.032299/3.464861 s. Wallet shielded/Falcon medians are 0.559473/0.603529 s against 0.582010/0.654935 s. Merge proof sizes are 292427/291979/291307 bytes and committed words remain 22217728. This includes cast reuse; it does not isolate the allocation-free witness change. No incremental acceptance follows from cross-run comparison with the accepted zero candidate. Parallel verification remains under test; an additional direct matched comparison against frozen zero is prepared.

## Continued follow-up audit

The earlier final-state paragraph was premature and is superseded. At 00:19 UTC the complete-versus-zero benchmark and queued projection comparison were confirmed live; projection core tests passed 211/211. The original-control parallel comparison does not establish its incremental benefit. Follow-up source snapshots and frozen binaries are retained; candidate work resumes within the original 02:35 UTC cutoff. No additional candidate has been accepted.

## Detailed hash census and quaternary prototype

Mixed first-level recursion: transcript seed 10, transcript step 2896, Merkle parent 5181, Merkle leaf 1457, other 2, total 9546. Node: seed 12, step 1612, Merkle parent 10032, leaf 2560, other 51, total 14267. Receipt: opt-O3/hash-category-census.log. Counts are diagnostic shape counts, not timed samples.

The cast-projection matched incremental screen (against frozen accepted zero) regressed: same 1.896688 vs 1.560378 s, mixed 1.707012 vs 1.511787 s; setup grew to 3.794/3.585 s from 1.673/1.697 s. It remains rejected independently, despite removing rows. Quaternary prototype borrows the native O2 tree/path implementation but adapts leanVM recursion to aligned path cuts. Native suites pass, core tests and host build are live. No new accepted commit.

## Accepted native verifier optimization

Local commit `096437a8` streams the unchanged structured Keccak matrix form over nonzero rows and directly maps VM coordinates. No protocol or proof bytes change. ABAB x3 against accepted `979226d1`, six samples per variant/workload, CPUs 36-47:

| Workload | Base prove/merge s | Streaming s | Base verify ms | Streaming verify ms | Bytes |
|---|---:|---:|---:|---:|---:|
| shielded | 0.641941 | 0.589602 | 28.474 | 19.549 | 215126 |
| falcon-l6 | 0.647889 | 0.666952 | 27.070 | 21.112 | 220174 |
| same | 1.474886 | 1.538743 | 39.490 | 30.354 | 293067 |
| mixed | 1.456563 | 1.449470 | 36.859 | 32.933 | 292203 |
| node-mixed | 1.581446 | 1.571580 | 39.279 | 36.334 | 292523 |

Accepted for lower verifier settlement time on all five workloads; no uniform proving speedup is claimed. These verification timers still exclude decoding. Focused Flock tests: 7/7, including dense/transpose equality and direct false-output rejection in all 25 lanes. Soundness note: artifacts/O3/soundness-streaming-bilinear.md. No push.

## Quaternary Merkle prototype, rejected on proof size

The adapted quaternary native tree/path code and leanVM aligned shared-subtree authentication passed 44 PCS tests, 11 Fiat-Shamir tests, and 211 core VM tests. Mixed HASH rows fell to 6998 and node HASH rows to 9347. Shared first/node shapes retained HASH height 2^14, so committed words were 21169152. Mixed screening samples were 1.588634/1.695958/1.601807 s, but mixed proofs were 352803 bytes and node proof 354435 bytes, exceeding the 300000-byte cap. No acceptance or claim of target eligibility follows. The timing run stopped at this failed screening gate. Source snapshots: quad-source.patch, quad-merkle.rs, quad-streaming-source.patch.


## Transcript packing follow-up, rejected

Three-scalar transcript packing passed 11 Fiat-Shamir and 210 leanVM core tests. A completed original-control run is retained as pack3-abab.log, but incremental acceptance uses pack3-vs-stream-abab.log (ABAB x3, six samples per variant/workload, CPUs 36-47).

| Workload | Streaming prove s | Packing prove s | Streaming verify ms | Packing verify ms | Packing bytes |
|---|---:|---:|---:|---:|---:|
| shielded | 0.593909 | 0.589700 | 18.774 | 21.523 | 215510 |
| falcon-l6 | 0.628335 | 0.653065 | 23.828 | 18.288 | 220654 |
| same | 1.488062 | 1.419759 | 31.148 | 30.711 | 291179 |
| mixed | 1.397619 | 1.442130 | 28.691 | 31.970 | 292619 |
| node-mixed | 1.757057 | 1.637591 | 36.950 | 35.826 | 292523 |

Packing is rejected: mixed proving and verification regress, Falcon proving regresses, and shielded admission including decoding measures 21.911 ms, exceeding 20 ms. No new acceptance or security claim. Snapshot: opt-O3/pack3-source.patch.

## Compact Keccak commitment screening

The five-group layout stores 651 used hash words in aligned groups of 512, 128, 8, 2, and 1. It preserves the original commitment domain and WHIR configuration, carries five sets of 64 slice values, and checks their weighted reconstruction against the original Flock claim. This prototype includes the rejected packing change; it is not an isolated compact-only result.

Deferred claim rejection tests passed 2/2 and core release tests passed 210/210. Frozen compact binaries and source snapshot are retained. Screening shapes: committed words 16,106,496 (accepted layout 22,217,728), same/mixed/node proof bytes 277,067/278,251/278,347. Early compact ABAB wallet/first-round measurements overlapped the final screening node jobs on CPUs 36-47 and are ineligible for timing acceptance. Later merge samples remain diagnostic. No compact candidate is accepted on this evidence. Soundness and remaining test limitations: opt-O3/compact-soundness-note.md. The accepted source has been restored to 096437a8.

The completed, non-overlapping mixed/node ABAB x3 measurements reject compact proving: mixed: streaming 1.342176 s, compact 1.514793 s; node-mixed: streaming 1.686335 s, compact 1.934660 s. These later comparisons began after screening ended. No further source changes or pushes.


## Longer worker spinning, rejected

Increasing the worker spin limit from 4096 to 65536 preserved proof bytes, rows, statements and verifier logic. Matched ABAB x3 against streaming on 36-47 gave shielded 0.535227 vs 0.523911 s, Falcon 0.582053 vs 0.574086 s, same 1.570259 vs 1.661656 s, mixed 1.500406 vs 1.442927 s, node 1.547963 vs 1.676500 s. Mixed proving and verification regressed (32.899 vs 27.913 ms), so this is not accepted. Receipt: spin-vs-stream-abab.log; snapshot: spin-source.patch.


## Retained PCS weight, rejected

Keeping the initial ring-switch weight on 12 threads instead of regenerating it preserves protocol and proof bytes. Completed matched ABAB x3: shielded: streaming 0.528254 s, retained 0.579011 s; falcon-l6: streaming 0.620508 s, retained 0.634571 s; same: streaming 1.440330 s, retained 1.451492 s; mixed: streaming 1.474388 s, retained 1.535999 s; node-mixed: streaming 1.731452 s, retained 1.808050 s. This does not establish a merge proving win; it remains rejected. Receipt: keep-vs-stream-abab.log; snapshot: keep-source.patch.


## Larger PCS weight chunks, rejected

Increasing initial weight-fill chunks from 256 to 1,024 preserved rows, proof bytes and protocol. Matched ABAB x3 against streaming gave shielded 0.536255 vs 0.542341 s, Falcon 0.583064 vs 0.584843 s, same 1.365212 vs 1.351208 s, mixed 1.377748 vs 1.383529 s, node 1.720248 vs 1.670130 s. Node proving regressed; the mixed change was less than 1%. This candidate is not accepted. Receipt: basis1024-vs-stream-abab.log; snapshot: basis1024-source.patch. Source restored to accepted prover.


## Decoding-inclusive accepted-proof admission audit

Six fresh verifier processes on CPUs 36-47, accepted streaming proof bytes: shielded: 21.967 ms; falcon-l6: 16.540 ms. Shielded exceeds the 20 ms cap in this audit. This is a measured limitation, not target eligibility. Raw receipt: opt-O3/accepted-admission-audit.json; individual verify/admission samples are in hometurf-12t.jsonl.


## Deferred Keccak bilinear reduction, rejected

The native Keccak matrix bilinear evaluator accumulated unreduced field products and reduced each matrix sum once. Focused Keccak tests passed 7/7 and the full Flock suite passed 42/42, including false-output and transcript rejection tests. Matched ABAB x3 against streaming preserved proof bytes and rows but regressed proving: shielded 0.568366 vs 0.561285 s, Falcon 0.597438 vs 0.596684 s, same 1.381245 vs 1.303352 s, mixed 1.523495 vs 1.423114 s, node 1.838314 vs 1.710771 s. It is rejected. Receipt: deferred-vs-stream-abab.log; source snapshot: deferred-reduce-source.patch.


## Isolated compact layout with SIMD refolding, rejected

This variant excludes transcript packing and uses the existing Flock packed partial-fold kernel instead of the naive scalar bit loop. Core release tests passed 210/210. Matched ABAB x3 on 36-47: same: streaming 1.383344 s, compact SIMD 1.683501 s; mixed: streaming 1.427099 s, compact SIMD 1.688182 s; node-mixed: streaming 1.809370 s, compact SIMD 1.930052 s. Committed words were 16,106,496 and same/mixed/node proofs 278,155/277,803/279,307 bytes. All merge proving medians regressed. Receipt: compactfast-vs-stream-abab.log; snapshot: compact-fast-source.patch.


## Compact layout with lincheck intermediate reuse, rejected

The prover optionally retains the outer-folded witness already produced by lincheck and uses it for compact-group slice values, avoiding a second full witness fold. This leaves the compact proof protocol unchanged. Core release tests passed 210/210. Matched ABAB x3 against streaming: same 1.740118 vs 1.637055 s, mixed 1.624077 vs 1.530544 s, node 1.698137 vs 1.440184 s. Same/mixed/node proof sizes remain 278,155/277,803/279,307 bytes and committed words 16,106,496. Despite smaller commitments, proving regresses, so the variant is rejected. Receipt: compactreuse-vs-stream-abab.log; snapshot: compact-reuse-source.patch.


## Coarser scheduler chunks, rejected

Reducing the scheduler oversubscription from 32 to 8 chunks per worker passed the 15 pool integration tests. Matched ABAB x3 against streaming preserved all proofs and rows but regressed: shielded 0.494506 vs 0.484825 s, Falcon 0.509716 vs 0.494498 s, same 1.227888 vs 1.186202 s, mixed 1.185041 vs 1.156289 s, node 1.562685 vs 1.443033 s. It is rejected. Receipt: chunk8-vs-stream-abab.log; snapshot: chunk8-source.patch.


## Decoding-inclusive merge root audit

Using accepted streaming proofs and six fresh verifier processes on 36-47, medians were same 33.20 ms verifier / 33.61 ms root including proof decode, mixed 29.57 / 29.95 ms, and node 33.60 / 33.96 ms. Raw samples: opt-O3/accepted-root-audit.json.
