# Lane D: native prover / PCS research

CPU slice 36–47, CARGO_BUILD_JOBS=12, RAYON_NUM_THREADS=12, LEANVM_NUM_THREADS=12. No pushes.

Snapshot: fc831598, branch lane/D, copied lane A WIP at ab39e040. No accepted optimization commits yet.

Initial build invocation rejected before running: bench-research requires comma-separated CPUs, not range syntax. Wrapper corrected; retry uses a fresh receipt.

Control build and workload measurements pending. Compiler row reductions belong to lane C; Poseidon and secp256k1 excluded.

## Initial evidence

D-control-build-t2 passed, 71.387 s wall. Session 81222 runs three controls sequentially (BLAKE2s 64B, BLAKE2s 1KiB, SHA256 1KiB), full application_tree, sample=1, seed=20261023. Each process produces two leaf timings and three merge timings; use leaf 0 for the requested quick single screen, retain leaf 1 as supplementary evidence.

Static gap: legacy application_support uses flock::quotient::prove_with and three openings. Native uses a different arithmetic/copy reduction, BLAKE2s reduction for statement hash, joint WHIR witness commitment (log inverse rate 2), index WHIR opening (rate 4), minimum 128 hash blocks and minimum 8192 arithmetic rows. Thus quotient stage is not directly comparable: native has arithmetic/hash sumcheck reductions instead. No second application proof or base adaptation is constructed by prove_base. Detailed timings and counts pending.

Archived screen evidence located: allocation, chunk, first-touch, identity-chunk, joint, padding, pair, quad, tiled, worker, worker16, avx2, factor, extension screen JSON; opening-sparse and opening-blockzero matched plans; profile-summary.json (historical recursive relation, not current native application evidence). Do not repeat these as new candidates.

## Control completed

All three receipts ok=true and files_unchanged=true; CPU slice 36–47 / 12 threads.

| Workload | leaf 0 s | leaf 1 s | leaf 0 certificate bytes |
|---|---:|---:|---:|
| blake2s-64b | 0.296018 | 0.355055 | 247956 |
| blake2s-1kib | 2.548662 | 2.508413 | 323356 |
| sha256-1kib | 6.389773 | 6.012264 | 347036 |

## Next diagnostic

Temporary `d_native_profile` harness uses precisely the same `Setup::new(program)` as SplitClosedSetup::from_program for its base, so it can time/verify a native base proof without paying for unrelated node setup/merges. Uses the same canonical seed and measured seed as leaf 0 in application_tree. Temporary tracing fields expose actual arithmetic gates and hash blocks; existing spans report arithmetic/hash witness, commitment, arithmetic/hash reduction, joint opening, index opening, compile witness. Diagnostic instrumentation is not an accepted candidate.

Candidate queued after profiling: batch the twelve native limb evaluations across all four columns into one evaluate_base_columns dispatch, preserving scalar emission and claim order. Current gate and copy evaluations independently dispatch once per 3-limb column (four dispatches); existing helper already supports a const number of columns. This extends shared-basis evaluation across columns without changing constraints, transcript or PCS parameters. Not yet edited or screened.

## SHA256 1KiB stage profile

D-profile-sha256-1kib-t1 ok=true, files_unchanged=true. Base-only diagnostic uses the same base Setup and seeds. 2,584,283 variables; 2,114,176 actual gates; 4,194,304 padded rows; 4 F192 columns / 12 F64 limbs. Index public_len=162; public_log=8; stack_log=26. 39 actual compression blocks, 128 padded.

| Stage | ms |
|---|---:|
| Private prove | 2150.000 |
| Compile witness | 87.400 |
| Arithmetic witness | 247.000 |
| Hash witness | 0.267 |
| Joint commitment | 561.000 |
| Arithmetic reduction | 558.000 |
| Hash reduction | 3.210 |
| Joint opening | 409.000 |
| Index opening | 261.000 |

Native has no quotient construction stage; arithmetic and hash reductions are reported separately. Commitment + openings = 1231 ms. Profile base prove=2146.857 ms versus 6389.773 ms in full-process leaf 0: same shape but context/residency or host variation unresolved; do not infer speedup. Need matched harness screens and full application rechecks for promising candidates.

D-profile-build-t1 compiled successfully but receipt failed files_unchanged due to Cargo.lock adding the diagnostic bench dependency. D-profile-build-t2 --locked passed with unchanged sources.

## Candidate batch12: quick screen

Shared twelve-limb basis evaluation, one dispatch instead of four at both native gate and copy evaluation points. Same transcript emission order and claims. No shape, field, PCS parameter, commitment or verifier change. CPU slice 36–47, 12 threads.

| Workload | Control s | Candidate s | Delta | Verdict |
|---|---:|---:|---:|---|
| blake2s-64b | 0.107793 | 0.101387 | -5.94% | promising, repeat/gates pending |
| blake2s-1kib | 1.278020 | 1.166964 | -8.69% | promising, repeat/gates pending |
| sha256-1kib | 2.418359 | 2.116085 | -12.50% | promising, repeat/gates pending |

## batch12 repeated screen

Frozen control binary artifacts/D-base-control preserves pre-candidate implementation. All runs use slice 36–47, 12 threads, identical seeds and shape. Three candidate and three control processes per workload; times below are prover-only medians. Host noise is material (SHA candidate trial 3 = 4.182 s).

| Workload | Control median s | Candidate median s | Delta | Verdict |
|---|---:|---:|---:|---|
| blake2s-64b | 0.135330 | 0.101387 | -25.08% | promising; full application/gates pending |

Trials blake2s-64b: control [0.107793491, 0.194798465, 0.135330392]; candidate [0.101386944, 0.120766839, 0.098606801].

| blake2s-1kib | 1.278020 | 1.222145 | -4.37% | promising; full application/gates pending |

Trials blake2s-1kib: control [1.2780197420000001, 1.214641347, 1.406946045]; candidate [1.166964009, 1.222145269, 1.388665549].

| sha256-1kib | 2.455886 | 2.337830 | -4.81% | promising; full application/gates pending |

Trials sha256-1kib: control [2.418359322, 2.45588588, 2.797469324]; candidate [2.116084938, 2.337830331, 4.182427301].


## Gap explanation (source-backed)

Legacy Boolean circuit SHA256 uses log_rows=20 (1,048,576 full-adder rows), six F64 cells per structured row. Native lowers full-adder identities into 2,114,176 live four-cell F192 multiply-add rows, then pads to 4,194,304 rows. These row units are different; comparing times per nominal input circuit row alone is misleading. Native commitment material contains twelve populated base limbs per padded arithmetic row; its joint stack has 2^26 words. The arithmetic index is separately committed at setup and opened per proof.

PCS differs: legacy quotient/opening.rs uses LOG_INV_RATE_0=1 (rate 1/2), while native private bridge uses joint inverse-rate-log 2 (rate 1/4) and fixed-index inverse-rate-log 4 (rate 1/16). These are existing validated profiles; changing them is outside this candidate and can affect proof bytes/shape. Native bridge minimum 128 compression slots and 8192 arithmetic rows add fixed overhead. The actual 39 hash compressions include claim hashing and fallback limb-typing obligations (private_trace::constrain_unused_limbs), not 39 application hash blocks. The native application hashes application identity plus statement inside the relation; the legacy application builds its claim hash on the host. Base key binding is via fixed index/context; no recursive child verifier is in the base relation.

No second leaf application proof or adaptation occurs in prove_base. Setup::prove checks the witness program, evaluates its fixed lowering schedule, checks bridge compression I/O, commits once, runs arithmetic/hash reductions, opens joint/index data and serializes for the proof-cap check. SplitClosedSetup::from_program separately creates/verifies a canonical base proof for recursive-node bootstrap; that is setup work, not repeated for each measured leaf. The full benchmark also retains the recursive node setup during native proving; diagnostic base-only runs retain only the identical base setup. Exact source of the observed timing discrepancy is not yet isolated.

batch12 exact transcript/claim-equivalence test passed (0.02 s execution), including compact and standalone layouts and parallel-size tables. Temporary diagnostics removed before final gates; only native_arithmetic.rs differs from lane-D snapshot. D-batch12-release-gates-t1 currently running; no accepted commit yet.

Final-source release progress: 80/80 format_recursion library tests passed in 55.03 s. rec_aggregation process PID 57450 confirmed running at 10:26:42 UTC (12-thread CPU slice, ~949% CPU), session 68995. Library suites are followed by doctests (no integration test directories in either package), clippy --all-targets -D warnings, and full application_tree candidate checks. Goal remains active; no accepted commit until these gates and full-process comparison pass.

## Checkpoint 2026-10-23 10:27 UTC

Final candidate source: lane-D/crates/format_recursion/src/native_arithmetic.rs only (unstaged, no optimization commit yet). Snapshot commit fc831598 is not an accepted optimization and should not be cherry-picked as a candidate.

D-batch12-release-gates-t1 passed, files_unchanged=true: 80 format_recursion tests passed; rec_aggregation 43 passed / 5 ignored (existing ignored cases). Total wall 207.643 s.

Live driver session 56104 runs, sequentially: D-batch12-doc-tests-t1; D-batch12-clippy-t1 (--all-targets -D warnings); D-batch12-app-build-t1; D-batch12-app-{blake2s-64b,blake2s-1kib,sha256-1kib}-t1. Inspect/poll this exact session before restarting anything. All commands pinned to CPUs36–47 and 12 threads. Compare full application candidate leaf0 bytes/shapes/timings to D-control-* receipts; evaluate noise before acceptance. If accepted, commit only native_arithmetic.rs with one candidate per commit on lane/D, no push. Continue further prover/PCS ideas afterward.

## Continuation 10:29 UTC

Previous goal turn classified as progress: three workload controls, profile, implemented/screened batch12, equivalence test and release suites completed. Revalidated live driver 56104 rather than restarting. D-batch12-doc-tests-t1 passed; D-batch12-clippy-t1 passed with all-targets -D warnings. Full application candidate BLAKE64/BLAKE1K receipts pass; SHA ongoing.

Read orchestrator updates: 10:18 ABAB + min-of-3 screens due shared host interference; 10:23 isolated base client is the desired wallet metric; 10:26 measurement-only joint rate 1/4 -> 1/2 request (query count, bytes, client proof time, leaf merge). Treat rate probe as explicitly requested diagnostic, never accepted silently under shape/size invariants. Existing application_tree --client-only emits witness only, so use the base-only diagnostic that actually calls identical Setup::prove/verify. Report its certificate bytes as proof_bytes + 36, confirmed against full application receipts.

Next actions: finish full application checks; alternate frozen base control and batch12 binaries three rounds on the same CPU slice; accept only if matched wins persist. Then requested rate probe and prover memory-copy investigation (eliminate two column clones while reconstructing copy leaves from original committed limbs, preserving transcript).

## Full application batch12 screen

CPU slice 36-47, 12 threads. D-batch12-app-* receipts all ok=true, files_unchanged=true. Both leaves preserve exact certificate bytes and statements. Base/node keys and shapes identical across control and candidate. All merges and final malformed-certificate checks pass. Timing gap to initial controls is contaminated by host load; follow with alternating frozen base controls/candidates.

| Workload | Control leaf0 s | Candidate leaf0 s | Delta | Verdict |
|---|---:|---:|---:|---|
| blake2s-64b | 0.296018 | 0.159468 | -46.13% | checks pass; noisy screen |
| blake2s-1kib | 2.548662 | 1.712589 | -32.80% | checks pass; noisy screen |
| sha256-1kib | 6.389773 | 2.740626 | -57.11% | checks pass; noisy screen |

## ABAB matched base-only confirmation

Frozen pre-candidate binary and batch12 binary alternated on CPUs 36–47, 12 threads, three rounds. Receipts all passed and proof bytes were unchanged.

| Workload | Control times | Candidate times | Median delta | Verdict |
|---|---|---|---:|---|
| blake2s-64b | 0.136, 0.105, 0.120 | 0.133, 0.111, 0.118 | -1.93% | confirmed matched win |
| blake2s-1kib | 1.126, 1.362, 1.357 | 1.158, 1.258, 1.127 | -14.65% | confirmed matched win |
| sha256-1kib | 2.439, 2.415, 2.265 | 2.319, 2.426, 2.541 | +0.46% | no consistent win |

Final batch12 verdict: REJECTED for acceptance now. ABAB confirmation does not preserve the SHA256 gain (median +0.46%, min-of-three +2.36%), and small-workload differences are noisy. Earlier blocked-order medians overstated confidence. A provisional local commit 0a137ef5 was made before inspecting the completed comparison table; it was immediately removed from lane/D via soft reset and the candidate source restored. DO NOT integrate 0a137ef5. No accepted optimization commits exist. Full patch and frozen executable preserved as D-batch12.patch and D-base-batch12. All correctness/release/clippy gates passed, so rejection is performance evidence only.

## PCS rate diagnostic, partial

D-rate2-probe-t1 used the identical SHA256 base shape: index log_rows=22, stack_log=26, 4 columns, 39 actual blocks padded to 128. `config_for_rate` reports level query counts and fixed grinding bits: rate 1/2 queries `[224,56,32,23,18]`, rate 1/4 queries `[112,45,28,21,16]`; both `[17,17,17,17,17]` grinding bits. Current rate 1/4 proof: 347,000 bytes (certificate 347,036), verify 6.21 ms. The probe did not change the prover, so no rate-comparison timing or size claim is established.

D-rate2-merge-blake1k-t1 verified a one-merge application tree under unchanged rate 1/4, 2.695 s leaf0 and 11.008 s merge. Rate 1/2 has not yet been compiled or measured; its changed byte/shape behavior must remain measurement-only. The 10:26 orchestrator request still needs actual rate-1/2 client and merge evidence. Poseidon and secp256k1 were not run.

## Checkpoint for continuation

No process is running now. Branch lane/D is clean at fc831598. No accepted performance commits. Candidate batch12 was rejected after ABAB evidence; do not integrate provisional 0a137ef5. Its patch and both frozen binaries are preserved. Rejected candidate passed correctness, release, doctest and clippy gates; rejection was timing evidence only.

The temporary `d_native_probe.rs` and one-merge `d_rate_tree.rs` examples were removed after their current-rate diagnostic receipts. Recreate from artifacts/D-native-profile.rs (remove bench::init_tracing line to avoid a dev dependency), or recover improved diagnostics from the receipt manifests/source logs if available. Rate-1/4 and rate-1/2 configs can be queried via pcs::whir::config_for_rate; actual measurement requires temporary JOINT_LOG_INV_RATE=1 in private_bridge.rs. Restore it afterward. Retain per-rate frozen binaries and alternate processes to address host load.

Still promising and NOT screened: eliminate duplicated native column clones in arithmetic reduction by moving columns 0 and 1 into zerocheck::prove_tables and reconstructing copy leaves from the committed stack limbs. Current code clones two full F192 columns before zerocheck and later rereads original cols for copy_leaves. The stack already contains all those limbs. Needs careful ownership changes to Prepared / reduction helpers and proof equality against the original for both compact and standalone layouts. This preserves relation/PCS/shape but may reduce allocations and memory traffic. Do not claim exhaustion or completion before screening it.

## Superseding live checkpoint

Driver session 72796 is live. It builds the measurement-only JOINT_LOG_INV_RATE=1 variant (D-rate1-probe-build-t1), then runs D-rate1-probe-{blake2s-64b,blake2s-1kib,sha256-1kib}-t1, then D-rate1-merge-blake1k-t1. Poll that exact handle before restarting. Worktree intentionally has temporary private_bridge.rs rate constant =1 and two untracked diagnostic examples, d_native_probe.rs and d_rate_tree.rs. Do not commit these diagnostics or treat changed proof sizes as accepted. The rate2 diagnostic frozen binaries are artifacts/D-rate2-client and artifacts/D-rate2-tree. Rate1 client harness reports raw proof bytes, add 36 for the certificate; the rate2 frozen client harness already reports certificate_bytes. All runs on CPU36-47, 12 threads. Restore rate2 and remove temporary examples after archiving rate1 evidence. Goal remains active; column-clone candidate remains unscreened.

## Actual rate-1/2 single diagnostic

All rate1 probe and merge receipts passed unchanged source checks. Rate means code rate: rate1=1/2, rate2=1/4. CPU36-47 / 12 threads. One run each, not a speedup claim due host noise.

| Workload | Current 1/4 cert bytes | 1/2 cert bytes | Byte delta | 1/2 prove s |
|---|---:|---:|---:|---:|
| blake2s-64b | 247956 | 319260 | +28.76% | 0.118638 |
| blake2s-1kib | 323356 | 411916 | +27.39% | 1.235209 |
| sha256-1kib | 347036 | 439988 | +26.78% | 2.303633 |

BLAKE1K rate1 leaf merge 5.601887 s, merged certificate452556 B; current rate2 single merge11.008056 s /355980 B. Node connector_start changes2228224 ->2883584, so this is explicitly a geometry-changing diagnostic. Preserve no accepted changes. Frozen both rate binaries, restored source rate2, matching alternating screens queued.

## Rate diagnostic ABAB completed

CPU36-47, 12 threads, three alternating trials for each wallet workload and leaf merge. Each role uses its own process; setup excluded from proving and merge stage timers. All proofs and trees verified, all receipts ok=true/files_unchanged=true. Binaries separately frozen with source receipt identity.

| Workload | Current rate1/4 min s | Rate1/2 min s | Delta | Cert growth | Verdict |
|---|---:|---:|---:|---:|---|
| blake2s-64b | 0.123780 | 0.096812 | -21.79% | +28.76% | diagnostic only, size/geometry changed |
| blake2s-1kib | 1.446338 | 1.210946 | -16.28% | +27.39% | diagnostic only, size/geometry changed |
| sha256-1kib | 2.722026 | 2.291975 | -15.80% | +26.78% | diagnostic only, size/geometry changed |

BLAKE1K leaf merge: rate1/4 minimum 6.058169 s, median 6.137601 s; rate1/2 minimum 5.310133 s, median 5.311078 s. Merged certificates 355980 -> 452556 B. Full evidence artifacts/D-rate-comparison.json. No rate change accepted.

## Owned columns candidate implementation

Previous turn classified as progress: rate probe built/run plus batch12 ABAB rejection. Current turn completed matched rate measurement. Prepared candidate eliminates two F192 column clones, consumes the four original columns during arithmetic reduction, releases addend/output before zerocheck, and reconstructs copy-check cells from the original committed stack limbs. It changes no circuit, scalar/claim order, PCS config or verifier check. Compact and standalone reductions now consume `Prepared.cols` through mutable borrowing; its stack remains available for openings. Mutation tests rebuild fresh prepared columns for each altered stack so every limb still receives the original independent rejection test.

D-owned-targeted-t1 passed: six arithmetic tests in 0.48 s, including shared-copy reference equality with random extension cells in compact and padded layouts, complete dense index-opening equality, full gate/public/transcript rejection, and compact/standalone transcript equality. Source edit/check cycle 29.189 s, mostly release compile. Rust-only task, no Lean files edited.

D-owned-probe-build-t1 passed. Session25005 screens original-rate frozen control (`artifacts/D-rate2-client`) and candidate on three workloads, alternating per workload, CPUs36-47/12 threads. Candidate enhanced diagnostic emits exact proof hashes; require equality with control and matching shape before timing verdict. No accepted commit yet.

## Owned columns quick screen

CPU36-47 /12 threads. All receipts passed with unchanged sources, exact proof hash, certificate bytes, query rows and base shape equal across all three workloads. Peak RAM is whole-process RSS high water, including setup.

| Workload | Control s | Owned s | Delta | Peak RSS MiB | Verdict |
|---|---:|---:|---:|---|---|
| blake2s-64b | 0.142738 | 0.127801 | -10.46% | 317.7 -> 313.7 | promising |
| blake2s-1kib | 1.584056 | 1.424266 | -10.09% | 3863.9 -> 3674.5 | promising |
| sha256-1kib | 2.974812 | 2.593121 | -12.83% | 7432.8 -> 7054.2 | promising |

## Owned columns five paired trials

CPU36-47 /12 threads. All receipts ok=true/files_unchanged=true; every one of15 candidate proofs has identical hash, certificate bytes, base shape and query counts to control. Prover stage only; separate setup excluded. RAM and CPU secondary evidence cover the entire process, including setup.

| Workload | Control min s | Owned min s | Min delta | Median delta | Pair wins | Verdict |
|---|---:|---:|---:|---:|---:|---|
| blake2s-64b | 0.122365 | 0.101969 | -16.67% | -12.10% | 4/5 | promising, final gates pending |
| blake2s-1kib | 1.466643 | 1.375876 | -6.19% | -5.81% | 5/5 | promising, final gates pending |
| sha256-1kib | 2.694340 | 2.593121 | -3.76% | -8.05% | 4/5 | promising, final gates pending |

## Final owned-column gates live

Driver session19470 runs D-owned-release-gates-t1 (`cargo test --locked --release -p format_recursion -p rec_aggregation`, full suites incl doctests), then D-owned-clippy-t1 (`--all-targets -D warnings`). Source now only native_arithmetic.rs and private_bridge.rs changes; temporary diagnostic examples removed and saved under artifacts/D-final-*. Exact proof hashes in D-owned-confirmation.json establish no transcript/geometry change on15 matched candidate runs. CPU36-47/12 threads throughout. Commit only after both gates pass. No accepted commit yet.

Potential follow-up prepared but not installed: artifacts/D-owned-reuse-native-arithmetic.rs reuses owned addend as zerocheck c in place, avoiding another full-column allocation. This is a separate small extension to screen after owned baseline is accepted, not part of the current gates. It may be too small for a matched runtime win, so reject if evidence is weak.

Context gap reconciliation: later alternating rate2 BLAKE1K wallet-only times [1.446338343, 1.536662959, 1.5548269239999999]; full node-resident leaf0 times [1.534622333, 1.7004710159999998, 1.463018646]. Median full/wallet ratio 0.999, minimum ratio 1.012. The original 3x discrepancy is not a stable context effect and cannot justify a 3x optimization claim. Dedicated wallet mode still avoids unrelated recursive-node setup and RAM.

## ACCEPTED owned columns

Commit `a96334fb23158d264ca4e3311db7adf3fa6e5415` on local branch lane/D, no pushes. Final release gate D-owned-release-gates-t1 passed (79 format_recursion,43 rec_aggregation,5 existing ignored, doctests); D-owned-clippy-t1 passed all-targets -D warnings. All source hashes unchanged during gates. Five paired confirmations preserve exact proof hashes, bytes, queries and base shapes; all workload minima and medians improve, pair wins4/5,5/5,4/5. Candidate removes memory copies only. Lane A should cherry-pick this commit, not the snapshot or removed batch12 commit. Follow-up addend reuse still to screen.

## Continuation checkpoint: accepted commit and follow-up

Accepted local commit a96334fb23158d264ca4e3311db7adf3fa6e5415 on lane/D. No pushes. This is the only accepted optimization commit, directly cherry-pickable without fc831598 snapshot. It owns native columns through reduction and reads copy cells from committed limbs, avoiding clones; proof/shape unchanged. Batch12 remains rejected. Rate1/2 remains diagnostic only, production constant2 restored.

Live session53262 now runs D-reuse-targeted-t1 (six arithmetic tests), D-reuse-build-t1, and D-reuse-screen-{owned,reuse}-{blake2s-64b,blake2s-1kib,sha256-1kib}-t1. All pinned CPU36-47/12 threads. Poll this exact handle before restarting. Accepted owned control is artifacts/D-owned-client. Follow-up changes only c construction: moves addend into c and adds output in place via parallel::for_each_mut; avoids one further full-column allocation. Worktree has this small native_arithmetic.rs edit and temporary untracked examples/d_native_probe.rs. Do not include diagnostic harness in any accepted commit. Next: inspect exact proof/shape equality and timing table; reject if weak, otherwise five paired rounds then release/clippy gates. Goal still active, not exhausted.

## Reuse addend buffer quick screen: REJECTED

CPU36-47,12 threads; all receipts ok=true/files_unchanged=true; six targeted arithmetic tests passed; exact proof hashes, certificate sizes, query counts and shapes matched accepted owned baseline. No release/clippy rerun needed for rejected variant. Patch saved D-reuse.patch and worktree restored to accepted a96334fb.

| Workload | Owned control s | Reuse s | Delta | Verdict |
|---|---:|---:|---:|---|
| blake2s-64b | 0.123773 | 0.128939 | +4.17% | reject mixed gain / regressions |
| blake2s-1kib | 1.579656 | 1.460416 | -7.55% | reject mixed gain / regressions |
| sha256-1kib | 2.662710 | 2.969932 | +11.54% | reject mixed gain / regressions |

Previous goal turn classified as progress: committed validated owned-column speedup and launched this follow-up. This turn completed live follow-up without restarting any finished receipt and restored the accepted worktree.

## Final lane-D audit

Lane-D scope is complete. Required controls and the SHA256 profile have authoritative Yukon receipts with unchanged source manifests. Profile evidence reports witness preparation (87 ms compile, 247 ms arithmetic witness, 0.267 ms hash witness), commitment/PCS (561 ms joint commitment), arithmetic reduction (558 ms), hash reduction (3 ms), joint opening (409 ms), and index opening (261 ms), with 2,114,176 live arithmetic gates padded to 4,194,304 rows, four F192 columns, 12 populated F64 limbs, 39 actual hash blocks padded to 128, stack_log=26, and index public_len=162. Native has no quotient construction stage; its arithmetic/hash reductions replace the old quotient stage. The gap explanation and no-duplication finding are source-backed above.

Candidate inventory is complete for prover/PCS scope: batch12 shared column-evaluation dispatch rejected after ABAB; PCS rate 1/2 rejected for proof-size and node-geometry change despite faster measurements; owned-column consumption accepted as a sound memory-traffic optimization in a96334fb; addend-buffer reuse rejected after mixed one-run screen. Archived prior AVX2, NTT, quad, joint, padding, sparse, block-zero, factor, identity-chunk and worker screens were not repeated. Poseidon and secp256k1 were omitted.

Acceptance evidence for a96334fb: exact proof hashes, certificate bytes, query rows, base shapes and node shapes match controls on 15 candidate runs; five paired trials per workload show minimum deltas BLAKE2s64 -16.67%, BLAKE2s1KiB -6.19%, SHA2561KiB -3.76%, with pair wins 4/5, 5/5, 4/5. D-owned-targeted-t1 passes six arithmetic equivalence/rejection tests. D-owned-release-gates-t1 passes 79 format_recursion tests and 43 rec_aggregation tests with 5 existing ignored; doctests pass. D-owned-clippy-t1 passes all-targets with -D warnings. Result manifests and log hashes were independently checked, current lane-D source is clean at a96334fb, CPU slice36-47 and 12 threads recorded throughout, and no pushes were made.

Lane A must cherry-pick a96334fb23158d264ca4e3311db7adf3fa6e5415. Do not cherry-pick fc831598 or removed 0a137ef5. Rate diagnostic binaries and rejected patches remain under artifacts for review.


## Shielded transfer and Falcon512 priority profile (2026-10-23)

The preceding final audit predates this priority and does not close it. Headline metric: **time to mempool-ready proof** = witness creation + the one proof the wallet sends. Mempool nodes verify this certificate natively and aggregators merge it as-is. Always report transmitted proof bytes, native verification ms, and peak client RAM beside that metric.

User-provided historical comparison (not a matched CPU36–47 measurement): shielded transfer new 13.2 s versus old application proof + wrap proof 12.3 s; Falcon512 new 12.0 s versus old application proof + wrap proof 11.9 s. The native proof was roughly 1.8× slower than the old application proof. These two workloads now take priority over further BLAKE/SHA tuning.

Current source: accepted lane/D a96334fb. Diagnostic d_priority_profile.rs uses the same Setup::new base backend, trace-satisfaction precheck, and height-zero Certificate encoding as SplitClosedSetup::prove_base, without recursive-node setup. CPU36–47, 12 threads; Yukon pinned 2e90b37. New controls/profile runs are necessary because prior SHA256 evidence cannot establish these workloads' bottlenecks. Old application-only controls omit the wrap proof and will not be mislabeled as time to mempool-ready proof.

RAM method: /proc/self/status VmHWM, reset via /proc/self/clear_refs=5 after setup. This measures the wallet phase with its resident preprocessed setup and allocator-retained setup pages; it is not a cold process loading a serialized proving key. Setup wall time and its original RSS high water are recorded separately. Native verification includes certificate decode and native verification in this wallet diagnostic; a standalone mempool process is not measured here. Independent reference checks are excluded from the historical witness timer; inclusive create-call wall time is also emitted to expose that difference.

Build receipts: D-priority-build-t1 correctly refused a locked dependency update; D-priority-build-t2 compiled successfully offline but its manifest check rejected the intentional Cargo.lock update. D-priority-build-t3 repeats only the build with the fixed lock and unchanged sources. No protocol or production source changes are proposed by these diagnostics.


### Priority profile: stage evidence

Receipts D-priority-profile-native-{shielded-transfer,falcon512}-t1 and D-priority-profile-old-{shielded-transfer,falcon512}-t1 all passed unchanged-source checks. Tracing diagnostics, one run each; CPU36–47/12 threads. Times below are rounded by the tracing tree and are for bottleneck attribution, not performance acceptance.

| Native stage | Shielded transfer ms | Falcon512 ms |
|---|---:|---:|
| Private prove total | 9340 | 9580 |
| Compile witness | 503 | 494 |
| Arithmetic witness | 1030 | 1060 |
| Hash witness | 0.426 | 0.390 |
| Joint commitment | 2870 | 2590 |
| Arithmetic reduction | 1680 | 1760 |
| Of which: native copy product | 1110 | 1160 |
| Of which: native zerocheck | 196 | 200 |
| Hash reduction | 3.27 | 3.51 |
| Joint opening | 2130 | 2370 |
| Index opening | 932 | 1110 |

Joint commitment + joint opening + index opening consume 63.5% / 63.3% of native proving time. Arithmetic reduction is another 18.0% / 18.3%, mostly the copy-product argument. Hash reduction is below 0.04%; application SHAKE/Keccak computations in Falcon and shielded application hashes have already become arithmetic gates, and must not be confused with the native bridge's 39 in-circuit BLAKE2s compression blocks (padded to 128). PCS Merkle hashing of encoded tables is additional work, included in the commitment spans.

| Native geometry | Shielded transfer | Falcon512 |
|---|---:|---:|
| Actual arithmetic gates | 12,378,752 | 11,961,088 |
| Padded arithmetic rows | 16,777,216 | 16,777,216 |
| Unfilled padded rows | 26.22% | 28.71% |
| Trace nodes | 15,113,223 | 14,311,025 |
| Native columns / populated F64 limbs | 4 / 12 | 4 / 12 |
| Stack log | 28 | 28 |
| Hash blocks actual / padded | 39 / 128 | 39 / 128 |
| Joint / index inverse-rate logs | 2 / 4 | 2 / 4 |
| Old Boolean application row log | 22 | 22 |

The old structured application proof works on 2^22 full-adder rows and F64 cells. Native compilation expands those adders into multiple F192 operations and reaches 2^24 padded rows: 4× as many padded arithmetic rows and three F64 limbs per native field cell. That is substantial extra representation/PCS work, despite eliminating the old wallet wrap proof. It is not a hidden second application proof: SplitClosedSetup::from_program uses Setup::new for the base; SplitClosedSetup::prove_base calls that backend once and emits the same height-zero certificate used here. Canonical proving for recursive bootstrap occurs during separate setup only.

The old profile spends 6.17 s / 6.04 s in quotient construction, 0.424 s / 0.415 s in its sum stage, and 0.238 s / 0.251 s in its witness transform/commit stage; its full proof with openings is 8.752 s / 8.532 s excluding witness creation. Native has no direct quotient-construction stage: arithmetic/hash reductions and their joint/index PCS work implement its different proof path. These totals cannot be compared stage-for-stage as if they were the same protocol.

Prover-side priority from these profiles: joint PCS commitment and openings first, then copy-product memory traffic and witness buffers. Compiler expansion is a large structural lever but remains lane C's responsibility; this lane changes no row policy. Do not optimize the tiny hash-reduction stage for these workloads. The previous rate-1/2 diagnostic is not accepted because it changes proof bytes and node geometry. No new optimization is accepted from these one-run profiles.


### Priority controls: final wallet and mempool results

One untraced wallet process and one independent mempool verification process per workload; CPU36–47/12 threads. These are quick development measurements, not medians or an accepted speedup. Headline proof bytes below include the full height-zero certificate that the wallet sends.

| Workload | Time to mempool-ready proof s | Witness s | One native proof s | Proof bytes sent | Native verification ms | Peak client RAM GiB |
|---|---:|---:|---:|---:|---:|---:|
| shielded-transfer | 10.977165 | 1.139606 | 9.837558 | 385,204 | 7.257033 | 32.401 |
| falcon512 | 11.530916 | 1.197996 | 10.332921 | 384,756 | 7.552864 | 32.188 |

Native raw proof sizes are 385,168 B / 384,720 B; transport adds 36 B. Certificate decoding and the native verifier are included in the standalone mempool verification time; setup and file I/O are excluded. Every certificate verified in a separate process. Peak client RAM is the wallet-phase RSS high water reset after setup, including resident setup and allocator-retained setup pages; it is not an isolated serialized-key-load measurement.

The inclusive client create-call + proof wall times are 11.019 s / 11.656 s, versus headline 10.977 s / 11.531 s. The extra 42 ms / 126 ms covers reference-instance creation and independent Boolean/reference checking excluded by the existing witness timer. Both values are retained rather than hiding that scope difference.

| Matched old application-only baseline | Witness ms | Application proof incl. openings s | Witness + application proof s | Application certificate bytes | Application-only peak RAM GiB | Native proof / old application proof |
|---|---:|---:|---:|---:|---:|---:|
| shielded-transfer | 52.443 | 8.368668 | 8.421111 | 882,408 | 12.033 | 1.176× |
| falcon512 | 73.845 | 8.824372 | 8.898217 | 881,384 | 12.331 | 1.171× |

Old wrap proving is excluded from these matched application-only controls. Do not add the historical wrap times to these new slice-specific application times or compare their application-only RAM with a complete old two-proof process. In these controls the native proof penalty is about 1.17×, not the historical approximately 1.8×; source state, concurrency and thread allocation differ from those historical receipts, so no causal speedup is attributed to a96334fb on these workloads. The user-provided old two-proof totals 12.3 s / 11.9 s remain historical context, not matched denominators.

The native witness step itself costs 1.140 s / 1.198 s, versus 52 ms / 74 ms for the structured old application witness. Thus witness recording adds about 1.1 s before native proving. The current native certificate is about 56.3% smaller than the old application certificate alone, but the native wallet phase uses about 2.6–2.7× that application-only RSS. Performance evaluation should preserve this bytes/RAM tradeoff.

| One-time wallet preprocessing, separate from headline | Setup s | Setup peak RSS GiB |
|---|---:|---:|
| shielded-transfer | 12.653352 | 14.534 |
| falcon512 | 13.840930 | 14.365 |

**Conclusion:** the requested priority profiling is complete. Both workloads are dominated by native joint PCS commitment/openings (~63% of proving), followed by copy-product work and witness preparation. The large expanded native representation and >32 GiB measured client RSS are the central prover-side feasibility issues. No extra wallet proof is hidden in the native path. No compiler policy, PCS rate, circuit shape, proof format, verifier check or soundness parameter was changed. No new optimization commit or push was made.

**Validation and reproducibility:** all ten runtime receipts passed ok=true/files_unchanged=true; stdout/stderr hashes, CPU affinity36–47,12-thread environment and pinned Yukon2e90b37 were independently checked. Profile and control native proof hashes, bytes and shapes match exactly for both workloads; old application proof digests match too. Source-only diagnostics were built in D-priority-build-t4 with unchanged-source checks; no new production change requires release-gate reruns. Full machine-readable evidence: artifacts/D-priority-summary.json. Reproduction source/manifests: D-priority-profile.rs, D-priority-format-Cargo.toml, D-priority-Cargo.lock. Frozen binary: D-priority-client. Runtime sequence: D-run-priority.py and D-run-priority.log; independent audit: D-summarize-priority.py.

Authoritative runtime receipts: D-priority-profile-{native,old}-{shielded-transfer,falcon512}-t1; D-priority-control-{native,old}-{shielded-transfer,falcon512}-t1; D-priority-mempool-{shielded-transfer,falcon512}-t1. No completed historical experiments were rerun. Temporary diagnostic example/dev dependency/lock change are removed after archiving; lane/D returns to accepted a96334fb.


## Orchestrator control audit and explicit reruns (2026-10-23)

Original receipt D-control-blake2s-64b-t1 reports parent and command affinity exactly [36,37,38,39,40,41,42,43,44,45,46,47], with 12 threads. An explicit taskset token is absent because pinned Yukon bench-research.py applies os.sched_setaffinity(0, cpus) in its child preexec_fn (lines126–128); --cpus is parsed as comma-separated CPU integers. The wrapper passes that comma list. The original receipt is therefore evidence of pinning, not evidence of an unpinned run. It lacks per-thread runtime samples. No other recorded lane-D receipt overlapped its 10:14:16–10:14:53 UTC interval; absence of an unrecorded historical build cannot be proven retroactively.

The original snapshot fc831598 was restored temporarily, including the pre-owned-column native_arithmetic.rs/private_bridge.rs. All common original/build code-manifest hashes match; only the external application-closure-plan.json metadata differs. D-control-recheck-build-t1 built --locked --release and emitted Cargo JSON: opt_level=3, debug_assertions=false, debuginfo=0. The rebuilt application_tree binary SHA256 is byte-for-byte identical to the original receipt binary: db2b9a3d5372bbdcb93d2bf219c2c021a602b065953382a440bacb25cad470f1. Thus the historical binary was also the verified release build. This audit does not screen the accepted owned-column change.

All runtime commands use explicit taskset -c36,37,38,39,40,41,42,43,44,45,46,47 (separate flag/value arguments), 12-thread environment, and the pinned Yukon 2e90b37 runner. A guard samples every live thread mask at 50 ms intervals, checks lane-D cargo/rustc/linker/C build processes before/during/after, and rejects affinity deviations or overlapping own builds. All six runs observed exactly CPUs 36–47 on every sampled thread, up to 12 threads, and zero lane-D builds. The build completed before any runtime measurement; no builds were launched until all six measurements ended.

| Control trial | Identical original application_tree leaf0 proof s | Leaf1 proof s | Wallet-only original-backend proof s |
|---|---:|---:|---:|
| 1 | 0.156836 | 0.124166 | 0.138141 |
| 2 | 0.114324 | 0.129024 | 0.114482 |
| 3 | 0.139873 | 0.144834 | 0.123917 |

These controls bracket lane C’s 0.126619 s result. The original 0.296018 s leaf0 singleton is superseded and must not be used as a candidate speedup denominator. Correct affinity and a release binary alone do not explain the original slow result; its cause is not established. The tree rerun median is 0.139873 s and the wallet-only median is 0.123917 s. Range/median is30.4% for tree leaf0 and 19.1% for wallet-only, so controls remain too noisy to resolve small effects. Do not claim the full-node context itself causes a stable 2× slowdown.

| Wallet-only trial | Time to mempool-ready proof s | Proof bytes sent | Native verification ms | Peak client RAM MiB |
|---|---:|---:|---:|---:|
| 1 | 0.148866 | 247,956 | 4.960367 | 319.730 |
| 2 | 0.121604 | 247,956 | 5.118612 | 317.227 |
| 3 | 0.135057 | 247,956 | 4.731468 | 317.711 |

Wallet-only RAM is whole-process VmHWM including base setup; no aggregator node key is built in that process. Verification is an in-process native check in this control audit. All three wallet proofs have identical exact hashes, shapes, query rows and 247,956-byte certificates. The full application_tree process also creates the aggregator node key and merges; its whole-process RSS must not be labeled wallet peak RAM.

**Screening gate:** no new candidate was screened. Further candidate screening remains gated on stable, slice-matched controls. Retain all repetitions and report their spread; a minimum alone is insufficient. The historical 0.296 s result is not the denominator for the previously accepted a96334fb: its archived acceptance evidence uses five interleaved paired control/candidate rounds from the dedicated base-only harness. This audit does not revalidate that candidate or attribute cross-context timing differences to it.

**Evidence:** D-control-recheck-build-audit.json, D-control-affinity-historical.json, D-control-recheck-summary.json, D-control-affinity-guard.py, D-run-control-recheck.py/log; six D-control-blake2s-64b-{wallet,tree}-recheck-t{1,2,3} receipts and their individual -guard.json files. Guard reports passed; receipt source-stability and stdout/stderr hashes independently passed. Frozen release binaries D-control-recheck-tree and D-control-recheck-wallet preserve exact executable identities.

An exploratory non-receipted invocation without enforced settings was excluded, as was D-control-blake2s-64b-rerun-t1, which failed before execution because its guard-script path was relative to the wrong working directory. Neither is a benchmark control or screening datum. No failed receipt was overwritten. Temporary original-source restoration and the diagnostic example are removed after archiving; lane/D returns clean to accepted a96334fb. No commits or pushes.


## Orchestrator correction: current reference and screening policy

This section supersedes the preceding audit's decision to suspend screening and its wording that the original control is superseded. Keep lane-D controls as the reference, including D-control-blake2s-64b-t1 for its original application_tree/source context; retain all reruns as additional evidence. Do not replace a lane-D control with lane C's compiler_rows --prove result, nor use a control from a different binary/source/process context as a candidate denominator. The differing timing tools are the orchestrator's most likely explanation for the discrepancy; the audit does not establish a unique cause or a permanent context penalty.

Pinning is confirmed in the actual runner implementation: pinned Yukon 2e90b37 bin/bench-research.py lines 126–128 calls subprocess.Popen with preexec_fn=lambda: os.sched_setaffinity(0, cpus). The original receipt records cpus exactly 36,37,38,39,40,41,42,43,44,45,46,47 and 12 threads. Six explicit reruns additionally sampled the live threads and observed only that mask; no lane-D build overlapped them. The original executable is byte-identical to the rebuilt release executable (opt_level=3, debug_assertions=false).

The orchestrator reports an unrelated mission's turbo-lean fastcheck process observed on cpu39 inside this slice. This is reported external evidence, not an observation made by this lane's historical build monitor. Pinning our workers does not reserve the cores or prevent unrelated processes from running there; monitoring our own builds cannot exclude outside contention. No outside mission process was stopped or changed.

**Current screening rule:** same slice, 12 threads, release builds, no own build overlap; interleave control A and candidate B as ABABAB, with at least three fresh-process runs per variant. Compare the minimum of three for the quick screen, as directed by the orchestrator; also retain every sample, paired order and spread. Keep witness plus the one wallet proof as time to mempool-ready proof, and record proof bytes, native verification ms and peak client RAM. Require unchanged proof hashes/bytes/shapes for a shape-preserving candidate. Small or inconsistent effects receive more paired trials before acceptance, followed by the existing release/clippy gates. Do not declare a win from the cross-lane 0.296/0.127 s comparison. No new candidate was screened during this correction.

## Profiling continuation: commitment encoding and hashing

Reuse the already-completed shielded-transfer and Falcon512 priority profile receipts; do not rerun completed profiling merely to restate the result. Both use the accepted a96334fb backend on CPUs36–47 with12 threads. The profile tree isolates the following large jobs (rounded tracing durations; diagnostic attribution only):

| Commitment job | Shielded transfer ms | Falcon512 ms |
|---|---:|---:|
| Initial joint commitment | 2870 | 2590 |
| First extension commitment in joint opening | 976 | 1000 |
| First extension commitment in index opening | 467 | 547 |
| Sum of those three jobs | 4313 | 4137 |
| Share of native proving | 46.2% | 43.2% |

The initial base encoding has log_domain24 and49 populated lanes: 49 × 2^24 × 8 bytes = 6.125 GiB of encoded F64 codeword, from a 1.53125 GiB message. The first extension encoding in each opening has log_domain23 and16 F192 lanes: 16 × 2^23 × 24 bytes = 3 GiB of encoded field data for each such job. These are buffer sizes inferred from the observed trace geometry and source layouts, not separate allocator peak measurements and not amounts to add to the measured whole-process RSS.

**Attribution correction:** in pcs/src/whir.rs::commit, the NTT base-encode span wraps transpose, RS encoding and the callback tree.absorb(row, rows). In ligero_commit_ext the NTT extension-encode span likewise includes builder.absorb. Both hash leaves and build Merkle state during encoding; their separate Merkle span wraps only builder.finish(). Therefore a 99.9% NTT share within a commitment does not mean BLAKE2s hashing is negligible or that transform arithmetic alone is the bottleneck. The tiny native Hash reduction stage concerns the 39 in-circuit bridge blocks, not the PCS Merkle trees. Source references: crates/pcs/src/whir.rs lines200–229 and264–296.

Current actionable profile target is the large combined encoding/streaming-hash/memory pass and the first extension commitment of each opening. Exact split between field-transform work and hashing is not established by existing spans; do not claim an NTT-only or hash-only optimization opportunity from this evidence. Copy-product work remains the next distinct arithmetic target (~1.11/1.16 s). Avoid repeating archived NTT/AVX2/etc. candidates without a new source-backed hypothesis. Circuit row policy remains lane C's scope, and no PCS rate change is accepted.

The wallet/mempool result table above remains authoritative for this profiling round: time to mempool-ready proof10.977/11.531 s, transmitted bytes385,204/384,756, native verification7.257/7.553 ms in separate mempool processes, peak client RAM32.401/32.188 GiB with resident setup state. These are single-run diagnostic controls, not a candidate speedup claim. No source edits, tests, builds or repeated benchmark runs were needed for this source-backed trace analysis. Worktree remains clean at a96334fb; no commits or pushes.


## Correct client measurement with loaded base key (2026-10-23)

Implemented `lane-D/crates/format_recursion/examples/application_client.rs`, with `prepare`, `prove`, and `verify` commands and optional `trusted-key-cache` support. `prepare` persists the actual preprocessed base `Setup`, including its prover tables. The wallet process loads that key, creates its witness, calls the base prover once, and serializes the standard height-zero certificate. It constructs no node setup and performs no merge or native verification in the wallet process. Each certificate is decoded and verified in a separate process against the authorized local key; altered statements and proofs are rejected there. Usage and cache trust/version limitations are documented in `lane-D/crates/format_recursion/client.md`.

**Time to mempool-ready proof** starts with the base key and static circuit loaded and ends with the complete certificate bytes in memory. It includes the complete current witness creation path, including fixture/instance reference work, the satisfaction check, one native proof, and serialization. Key loading, static circuit construction, certificate file output, and verification are outside the headline; their independent timings are preserved below and in JSON. This is the correct client measurement. These numbers describe this process boundary on the shared host; they are not a candidate performance comparison.

All runs use a release binary (optimization level 3, debug assertions disabled), 12 threads, and explicit `taskset -c 36,37,38,39,40,41,42,43,44,45,46,47`. Every sampled live thread had exactly that mask. No lane-D build overlapped any runtime measurement. Pinning does not reserve the slice: unrelated fastcheck/Lean processes with overlapping masks were observed, and scheduling variability is visible in the recorded counters.

Each row reports three fresh-process measurements: headline time and native verification are the minimum of three; peak client RAM is the maximum of three. RAM is Linux VmHWM from the loaded-key witness/proof/encoding boundary, including the resident base key and static circuit. Offline preprocessing memory is outside this client phase. All repeated certificate hashes, bytes, base-key roots, and shapes match exactly within a workload.

| Workload | Time to mempool-ready proof s (min/3) | Proof bytes sent | Native verification ms (min/3) | Peak client RAM GiB (max/3) |
|---|---:|---:|---:|---:|
| BLAKE2s 64 B | 0.119769 | 247,956 | 5.889738 | 0.308 |
| BLAKE2s 1 KiB | 1.528974 | 323,356 | 6.969076 | 3.577 |
| SHA256 1 KiB | 2.927579 | 347,036 | 7.547518 | 6.899 |
| Keccak256 1 KiB | 3.111876 | 346,652 | 7.158497 | 7.228 |
| MPT storage proof | 12.858749 | 386,356 | 7.901137 | 28.318 |
| Shielded transfer | 13.358411 | 385,204 | 7.884659 | 27.776 |
| Falcon512 | 13.388206 | 384,756 | 7.714183 | 27.772 |

| Workload | All headline samples s | Median s | Range / median | All native verification samples ms |
|---|---|---:|---:|---|
| BLAKE2s 64 B | 0.172939, 0.130556, 0.119769 | 0.130556 | 40.7% | 9.798532, 10.932844, 5.889738 |
| BLAKE2s 1 KiB | 4.342364, 1.528974, 1.578815 | 1.578815 | 178.2% | 7.297639, 7.030073, 6.969076 |
| SHA256 1 KiB | 5.278719, 3.066193, 2.927579 | 3.066193 | 76.7% | 7.889981, 8.051589, 7.547518 |
| Keccak256 1 KiB | 6.052641, 3.240141, 3.111876 | 3.240141 | 90.8% | 7.158497, 7.569910, 9.414777 |
| MPT storage proof | 15.906079, 13.238489, 12.858749 | 13.238489 | 23.0% | 9.567239, 8.387892, 7.901137 |
| Shielded transfer | 14.427897, 13.792415, 13.358411 | 13.792415 | 7.8% | 8.030180, 7.884659, 8.464452 |
| Falcon512 | 14.181943, 13.388206, 24.283758 | 14.181943 | 76.8% | 7.761278, 8.350171, 7.714183 |

| Workload | Key-load samples s (excluded) | Static-circuit samples s (excluded) | Witness samples s (included) | Proof samples s (included) |
|---|---|---|---|---|
| BLAKE2s 64 B | 0.319797, 0.288375, 0.286699 | 0.008107, 0.008538, 0.007683 | 0.010755, 0.009657, 0.009897 | 0.161977, 0.120661, 0.109647 |
| BLAKE2s 1 KiB | 5.528194, 4.786503, 4.498860 | 0.225033, 0.163379, 0.160098 | 0.228825, 0.144027, 0.136988 | 4.112672, 1.384377, 1.441311 |
| SHA256 1 KiB | 14.021652, 9.173739, 8.731209 | 0.458687, 0.376728, 0.389711 | 0.388165, 0.288434, 0.283802 | 4.889917, 2.777173, 2.643221 |
| Keccak256 1 KiB | 12.187875, 9.692551, 9.450468 | 11.644793, 9.647049, 9.354747 | 0.485040, 0.281169, 0.285276 | 5.566982, 2.958322, 2.826006 |
| MPT storage proof | 43.962415, 36.749297, 37.921564 | 37.045536, 29.818383, 31.021261 | 1.616801, 1.443931, 1.431070 | 14.286962, 11.792438, 11.425591 |
| Shielded transfer | 41.636787, 38.872050, 47.103478 | 2.439439, 2.444646, 2.552036 | 1.512214, 1.383425, 1.257153 | 12.914898, 12.408187, 12.100133 |
| Falcon512 | 36.687791, 37.439572, 63.421749 | 1.824922, 1.891879, 2.380118 | 2.402808, 2.492027, 3.587806 | 11.777801, 10.894813, 20.694518 |

### SHA256 gap diagnosis

The historical 2.146857 s isolated proof versus 6.389773 s tree leaf-0 proof is not reproduced as a stable recursive-setup penalty. Nine matched fresh-process diagnostics use the identical witness and base shape in three contexts, with two proofs per process. The first-round contexts all enable the same existing tracing spans. Every one of the 18 certificates and all three wallet SHA certificates is identical, including its 347,036-byte encoding. The accepted backend is a96334fb; the original slow tree receipt predates its owned-column change, so these observations cannot assign an exact cause retrospectively to that old singleton.

| Context | First proof + serialization samples s | Warm samples s | First min s | Warm min s |
|---|---|---|---:|---:|
| base-new | 2.462171, 2.712376, 2.982010 | 1.915614, 2.518787, 2.221138 | 2.462171 | 1.915614 |
| node | 2.613822, 2.650684, 2.628773 | 2.138032, 1.996241, 2.820687 | 2.613822 | 1.996241 |
| base-load | 3.174327, 2.586828, 3.145886 | 2.213423, 1.861859, 2.865803 | 2.586828 | 1.861859 |

Source inspection: `SplitClosedSetup::prove_base` calls the base prover exactly once; its extra work is a trace-satisfaction/public-output check. Recursive setup does create a bootstrap proof, but it finishes before the measured leaf proof and is absent from the new wallet executable. `Setup::prove` performs a size-validation encoding before the certificate is encoded; this is serialization, not a second proof. Neither the old leaf timer nor the new proof timer includes recursive key setup or merges.

| SHA context | First-proof minor faults (three samples) | Warm minor faults | First-proof aggregate system CPU s | Warm aggregate system CPU s | Resident RAM before first proof GiB |
|---|---|---|---|---|---|
| base-new | 19744, 19957, 18630 | 49, 242, 215 | 5.00, 6.40, 7.83 | 0.01, 0.06, 0.05 | 3.509, 3.510, 3.508 |
| node | 5902, 5284, 5245 | 19, 16, 548 | 3.11, 5.52, 3.91 | 0.02, 0.04, 0.01 | 8.185, 8.172, 8.154 |
| base-load | 16571, 15049, 15175 | 66, 70, 11 | 6.25, 5.01, 7.47 | 0.02, 0.02, 0.14 | 4.525, 4.525, 4.526 |

All 18 context proofs have zero major faults. Minor first-touch/allocation faults and aggregate system CPU generally fall sharply on a warm proof. Node residency raises retained RAM, but does not produce a persistent threefold proof-time increase: first-proof minima are 2.462171 s with fresh base setup, 2.613822 s with node setup retained, and 2.586828 s with the loaded base key. These measurements support a first-touch/allocation cost; they do not identify one particular allocator policy or NUMA mechanism.

Scheduling is independently material even without a node setup: SHA wallet trial 1 took 5.278719 s (4.889917 s proving), with 29.927012 aggregate thread-seconds of runnable scheduler wait, 274,934 minor faults, and 31.694596 thread CPU seconds. Trial 2 took 3.066193 s (2.777173 s proving), with 0.434599 scheduler-wait seconds, 76,330 minor faults, and 26.702870 thread CPU seconds. The scheduler counter measures time runnable threads could not run; it excludes waiting at a prover barrier and cannot be interpreted as a directly subtractable wall-time duration. Outside processes with overlapping affinity were observed separately; the data do not assign the delay to a specific outside PID.

**Cause conclusion:** there is one base proof, not duplicated proving work. Current variability has measured first-touch/allocation and runnable scheduling components. The matched experiments do not support recursive setup residency as the cause of a fixed 3x gap. The exact cause of the historical 6.389773 s run remains unconfirmed because that run did not record these counters. It would be incorrect to report a specific historical mechanism as established or to use that old singleton as a denominator for the new client mode.

### Batch12 continuation and gates

The parallel read-only audit completed independently while the client work ran. It verified 48 existing receipts, their source-stability manifests and every stdout/stderr hash. Batch12 already completed three paired repetitions per workload and release tests, doctests, and clippy with warnings denied. Its historical sequence was AB, BA, AB (A1 B1 B2 A2 A3 B3), rather than the subsequently requested strict ABABAB screen. No new candidate screen was performed here. Future screens retain the explicit ABABAB rule and minimum of three.

**Batch12 remains rejected.** The historical isolated-harness minimum-of-three time to mempool-ready proof was control/candidate 0.113200/0.119966 s for BLAKE2s 64 B (+5.98%), 1.257287/1.259528 s for BLAKE2s 1 KiB (+0.18%), and 2.604769/2.677908 s for SHA256 (+2.81%). Its preliminary negative percentages did not hold. These are matched historical screen results, not comparisons against the loaded-key matrix. Do not integrate removed provisional commit 0a137ef5. Evidence: `artifacts/D-batch12-independent-audit.md`.

### Reproducibility and validation

All 58 runtime receipts passed, with unchanged source manifests, verified stdout/stderr hashes, successful affinity/build guards, and separately verified certificates. Machine-readable full phases, hashes, shapes, samples and resource counters: `artifacts/D-wallet-mode-summary.json`. Independent recomputation: `artifacts/D-summarize-wallet-mode.py`. Run sequence/logs: `D-run-wallet-mode.py/.log` and `D-repeat-wallet-mode.py/.log`. Release build receipt: `D-client-cache-build-t3`; frozen executable hashes: `artifacts/D-wallet-binaries-before-gates.json`. Frozen executables: `artifacts/D-wallet-application_client` and `artifacts/D-wallet-client_context_probe`. Keys: `artifacts/D-client-keys`; certificates: `artifacts/D-wallet-certificates`. Every runtime has its own `-guard.json`.

- `D-wallet-fmt-t2`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo fmt --all -- --check`.
- `D-wallet-cache-test-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion --features trusted-key-cache --example application_client`.
- `D-wallet-release-tests-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion -p pcs -p rec_aggregation --features format_recursion/trusted-key-cache`.
- `D-wallet-clippy-t2`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo clippy --locked --release -p format_recursion -p pcs -p rec_aggregation --all-targets --features format_recursion/trusted-key-cache -- -D warnings`.
- `D-wallet-default-check-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo check --locked --release -p format_recursion -p pcs -p rec_aggregation --all-targets`.

The cache roundtrip test preserves exact proof encoding, base root and shape and checks rejection of changed outputs and proof data. The example suite passed 2 tests; the feature-enabled release suites passed 79 format_recursion, 44 pcs and 43 rec_aggregation tests, with 6 existing manual tests ignored and zero failures. Doctests passed. Clippy covers their targets with warnings denied. A separate default-feature release check covers those targets without enabling cache support. No Lean sources were edited. All builds and tests ran after the final client measurement.

The initial clippy receipt D-wallet-clippy-t1 failed on the diagnostic probe not reading its witness-report field. The probe now emits that report before its proof timers, and D-wallet-clippy-t2 passes. This is an output-only diagnostic change after measurements; its exact measured source is archived as artifacts/D-wallet-client_context_probe-measured.rs. The wallet executable and all library/prover sources used for the completed measurements and release tests are unchanged by this fix. The failed receipt is retained.

Implementation committed locally on lane/D as `e00d34b484a9bd610f00d6332c840eca4353c621` (parent accepted backend a96334fb). Worktree is clean. No push. This commit adds the client measurement path and cache support; batch12 is excluded.


## Rate diagnostic disposition, user decision

**declined by user: +27% proof size**. JOINT_LOG_INV_RATE remains 2 (rate 1/4). The throwaway diagnostic is closed; no further rate runs or optimization commit. The interrupted D-rateprobe-merge-blake2s-64b-A-t2 receipt remains incomplete and is not reused. Prior completed measurements remain archived as diagnostic evidence.
