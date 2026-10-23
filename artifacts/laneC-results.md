# Lane C: time to mempool-ready proof

Snapshot: `8db3aaa7`, from lane A's dirty tree based on `ab39e040`. No pushes. All builds and measurements use CPUs 24-35, CARGO_BUILD_JOBS=12, RAYON_NUM_THREADS=12, LEANVM_NUM_THREADS=12. Timings are single development screens, not medians. Receipts are `C-*` under the parent workspace, using Yukon `2e90b37`.

## Proof-path reconciliation

The quoted 1.431 s BLAKE2s 1 KiB value is the historical `C-rows-blake1k-control-t1` backend-only screen, not the headline wallet metric. It used direct `private_recursion::Setup::prove`, so it was removed from the headline ranking. The current split-closure screen uses `SplitClosedSetup::from_program` and `SplitClosedSetup::prove_base`; the same-tree control measured 1.634 s certificate creation plus 0.207 s witness, 1.841 s time to mempool-ready proof.

The real `application_tree` path on the same lane-C tree and same seed emitted the same base shape, base key, node key, statement and exact 323,356-byte certificate. The compiler certificate and application_tree certificate are byte-for-byte identical, SHA-256 `cc53c0753eac137d2c18f05dad97836a64e8e15016c3edbdd6920106eb9188e4`. An archived lane-A certificate is identical too. Both paths therefore include the same split base proof: private arithmetic witness, joint WHIR commitment, arithmetic and hash reductions, joint opening and index opening, with the same minimum padding (`n_blocks=39`, `block_log=7`, base shape log rows 21). The independent application_tree verification receipt passed.

Lane D's 2.549 s and lane A's 1.520 s are different wall-time samples on different CPU slices and process workloads. The reconciled same-tree calls are 1.634 s (`compiler_rows`) and 1.650 s (`application_tree` leaf 0), with the identical output; this comparison establishes proof-path identity, not the cause of the cross-lane timing spread. Timer boundaries differ slightly: application_tree includes an additional preflight `trace.satisfied()` before prove_base, which also checks satisfaction internally; compiler_rows includes certificate serialization in its proof timer, whereas application_tree reports serialization separately from that timer. Both execute the full same proof path. No cause is assigned to the cross-lane wall-time spread from these single samples. The proof-path identity and output-byte identity are established in `artifacts/laneC-reconciliation.json`. Do not use the historical 1.431 s value for time to mempool-ready proof.

## Headline: time to mempool-ready proof

The headline metric is witness construction plus creation and serialization of the one base certificate the wallet sends. Mempool nodes verify it natively, and aggregators merge that certificate as-is. Per-relation setup is preprocessing and is excluded. Witness time includes instance construction and independent reference/Boolean evaluation, not just trace recording. Report certificate bytes and native verification ms alongside this metric. Rank candidate policies by the change in time to mempool-ready proof; arithmetic rows are supporting diagnostics.

<!-- mempool-table-start -->
|Rank|Workload|Control time to mempool-ready proof ms|Trimmed time to mempool-ready proof ms|Change|Control / trimmed proof bytes|Control / trimmed native verification ms|
|---:|---|---:|---:|---:|---:|---:|
|1|keccak256-1KiB|4093.24|1885.49|-2207.75 ms (-53.9%)|346,652 / 324,060|6.14 / 5.76|
|2|sha256-1kib|3362.06|2064.20|-1297.87 ms (-38.6%)|347,036 / 323,836|5.86 / 5.80|
|3|falcon512|13713.04|13153.26|-559.77 ms (-4.1%)|384,756 / 384,596|8.65 / 6.27|
|4|blake2s-64b|363.51|157.42|-206.08 ms (-56.7%)|247,956 / 250,500|7.44 / 7.24|
|5|blake2s-1kib|1936.10|1834.82|-101.28 ms (-5.2%)|323,356 / 324,124|9.90 / 6.64|
|6|shielded-transfer|13243.01|13476.35|+233.34 ms (+1.8%)|385,204 / 384,660|6.76 / 6.61|
| |mpt-storage-proof|unavailable|13704.73|unranked|unavailable / 386,356|unavailable / 6.06|

Ranking is by absolute change in time to mempool-ready proof (most time saved first), within each matched workload pair. It does not compare unlike workload latencies as optimization wins. Rows and backend-only proof timings are supporting evidence. One run per policy, CPUs 24-35, 12 threads, seed 20261024. MPT default already trims and its complete-output proof is infeasible. All feasible matched pairs are complete; all generated wallet certificates passed native verification.

## Candidate 1: unused full-adder output trimming everywhere

Status: experimental explicit override only. Production default still trims only relations with Boolean log rows >=23. Enabling this for smaller workloads changes circuit shapes and may change proof sizes. Integration as the default requires explicit user sign-off. The research override is selected from the fixed circuit and never from witness values.

Soundness argument: free inputs retain b*b=b constraints. Each retained sum is x+y+c over characteristic two and each retained carry is x*y+c*(x+y). Boolean inputs imply Boolean retained outputs by induction. Backward reachability starts at all public output bits and marks all operands of every retained output, including both sum and carry source components. Only components outside this dependency closure are omitted. Public packing, hash constraints, checks and verifier logic are unchanged. This is an equivalence argument for the compiler pass, not a new formal security proof.

The regression test exhausts all eight assignments of a two-adder circuit, compares trimmed and control claims, checks fixed trace shape across assignments, rejects a wrong claim, and forges a non-Boolean free input while also forging the host acceptance check to ensure the actual arithmetic proof rejects it.

## Other candidates reviewed

The native application path packs only the 512 public statement bits and hashes a 96-byte relation/statement claim; application hash computations themselves are full-adder circuits. Therefore hash-input packing in this adapter is bounded overhead, not proportional to application hash count. Broad Boolean/range-check removal is not sound without a typing argument; retain free input constraints. Existing private lowering already fuses multiply/add pairs. No adder-chain rewrite is accepted without a separate soundness and equivalence screen.

## Historical backend-only screen

Matched native Setup proofs, seed 20261023. Control uses complete outputs; candidate trims all outputs outside the public dependency closure. These policy overrides are explicit; default MPT already trims. MPT complete-output control is census only because it exceeds the backend cap.

|Workload|Control rows|Trimmed rows|Reduction|Control proof ms|Trim proof ms|
|---|---:|---:|---:|---:|---:|
|blake64|120,080|108,891|9.3%|126.619113|124.613715|
|blake1k|1,436,512|1,251,578|12.9%|1431.319984|1551.5967320000002|
|sha1k|2,113,328|1,761,212|16.7%|4977.059862|5215.658696|
|keccak1k|3,315,830|1,897,195|42.8%|6165.571500999999|3661.058998|
|shielded|12,377,903|10,248,052|17.2%|23306.577161|12240.314906|
|falcon|11,960,207|8,798,175|26.4%|11690.516485|11169.143587|
|mpt|26,639,333|15,001,840|43.7%|not run|11874.696319|

Full machine-readable gate census, omitted sums/carries (including padded/dead rows), Boolean free inputs, packing and checks are in each receipt stdout. There are no separate adapter range-check nodes; Boolean inputs retain one check each. Packing lowering can add range constraints, so this does not claim the lowered circuit contains no range constraints. All adapter traces have four public pack nodes and one claim hash, lowered to 39 compression blocks.

## Decision and integration guidance

Rank rollout candidates using the headline time to mempool-ready proof table. The historical backend-only screen is not the decision metric: its BLAKE2s 1 KiB and SHA256 1 KiB regressions did not carry over to the actual wallet-certificate runs. Do not enable trimming globally from one development screen. Account for proof-byte changes alongside latency wins, and obtain the requested sign-off for shape changes. MPT already uses lane A's trimmed policy and has no feasible complete-output proof control.

The candidate is exposed only through the research example's `--trim` flag. The existing `Application::new()` policy is unchanged, so existing default trace shapes and certificate formats are unchanged by this lane. A default policy change for Keccak/shielded, or for all relations, explicitly changes those relations' circuit shapes and requires the requested user sign-off. Actual encoded wallet-certificate bytes for both policies are reported in the headline table. Native verification measures the decoded certificate check; transport decoding is excluded.

Reproduce a matched pair with the pinned runner and the same CPU/thread environment: build `cargo build --release -p format_recursion --example compiler_rows`, then run `target/release/examples/compiler_rows keccak1k --prove` and `target/release/examples/compiler_rows keccak1k --trim --prove`. Workload names are blake64, blake1k, sha1k, keccak1k, shielded, falcon and mpt. For MPT omit `--prove` from the complete-output control. `artifacts/laneC-census.json` preserves every measured gate count and proof timing with its receipt name.

Build receipts t1/t2 and the mutating format receipt are not release gates: source edits overlapped those initial builds, and formatting intentionally changed source. Frozen build t3 and all completed row screens passed their receipt checks. Release gate results follow below.


## Release gates

All frozen release receipts passed on CPUs 24-35 with 12 threads: `C-release-gates-t1` (`cargo test --release -p format_recursion -p rec_aggregation --lib --examples`), `C-clippy-t1` (`cargo clippy --release -p format_recursion -p rec_aggregation --all-targets -- -D warnings`), and `C-fmt-check-t1` (`cargo fmt --all -- --check`). Format recursion: 79 library tests passed. Rec aggregation: 43 library tests passed, five existing ignored tests remained ignored. Example tests also passed, including the native compiler regression in both application_tree and compiler_rows. No tests or verifier checks were relaxed. `git diff --check` passed. No Lean proof files were edited.

The enhanced compiler regression checks that a trimmed proof is rejected by a complete-output setup and that the trimmed setup rejects a complete-output trace, even though both policies produce the same application claim. It also verifies fixed program identity across all eight input assignments for both policies. Exact receipt hashes and gate commands are preserved in `artifacts/laneC-gates.json`.

Lane A: cherry-pick only the compiler screen commit on top of your current tree, not snapshot `8db3aaa7`. This lane changes only native application support, adds compiler_rows, and records artifacts. It does not touch prover/PCS code, recursive merge code, or production policy defaults. No push was made.


## Wallet metric reporting update

`compiler_rows --prove` now measures the split-closure base certificate, with per-relation setup excluded. It measures the full `Application::create` call for the wallet witness, then `prove_base` plus certificate serialization, and reports their sum as time to mempool-ready proof. Mempool nodes verify this certificate natively, and aggregators merge it as-is. Verification timing is recorded separately. `artifacts/laneC-mempool.json` contains all witness/proof components, certificate bytes, native verification times and base shapes from the passing `C-mempool-*` receipts. The earlier backend-only screen remains preserved as historical compiler evidence, without using it to rank rollout candidates.

Using time to mempool-ready proof, the strongest absolute savings were Keccak (2,207.75 ms) and SHA256 (1,297.87 ms), followed by Falcon (559.77 ms), BLAKE2s 64 B (206.08 ms), and BLAKE2s 1 KiB (101.28 ms). Shielded regressed by 233.34 ms. These are single-run development screens, not robust estimates. Both BLAKE2s candidates increased certificate bytes. Production defaults remain unchanged; default BLAKE2s 64 B measured 247,956 B, matching the required baseline. MPT already uses the trimmed policy, so it has no candidate-versus-default improvement claim.


The reporting-only harness update passed `C-mempool-tests-t1` (release compiler_rows example tests), `C-mempool-clippy-t1` (both packages, all targets, `-D warnings`), and `C-mempool-fmt-check-t1`. The previous full library/example release gate remains preserved; library and compiler-policy implementations were not changed by the reporting update. No pushes.


Reconciliation receipts: `C-reconcile-build-t1`, `C-reconcile-compiler-t1`, `C-reconcile-application-t1`, `C-reconcile-independent-verify-t1` (five saved certificates), `C-reconcile-clippy-t1` and `C-reconcile-fmt-check-t1` all passed with frozen sources. The only source update adds optional certificate export and key/hash reporting to the research tool. No proving implementation, parameter, verifier check or policy default changed.
