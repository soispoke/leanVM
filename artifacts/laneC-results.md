# Lane C: WALLET time to mempool-ready proof

Snapshot: `8db3aaa7`, from lane A's dirty tree based on `ab39e040`. No pushes. All builds and measurements use CPUs 24-35, CARGO_BUILD_JOBS=12, RAYON_NUM_THREADS=12, LEANVM_NUM_THREADS=12. Historical timings are single development screens; BLAKE2s 64 B and the completed native boundary screens are superseded by the ABAB medians below. Receipts are `C-*` under the parent workspace, using Yukon `2e90b37`.

## Repeated boundary screen: native SHA256 1 KiB

Three ABAB blocks, six samples per policy, CPUs 24-35, 12 threads, seed 20261024. A is complete-output control; B trims unused outputs. The full split `prove_base` path and serialized certificates are measured. Each timing sample has a separate wallet-only resource process; its certificate must match the full split certificate byte-for-byte. The one invalid resource receipt `C-boundary-sha1k-b3-A1-resources-t1` is excluded: the shared administrative plan JSON changed while the process ran, with all lane-C code unchanged. Its replacement is `...-t2`. Subsequent receipts use frozen `artifacts/laneC-run-plan.json`. Completed valid timing samples were preserved.

|Role and metric|A control|B trimmed|
|---|---:|---:|
|WALLET time to mempool-ready proof, median [min, max] ms|3464.58 [3172.11, 3806.26]|1805.42 [1779.22, 1963.59]|
|WALLET witness ms|367.30|203.91|
|WALLET proof bytes|347,036|323,836|
|WALLET transaction peak RSS KiB|7,613,130|4,070,106|
|WALLET transaction start RSS KiB|3,142,568|1,734,666|
|WALLET additional transaction peak RSS KiB|4,475,976|2,336,046|
|MEMPOOL NODE native verification ms|8.06|7.07|
|ONE-TIME setup wallet key ms|2774.15|1923.83|

Native WALLET median time to mempool-ready proof falls 47.9%, with non-overlapping sample ranges. Native ONE-TIME setup padded arithmetic log rows fall 22 → 21. The trimmed proof uses 23,200 fewer WALLET bytes. RSS includes the wallet base key and retained allocator pages, with the setup high-water mark reset before the transaction; it never includes an aggregator node key. ONE-TIME wallet key setup is reported separately and is never added to transaction time. **Shape change:** this is a validated opt-in candidate for native SHA256; production defaults remain unchanged pending the requested sign-off. **Quotient paths:** ONE-TIME setup padded rows stay at 2²⁰, and WALLET computation/bytes are unaffected by the native flag; no quotient A/B timing delta was measured. Raw samples: `artifacts/laneC-boundary-abab.json`; summary: `artifacts/laneC-boundary-sha1k-summary.json`. AGGREGATOR merges remain outside this screen.

## Repeated boundary screen: native Keccak 1 KiB

Three ABAB blocks, six samples per policy, CPUs 24-35, 12 threads, seed 20261024. A is complete-output control; B trims unused outputs. The measured roles and certificate identity checks match the SHA256 screen.

|Role and metric|A control|B trimmed|
|---|---:|---:|
|WALLET time to mempool-ready proof, median [min, max] ms|3265.80 [3201.97, 3471.07]|1668.75 [1624.55, 1804.40]|
|WALLET witness ms|329.22|208.23|
|WALLET proof bytes|346,652|324,060|
|WALLET transaction peak RSS KiB|7,952,854|4,081,896|
|WALLET transaction start RSS KiB|3,319,166|1,740,592|
|WALLET additional transaction peak RSS KiB|4,634,132|2,342,074|
|MEMPOOL NODE native verification ms|6.48|6.66|
|ONE-TIME setup wallet key ms|11881.13|10470.32|

Native WALLET median time to mempool-ready proof falls 48.9%, with non-overlapping sample ranges. Native ONE-TIME setup padded arithmetic log rows fall 22 → 21. The trimmed proof uses 22,592 fewer WALLET bytes. No MEMPOOL NODE verification speedup is established in this development screen (medians 6.48 → 6.66 ms, ranges overlap). The native flag does not alter quotient rows or claims: quotient padded rows stay at 2²⁰, so no leanPCS or leanR1CS-via-leanVM WALLET improvement is claimed. Full samples: `artifacts/laneC-boundary-abab.json`; summary: `artifacts/laneC-boundary-keccak1k-summary.json`. AGGREGATOR merges remain outside this compiler screen.

## Cross-path result: quotient proofs and native trimming

The unused-output candidate acts only in `native_application_support::Application::create`, after `circuit_suite::build` constructs the shared Boolean circuit. Native lowering emits independent equations for a full adder's sum and carry. The quotient backend uses one full-adder row for both outputs. Its circuit rows, wiring, index, witness construction, prover parameters, PCS openings and verifier are unchanged by this flag. Thus the native SHA256/Keccak padding wins do **not** apply to leanPCS or leanR1CS via leanVM. No quotient WALLET speedup is claimed, and no independent A/B timing is fabricated for these identical quotient computations.

The new frozen `C-quotient-census-all-t1` screen runs circuit wiring validation and records the complete description hash for each workload on CPUs 24-35 with 12 threads. All following row metrics are **ONE-TIME setup** metadata. “Cut needed” is used rows minus the next lower padded capacity; the after column applies the native trimming candidate. Whole-row DCE is an analysis-only opportunity, not an implemented pass.

|Workload|ONE-TIME setup quotient used rows|ONE-TIME setup quotient padded log rows, before → after|ONE-TIME setup cut needed for next lower boundary|ONE-TIME setup wholly dead non-input rows|ONE-TIME setup hypothetical whole-row DCE padded log|
|---|---:|---:|---:|---:|---:|
|blake2s-64b|31,228|15 → 15|14,844|0|15|
|blake2s-1kib|502,762|19 → 19|240,618|0|19|
|sha256-1kib|615,220|20 → 20|90,932|0|20|
|keccak256-1KiB|1,003,539|20 → 20|479,251|0|20|
|shielded-transfer|3,700,667|22 → 22|1,603,515|0|22|
|falcon512|4,019,906|22 → 22|1,922,754|1,664|22|
|mpt-storage-proof|8,379,278|23 → 23|4,184,974|3,714|23|

Quotient SHA256 needs 90,932 shared Boolean rows removed to reach 2¹⁹, and has no wholly dead rows under this conservative backward analysis. Native trimming removes arithmetic output equations, not those full-adder rows. Falcon has 1,664 wholly dead non-input rows and MPT has 3,714; removing them alone crosses no quotient boundary. A shared optimization must rewrite the Boolean circuit (for example a separately validated adder-chain rewrite). This lane rejects whole-row DCE as the next performance candidate on the census evidence; no circuit or protocol rewrite is accepted here.

Historical context below comes from `experiments/pcs-r1cs/evidence/2026-10-22-full`: medians of three, 16 threads on CPUs 0-15. These are **WALLET historical client-stage sums** (witness + quotient PIOP + all openings), not newly measured complete time to mempool-ready proof: the archived timer does not include the independent reference check or final serialization. They must not be treated as a matched comparison with current 12-thread native screens. PCS uses a Keccak proof transcript; R1CS-via-leanVM uses BLAKE2s. Application hashes are unchanged.

|Workload|WALLET historical quotient client stages ms, PCS / R1CS-via-leanVM|MEMPOOL NODE historical native verification ms, PCS / R1CS-via-leanVM|WALLET quotient effect of native trimming|
|---|---:|---:|---|
|blake2s-64b|not in archived full matrix|not in archived full matrix|unchanged work; paired timing delta not measured|
|blake2s-1kib|911.56 / 887.10|8.21 / 8.18|unchanged work; paired timing delta not measured|
|sha256-1kib|1596.04 / 1662.32|8.71 / 8.66|unchanged work; paired timing delta not measured|
|keccak256-1KiB|1615.15 / 1667.84|8.78 / 9.03|unchanged work; paired timing delta not measured|
|shielded-transfer|6513.26 / 6602.36|9.79 / 10.09|unchanged work; paired timing delta not measured|
|falcon512|6560.01 / 6620.98|9.86 / 9.32|unchanged work; paired timing delta not measured|
|mpt-storage-proof|14268.35 / 14345.74|9.98 / 10.02|unchanged work; paired timing delta not measured|

**WALLET quotient proof bytes:** the native trimming flag changes neither quotient proof parameters nor transport. These archived raw samples do not record the serialized wallet proof transport size; aggregator transport bytes and EVM calldata bytes are different metrics and are not substituted. No newly measured quotient byte value or RAM value is claimed. **ONE-TIME setup:** quotient key construction is unaffected. **AGGREGATOR:** quotient claims/openings are unaffected; no merge timing improvement is claimed. Native WALLET proof bytes and MEMPOOL NODE verification changes remain in the native tables below. Native ONE-TIME wallet key setup changes are reported separately for each repeated candidate.

Machine-readable results and exact historical source paths: `artifacts/laneC-quotient-census.json` and `artifacts/laneC-quotient-effects.json`. The current native candidate therefore helps path 3 only; it gives no demonstrated improvement for leanPCS or leanR1CS via leanVM.

## Metric roles and BLAKE2s 64 B ABAB confirmation

Every metric uses these role labels: WALLET is per transaction (witness plus the one proof sent, serialized bytes, transaction RAM); MEMPOOL NODE is native verification ms; AGGREGATOR is node merging; ONE-TIME setup is per-application key construction and static circuit metadata. ONE-TIME setup is never added to WALLET transaction latency. Historical values below retain this same role mapping. This lane does not report AGGREGATOR timing in the ABAB screen.

The earlier WALLET 363 ms control versus 157 ms trimmed pair is noisy single-run evidence and is superseded for decisions by the ABAB confirmation below. Three ABAB blocks, six fresh-process samples per policy, completed on CPUs 24-35 with 12 threads. A is complete-output control and B is trimmed. Each WALLET transaction uses the same input seed. The WALLET timing path is the reconciled split base proof. ONE-TIME setup wallet key construction and WALLET RAM use a separate base-key-only process that never constructs a node key; its certificate must match the timed WALLET certificate byte-for-byte. Linux RSS high-water is reset immediately before witness creation, so the prior ONE-TIME setup memory peak is excluded from the WALLET transaction peak. The retained wallet key and allocator-resident pages at transaction start are reported as the WALLET RAM baseline.

ABAB result (three ABAB blocks, six fresh-process samples per policy):

|Policy|WALLET time to mempool-ready proof, median [min, max] ms|WALLET witness ms|WALLET proof ms|WALLET proof bytes|WALLET transaction RAM additional peak KiB|MEMPOOL NODE native verify ms|ONE-TIME setup wallet key ms|ONE-TIME setup peak RSS KiB|
|---|---:|---:|---:|---:|---:|---:|---:|---:|
|A control|143.80 [127.58, 161.17]|7.90|135.27|247,956|134,710|4.99|99.63|190,844|
|B trimmed|141.75 [128.62, 169.29]|6.00|136.09|250,500|149,432|6.16|84.07|180,826|

|Policy|WALLET transaction start RSS KiB|WALLET transaction peak RSS KiB|WALLET additional peak RSS KiB|
|---|---:|---:|---:|
|A control|190,844|325,346|134,710|
|B trimmed|180,826|330,108|149,432|

WALLET RAM rows are medians from the separate wallet-only processes. They include the resident wallet base key and allocator pages, exclude the aggregator node key, and exclude the earlier ONE-TIME setup high-water mark. Additional peak is measured per sample above transaction start. It is RSS, not allocated-byte accounting or a claim about other wallet implementations. ONE-TIME setup wallet key time includes circuit construction, canonical witness and base-key construction; it excludes runtime initialization and every transaction. The split-key preprocessing measurement is separately tagged ONE-TIME setup and is not the wallet-only key figure.

**Decision:** BLAKE2s 64 B trimming is not an accepted optimization from this ABAB screen. WALLET median time improves only 2.04 ms (1.4%), ranges overlap, WALLET proof bytes increase 2,544 B, WALLET transaction RAM increases 14,722 KiB, and MEMPOOL NODE median verification increases 1.16 ms. ONE-TIME wallet key setup is separate and falls by 15.56 ms in this sample; it is never added to WALLET transaction time. The full per-sample records and receipt names are in `artifacts/laneC-abab.json`; summaries are in `artifacts/laneC-abab-summary.json`.


## Role labels for the padding census

The padding census is ONE-TIME shape evidence. Its rows, padded log rows and boundary margins predict proof-shape classes; they are not WALLET transaction timings. The timing table reports WALLET, MEMPOOL NODE and ONE-TIME setup roles explicitly. AGGREGATOR timings are outside this compiler lane and remain owned by lane E.

## Proof-path reconciliation

The quoted 1.431 s BLAKE2s 1 KiB value is the historical `C-rows-blake1k-control-t1` backend-only screen, not the headline wallet metric. It used direct `private_recursion::Setup::prove`, so it was removed from the headline ranking. The current split-closure screen uses `SplitClosedSetup::from_program` and `SplitClosedSetup::prove_base`; the same-tree control measured 1.634 s certificate creation plus 0.207 s witness, 1.841 s time to mempool-ready proof.

The real `application_tree` path on the same lane-C tree and same seed emitted the same base shape, base key, node key, statement and exact 323,356-byte certificate. The compiler certificate and application_tree certificate are byte-for-byte identical, SHA-256 `cc53c0753eac137d2c18f05dad97836a64e8e15016c3edbdd6920106eb9188e4`. An archived lane-A certificate is identical too. Both paths therefore include the same split base proof: private arithmetic witness, joint WHIR commitment, arithmetic and hash reductions, joint opening and index opening, with the same minimum padding (`n_blocks=39`, `block_log=7`, base shape log rows 21). The independent application_tree verification receipt passed.

Lane D's 2.549 s and lane A's 1.520 s are different wall-time samples on different CPU slices and process workloads. The reconciled same-tree calls are 1.634 s (`compiler_rows`) and 1.650 s (`application_tree` leaf 0), with the identical output; this comparison establishes proof-path identity, not the cause of the cross-lane timing spread. Timer boundaries differ slightly: application_tree includes an additional preflight `trace.satisfied()` before prove_base, which also checks satisfaction internally; compiler_rows includes certificate serialization in its proof timer, whereas application_tree reports serialization separately from that timer. Both execute the full same proof path. No cause is assigned to the cross-lane wall-time spread from these single samples. The proof-path identity and output-byte identity are established in `artifacts/laneC-reconciliation.json`. Do not use the historical 1.431 s value for time to mempool-ready proof.

## Headline: WALLET time to mempool-ready proof

The headline metric is witness construction plus creation and serialization of the one base certificate the wallet sends. Mempool nodes verify it natively, and aggregators merge that certificate as-is. Per-relation setup is preprocessing and is excluded. Witness time includes instance construction and independent reference/Boolean evaluation, not just trace recording. Report certificate bytes and native verification ms alongside this metric. Rank candidate policies by the change in time to mempool-ready proof; arithmetic rows are supporting diagnostics.

<!-- mempool-table-start -->
|Rank|Workload|WALLET control time to mempool-ready proof ms|WALLET trimmed time to mempool-ready proof ms|WALLET change|WALLET control / trimmed proof bytes|MEMPOOL NODE control / trimmed native verification ms|
|---:|---|---:|---:|---:|---:|---:|
|1|sha256-1kib (ABAB medians)|3464.58|1805.42|-1659.16 ms (-47.9%)|347,036 / 323,836|8.06 / 7.07|
|2|keccak256-1KiB (ABAB medians)|3265.80|1668.75|-1597.05 ms (-48.9%)|346,652 / 324,060|6.48 / 6.66|
|3|falcon512|13713.04|13153.26|-559.77 ms (-4.1%)|384,756 / 384,596|8.65 / 6.27|
|4|blake2s-1kib|1936.10|1834.82|-101.28 ms (-5.2%)|323,356 / 324,124|9.90 / 6.64|
|5|blake2s-64b (ABAB medians)|143.80|141.75|-2.04 ms (-1.4%; not accepted)|247,956 / 250,500|4.99 / 6.16|
|6|shielded-transfer|13243.01|13476.35|+233.34 ms (+1.8%)|385,204 / 384,660|6.76 / 6.61|
| |mpt-storage-proof|unavailable|13704.73|unranked|unavailable / 386,356|unavailable / 6.06|

Ranking is by absolute change in time to mempool-ready proof (most time saved first), within each matched workload pair. It does not compare unlike workload latencies as optimization wins. Rows and backend-only proof timings are supporting evidence. BLAKE2s 64 B, SHA256 and Keccak use six samples per policy from three ABAB blocks; other workload figures remain single runs. CPUs 24-35, 12 threads, seed 20261024. MPT default already trims and its complete-output proof is infeasible. All feasible matched pairs are complete; all generated wallet certificates passed native verification.

## Padding census and boundary priority

Bridge shape uses `blocks = next_power_of_two(max(actual hash blocks, 128))`, six connector rows per padded block, public-prefix alignment, and an arithmetic floor of 8,192 rows. For these workloads, actual hash blocks are 39, so the 128-block minimum binds every row census; the 8,192 arithmetic floor binds none. The table reports index gate rows excluding the 256-row public prefix, then padded index log rows. The lower-bound margin includes the public prefix and connector alignment.

|Workload|Gate rows excluding public prefix, control → trimmed|Padded log rows, control → trimmed|Index rows above next lower boundary (including public), control → trimmed|Crosses boundary?|
|---|---:|---:|---:|---|
|sha256-1kib|2,114,176 → 1,762,048|22 → 21|17,280 → 713,728|yes|
|keccak256-1KiB|3,316,608 → 1,897,984|22 → 21|1,219,712 → 849,664|yes|
|mpt-storage-proof|26,640,128 → 15,002,624|25 → 24|9,863,168 → 6,614,272|yes|
|blake2s-64b|120,960 → 109,696|17 → 17|55,680 → 44,416|no|
|blake2s-1kib|1,437,312 → 1,252,352|21 → 21|388,992 → 204,032|no|
|shielded-transfer|12,378,752 → 10,248,832|24 → 24|3,990,400 → 1,860,480|no|
|falcon512|11,961,088 → 8,798,976|24 → 24|3,572,736 → 410,624|no|


SHA256 is the highest-value crossing: trimming removes enough gates to move from 2²² to 2²¹ padded rows. Keccak also crosses 2²² to 2²¹. MPT crosses 2²⁵ to 2²⁴ and is already trimmed by the production large-circuit policy. BLAKE2s 64 B, BLAKE2s 1 KiB, shielded and Falcon remain in their existing padded classes. The exact per-workload margins, public prefix, alignment, minimum hash-block padding and counterfactual block-floor check are in `artifacts/laneC-padding.json`; the census receipt is `C-padding-census-t2`.

The reported SHA256 17,024-gate excess is correct when counting gate rows alone. Adding the public prefix makes its exact excess 17,280 index rows; accounting for alignment means a minimum cut of 17,200 compiler rows suffices to cross. Full trimming cuts 352,116 compiler rows. After trimming, Falcon is the nearest remaining lower-boundary opportunity: another 410,591 compiler rows would be required to reach 2²³ padded rows. This is a target, not an implemented optimization.

Checking the minimum hash padding without changing it: 39 useful blocks would round to 64 rather than 128 if the floor were removed. The bridge would save 384 connector rows plus at most one alignment chunk. This changes neither the padded arithmetic log nor the joint-stack log for any of these workloads. For SHA256 control it would still need 2²² arithmetic rows, so reducing the hash floor alone cannot cross the targeted boundary. The 8,192-row arithmetic floor is far below even the smallest workload and provides no opportunity here. No minimum, WHIR configuration or verifier check has been changed; validating a lower hash floor belongs with lane D's prover/PCS work.

Reusing the already measured, reconciled wallet path rather than repeating completed runs: SHA256 time to mempool-ready proof was 3,362.06 → 2,064.20 ms (38.6% lower), proof bytes 347,036 → 323,836, native verification 5.86 → 5.80 ms. Keccak was 4,093.24 → 1,885.49 ms (53.9% lower), proof bytes 346,652 → 324,060, native verification 6.14 → 5.76 ms. These are the existing single-run `C-mempool-sha1k-*` and `C-mempool-keccak1k-*` receipts through the proven-identical split base path. Halving a padded dimension does not guarantee halving total wallet latency because witness construction and other proof stages remain. All candidate defaults still require the requested shape-change sign-off.

The census reuses frozen lowering results and validates all 13 available actual base shapes against their measured connector position, block log and padded arithmetic log. The untrimmed MPT 2²⁵ entry is a theoretical census shape above the backend cap, not a working key or proof. `C-padding-census-t2` passed with frozen source. No Rust or Lean proof code was edited in this census update.

The client-path timing table above is the decision evidence for boundary candidates. SHA256 and Keccak are the first candidates for user sign-off because their trimmed policies cross a power-of-two proof-shape boundary. This priority is independent of raw row reduction.

## Candidate 1: unused full-adder output trimming everywhere

Status: experimental explicit override only. Production default still trims only relations with Boolean log rows >=23. Enabling this for smaller workloads changes circuit shapes and may change proof sizes. Integration as the default requires explicit user sign-off. The research override is selected from the fixed circuit and never from witness values.

Soundness argument: free inputs retain b*b=b constraints. Each retained sum is x+y+c over characteristic two and each retained carry is x*y+c*(x+y). Boolean inputs imply Boolean retained outputs by induction. Backward reachability starts at all public output bits and marks all operands of every retained output, including both sum and carry source components. Only components outside this dependency closure are omitted. Public packing, hash constraints, checks and verifier logic are unchanged. This is an equivalence argument for the compiler pass, not a new formal security proof.

The regression test exhausts all eight assignments of a two-adder circuit, compares trimmed and control claims, checks fixed trace shape across assignments, rejects a wrong claim, and forges a non-Boolean free input while also forging the host acceptance check to ensure the actual arithmetic proof rejects it.

## Other candidates reviewed

The native application path packs only the 512 public statement bits and hashes a 96-byte relation/statement claim; application hash computations themselves are full-adder circuits. Therefore hash-input packing in this adapter is bounded overhead, not proportional to application hash count. Broad Boolean/range-check removal is not sound without a typing argument; retain free input constraints. Existing private lowering already fuses multiply/add pairs. No adder-chain rewrite is accepted without a separate soundness and equivalence screen.

## Historical backend-only screen

Matched native Setup proofs, seed 20261023. Control uses complete outputs; candidate trims all outputs outside the public dependency closure. These policy overrides are explicit; default MPT already trims. MPT complete-output control is census only because it exceeds the backend cap.

|Workload|ONE-TIME setup control rows|ONE-TIME setup trimmed rows|ONE-TIME setup row reduction|WALLET historical control proof ms|WALLET historical trimmed proof ms|
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

Lane A: cherry-pick the research commits after snapshot `8db3aaa7`, resolving research-helper conflicts with your current tree; do not cherry-pick the snapshot itself. This lane changes only native application support, adds compiler_rows, and records artifacts. It does not touch prover/PCS code, recursive merge code, or production policy defaults. No push was made.


## Wallet metric reporting update

`compiler_rows --prove` now measures the split-closure base certificate, with per-relation setup excluded. It measures the full `Application::create` call for the wallet witness, then `prove_base` plus certificate serialization, and reports their sum as time to mempool-ready proof. Mempool nodes verify this certificate natively, and aggregators merge it as-is. Verification timing is recorded separately. `artifacts/laneC-mempool.json` contains all witness/proof components, certificate bytes, native verification times and base shapes from the passing `C-mempool-*` receipts. The earlier backend-only screen remains preserved as historical compiler evidence, without using it to rank rollout candidates.

Using the historical single-run WALLET time to mempool-ready proof, the observed absolute savings were Keccak (2,207.75 ms) and SHA256 (1,297.87 ms), followed by Falcon (559.77 ms), BLAKE2s 64 B (206.08 ms), and BLAKE2s 1 KiB (101.28 ms). Shielded regressed by 233.34 ms. These are single-run development screens, not robust estimates. Both BLAKE2s candidates increased certificate bytes. The historical BLAKE2s 64 B timing claim above is superseded by ABAB: WALLET 143.80 → 141.75 ms, with no accepted win. Production defaults remain unchanged; WALLET default BLAKE2s 64 B measured 247,956 B, matching the required baseline. MPT already uses the trimmed policy, so it has no candidate-versus-default improvement claim.


The reporting-only harness update passed `C-mempool-tests-t1` (release compiler_rows example tests), `C-mempool-clippy-t1` (both packages, all targets, `-D warnings`), and `C-mempool-fmt-check-t1`. The previous full library/example release gate remains preserved; library and compiler-policy implementations were not changed by the reporting update. No pushes.


Reconciliation receipts: `C-reconcile-build-t1`, `C-reconcile-compiler-t1`, `C-reconcile-application-t1`, `C-reconcile-independent-verify-t1` (five saved certificates), `C-reconcile-clippy-t1` and `C-reconcile-fmt-check-t1` all passed with frozen sources. The only source update adds optional certificate export and key/hash reporting to the research tool. No proving implementation, parameter, verifier check or policy default changed.

The ABAB harness update passed `C-abab-tests-t1`, `C-abab-clippy-t1` and `C-abab-fmt-check-t1`. The native adder regression still rejects wrong claims and forged non-Boolean witnesses. No verifier checks, proof parameters or production defaults changed.

## Compiler-lane integration checkpoint

Local branch is `lane/C`; no pushes. The snapshot commit `8db3aaa7` must not be cherry-picked onto lane A. Research code through `73dc61d7` exposes explicit trimming overrides and measurements while preserving production policy defaults, proof parameters and every verifier check. The quotient census adds reporting only; no shared circuit, witness, prover, PCS or verifier implementation is changed. Whole-row DCE is rejected as a performance candidate because its tiny row savings cross no quotient padding boundary. Existing constant folding, repeated-add cancellation and multiply/add fusion already cover the simple redundant-constraint cases; no unverified adder-chain rewrite is introduced.

SHA256 and Keccak native output trimming are ready for the requested shape-change review based on six matched samples per policy for each. Their proof shapes change deliberately and remain opt-in. Quotient SHA256 and Keccak stay at 2²⁰ rows and have no measured improvement from this candidate. BLAKE2s 64 B trimming remains unaccepted because its repeated WALLET improvement is noise-sized with larger proofs/RAM. MPT already uses the large-circuit trim policy; the untrimmed MPT shape is above capacity, so there is no valid untrimmed proof-time control to repeat. Lane A owns default rollout and integration; the compiler lane does not change node merges or prover/PCS code.

## Final frozen boundary/census gates

`C-boundary-release-gates-t1`, `C-boundary-clippy-t1` and `C-boundary-fmt-check-t1` all passed on CPUs 24-35 with 12 threads. Release tests: format_recursion 79 passed; rec_aggregation 43 passed with its five existing ignored tests unchanged; all example tests passed, including non-Boolean forgery and cross-policy rejection. Clippy checked both packages and all targets with `-D warnings`. Formatting and `git diff --check` passed. No verifier check, proof parameter or policy default changed. No Lean proof source was edited.

`artifacts/laneC-boundary-audit.json` records 48 valid receipts for the 24 complete WALLET samples and their separate wallet-resource processes, verifies identical Rust hashes across all runs, checks deterministic certificate identity within each policy, and confirms wallet-only certificates equal full split `prove_base` certificates. Both SHA256 and Keccak improve in all six matched A→B pairs. The censused quotient circuits all pass wiring validation. New results remain opt-in research evidence for the explicit native shape-change decision; no automatic rollout or push was performed.

Integration order after the snapshot: `12d9f6d8` (research trim override, census and rejection tests), `df3d6dae` (complete WALLET metric), `b06e0de5` (path/byte reconciliation), `aa4fb157` (native padding census), `09ba5656` (BLAKE64 ABAB/resource harness), `73dc61d7` (role tags), followed by the boundary/quotient evidence commit. On lane A, preserve your newer prover changes and the existing large-circuit default when resolving helper conflicts. Enable SHA256/Keccak default trimming only after the requested user shape-change sign-off. BLAKE64 remains unchanged at 247,956 WALLET bytes by default. The row-count candidates do not alter quotient circuits or accelerate leanPCS/leanR1CS-via-leanVM.
