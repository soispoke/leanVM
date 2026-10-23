# Lane C compiler row screens

Snapshot: `8db3aaa7`, from lane A's dirty tree based on `ab39e040`. No pushes. All builds and measurements use CPUs 24-35, CARGO_BUILD_JOBS=12, RAYON_NUM_THREADS=12, LEANVM_NUM_THREADS=12. Timings are single development screens, not medians. Receipts are `C-*` under the parent workspace, using Yukon `2e90b37`.

## Candidate 1: unused full-adder output trimming everywhere

Status: experimental explicit override only. Production default still trims only relations with Boolean log rows >=23. Enabling this for smaller workloads changes circuit shapes and may change proof sizes. Integration as the default requires explicit user sign-off. The research override is selected from the fixed circuit and never from witness values.

Soundness argument: free inputs retain b*b=b constraints. Each retained sum is x+y+c over characteristic two and each retained carry is x*y+c*(x+y). Boolean inputs imply Boolean retained outputs by induction. Backward reachability starts at all public output bits and marks all operands of every retained output, including both sum and carry source components. Only components outside this dependency closure are omitted. Public packing, hash constraints, checks and verifier logic are unchanged. This is an equivalence argument for the compiler pass, not a new formal security proof.

The regression test exhausts all eight assignments of a two-adder circuit, compares trimmed and control claims, checks fixed trace shape across assignments, rejects a wrong claim, and forges a non-Boolean free input while also forging the host acceptance check to ensure the actual arithmetic proof rejects it.

## Other candidates reviewed

The native application path packs only the 512 public statement bits and hashes a 96-byte relation/statement claim; application hash computations themselves are full-adder circuits. Therefore hash-input packing in this adapter is bounded overhead, not proportional to application hash count. Broad Boolean/range-check removal is not sound without a typing argument; retain free input constraints. Existing private lowering already fuses multiply/add pairs. No adder-chain rewrite is accepted without a separate soundness and equivalence screen.

## Measurements

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

Do not enable trimming globally from this screen. BLAKE2s 1 KiB and SHA256 1 KiB lost proving time despite lower arithmetic row counts. Keccak and shielded showed the strongest matched wins; Falcon showed a smaller win; BLAKE2s 64 B was nearly flat. Any timing conclusion remains limited to one development run. MPT already uses lane A's trimmed policy and has no feasible complete-output proof control.

The candidate is exposed only through the research example's `--trim` flag. The existing `Application::new()` policy is unchanged, so existing default trace shapes and certificate formats are unchanged by this lane. A default policy change for Keccak/shielded, or for all relations, explicitly changes those relations' circuit shapes and requires the requested user sign-off. No new certificate byte-size claim is made for the research override.

Reproduce a matched pair with the pinned runner and the same CPU/thread environment: build `cargo build --release -p format_recursion --example compiler_rows`, then run `target/release/examples/compiler_rows keccak1k --prove` and `target/release/examples/compiler_rows keccak1k --trim --prove`. Workload names are blake64, blake1k, sha1k, keccak1k, shielded, falcon and mpt. For MPT omit `--prove` from the complete-output control. `artifacts/laneC-census.json` preserves every measured gate count and proof timing with its receipt name.

Build receipts t1/t2 and the mutating format receipt are not release gates: source edits overlapped those initial builds, and formatting intentionally changed source. Frozen build t3 and all completed row screens passed their receipt checks. Release gate results follow below.


## Release gates

All frozen release receipts passed on CPUs 24-35 with 12 threads: `C-release-gates-t1` (`cargo test --release -p format_recursion -p rec_aggregation --lib --examples`), `C-clippy-t1` (`cargo clippy --release -p format_recursion -p rec_aggregation --all-targets -- -D warnings`), and `C-fmt-check-t1` (`cargo fmt --all -- --check`). Format recursion: 79 library tests passed. Rec aggregation: 43 library tests passed, five existing ignored tests remained ignored. Example tests also passed, including the native compiler regression in both application_tree and compiler_rows. No tests or verifier checks were relaxed. `git diff --check` passed. No Lean proof files were edited.

The enhanced compiler regression checks that a trimmed proof is rejected by a complete-output setup and that the trimmed setup rejects a complete-output trace, even though both policies produce the same application claim. It also verifies fixed program identity across all eight input assignments for both policies. Exact receipt hashes and gate commands are preserved in `artifacts/laneC-gates.json`.

Lane A: cherry-pick only the compiler screen commit on top of your current tree, not snapshot `8db3aaa7`. This lane changes only native application support, adds compiler_rows, and records artifacts. It does not touch prover/PCS code, recursive merge code, or production policy defaults. No push was made.
