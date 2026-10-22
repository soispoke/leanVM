# Private circuit-index WHIR profiles

Date:2026-10-22. Base `bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47` already contains compact native witness layout and joint WHIR inverse-rate-log2 (code rate1/4). Yukon local and upstream checked at `db146971d12a76ac9a056d175b9e717e522c1c01`. No Lean changes.

## Implementation

- `785c28a2aa2b5d7c7b3def99dc2de8b03d238f4a`: fixed circuit-index commitment/opening inverse-rate-log2 (rate1/4), native/symbolic agreement, explicit transcript binding.
- `c3f7c8f12c4f3703d9c1fc40764c94dc741d2f74`: change private index exponent2→3 (rate1/8), plus three production-profile assertions.

The generalization adds `Index::new_with_rate` and stored trusted index rate. `Index::new` remains rate1/2. Native witness openings and the standalone default retain rate1/2 and their original v1 label. Alternate native index profiles use a v2 label with explicit rate; private bridge v4 binds joint and index rates. Index commitment, concrete index opening and symbolic index opening all select the same production `config_for_rate`. Circuit equations and sigma wiring do not change.

Existing production128-bit parameter derivation selects query counts, OOD parameters and grinding. No ad hoc reduction of queries or security target occurs. Fewer index queries shrink child proofs and the next recursive verifier, while the larger index encoding costs more setup/opening work.

## Validation

Each profile passed all **60 release library tests** and all-targetreleaseClippy with `-D warnings`. The added alternate-index test proves and records an index2 proof, preserves the default circuit shape, checks distinct roots, then changes the trusted rate and requires both concrete and symbolic rejection. Existing private bridge tests exercise all connector slots with actual malformed proofs and bypassed prover prechecks. Seven actual proofs (four small leaves, two parents and one root) verified in each depth2 run.

## Four threads, CPUs48-51, chain length16

| Metric | Index code rate1/4 | Index code rate1/8 |
|---|---:|---:|
| First-parent proving median |4.767s|5.192s|
| Root proving |9.382s|4.200s|
| Root Rust verification |6.626ms|6.195ms|
| Root total serialized proof |420,352B|356,920B|
| Root actual native circuit rows |2,422,784|1,767,424|
| Root padded native rows |2^22|2^21|
| Root compression count |33,808|30,799|
| Whole process |22.022s|17.668s|
| Sampled aggregate peak RSS |9.782GiB|6.126GiB|

The main improvement is structural: the larger encoding expansion reduces recursive verifier hashes enough to cross the32,768-compression batching boundary. This halves the padded native circuit at the root. The first-parent proving time increases, demonstrating the encoding tradeoff. Times are from one process per profile, with medians across distinct parent proofs; the root has one sample. Host load and caching remain confounders. No repeat-series or matched leanVM speed claim is made. Native rows are F192 multiply-add constraints, not VM cycles.

The earlier rate1/4 depth1 run separately verified2→1:5.591s proving,6.170ms verification,391,872B; whole6.961s,peak5.077GiB.

## Evidence

All paths relative to this report's directory:

- `index-rate2-tests/`, `index-rate2-clippy/`, `index-rate2-build/`, `index-rate2-depth1/`, `index-rate2-depth2/`.
- `index-rate3-tests-v2/`, `index-rate3-clippy/`, `index-rate3-build/`, `index-rate3-depth2/`.
- `index-rates-summary.json`: extracted level counts/shapes/times.

Both tree receipts hash every tracked Rust/TOML/Cargo.lock input and the actual executable before/after, record clean source commits, requested affinity, thread settings, resource bounds and raw events. Memory admission used project memguard; the new Yukon adapter applied24GiB for index2 and32GiB for index3, with40GiB shared reserve. Builds are measured separately.

`index-rate3-tests/` preserves an intentionally invalidated development receipt: all60tests passed, but a test-source edit during compilation triggered the adapter's unchanged-source guard. The source was frozen and the successful fresh gate is `index-rate3-tests-v2/`.

No tagged challenge-ROM adapter, one fixed recursive circuit, ZK property, new Lean security certificate, official challenge score or end-to-end formal implementation guarantee is supplied. No fullsize tree run was launched by this lane.
