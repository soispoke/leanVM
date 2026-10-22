# Private trace compiler optimization lane

Date: 2026-10-22. Yukon local and upstream HEAD: `86b1153b747d3ae442901dbc97ae475801c3e28e`. No Lean edits or accelerator claims.

## Commits

- `c198a55d554b255726894733fbdafd6dbfea4d6d`: lazy per-limb Boolean decomposition, partial upper-limb ranges, cached aliases, checked allocation estimator.
- `d6acba4a651a0a66f98003790efc3c636fd20043`: precompute fixed BLAKE2s compression blocks; cache fixed hash limbs.

Both are based on `0bf35096`. Only `crates/format_recursion/src/private_trace.rs` changes. Worktree is clean.

## Preservation argument

Every source is reconstructed from F64 coefficients before projection. A touched coefficient is reconstructed from Boolean bits; untouched full coefficients retain the existing private compression typing obligation. A partial upper coefficient is reconstructed from exactly the remaining bits and zero padding. Original high coefficients therefore cannot compensate for malformed projected values. Repeated source and aligned alias projections reuse constrained bits. Explicit identity slices still enforce the inferred range through coefficient typing.

Compression folding tests a set of canonical public-pinned variable IDs. It never tests private witness word values. With a fixed CV and message, native BLAKE2s yields fixed outputs, which become public-pinned constants. Counters and final flags are fixed by program lengths. A subsequent private block receives that fixed CV. One valid fixed terminal compression is retained if needed by the existing bridge's nonempty schedule requirement. Original trace hash-output equations remain, so changed intermediate hash outputs are rejected.

## Validation

- Combined release library tests: **56 passed**. Includes all 193 widths, checked rows/variables/compression bounds, partial-word ranges, sparse projection boundaries, malformed outputs and extension coefficients, and four constant-prefix message lengths with private zero witnesses.
- All-target release Clippy for `format_recursion`: **passed with `-D warnings`**.
- Cargo format and diff whitespace checks passed.
- Rust 1.99.1, native CPU + pclmul flags, four workers, CPUs48-51, separate target cache. Existing 24GiB memguard used.
- Tests receipt: `compiler-tests-fold/result.json` (31.07s including compile, 0.461GiB peak). Clippy: `compiler-clippy/result.json` (19.04s, 0.441GiB peak). Receipts correctly mark dirty precommit source; their binary digest is taskset, not a pinned cryptographic benchmark artifact. Root integration must retain actual binary/source provenance for performance runs.

## Performance scope

A sparse projection of one full F192 value now needs only64 Boolean bits rather than192. A 96-bit explicit range uses32 Boolean bits and typed low F64, rather than96 bits. Fixed hash prefix blocks disappear from the compression schedule; private zero words remain. These are structural counts, not measured proving speedups. No large tree timing run was launched in this lane. Full tagged hash chains consuming all128 bits remain a bottleneck.
