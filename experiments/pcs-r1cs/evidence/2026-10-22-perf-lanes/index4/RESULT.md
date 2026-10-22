# Private index rate 1/16 probe

22 October 2026. Source `4531448b0c6b6088d172ee8b8097ddf89ef128a6`, based on root `02954a12`. Yukon local/upstream both `8e19ffca7f1ed46a111f81cef61b06e51604a27e` at phase start. No Lean edits.

Only change: private index `INDEX_LOG_INV_RATE` 3 → 4, plus a configuration assertion. Joint rate remains 1/4 and compact native layout remains unchanged. Rate 1/16 is already supported by the production WHIR parameter generator; concrete and symbolic transcript/index metadata already bind the chosen rate. This is implementation/configuration evidence, not a new composition proof.

## One local probe

Four leaves, chain length 16, two recursion levels. Four threads, CPUs 40-43, Xeon Gold 6230R, pinned Rust 1.99.1, native/PCLMUL release flags. Seven proofs verified, all statement checks passed. No warmup or repeated-trial claim.

| Stage | Proofs | Native padded rows | Compression count | Median prove | Median Rust verify | Total proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Leaf | 4 | 16,384 | 17 | 54.7 ms | 6.60 ms | 207,960-209,864 |
| Parent 1 | 2 | 2,097,152 | 18,053 | 4.681 s | 5.993 ms | 337,112-337,784 |
| Root | 1 | 2,097,152 | 29,129 | 4.613 s | 5.980 ms | 338,872 |

Medians are across distinct proofs within one process. Prove excludes setup and symbolic recording; the raw records also report preparation and setup times. Whole process: 17.717 s. Peak RSS: 7.309 GiB (wait4 high water and sampled group RSS, not cgroup accounting). Source/binary hashes remained unchanged.

First-parent compression count declined from the coordinator's index3 value 19,100 to 18,053, about 5.5%; this did not cross 16,384 or shrink native padding. Even hypothetically crossing that hash threshold alone would leave native rows above 2^20 because the nonconnector rows remain substantial. This small probe does not establish a speed improvement over index3 or leanVM. The coordinator's full-size index3 run sits near a different 32,768-compression threshold, so a full-size index4 measurement is still useful before adoption.

## Checks and provenance

- 60 release library tests passed, test execution 8.88 s; includes 54 actual
malformed connector proofs rejected and concrete/symbolic verifier controls.
- Release library/test Clippy passed with warnings denied; fmt passed.
- Memguard admitted 32 GiB. All build/test/benchmark checks used latest Yukon's
`bench-research.py`, 32 GiB group budget and 40 GiB shared reserve; no stop.
- Failed initial build receipt is retained under `build/`: resolving the cargo
rustup proxy changed argv0 dispatch, so it exited usage before compilation. `build-direct-cargo/` uses the exact toolchain cargo binary and passed.
- `tests/`, `clippy/`, `depth2-chain16/` contain guarded receipts and raw logs.
Consolidated measurements are in `summary.json`. Source worktree is clean.

Frozen executable: `/root/yukon-autoresearch/workspaces/leanr1cs-perf-20261022/index4-target/release/examples/private_tree`

SHA256: `1f34bb2aaff4eee1a20d398f2f2c94ca47f961450713d65b3b553ec0da8aa625`.

No full-size run was duplicated in this lane. No closed fixed-shape recursion, Lean composition certificate, zero-knowledge property, official challenge score or matched leanVM performance result is claimed here.
