# Validation of the published comparison branch

The source revision is `7298edef45f55b64e29fe20dbfb7a1cddff41d70`. Its tree was clean at measurement start. `manifest.json` records source hashes and environment; `commands.json` records memory admissions and exact commands. `regressions.json` records the subsequent upstream/default-recursion and opening regression checks.

There are 36 measured records and 12 warmups: nine measured pairs at fan-in one and nine at fan-in two. All 153 guest mutation checks pass. Four Rust unit tests, Python runner regressions, all-targets Clippy, upstream quotient/EVM tests, the unchanged default two-to-one recursion path, and individual opening regressions pass. Instruction counts, bytecode sizes, padded cycles and execution gas match the earlier research implementation for all 48 records.

Wall times are observations under active machine load. They are not directly comparable across runs as a performance regression test. This run's warm serial medians are 1.484 s / 2.697 s for one application and 2.775 s / 5.708 s for two (PCS / R1CS). The preserved earlier research run was faster on both paths. No speedup or slowdown is attributed to source cleanup; the exact work counts did not change.

This evidence covers the stated prototype, not an independent cryptographic audit, arbitrary R1CS support, optimized Keccak or a production dependency-frame implementation.
