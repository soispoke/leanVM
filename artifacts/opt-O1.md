# O1: native Keccak per-permutation optimization

In progress. Start 2026-10-23 approximately 23:31 UTC, deadline 2026-10-24 02:31 UTC. Worktree `opt-O1`, branch `opt/O1`, control `9e5f41c4`. No push. Timing slice 12-23, 12 threads; builds/tests 48-63, four jobs.

## Control

Fresh release binaries built from unmodified `9e5f41c4` with Rust 1.99.1, native CPU flags, Keccak protocol feature. Stored in `artifacts/opt-O1/control/`. SHA256: deferred_merge `9acf34fc0199451914a85c1f534c4691d6d05e29b56befd494fdee2686af4d19`; sparse_tree `c68ce6b4e6352a7a9b82246add33989508c65b01299376d19f2935fc1f3bc2be`.

Initial first-level screens: 3.565338 / 3.488746 s, 33,554,432 words, 999,496 rows, 206,192 proof bytes, 8.677 / 12.491 ms core verification, 25.731 / 25.134 ms root. These are preliminary screens, not accepted ABAB comparisons. Node screen: 4.469066 s, 33,554,432 words, 1,139,668 rows, 205,552 proof bytes, 9.972 ms core verification, 41.881 ms root. Three-sample baseline medians: first 3.577805 s and node 4.877695 s (baseline-driver.log).

## Structural census

The existing Flock Keccak relation already uses only 38,400 chi product bits plus constant, input and output bits (41,664 useful slots) per permutation. Theta/rho/pi/iota are linear forms, not committed intermediates. Klog16 rounds this to 65,536 Boolean slots, 1,024 packed F64 words. Simply committing chi only or folding round constants is already implemented and cannot be claimed as a new optimization.

The sparse first-level control has 1,727,231 F192 witness elements before power-of-two padding (zlog21). Its arithmetic limb table is 6,291,456 F64 words, but q alignment rounds its offset to 16,777,216 words, followed by 16,777,216 Keccak words. This is the origin of the 33,554,432 committed-word total. The 17 connector rows apply to the dense bridge; measured mixed merges use the sparse port-column backend with 50 lane ports. A dense six-row change would not directly optimize these mixed merges.

Stage timing census pending tracing-enabled diagnostic binaries. Diagnostic instrumentation uses existing tracing spans and adds no prover timers.

## Stack packing candidate (pending matched timing)

Place q first and arithmetic limbs after it. This removes alignment holes while keeping every coordinate binding, all 50 ports and the same native Keccak relation. Offsets are mirrored in the recursive recorder. The power-of-two cube remains log25, but actual committed lanes can shrink. An earlier draft incorrectly rejected this based only on the cube size; that draft is superseded. Targeted honest, wrong-output, swapped-connector and tampered-proof tests passed; ABAB is pending.
