# Checked native-field versus leanVM outer aggregation

See [TABLE.md](TABLE.md) for the comparison, [summary.json](summary.json) for timing ranges and aggregate totals, and [the implementation note](../../recursion/NATIVE.md) for scope and reproduction.

All eight jobs completed: 40 measured samples and eight warmups verified. The harness confirmed identical child proof bytes and public claims across both backends. All 34 benchmark tampering cases were rejected. Peak process memory stayed below the admitted 32 GiB and available system memory stayed above 186 GiB.

The measured code is commit `8cb44029423ab48b6d36bf544e445406fc92e232`. `source-sha256.json` records source contents, and each job records its binary hash and environment. The compiler is Rust 1.99.1 with native CPU and explicit carry-less multiplication enabled. `validation/` contains the 22 circuit/backend tests, eight harness tests, four runner tests, Clippy, build, formatting and source audit records.

Both paths verify the quotient PIOP and all three openings of independent proofs of one small application. This is a single outer aggregation level, not repeated self-recursion, a recursion.fast entry, or a formally proved new composition. At eight children, preparation plus proving plus verification is 8.34 s for the native-field experiment and 7.32 s for leanVM. These shared-host medians do not establish an architectural winner.
