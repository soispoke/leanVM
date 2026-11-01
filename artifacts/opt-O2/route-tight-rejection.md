# Rejected tight node shape

The opt-in `keccak-route-tight` experiment changed the node wrapper to `(row_log, z_log)=(20,20)` while retaining q-first packing. Its build succeeded and the 65-test package plus Clippy passed, but the timed node example did not construct a setup: `SparseSetup::new_with_padding` returned `None` at `sparse_tree.rs:182` because the generated R1CS exceeded the requested row or column bound. Therefore it has no valid timing, call, word, proof, or verifier claim and is rejected before benchmarking.

A diagnostic build measured the natural node R1CS as 963,855 rows and 1,123,131 columns. The 20-bit row bound would fit (1,048,576), but the 20-bit column bound would not; the requested shape is therefore structurally impossible without changing the circuit relation.
