# Common-key recursive closure baseline

The experimental native backend now proves leaves and internal nodes with one circuit and one setup/key. Functional tests cover repeated composition through height four and a mixed-height node at height five. Each measured eight-leaf tree creates and verifies all 15 certificates with the same key. The [recursion-layer specification](../../recursion/CLOSED.md) describes the public key pin, bounded nonwrapping height, leaf/node relation, dummy leaf branch and backend soundness assumptions.

This establishes tested implementation closure. The formal native arithmetic/Flock/PCS composition proof, recursive knowledge extractor/security loss and official recursion.fast integration remain open. It is not a claim of formal or official certification. The common recursive circuit is also used for leaves, making this initial construction slower than the earlier finite-tree prototype. Earlier leanVM and Flock timings have different workloads or boundaries and are not matched speedup comparisons for this new circuit.

## Small-tree results

Fresh-process medians over three trials, 16 BLAKE2s chain steps per distinct leaf, 32 workers and CPUs 0-63. Total is Yukon child-process elapsed time, including one common setup, every proof, explicit verification, serialization/reporting and wrong-root/height rejection checks. Root creation includes recording, child prechecks, witness preparation and proving; it excludes setup and explicit root verification. Each per-stage column is a separate median and should not be added to reconstruct the process median.

| Leaves | Certificates | Total (s) | Setup (s) | All creation (s) | Root creation (s) | Root verification (ms) | Root certificate (bytes) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 3 | 8.120 | 2.714 | 5.194 | 1.504 | 6.139 | 329,852 |
| 4 | 7 | 14.313 | 2.788 | 11.258 | 1.483 | 6.299 | 329,564 |
| 8 | 15 | 26.342 | 2.865 | 23.183 | 1.473 | 6.195 | 330,044 |

A certificate includes the 36-byte height/statement header. Merkle pruning can make certificate length differ across distinct statements. Every corresponding deterministic certificate matches exactly across repetitions and worker comparisons. Shape is fixed at 2,097,152 native rows, 1,024 public scalars, 65,536 padded hash blocks and stack log 26. The common key also matches across all three tree depths. Sampled process peak RSS is about 8.03 GiB. These are hash-chain fixtures, not shielded-transfer measurements.

## Initial autoresearch screens

Three alternating fresh-process pairs each on two leaves at chain 16. Controls are measured again for each screen. Worker changes use the same binary, fixed circuit, security parameters, key and deterministic statements. Every per-position certificate length, scalar count and Merkle phase count is unchanged.

| Candidate | Control / candidate total (s) | Paired total reduction | Control / candidate root creation (s) | Decision |
| --- | ---: | ---: | ---: | --- |
| 64 workers | 8.677 / 12.370 | -42.56% (0/3 wins) | 1.542 / 1.715 | Reject |
| 16 workers | 8.741 / 9.874 | -13.97% (0/3 wins) | 1.603 / 2.053 | Reject |

Paired reductions are medians of per-pair ratios, not ratios of the independent medians. Both candidates clearly regress and fail the predeclared retention rule; no independent confirmation series is justified. Keep 32 workers for this construction. The old finite-tree worker profile is a separate result and remains unchanged.

The serial tracing diagnostic places the largest costs in the joint commitment and polynomial openings. It is diagnostic only and is excluded from the baseline medians. The optimization goal remains active: a candidate must first pass a repeated screen, then at least seven independent target-fixture pairs with a positive interval and unchanged geometry/lengths before retention. The exact plan is archived.

## Validation and provenance

All 76 native release tests pass. Targeted release Clippy with tests/examples and `-D warnings`, formatting, strict rustdoc and the release benchmark build pass. Three independent Python validator tests exercise a positive fixture plus 16 negative semantic/receipt controls. The final audit independently recomputes all BLAKE2s leaf and node statements, checks 23 admitted tree processes and 117 locally verified certificates, compares deterministic geometry and verifies serial admitted measurement intervals. No Lean source changed; native tests do not prove backend soundness.

Yukon was fetched and matched upstream at `034f7e7d3dcdbfb8c395bc06ab3dd8069df1fd4b`; runner SHA256 is `ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e`. Rust 1.99.1 uses `-C target-cpu=native -C target-feature=+pclmulqdq`. Builds use four Cargo jobs, a 96 GiB sampled process-group budget and 40 GiB host reserve; measured tree jobs use 16 GiB and the same reserve on the shared Xeon Gold 6230R host. Source and binary hashes, exact commands, thread settings and raw stdout/stderr are retained. Process-group RSS is sampled, not cgroup isolation.

Failed early shape convergence, formatting, Clippy and rustdoc attempts are retained. The final rustdoc check exposed an existing array-notation link warning; its correction changes comment markup only. All measured Rust/Cargo source bytes otherwise match the published source, and the audit checks that exact exception. One diagnostic was accidentally launched before the serial baseline controller finished: the overlapping four-leaf trial and that diagnostic are excluded. An eight-leaf trial was then terminated while stopping that overlap. Both baseline trials were replaced under fresh labels after their processes stopped. The exclusions and original receipts remain in the archive; no failed or contended run supports the table.

## Reproduce

Build `cargo build --locked --release -p rec_aggregation --example closed_tree` with the recorded flags through current Yukon, then measure `closed_tree --depth 1 --chain 16`, depths 2 and 3, with `LEANVM_NUM_THREADS=32`. The source-bound archived wrappers preserve the exact original paths. Use fresh output directories and adapted paths for a rerun. `closure_probe` performs metadata convergence without commitments. An exact metadata and constant-vector fixed point is required before the setup is committed; this is not a key hash fixed point.

Run `python3 verify-archive.py` here to validate archive checksums without extraction. [results.json](results.json) contains the full baseline/screen records and geometry. [validate-closed-tree.py](validate-closed-tree.py) independently checks a raw benchmark stdout path together with its sibling Yukon result receipt. `raw-evidence.tar.gz` includes raw logs, receipts, failed attempts, source patch, specification, protocols and scripts; its internal manifest binds every member. Executable binaries and compiler caches are excluded. The executable hash is retained in every benchmark receipt.
