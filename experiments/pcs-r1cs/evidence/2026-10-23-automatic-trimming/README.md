# Uniform automatic native output trimming

The user superseded the relation table with a generator-only lowering rule: compile both output-dependency variants, compute their exact native arithmetic/hash bridge layouts, and trim if and only if arithmetic log_rows or padded hash-slot exponent decreases. Equal padded shapes retain the untrimmed graph. There is no workload-name table or global flag in the default selection. Explicit overrides remain research and rejection-test controls.

`format_recursion::application_lowering::select` accepts fixed circuit wiring and public-output sources only. It derives the application identity from that circuit, lowers synthetic inputs through both fixed graphs, and calls `PrivateShape::plan` on the actual lowered row/public/compression counts. Planning includes public anchors, connector alignment, six connector rows per padded hash slot, and minimum arithmetic/hash padding. The private lowerer derives structure from operations and immutable constants, not witness values. `Application::new` selects once during setup; subsequent witnesses use the selected graph.

`PrivateShape::plan` is metadata-only and can describe untrimmed MPT above the cap. `PrivateShape::for_circuit` and bridge key construction keep the original arithmetic-row cap. Checked layout arithmetic rejects address overflows. Joint inverse commitment rate remains 4; the verifier and its acceptance equations are unchanged.

The verification-only `automatic_lowering_check` example compares each automatic decision with the previously accepted explicit policy, asserts exact trace-program identity and values, constructs the native key, and checks its root and the public claim digest against archived receipts. `reference.json` contains those independent expected keys/digests and their provenance; it is test data, not a default-policy table. No proving or re-timing is performed. The earlier wallet measurements remain applicable to the identical circuits.

| Workload | Automatic trimming | Arithmetic exponent, untrimmed to trimmed | Hash-slot exponent, untrimmed to trimmed |
|---|---|---:|---:|
| BLAKE2s 64B | off | 17 to 17 | 7 to 7 |
| BLAKE2s 1KiB | off | 21 to 21 | 7 to 7 |
| SHA256 1KiB | on | 22 to 21 | 7 to 7 |
| Keccak256 1KiB | on | 22 to 21 | 7 to 7 |
| MPT | on | 25 to 24 | 7 to 7 |
| Shielded | off | 24 to 24 | 7 to 7 |
| Falcon | off | 24 to 24 | 7 to 7 |

The purity regression independently regenerates circuits with and without a padding reduction, repeats selection, checks equal identities and selected shapes, and verifies that all-zero and all-one witnesses produce the same fixed program. A separate connector-boundary test checks bridge alignment and retained cap enforcement. The native-adder test continues to reject trimmed proofs under untrimmed keys and untrimmed proofs under trimmed keys, as well as forged non-Boolean arithmetic. All split-closure adversarial tests remain enabled.

Reproduce the seven checks by building `cargo build --release -p format_recursion --example automatic_lowering_check`, then running the example with this `reference.json` and one workload name per process. Checks and release gates use CPUs 48-63, CARGO_BUILD_JOBS=4, Rust 1.99.1, LEANVM_NUM_THREADS=12 and RAYON_NUM_THREADS=12. Timed wallet rows were not rerun. The implementation source commit is bf78cd98; gate commands, logs, source hashes and final reconciliation rows are archived here.

Final gates pass on unchanged Rust sources: formatting, release all-target Clippy with `-D warnings`, 77 circuit_suite tests (4 ignored), 92 format_recursion tests, 43 rec_aggregation tests (5 ignored), doc tests and the bidirectional cross-key native-adder regression. All seven final reconciliation processes pass. No timing was repeated because every accepted native key and claim digest matches.
