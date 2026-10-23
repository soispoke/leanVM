# Approved native output trimming defaults

The user approved this change at 11:40 UTC on 2026-10-23. `native_application_support::DEFAULT_OUTPUT_TRIMMING` replaces the circuit-size heuristic with an explicit per-relation table. SHA256 1KiB, Keccak256 1KiB and MPT default to trimming. BLAKE2s 64B/1KiB, shielded and Falcon default to no trimming; unknown relations also default to no trimming. Explicit lane C research overrides and the census remain available. The joint inverse commitment rate remains 4 (`JOINT_LOG_INV_RATE = 2`); no rate reduction was applied.

The approved padded native-row transitions are SHA/Keccak `2^22` to `2^21` and MPT `2^25` to `2^24`. Untrimmed MPT exceeds the unchanged native row cap. Fresh default wallet receipts confirm log_rows 21, 21 and 24. The same application claims remain bound; trimming changes the pinned native circuit key. The native-adder regression proves both graph variants, checks rejection in both cross-key directions, and retains rejection of forged non-Boolean witnesses. Split-closure adversarial tests remain enabled.

Measurements use Rust 1.99.1, CPUs 0-11, LEANVM_NUM_THREADS=12 and RAYON_NUM_THREADS=12. Each wallet and mempool measurement uses a separate process. Wallet time includes native witness construction, proving and transport encoding, excluding trusted setup and reference checks. Peak RSS is wait4 per-process RSS including setup. The wallet's same-process verification is diagnostic; the table uses the separate mempool process including decoding. The table uses the final run of a frozen executable after the release build, not a minimum across screens. An earlier build was also measured; the rebuilt executable had a different binary hash despite unchanged Rust source, and all three certificate byte strings match exactly between runs. This is not an ABAB rerun. Lane C's earlier ABAB remains supporting historical evidence. Builds and release gates use CPUs 48-63 and CARGO_BUILD_JOBS=4.

| Relation | Wallet s | Peak RSS GiB | Certificate bytes | Standalone verify ms | Native log_rows |
|---|---:|---:|---:|---:|---:|
| sha256-1kib | 1.706 | 4.395 | 323,836 | 6.336 | 21 |
| keccak256-1KiB | 1.496 | 4.069 | 324,060 | 9.269 | 21 |
| mpt-storage-proof | 10.535 | 30.925 | 386,356 | 7.491 | 24 |

For context, historical `integrator-reference12` untrimmed SHA/Keccak wallets at 87151953 measured 2.620/2.703 s, 8.167/7.835 GiB and 347,036/346,652 bytes. The fresh defaults are about half the RSS with smaller transported certificates. The historical baseline was read, not rerun. No untrimmed MPT proof is claimed.

Reproduce with `cargo build --release -p rec_aggregation --example application_role_profile`, then `python3 experiments/pcs-r1cs/measure_trim_defaults.py --output <new-directory> --target <cargo-target-directory>`. The driver records the executable SHA256, pinned base key and expected statement and appends measurements under a lock to P/artifacts/matched-12t.jsonl. The Rust policy source is 8ecd1757; final measurement receipts identify 89401e86, which also freezes the executable before measurements. Subsequent documentation and measurement-driver commits do not change measured Rust source. The frozen source hashes are archived alongside the raw role logs, certificates and summaries.
