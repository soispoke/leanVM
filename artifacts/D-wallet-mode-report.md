## Correct client measurement with loaded base key (2026-10-23)

Implemented `lane-D/crates/format_recursion/examples/application_client.rs`, with `prepare`, `prove`, and `verify` commands and optional `trusted-key-cache` support. `prepare` persists the actual preprocessed base `Setup`, including its prover tables. The wallet process loads that key, creates its witness, calls the base prover once, and serializes the standard height-zero certificate. It constructs no node setup and performs no merge or native verification in the wallet process. Each certificate is decoded and verified in a separate process against the authorized local key; altered statements and proofs are rejected there. Usage and cache trust/version limitations are documented in `lane-D/crates/format_recursion/client.md`.

**Time to mempool-ready proof** starts with the base key and static circuit loaded and ends with the complete certificate bytes in memory. It includes the complete current witness creation path, including fixture/instance reference work, the satisfaction check, one native proof, and serialization. Key loading, static circuit construction, certificate file output, and verification are outside the headline; their independent timings are preserved below and in JSON. This is the correct client measurement. These numbers describe this process boundary on the shared host; they are not a candidate performance comparison.

All runs use a release binary (optimization level 3, debug assertions disabled), 12 threads, and explicit `taskset -c 36,37,38,39,40,41,42,43,44,45,46,47`. Every sampled live thread had exactly that mask. No lane-D build overlapped any runtime measurement. Pinning does not reserve the slice: unrelated fastcheck/Lean processes with overlapping masks were observed, and scheduling variability is visible in the recorded counters.

Each row reports three fresh-process measurements: headline time and native verification are the minimum of three; peak client RAM is the maximum of three. RAM is Linux VmHWM from the loaded-key witness/proof/encoding boundary, including the resident base key and static circuit. Offline preprocessing memory is outside this client phase. All repeated certificate hashes, bytes, base-key roots, and shapes match exactly within a workload.

| Workload | Time to mempool-ready proof s (min/3) | Proof bytes sent | Native verification ms (min/3) | Peak client RAM GiB (max/3) |
|---|---:|---:|---:|---:|
| BLAKE2s 64 B | 0.119769 | 247,956 | 5.889738 | 0.308 |
| BLAKE2s 1 KiB | 1.528974 | 323,356 | 6.969076 | 3.577 |
| SHA256 1 KiB | 2.927579 | 347,036 | 7.547518 | 6.899 |
| Keccak256 1 KiB | 3.111876 | 346,652 | 7.158497 | 7.228 |
| MPT storage proof | 12.858749 | 386,356 | 7.901137 | 28.318 |
| Shielded transfer | 13.358411 | 385,204 | 7.884659 | 27.776 |
| Falcon512 | 13.388206 | 384,756 | 7.714183 | 27.772 |

| Workload | All headline samples s | Median s | Range / median | All native verification samples ms |
|---|---|---:|---:|---|
| BLAKE2s 64 B | 0.172939, 0.130556, 0.119769 | 0.130556 | 40.7% | 9.798532, 10.932844, 5.889738 |
| BLAKE2s 1 KiB | 4.342364, 1.528974, 1.578815 | 1.578815 | 178.2% | 7.297639, 7.030073, 6.969076 |
| SHA256 1 KiB | 5.278719, 3.066193, 2.927579 | 3.066193 | 76.7% | 7.889981, 8.051589, 7.547518 |
| Keccak256 1 KiB | 6.052641, 3.240141, 3.111876 | 3.240141 | 90.8% | 7.158497, 7.569910, 9.414777 |
| MPT storage proof | 15.906079, 13.238489, 12.858749 | 13.238489 | 23.0% | 9.567239, 8.387892, 7.901137 |
| Shielded transfer | 14.427897, 13.792415, 13.358411 | 13.792415 | 7.8% | 8.030180, 7.884659, 8.464452 |
| Falcon512 | 14.181943, 13.388206, 24.283758 | 14.181943 | 76.8% | 7.761278, 8.350171, 7.714183 |

| Workload | Key-load samples s (excluded) | Static-circuit samples s (excluded) | Witness samples s (included) | Proof samples s (included) |
|---|---|---|---|---|
| BLAKE2s 64 B | 0.319797, 0.288375, 0.286699 | 0.008107, 0.008538, 0.007683 | 0.010755, 0.009657, 0.009897 | 0.161977, 0.120661, 0.109647 |
| BLAKE2s 1 KiB | 5.528194, 4.786503, 4.498860 | 0.225033, 0.163379, 0.160098 | 0.228825, 0.144027, 0.136988 | 4.112672, 1.384377, 1.441311 |
| SHA256 1 KiB | 14.021652, 9.173739, 8.731209 | 0.458687, 0.376728, 0.389711 | 0.388165, 0.288434, 0.283802 | 4.889917, 2.777173, 2.643221 |
| Keccak256 1 KiB | 12.187875, 9.692551, 9.450468 | 11.644793, 9.647049, 9.354747 | 0.485040, 0.281169, 0.285276 | 5.566982, 2.958322, 2.826006 |
| MPT storage proof | 43.962415, 36.749297, 37.921564 | 37.045536, 29.818383, 31.021261 | 1.616801, 1.443931, 1.431070 | 14.286962, 11.792438, 11.425591 |
| Shielded transfer | 41.636787, 38.872050, 47.103478 | 2.439439, 2.444646, 2.552036 | 1.512214, 1.383425, 1.257153 | 12.914898, 12.408187, 12.100133 |
| Falcon512 | 36.687791, 37.439572, 63.421749 | 1.824922, 1.891879, 2.380118 | 2.402808, 2.492027, 3.587806 | 11.777801, 10.894813, 20.694518 |

### SHA256 gap diagnosis

The historical 2.146857 s isolated proof versus 6.389773 s tree leaf-0 proof is not reproduced as a stable recursive-setup penalty. Nine matched fresh-process diagnostics use the identical witness and base shape in three contexts, with two proofs per process. The first-round contexts all enable the same existing tracing spans. Every one of the 18 certificates and all three wallet SHA certificates is identical, including its 347,036-byte encoding. The accepted backend is a96334fb; the original slow tree receipt predates its owned-column change, so these observations cannot assign an exact cause retrospectively to that old singleton.

| Context | First proof + serialization samples s | Warm samples s | First min s | Warm min s |
|---|---|---|---:|---:|
| base-new | 2.462171, 2.712376, 2.982010 | 1.915614, 2.518787, 2.221138 | 2.462171 | 1.915614 |
| node | 2.613822, 2.650684, 2.628773 | 2.138032, 1.996241, 2.820687 | 2.613822 | 1.996241 |
| base-load | 3.174327, 2.586828, 3.145886 | 2.213423, 1.861859, 2.865803 | 2.586828 | 1.861859 |

Source inspection: `SplitClosedSetup::prove_base` calls the base prover exactly once; its extra work is a trace-satisfaction/public-output check. Recursive setup does create a bootstrap proof, but it finishes before the measured leaf proof and is absent from the new wallet executable. `Setup::prove` performs a size-validation encoding before the certificate is encoded; this is serialization, not a second proof. Neither the old leaf timer nor the new proof timer includes recursive key setup or merges.

| SHA context | First-proof minor faults (three samples) | Warm minor faults | First-proof aggregate system CPU s | Warm aggregate system CPU s | Resident RAM before first proof GiB |
|---|---|---|---|---|---|
| base-new | 19744, 19957, 18630 | 49, 242, 215 | 5.00, 6.40, 7.83 | 0.01, 0.06, 0.05 | 3.509, 3.510, 3.508 |
| node | 5902, 5284, 5245 | 19, 16, 548 | 3.11, 5.52, 3.91 | 0.02, 0.04, 0.01 | 8.185, 8.172, 8.154 |
| base-load | 16571, 15049, 15175 | 66, 70, 11 | 6.25, 5.01, 7.47 | 0.02, 0.02, 0.14 | 4.525, 4.525, 4.526 |

All 18 context proofs have zero major faults. Minor first-touch/allocation faults and aggregate system CPU generally fall sharply on a warm proof. Node residency raises retained RAM, but does not produce a persistent threefold proof-time increase: first-proof minima are 2.462171 s with fresh base setup, 2.613822 s with node setup retained, and 2.586828 s with the loaded base key. These measurements support a first-touch/allocation cost; they do not identify one particular allocator policy or NUMA mechanism.

Scheduling is independently material even without a node setup: SHA wallet trial 1 took 5.278719 s (4.889917 s proving), with 29.927012 aggregate thread-seconds of runnable scheduler wait, 274,934 minor faults, and 31.694596 thread CPU seconds. Trial 2 took 3.066193 s (2.777173 s proving), with 0.434599 scheduler-wait seconds, 76,330 minor faults, and 26.702870 thread CPU seconds. The scheduler counter measures time runnable threads could not run; it excludes waiting at a prover barrier and cannot be interpreted as a directly subtractable wall-time duration. Outside processes with overlapping affinity were observed separately; the data do not assign the delay to a specific outside PID.

**Cause conclusion:** there is one base proof, not duplicated proving work. Current variability has measured first-touch/allocation and runnable scheduling components. The matched experiments do not support recursive setup residency as the cause of a fixed 3x gap. The exact cause of the historical 6.389773 s run remains unconfirmed because that run did not record these counters. It would be incorrect to report a specific historical mechanism as established or to use that old singleton as a denominator for the new client mode.

### Batch12 continuation and gates

The parallel read-only audit completed independently while the client work ran. It verified 48 existing receipts, their source-stability manifests and every stdout/stderr hash. Batch12 already completed three paired repetitions per workload and release tests, doctests, and clippy with warnings denied. Its historical sequence was AB, BA, AB (A1 B1 B2 A2 A3 B3), rather than the subsequently requested strict ABABAB screen. No new candidate screen was performed here. Future screens retain the explicit ABABAB rule and minimum of three.

**Batch12 remains rejected.** The historical isolated-harness minimum-of-three time to mempool-ready proof was control/candidate 0.113200/0.119966 s for BLAKE2s 64 B (+5.98%), 1.257287/1.259528 s for BLAKE2s 1 KiB (+0.18%), and 2.604769/2.677908 s for SHA256 (+2.81%). Its preliminary negative percentages did not hold. These are matched historical screen results, not comparisons against the loaded-key matrix. Do not integrate removed provisional commit 0a137ef5. Evidence: `artifacts/D-batch12-independent-audit.md`.

### Reproducibility and validation

All 58 runtime receipts passed, with unchanged source manifests, verified stdout/stderr hashes, successful affinity/build guards, and separately verified certificates. Machine-readable full phases, hashes, shapes, samples and resource counters: `artifacts/D-wallet-mode-summary.json`. Independent recomputation: `artifacts/D-summarize-wallet-mode.py`. Run sequence/logs: `D-run-wallet-mode.py/.log` and `D-repeat-wallet-mode.py/.log`. Release build receipt: `D-client-cache-build-t3`; frozen executable hashes: `artifacts/D-wallet-binaries-before-gates.json`. Frozen executables: `artifacts/D-wallet-application_client` and `artifacts/D-wallet-client_context_probe`. Keys: `artifacts/D-client-keys`; certificates: `artifacts/D-wallet-certificates`. Every runtime has its own `-guard.json`.

- `D-wallet-fmt-t2`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo fmt --all -- --check`.
- `D-wallet-cache-test-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion --features trusted-key-cache --example application_client`.
- `D-wallet-release-tests-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion -p pcs -p rec_aggregation --features format_recursion/trusted-key-cache`.
- `D-wallet-clippy-t2`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo clippy --locked --release -p format_recursion -p pcs -p rec_aggregation --all-targets --features format_recursion/trusted-key-cache -- -D warnings`.
- `D-wallet-default-check-t1`: passed, unchanged source manifest and log hashes checked. Command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo check --locked --release -p format_recursion -p pcs -p rec_aggregation --all-targets`.

The cache roundtrip test preserves exact proof encoding, base root and shape and checks rejection of changed outputs and proof data. The example suite passed 2 tests; the feature-enabled release suites passed 79 format_recursion, 44 pcs and 43 rec_aggregation tests, with 6 existing manual tests ignored and zero failures. Doctests passed. Clippy covers their targets with warnings denied. A separate default-feature release check covers those targets without enabling cache support. No Lean sources were edited. All builds and tests ran after the final client measurement.

The initial clippy receipt D-wallet-clippy-t1 failed on the diagnostic probe not reading its witness-report field. The probe now emits that report before its proof timers, and D-wallet-clippy-t2 passes. This is an output-only diagnostic change after measurements; its exact measured source is archived as artifacts/D-wallet-client_context_probe-measured.rs. The wallet executable and all library/prover sources used for the completed measurements and release tests are unchanged by this fix. The failed receipt is retained.

Implementation committed locally on lane/D as `e00d34b484a9bd610f00d6332c840eca4353c621` (parent accepted backend a96334fb). Worktree is clean. No push. This commit adds the client measurement path and cache support; batch12 is excluded.
