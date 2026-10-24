# O4 L6 integration validation

Validated source: 76316d5c11fcc2d505a93ccfb1aab1f444600ea6. This evidence-only commit follows the validated source. Required default suites, fmt and Clippy passed; supported Keccak circuit, format, transcript, primitive and Flock checks passed. The unsupported extra legacy VM configuration failed and is explicitly recorded in feature-scope.md and the unmodified log summary. No test was disabled.

All seven reference workloads reconcile keys, claims and programs with no retiming. The correctness-only published-control comparison uses seed 20261024 and confirms exact key, shape, statement, certificate length and certificate SHA256 equality for all seven workloads. Timing is excluded from the compatibility comparison and is not optimization evidence. Full logs, certificates and binaries remain in artifacts/O4 with hashes in gate-summary.json.
