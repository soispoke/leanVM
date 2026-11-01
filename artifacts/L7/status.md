# L7 final local status

Full Keccak protocol and instruction migration implemented, locally committed, and not pushed. Wallet and same/mixed/node-mixed merge ABAB ×3 completed, including separate exact L6 Falcon/MPT fixture variants.

Core210, integration25 (2 ignored), Flock5 and native suites pass; host/core all-target clippy passes. Exact guests build. Wrong-path/transcript/program/proof and exact-witness rejection checks pass. Security/query config is unchanged at128 bits with grinding. Frozen raw samples, manifests and locked metric rows are retained.

See [full report](../../../artifacts/hometurf-keccak-everywhere-leanvm.md) for metrics, L6 comparisons and measurement boundaries. L6 Merkle/same-program paired medians are reserved where unavailable; no performance target is claimed. Full Keccak recursion costs roughly2.6–2.9s per merge in these measurements.
