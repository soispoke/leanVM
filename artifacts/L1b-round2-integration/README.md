# Lane integration round 2

Integrated source chains: L2b `bc1f691a..6fe04622`, L4b `020448f2..796cf1b0`, and L3c `3bf7091f..4353823c`. The L4b/L3c module-list conflict was resolved by retaining both sets of exports. The shared measurement log is archived from the coordinator artifact directory. Untracked lane files are excluded, apart from the expressly requested evidence copies.

Sparse carried trees, native Keccak compilation, ML-DSA and shared word tables remain explicit research entry points. Ordinary compiler construction leaves native Keccak disabled. The default native arithmetic row cap remains log24. The larger log26 cap requires `--features experimental-log26`; add that flag to archived ML-DSA build commands when reproducing those research measurements. The feature changes only the resource cap and is disabled by default. The historical lane reports and summary receipts are archived unchanged.

Release verification uses CPUs 48-63, four Cargo jobs and twelve runtime threads. The sparse-tree example is run as an untimed regression with its root settlement, rejection probes and node-key reuse checks enabled. Its incidental timing output is not a new benchmark result. No performance claims are derived from integration checks.
