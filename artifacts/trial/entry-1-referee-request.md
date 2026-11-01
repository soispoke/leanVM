# Entry 1 referee freeze and held-out draw

The referee recorded `freezes/entry-1/freeze.json` and snapshotted every declared retained setup file, generator file, interface note and binary under that directory. The selected applications in `heldout-entry-1.json` are **Keccak-256 1 KiB** and **MPT**, drawn only after that freeze. No aggregate setup change is permitted for this entry; changed binaries or keys require a new entry/freeze and draw.

Canonical application descriptions are `P/artifacts/keccak-statements.md` and the existing `circuit_suite::Keccak256OneKiB` and `MptStorageProof` predicates. The referee's seeded input generator is `P/trial-ref/experiments/challenge/inputgen/`, with a binary at `P/target-trial-inputgen/release/trial-inputgen`. The draw seed is in the receipt; generate independent per-child inputs from it. If a workload exceeds the declared fixed shape or the decoder cannot express it, report that limitation, do not substitute a BLAKE2s preimage or rebuild the aggregate key. The three local BLAKE2s demo apps are useful structural evidence, not these held-out applications or workload A/B.

Entry 1 declares approximately 366 MiB of retained aggregate artifacts. Whether the 64 MiB application-key cap also covers a shared aggregate cache is ambiguous in the page; all bytes will be reported without charging only the 32-byte digest.
