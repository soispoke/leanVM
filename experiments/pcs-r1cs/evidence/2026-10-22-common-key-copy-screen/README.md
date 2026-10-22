# Native copy-fingerprint chunk screen

Rejected increasing the parallel copy-fingerprint chunk width from 256 to 1024. The accepted hybrid opener at f23eddd9 remains unchanged.

Three alternating two-leaf fresh-process pairs, chain16. Each process creates and locally verifies three certificates and rejects changed roots/heights. The callback chunk offset was updated consistently with its width in the measured candidate. Positive paired reductions mean faster.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.560 | 7.410 | +1.15% | 2/3 |
| All creation | 4.509 | 4.421 | +1.78% | 2/3 |
| Root creation | 1.276 | 1.263 | +0.86% | 3/3 |

The screen does not justify the frozen target retention threshold of at least 3% paired median total or creation improvement, 6/7 independent target wins, a positive bootstrap95 lower bound, and no companion regression over 1%. No eight-leaf confirmation was run. All exact keys, shapes, independently recomputed statements and per-position certificate sizes/scalar/Merkle-phase counts match the published common-key baseline.

The corrected fingerprint test passes against the independent scalar reference, including zero, one and extension-field cells. A fresh release build passes. An initial width-only edit left the callback stride at256; its targeted test failed. The shell driver continued to a build, which was terminated and is excluded. The failed source patch, receipts and corrected patch are preserved. No timed observation was excluded.

A prior proposed implicit identity-tree edit was abandoned at source preflight: the accepted code already uses vec![F192::ONE]. Its no-op test was removed without a performance claim. The chunk test was deliberately cheap: the traced copy-leaf stage was only about14ms, so large whole-prover gains were unlikely.

Yukon upstream was checked at phase start and isolated at1ffa172ef1ccec3fe91256bb733c060222805731. Its current benchmark runner SHA256 remains ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. The new checked-build admission API is opt-in and has no qualified real runner here; the standard source-bound benchmark runner remains in use. No pipeline speedup is claimed for that API.

Rust1.99.1, native CPU plus pclmulqdq, 32 workers, CPUs0-63, four Cargo jobs, serial timed jobs. Build/test budget96GiB, benchmark16GiB, host reserve40GiB. The shared Xeon Gold6230R host is not dedicated; RSS is sampled process-group memory, not cgroup isolation. Controls reuse the exact frozen hybrid executable after source/binary identity checks. Every timed receipt is bound to its exact source manifest, build and executable. The audit rejects overlapping recorded intervals and verifies that accepted Rust/Cargo sources were restored.

The archive contains both source patches, exact commands, raw logs, source/binary hashes, plan, failed checks and passing replacement receipts. Run python3 verify-archive.py here for integrity without extraction. This is local performance evidence, not official recursion.fast certification or a formal composition/security proof. The optimization goal remains active.
