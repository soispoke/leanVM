# Entry 0: unchanged current best

Source: 65745ca1, local branch trial/entrant. Prepared 2026-10-23 18:05 UTC pending referee ENTRY-FORMAT.md; this is an early baseline handoff, not a claim of eligibility or a completed format submission.

Protocol: BLAKE2s. Two real applications (BLAKE2s shielded and Merkle), four fixed carried slots including two wrapper identities. Historical measured mixed node 0.9419 s; complete root 21.09 ms, individual settlements 7.97 ms node, 8.05 ms first wrapper, 0.80 ms shielded, 0.16 ms Merkle. These are external historical 3-process measurements on cores 12-23, not fresh trial measurements or the required five rounds. Evidence: P/artifacts/hometurf-sparse-tree.md and ht-L2r/artifacts/sparse-tree/outerparallel-provenance.json.

Known failures/missing: unchanged applications are not Keccak A/B; Falcon decoded relation exceeds wallet RAM and byte gates; three-real-app tree unsupported; fixed-shape admission is not arbitrary held-out admission; coordinator security calculator and independent upgrade backend not supplied here. No official score or referee result claimed.
