# L6 Keccak everywhere, work in progress

No Keccak-everywhere result or sub-second merge verdict is established yet. No push performed.

Worktree `P/ht-L6`, branch `hometurf/L6`, based on L4k `796cf1b0`. Published ref was `1f50df0a`; L2r prerequisite range from the common ancestor through `bc1f691a` was required because L4k lacked row_format, then requested `bc1f691a..6fe04622` was cherry-picked. Current imported tip `0321bfe2`.

Shared statement definition: `P/artifacts/keccak-statements.md`. Shielded Keccak implementation matches its independent RustCrypto reference. Native application requires 56 permutations. Boolean circuit census: 6,744,762 rows. Native lowering: 348,049 arithmetic rows, 524,288 padded rows, 6,422,528 committed F64 words, 293,824 proof bytes.

Initial BLAKE2s-protocol control observations for shielded-Keccak: 0.429114669 s then 0.476379927 s. Second fresh process peak RSS 982,864 KiB; whole process 30.539849096 s, mostly fixed circuit construction/identity setup excluded from wallet timer. These are exploratory samples, not ABAB medians. Timing uses cores 12-23 and both thread knobs set to 12. Builds/tests use cores 48-63 with CARGO_BUILD_JOBS=4. Raw stdout/receipt are `P/artifacts/L6-shielded-control.*`.

Remaining: finish shared application vectors, native Merkle edition, protocol transcript/Merkle/identity/claim/recursive-verifier switch with grinding retained, zero BLAKE2s rows, security parameter audit, five wallets and both mixed merges/root settlement in three ABAB rounds, lever screens if needed, verifier-level adversarial probes, final release checks and local commits. Current protocol remains BLAKE2s, and native Keccak application results must not be described as Keccak everywhere.

Standalone control proof verification succeeds in 11.369144 ms; verifier whole-process RSS 598,972 KiB. Native sponge passes RustCrypto reference checks at word lengths 0,1,4,8,16,17,18,33,34,128; exact-rate and multi-rate padding are covered.

Initial Merkle-Keccak application-only bridge control: 0.03449795 s wallet, 75,152 KiB wait4 RSS (in-process VmHWM 76,660 KiB, differing accounting), 194,584 proof bytes, 9.55529 ms separate verification, 690 arithmetic rows, 131,072 committed words and 17 permutations. Root seed 1 `8d1c538daaf507f9783e9cd7a2875ae611664056ac8d05b30bad55d0359dc2a9`. This raw-root bridge omits the canonical application-identity claim envelope used by shielded; it is a lower-bound exploratory control and must be upgraded before the requested paired wallet comparison.
