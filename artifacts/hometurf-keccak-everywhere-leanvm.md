# L7: Keccak throughout leanVM

Full protocol migration is implemented locally. Nothing has been pushed. Candidate `lvm-L7`, branch `hometurf/L7`, is based on `a40a7fa6`; instruction stage is local commit `ef342ea4`, with the protocol migration saved in local commit `94652ae8`. Control is the same baseline plus identical application harnesses and fixed-pair merge extension.

Keccak-f[1600] now underlies protocol hashing, native/recursive Fiat-Shamir, PCS/Merkle trees, program identities, SDK public commitments and guest application hashing. Standard Keccak-256 uses rate136 and suffix01. Fiat-Shamir seed/grinding preimages are `LVFSH001 || a32 || b32` (72 bytes); steps are `LVFSS001 || state32 || tagged_block64` (104 bytes). Grinding and the security/query tables remain in place. Leaf/tree envelopes are version15/11; program domain is `leanvm-rv64im-keccak-13`. The old BLAKE protocol module, opcode, instruction class and SDK implementation are removed. Historical directory/package names may remain.

The custom2 opcode0x5b reads25 lanes and writes25 separate output lanes in a512-byte-aligned bank. The CPU uses the generic Keccak gate-list circuit, k_log16; the separately optimized Flock circuit is tested but is not the CPU circuit. Recursion uses full25-lane states and a50-port permutation table. Merkle sibling lanes are witness values, preserving circuit shape across proofs.

## Measurement method

ABAB ×3, six fresh processes per variant/workload, CPU24–35,12 threads. A is baseline/software application Keccak; B is full protocol and instruction Keccak. Whole-process peak RSS is KiB. Verification uses a separate process. Leaves use rate1/4; recursion1/2. Merge setup is timed separately, excluded from merge seconds and included in RSS. Frozen executables/ELFs and SHA256 manifests, individual stdout/stderr, resources and raw samples are retained. Metrics append under a file lock to `artifacts/hometurf-12t.jsonl`, system leanvm, laneL7. Rows describe direct recursion circuits; cycles apply to guest execution.

## Full protocol wallet medians

| Workload | Variant | Prove s | RSS KiB | Proof bytes | Fresh verify ms | Verify RSS KiB | Cycles | Words |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| shielded | A | 0.992980 | 1255536 | 244006 | 15.069239 | 65434 | 403435 | 13850016 |
| shielded | B | 0.483123 | 515052 | 215190 | 24.269347 | 83672 | 106245 | 5182376 |
| merkle | A | 0.320280 | 399040 | 217878 | 14.722684 | 65520 | 102140 | 3595888 |
| merkle | B | 0.139433 | 136486 | 192702 | 25.445656 | 81810 | 12339 | 690776 |
| keccak1k | A | 0.205432 | 227040 | 211478 | 13.245565 | 67342 | 47956 | 1885616 |
| keccak1k | B | 0.109415 | 116266 | 187694 | 25.510800 | 82588 | 6007 | 472632 |
| falcon | A | 0.669352 | 691598 | 231358 | 18.261516 | 64836 | 147758 | 7916072 |
| falcon | B | 0.555896 | 557780 | 220430 | 26.646646 | 80854 | 109170 | 6097480 |
| mpt | A | 0.964493 | 1211004 | 242574 | 13.812529 | 65620 | 396805 | 13400864 |
| mpt | B | 0.354772 | 398956 | 218358 | 26.826674 | 80952 | 84571 | 3493288 |

## Full protocol merge medians

| Case | Variant | Merge s | Setup s | RSS KiB | Proof bytes | Fresh verify ms | Verify RSS KiB | Circuit rows | Words |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| same | A | 0.439741 | 0.286505 | 512310 | 258859 | 12.895333 | 189462 | 130765 | 5948416 |
| same | B | 2.922261 | 2.571911 | 2615528 | 307563 | 38.874275 | 1026626 | 890514 | 26674176 |
| mixed | A | 0.385583 | 0.266183 | 516512 | 259755 | 14.111946 | 194674 | 125960 | 5948416 |
| mixed | B | 2.627567 | 2.275116 | 2631696 | 308107 | 32.321265 | 1003744 | 824472 | 26674176 |
| node-mixed | A | 0.402534 | 0.255199 | 526264 | 260107 | 15.357465 | 199508 | 116717 | 5948416 |
| node-mixed | B | 2.934781 | 2.219887 | 2813506 | 307019 | 40.801253 | 1002732 | 1235791 | 26674176 |

Full Keccak improves wallet proving time and memory for these applications, while recursive proving cost and memory increase substantially. This is measured end-to-end behavior, not a projection from standalone permutation timings.

## Statement parity and remaining work

Shielded is exact depth20 seed20261024,1680-byte input, statement `599943d4ea06d97bbd20b602add63200e167a17a72d9775d91d33fa3eb72e4d3`, validity1. Merkle is exact depth16 seed1, bit1=current left, corrected root `1357b0fe3e7707641fdc297b6e3b8810a9d98be16f1474446ce61974bb7d4327`. The opposite-orientation root was withdrawn before ABAB. Keccak1KiB uses shared splitmix seed20261024.

Falcon512 and MPT A/B match each other but currently use VM-native `batch(1)`/`reads(1)` fixtures. They do not match the exact L6 fixtures/statements: Falcon uses a different key/message/signature, and VM-native MPT includes blockheader anchoring whereas L6 is bounded storage inclusion. These rows must not be presented as exact paired L6 comparisons. Exact fixture variants are measured separately below. Available L6 medians are compared below. See `artifacts/keccak-statements.md`. No missing L6 median is inferred.

## Validation

Final protocol core release suite:210 passed. Focused Keccak Flock suite:5 passed, including transcript-label and tamper rejection. Native Fiat-Shamir11, SDK14, PCS44 and primitives35 passed. Clippy over changed crates/all targets passed. Verifier integration:25 passed,2 pre-existing ignored; the malformed-ELF fixture was adapted to the rebuilt writable segment layout. Full-protocol shielded/Merkle wrong-path and tampered-proof rejection screens pass. Same, mixed and node-mixed merge program-identity/output/root tamper checks pass for both variants. Security/query config diff against baseline is empty; SECURITY_BITS remains128 and grinding remains enabled.

Historical instruction-only/BLAKE-protocol ABAB is retained unchanged in `wallet-abab/` and `merge-abab/`. Current full-protocol rows are isolated in `protocol-wallet-abab/` and `protocol-merge-abab/`; the historical rows are not substituted for full-protocol results. The optimized primitives were reused from upstream PR636 commit5746f579 without importing its GKR architecture, and optimized standalone Flock Keccak from L4k796cf1b0.

## Exact L6 Falcon and MPT variants

The fixture export tool `artifacts/L7/export-exact-fixtures.rs` reads L6 circuit_suite directly. Frozen JSON is `artifacts/exact-l6-fixtures-seed20261024.json`. Both A and B use new guest variants, leaving the VM-native measurements unchanged. Falcon exposes SHAKE256(NIST-encoded public key || message), validity1 and zero padding as the 64-byte L6 statement. MPT proves bounded account/storage inclusion with at most 9/7 nodes, 532-byte inner nodes, 148/70-byte leaves, hashed references, canonical RLP/path checks and nonzero storage. It exposes Keccak256(R32||A20||S32||V32), validity1 and zero padding. As with shielded, the VM receipt's public output is the SDK digest of this statement.

| Workload | Variant | Prove s | RSS KiB | Proof bytes | Verify ms | Verify RSS KiB | Cycles | Words |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| falcon-l6 | A | 0.708188 | 863294 | 227382 | 13.965558 | 66880 | 209954 | 9401760 |
| falcon-l6 | B | 0.519865 | 561496 | 220110 | 27.439591 | 78910 | 125526 | 6146232 |
| mpt-l6 | A | 0.874314 | 1190320 | 242254 | 13.462169 | 66404 | 409373 | 13311136 |
| mpt-l6 | B | 0.507386 | 547580 | 218102 | 24.196400 | 81792 | 144097 | 5725608 |

Exact MPT seed20261024 statement: `ebce2b98f2d26e025e2ed7f93f05af0635092210079ee9cb8fb0b2d91ec88862`, validity1. The corresponding proof has 8 account nodes and 6 storage nodes. Both workload receipts prove and verify in fresh processes for all 12 A/B samples. Raw artifacts: `exact-l6-wallet-abab/`.

## Comparison with available L6 medians

Both candidates use Keccak throughout and retain 128-bit targets and grinding. L6 runs on CPUs12–23 and L7 on24–35, each12 threads. These are separate implementations and PCS layouts: L6 joint inverse rate4/index16 versus L7 leaves1/4 and recursion1/2. L7 public outputs commit the application statement through the SDK; L6 uses its stated raw-root/canonical claim envelopes. L6 wallet time excludes key setup; L7 wallet time includes its prover initialization. Whole-process RSS includes setup in both. These differences are part of the measured implementations, so the table does not isolate a hash primitive's cost.

| Wallet | L6 prove s | L7 prove s | L6 RSS KiB | L7 RSS KiB | L6 proof bytes | L7 proof bytes | L6 verify ms | L7 verify ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| shielded | 0.809183 | 0.483123 | 980804 | 515052 | 286896 | 215190 | 11.019 | 24.269 |
| falcon | 10.527342 | 0.519865 | 14051744 | 561496 | 361720 | 220110 | 12.087 | 27.440 |
| keccak | 0.156304 | 0.109415 | 210792 | 116266 | 238992 | 187694 | 11.099 | 25.511 |
| mpt | 2.577743 | 0.507386 | 3572454 | 547580 | 324072 | 218102 | 10.789 | 24.196 |
| depth16 Merkle | pending | 0.139433 | pending | 136486 | pending | 192702 | pending | 25.446 |

| Composition | L6 merge s | L7 merge s | L6 RSS KiB | L7 RSS KiB | L6 proof bytes | L7 proof bytes | L6 complete root ms | L7 complete root ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mixed | 3.590186 | 2.627567 | 5194844 | 2631696 | 206192 | 308107 | 27.219 | 32.321 |
| node-mixed | 4.494221 | 2.934781 | 6028958 | 2813506 | 205552 | 307019 | 43.607 | 40.801 |

L6 merge figures use its fixed-prefix optimization and explicit wrapper layout. L7 node-mixed merges two identical copies of the measured mixed child. Both complete-root timings settle the active carried claims; the smaller L6 core-only verifier timing is not substituted here. Same-program L7 results appear above; no matching L6 same-program median was available.

## Final local validation and provenance

Candidate local HEAD: `146a0e94`. No push. Core210, verifier integration25 (2 pre-existing ignored), focused Flock5, primitives35, PCS44, Fiat-Shamir11 and SDK14 tests passed. Final host/core all-target clippy passed. Exact RISC-V guests build successfully; the nightly guest toolchain has no cargo-clippy component, so no guest-bin clippy pass is claimed. Wrong paths, wrong transcript labels, changed programs, mutated exact Falcon/MPT witnesses and tampered leaf/root proofs are covered by the tests/screens described above. `exact-statement-parity.json` records equality of Falcon and MPT statements with L6 receipts. The final config diff is empty. Historical failed logs remain available and are superseded by the named successful final runs.

The implementation and L7 measurement work are complete. The L6 Merkle median and a matching L6 same-program comparison remain unavailable; their cells are reserved. No performance target is claimed: full-protocol recursive merges remain above one second.

Completion audit: `hometurf-L7/completion-audit.json`, reproduced by `lvm-L7/artifacts/L7/audit-completion.py`, passes all L7 requirements and verifies 240 successful fresh-process receipts, frozen hashes, ABAB ordering, medians and JSONL records. External L6 comparison cells do not leave a required L7 measurement outstanding.
