# leanR1CS vs RISC-V leanVM for EIP-8288

Study of 2026-10-23 and 2026-10-24. It asks whether a frozen circuit format (leanR1CS: R1CS/CCS rows, native hash rows, optional lookups) can serve EIP-8288's proving and recursive aggregation as well as RISC-V leanVM, measured under the same rules on the same machine. This page is the entry point to the code and evidence. The findings, decisions and the challenge built from them are in the Hardness vault: [leanR1CS vs leanVM Results](https://github.com/soispoke/hardness/blob/main/research/experiments/leanR1CS%20vs%20leanVM%20Results.md) and [leanR1CS Challenge](https://github.com/soispoke/hardness/blob/main/research/experiments/leanR1CS%20Challenge.md).

## Summary

With BLAKE2s as the protocol hash, leanR1CS wallets beat leanVM by 1.5 to 6x on statements dominated by a hash that has native rows (BLAKE2s, Merkle paths, leanXMSS, the shielded spend), proofs check about 3x faster, and a true-R1CS mixed merge tree under one application-independent key fits the 1 s interval at about 2x leanVM's merge time. Integer-heavy statements (SHA-256, the MPT storage proof, Falcon-512, ML-DSA-44) are 5 to 13x slower as circuits, and lookup tables made them slower still. Native Keccak rows make Keccak-heavy statements fast (Keccak-256 of 1 KiB 0.076 s, MPT 1.50 s) and halve Falcon-512. With Keccak-f[1600] as the only hash, leanVM is faster at every stage; after one optimization round its merges take 1.08 / 1.25 s against leanR1CS's 1.46 / 2.19 s, and neither sustains one merge per second.

## Setup

One shared Xeon 6230R host. Every timed run used 12 threads on a reserved 12-core slice (`taskset -c <slice> env RAYON_NUM_THREADS=12 LEANVM_NUM_THREADS=12`); builds ran on separate cores. Comparisons are ABAB-alternated (three rounds unless stated) with medians; single runs are labelled. Wallet time is witness plus proof with setup excluded unless stated; RAM is whole-process peak; verification runs in a separate process. Both systems prove the same statements with matching digests ([hometurf-statements.md](../../artifacts/hometurf-statements.md), [keccak-statements.md](../../artifacts/keccak-statements.md)). No proof is zero knowledge, and no new construction here has a soundness proof; rejection tests that bypass prover prechecks are regression evidence only.

leanVM is `riscv-exploration` at `a40a7fa6` (rv64im plus a hash instruction). leanR1CS is this branch.

## Results

Wallet proofs, BLAKE2s protocol:

| Statement | leanVM | leanR1CS | Report |
|---|---:|---:|---|
| BLAKE2s 64 B / 1 KiB | 0.082 / 0.184 s | 0.024 / 0.029 s | [hometurf-results.md](../../artifacts/hometurf-results.md) |
| Merkle path, depth 20 / 32 | 0.074 / 0.080 s | 0.024 / 0.024 s | same |
| leanXMSS verification | 0.103 s | 0.042 s | same |
| Shielded spend, BLAKE2s edition | 0.151 s | 0.095 s small lookups; 0.042 s sparse R1CS | [hometurf-lookup-small.md](../../artifacts/hometurf-lookup-small.md), [hometurf-row-format-comparison.md](../../artifacts/hometurf-row-format-comparison.md) |
| SHA-256 1 KiB | 0.31 s | 1.72 s bit-level; 3.14 s small lookups | [hometurf-integer-lookups.md](../../artifacts/hometurf-integer-lookups.md) |
| Falcon-512 (decoded inputs on leanR1CS) | 0.53 s | 13.4 s bit-level; 5.88 s with Keccak rows | [hometurf-keccak-rows.md](../../artifacts/hometurf-keccak-rows.md) |
| MPT storage proof | 1.30 s | 12.4 s bit-level; 1.50 s with Keccak rows | same |
| Keccak-256 1 KiB | 0.21 s | 1.56 s bit-level; 0.076 s with Keccak rows | same |
| ML-DSA-44 | 6.44 s, 8.0 GiB | 63-72 s, 107 GiB with Keccak rows | [hometurf-mldsa-leanvm.md](../../artifacts/hometurf-mldsa-leanvm.md), [hometurf-keccak-rows.md](../../artifacts/hometurf-keccak-rows.md) |

Merges, BLAKE2s protocol:

| Merge | leanVM | leanR1CS | Report |
|---|---:|---:|---|
| First-level, mixed applications | 0.40-0.42 s (key fixed to one pair) | 0.75-0.98 s (application-independent key) | [hometurf-mixed-merge.md](../../artifacts/hometurf-mixed-merge.md), [hometurf-sparse-tree.md](../../artifacts/hometurf-sparse-tree.md) |
| Node (merged + merged), mixed | 0.37-0.59 s | 0.94-0.97 s | [hometurf-sparse-tree.md](../../artifacts/hometurf-sparse-tree.md) |
| Root acceptance | not measured | 21 ms | same |

Keccak-f[1600] as the only hash, challenge harness, warm medians:

| | leanVM before / after optimization | leanR1CS before / after optimization | Report |
|---|---:|---:|---|
| First-level merge | 2.28 / 1.08 s | 3.21 / 1.46 s | [opt-final.md](../../artifacts/opt-final.md) |
| Node merge | 2.62 / 1.25 s | 4.22 / 2.19 s | same |
| Root acceptance | 41.9 / 32.1 ms | 51.8 / 49.9 ms | same |
| Wallet shielded / Falcon | 0.38 / 0.38 s, after 0.40 / 0.37 s | 0.75 / 10.4 s, after 0.70 / 10.0 s | same |
| Merges per second at one arrival per second | 0.76 | 0.45 | same |

Lookups: small 4-bit tables cut the shielded spend from 148k to 45k rows but made SHA-256 and Falcon slower. Byte-sized tables (LOGIC8, ADD8, MUL8, 2^18 rows) were a net loss on Falcon (12.9 s vs 5.88 s), SHA-256 (4.54 s vs 1.53 s) and did not beat small lookups on the shielded spend ([hometurf-word-tables.md](../../artifacts/hometurf-word-tables.md), [hometurf-keccak-word-tables.md](../../artifacts/hometurf-keccak-word-tables.md)).

## Where everything is

Reports are in [`artifacts/`](../../artifacts) under the names the lanes used; this table maps them to topics. All raw measurements are one JSON line each in [hometurf-12t.jsonl](../../artifacts/hometurf-12t.jsonl).

| Topic | Reports | Code |
|---|---|---|
| Native hash rows, home-turf wallets | [hometurf-results.md](../../artifacts/hometurf-results.md) | this branch |
| leanVM baselines and fixed-pair mixed merge | [hometurf-L2-results.md](../../artifacts/hometurf-L2-results.md), [hometurf-mixed-merge.md](../../artifacts/hometurf-mixed-merge.md) | branch `research/leanr1cs-study/leanvm-baselines` |
| Merge cost diagnosis, rate trade-off, first node merge | [hometurf-L4.md](../../artifacts/hometurf-L4.md), [hometurf-L4-node-handoff.md](../../artifacts/hometurf-L4-node-handoff.md) | this branch |
| Lookup tables (small, integer, byte-sized) | [hometurf-lookup-small.md](../../artifacts/hometurf-lookup-small.md), [hometurf-L3-lookups.md](../../artifacts/hometurf-L3-lookups.md), [hometurf-integer-lookups.md](../../artifacts/hometurf-integer-lookups.md), [hometurf-lookup-model.md](../../artifacts/hometurf-lookup-model.md), [hometurf-word-tables.md](../../artifacts/hometurf-word-tables.md), [hometurf-keccak-word-tables.md](../../artifacts/hometurf-keccak-word-tables.md) | this branch, opt-in |
| Row format and carried claims | [hometurf-row-format-comparison.md](../../artifacts/hometurf-row-format-comparison.md), [hometurf-deferred-r1cs-claims.md](../../artifacts/hometurf-deferred-r1cs-claims.md) | this branch |
| Application-independent mixed merge tree | [hometurf-sparse-tree.md](../../artifacts/hometurf-sparse-tree.md), [CLOSED-RECURSION.md](../../artifacts/CLOSED-RECURSION.md) | this branch |
| Native Keccak rows, Falcon, MPT, ML-DSA circuit | [hometurf-keccak-rows.md](../../artifacts/hometurf-keccak-rows.md) | this branch, opt-in |
| ML-DSA-44 on leanVM | [hometurf-mldsa-leanvm.md](../../artifacts/hometurf-mldsa-leanvm.md) | branch `research/leanr1cs-study/leanvm-mldsa` |
| Keccak everywhere | [hometurf-keccak-everywhere-r1cs.md](../../artifacts/hometurf-keccak-everywhere-r1cs.md), [hometurf-keccak-everywhere-leanvm.md](../../artifacts/hometurf-keccak-everywhere-leanvm.md) | this branch (`keccak-protocol` feature); branch `research/leanr1cs-study/leanvm-keccak-everywhere` |
| Challenge trial (referee and entrant) | [trial/referee-report.md](../../artifacts/trial/referee-report.md), [trial/rules-feedback.md](../../artifacts/trial/rules-feedback.md), [trial/entrant-report.md](../../artifacts/trial/entrant-report.md), [trial/entrant-feedback.md](../../artifacts/trial/entrant-feedback.md), [trial/ENTRY-FORMAT.md](../../artifacts/trial/ENTRY-FORMAT.md) | branches `research/leanr1cs-study/challenge-referee` (harness in `experiments/challenge/`) and `research/leanr1cs-study/challenge-entrant` |
| Keccak merge optimization round | [opt-final.md](../../artifacts/opt-final.md), [opt-scoreboard.md](../../artifacts/opt-scoreboard.md), [opt-O1.md](../../artifacts/opt-O1.md), [opt-O2.md](../../artifacts/opt-O2.md) and its soundness notes in `artifacts/opt-O2/`, [opt-O3.md](../../artifacts/opt-O3.md), [opt-O4.md](../../artifacts/opt-O4.md), [O1b-process-incident.md](../../artifacts/O1b-process-incident.md) | this branch (leanR1CS); branch `research/leanr1cs-study/leanvm-keccak-everywhere` (leanVM); unintegrated leanR1CS candidate on `research/leanr1cs-study/r1cs-compact-merge` |
| Earlier native-prover lanes | [laneC-results.md](../../artifacts/laneC-results.md), [laneD-results.md](../../artifacts/laneD-results.md), [D-wallet-mode-report.md](../../artifacts/D-wallet-mode-report.md), [D-batch12-independent-audit.md](../../artifacts/D-batch12-independent-audit.md), and `experiments/pcs-r1cs/evidence/2026-10-2*` | this branch |

## Reproducing a number

Each report lists its source commit, binary hashes, commands, core slice and every sample. The challenge harness on `research/leanr1cs-study/challenge-referee` (`experiments/challenge/`, see its README) reruns both systems with the trial's boundaries: fresh seeded inputs, cold and warm runs, process-group RSS, complete forwarded bytes and the one-per-second cadence.

## Commit history

The lanes worked in local worktrees of one shared repository whose git directory was later removed. Everything already pushed to this branch keeps its history. The work that was never pushed was recovered from the worktree files and committed as one snapshot per lane on the `research/leanr1cs-study/*` branches, each on its original public base (`a40a7fa6`, `65745ca1` or `9e5f41c4`) and with its original local tip named in the commit message. Local commit hashes cited in reports for those lanes, such as `096437a8` or `dc58826b`, therefore no longer resolve; the snapshot branch holds their final tree.

| Branch | Content | Base |
|---|---|---|
| `research/leanr1cs-study/leanvm-baselines` | home-turf leanVM guests and harness, fixed-pair mixed merge | `a40a7fa6` |
| `research/leanr1cs-study/leanvm-mldsa` | ML-DSA-44 as a plain RISC-V program | `a40a7fa6` |
| `research/leanr1cs-study/leanvm-keccak-everywhere` | Keccak-only leanVM, then the optimization round on top | `a40a7fa6` |
| `research/leanr1cs-study/challenge-referee` | challenge harness and Keccak shielded circuit | `65745ca1` |
| `research/leanr1cs-study/challenge-entrant` | trial entries 0-8 (six-slot key bundle, raw-byte Falcon) | `65745ca1` |
| `research/leanr1cs-study/r1cs-compact-merge` | unintegrated compact Keccak merge candidate (1.415 s first-level, own cores) | `9e5f41c4` |

## Not shown

No soundness proof for the native Keccak rows, the carried-claims tree or the lookup arguments; no zero knowledge; no eligible challenge score for either system; no counted comparison of the frozen surface; no realistic-hardware or phone measurements.
