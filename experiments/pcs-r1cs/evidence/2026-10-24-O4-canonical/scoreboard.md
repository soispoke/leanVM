# O4 optimization scoreboard

Round: 2026-10-23 23:31-2026-10-24 02:31 UTC. Timed slice cores 0-11, 12 threads. Five rounds, 10 warm samples per component.

Trial references: leanR1CS first/node 3.21/4.22 s; leanVM 2.28/2.62 s.

Scope remains the trial controls: R1CS shielded+Merkle independent children; VM A+B first and duplicated-child node. No eligible challenge scalar or full AB+AH tree is claimed. Complete certificate transport boundaries are retained.

## Best observed completed referee pass

| System | Commit | Trial first/node s | Current first/node s | Pass |
|---|---|---|---|---|
| r1cs | `062eb3c4a071aacf271ac657e2ed13e6f12099e5` | 3.21 / 4.22 | 1.4630 / 2.1915 | r155-final-canonical-streaming |
| vm | `096437a8e89edcd857fab8c9c57dcc53d5ac3f71` | 2.28 / 2.62 | 1.0809 / 1.2468 | r155-final-canonical-streaming |

Selected by the lowest sum of first and node medians within one completed pass, solely as a reporting choice. This is not an eligible score or a matched causal comparison between passes. Admission, root, proof limits and workload scope remain separate.

## Initial frozen trial

Status: complete. Commits: R1CS `9e5f41c4`, VM `146a0e94`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 3.6840 (10) | 4.7461 (10) | 0.0675 (10) | 1.1237 (10) | 12.8632 (10) | 23.6481 (10) | 25.7109 (10) |
| vm | 2.4781 (10) | 2.8727 (10) | 0.0574 (10) | 0.4911 (10) | 0.4716 (10) | 29.3625 (10) | 28.2654 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.202631 | 296.104 | 225.666 | 47 |
| vm | 0.325471 | 184.348 | 118.545 | 40 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r45-o1witness-vmzero

Status: complete. Commits: R1CS `636f69d4`, VM `979226d1`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 3.5725 (10) | 4.6076 (10) | 0.0943 (10) | 1.1146 (10) | 14.6706 (10) | 42.1509 (10) | 42.0963 (10) |
| vm | 1.3101 (10) | 1.4675 (10) | 0.0762 (10) | 0.5269 (10) | 0.5268 (10) | 46.0394 (10) | 46.9935 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.215619 | 278.269 | 209.502 | 48 |
| vm | 0.721146 | 83.201 | 22.797 | 18 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r45-o1witness-vmzero`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r60-o1-o2-cap

Status: complete. Commits: R1CS `92b4c54c`, VM `979226d1`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 2.0509 (10) | 4.2313 (10) | 0.0658 (10) | 0.9771 (10) | 12.5839 (10) | 21.2871 (10) | 28.4956 (10) |
| vm | 1.1839 (10) | 1.4403 (10) | 0.0447 (10) | 0.4515 (10) | 0.4894 (10) | 26.1231 (10) | 27.0338 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.217729 | 275.572 | 205.223 | 47 |
| vm | 0.660445 | 90.848 | 29.919 | 21 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r60-o1-o2-cap`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r90-simd-streaming

Status: complete. Commits: R1CS `3d9bf5ef`, VM `096437a8`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 1.9357 (10) | 4.1242 (10) | 0.0759 (10) | 0.7527 (10) | 10.9945 (10) | 25.2656 (10) | 26.3530 (10) |
| vm | 1.1643 (10) | 1.4465 (10) | 0.0503 (10) | 0.4240 (10) | 0.4457 (10) | 23.1030 (10) | 24.9698 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.237770 | 252.345 | 183.991 | 47 |
| vm | 0.698613 | 85.885 | 25.611 | 19 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r90-simd-streaming`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r105-quad-streaming

Status: complete. Commits: R1CS `af32e484`, VM `096437a8`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 2.0082 (10) | 2.4486 (10) | 0.0733 (10) | 0.8566 (10) | 11.6031 (10) | 23.7022 (10) | 28.5203 (10) |
| vm | 1.2323 (10) | 1.4644 (10) | 0.0547 (10) | 0.4767 (10) | 0.4678 (10) | 24.7570 (10) | 25.3255 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.393693 | 152.403 | 88.811 | 37 |
| vm | 0.699033 | 85.833 | 25.672 | 19 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r105-quad-streaming`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r135-canonical-streaming

Status: complete. Commits: R1CS `062eb3c4`, VM `096437a8`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 1.6224 (10) | 2.2606 (10) | 0.0911 (10) | 0.8981 (10) | 11.4878 (10) | 24.6892 (10) | 26.4590 (10) |
| vm | 1.1627 (10) | 1.3541 (10) | 0.0565 (10) | 0.5014 (10) | 0.4838 (10) | 23.4533 (10) | 22.0319 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.409627 | 146.475 | 82.052 | 35 |
| vm | 0.641928 | 93.468 | 32.621 | 22 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r135-canonical-streaming`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## r155-final-canonical-streaming

Status: complete. Commits: R1CS `062eb3c4a071aacf271ac657e2ed13e6f12099e5`, VM `096437a8e89edcd857fab8c9c57dcc53d5ac3f71`.

| System | First s | Node s | Root s | Shielded s | Falcon s | Shielded admission ms | Falcon admission ms |
|---|---|---|---|---|---|---|---|
| r1cs | 1.4630 (10) | 2.1915 (10) | 0.0499 (10) | 0.7014 (10) | 10.0226 (10) | 16.4417 (10) | 22.6030 (10) |
| vm | 1.0809 (10) | 1.2468 (10) | 0.0321 (10) | 0.3969 (10) | 0.3707 (10) | 16.9016 (10) | 21.6814 (10) |

| System | Cadence throughput /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.445632 | 134.640 | 71.150 | 34 |
| vm | 0.758990 | 79.052 | 18.687 | 15 |

Evidence: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/O4/r155-final-canonical-streaming`. Initial frozen trial binaries retain their original source overlays and hashes; subsequent runs identify frozen candidate builds in selection.json. Timing differences from the trial alone do not establish a matched optimization win.

## Matched quaternary integration comparison

ABAB x3 on cores 0-11, six complete external samples per variant and workload. A: binary cap plus SIMD `3d9bf5ef`; B: quaternary cap plus SIMD `af32e484`. This is separate from the five-round full referee passes.

| Workload | A median s | B median s | Reduction | A / B certificate bytes |
|---|---:|---:|---:|---|
| first | 2.0739 | 2.0069 | 3.2% | 193304 / 235240 |
| node | 4.7291 | 2.7107 | 42.7% | 202765 / 237485 |

Evidence: `artifacts/O4/matched-quad-v-binary`. Full root, admission and cadence checks remain separate.

## Matched virtual-prefix integration comparison

ABAB x3 on cores 0-11, six complete external samples per variant and workload. A: quaternary cap plus SIMD `af32e484`; B: virtual prefix plus fast quaternary cap and SIMD `c91e6aab`. Rejected as an incremental latency optimization: first effectively unchanged, node 4.5% slower. This is separate from the five-round full referee passes.

| Workload | A median s | B median s | Reduction | A / B certificate bytes |
|---|---:|---:|---:|---|
| first | 2.0514 | 2.0448 | 0.3% | 235240 / 228936 |
| node | 2.5316 | 2.6449 | -4.5% | 237485 / 236621 |

Evidence: `artifacts/O4/matched-prefix-v-quad`. Full root, admission and cadence checks remain separate.

## Matched regular-cap virtual-prefix comparison

ABAB x3 on cores 0-11, six complete external samples per variant and workload. A: fast quaternary cap `af32e484`; B: virtual prefix with regular quaternary cap `c91e6aab`. Rejected: first 5.1% slower and node 3.6% slower. This is separate from the five-round full referee passes.

| Workload | A median s | B median s | Reduction | A / B certificate bytes |
|---|---:|---:|---:|---|
| first | 2.0728 | 2.1784 | -5.1% | 235240 / 228648 |
| node | 2.5846 | 2.6786 | -3.6% | 237485 / 238061 |

Evidence: `artifacts/O4/matched-prefix-regular-v-quad`. Full root, admission and cadence checks remain separate.

## Matched canonical-routing comparison

ABAB x3 on cores 0-11, six complete external samples per variant and workload. A: fast quaternary cap `af32e484`; B: canonical routing `062eb3c4`. This is separate from the five-round full referee passes.

| Workload | A median s | B median s | Reduction | A / B certificate bytes |
|---|---:|---:|---:|---|
| first | 1.8822 | 1.6589 | 11.9% | 235240 / 221192 |
| node | 2.5934 | 2.5465 | 1.8% | 237485 / 237965 |

Evidence: `artifacts/O4/matched-canonical-v-quad`. Full root, admission and cadence checks remain separate.

