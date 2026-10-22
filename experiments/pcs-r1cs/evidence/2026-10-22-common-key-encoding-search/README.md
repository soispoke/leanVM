# Common-key encoder research

Retained the PCLMUL pair kernel after repeated whole-tree measurements.

The experiment keeps the common circuit, setup key, transcript, security parameters, statements and every per-position certificate byte length, scalar count and Merkle phase count unchanged. These are chain16 local fixtures, not shielded-transfer workloads or matched leanVM/Flock comparisons.

## Screens

Three alternating fresh-process pairs, two leaves and three certificates per process. Positive reductions mean faster. Medians of paired ratios differ from ratios of the displayed medians.

| Candidate | Total control / candidate (s) | Paired total reduction | All creation reduction | Root creation reduction |
| --- | ---: | ---: | ---: | ---: |
| Tiled transpose/NTT fusion | 8.035 / 7.995 | +0.50% (2/3) | +0.26% | +2.12% |
| PCLMUL pair kernel | 8.029 / 8.090 | -0.99% (1/3) | +3.26% | +4.52% |

Naive fusion replaced the row-major transpose with strided column reads. A preliminary smoke was slower, but is excluded because its original wrapper bound the control run to the candidate source directory. The original wrapper, executable hashes and logs are preserved. Tiled fusion reads adjacent source residues together, uses cache-bounded scratch and falls back to the original transpose when tiling would add a gathered sweep. Direct full-codeword and callback exact-coverage tests cover replication, fallback and tiled plans, odd/non-power-of-two lane counts and repeated gathered passes. All 44 active PCS tests passed (one existing ignored test). Its small end-to-end gain was insufficient for confirmation.

The pair kernel targets x86 with PCLMULQDQ but without the AVX2 VPCLMUL path. It issues two carry-less products, packs their high/low halves and reduces both field elements together with SIMD shifts/XORs. The existing vector kernels and scalar field arithmetic are unchanged. Five encoder reference tests and all 76 native tests passed. A later compile-time guard broadening covers VPCLMUL without AVX2; targeted encoder tests and the rebuilt executable passed after that change. Screen source and the formatted target source have separate preserved patches.

## Independent eight-leaf confirmation

Seven new alternating pairs, 15 locally verified certificates per process. Each process includes common setup, every proof creation, explicit verification, serialization/reporting and wrong-root/height rejection checks. Creation includes recording, child prechecks, witness preparation and proving. No timed jobs overlap.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| Whole process | 25.741 | 25.081 | +3.22% | 7/7 | [+2.19, +4.37]% |
| All creation | 22.663 | 21.943 | +2.92% | 7/7 | [+2.58, +4.74]% |
| Root creation | 1.477 | 1.428 | +2.46% | 5/7 | [-0.15, +5.22]% |
| Setup | 2.870 | 2.755 | +2.84% | 5/7 | [-0.06, +6.76]% |

Decision: retain. Retention requires at least 3% paired median reduction in total or all creation, at least 6/7 target wins, a positive paired bootstrap 95% interval and no companion regression over 1%. Root-only gains do not qualify. All keys, shapes and corresponding proof lengths match the published common-key baseline. The independent validator recomputes each leaf/node statement.

Final target-source release gates pass: 76 native tests, 43 active PCS tests (one existing ignored), Clippy with tests/examples and warnings denied, formatting, strict rustdoc, and x86 checks covering AVX-512 VPCLMUL, AVX2 VPCLMUL and VPCLMUL without AVX2. Cross-feature checks type-check the arms; only the native host configuration was executed.

## Provenance and reproduction

Yukon is pinned at ab2cc2ec9b55c35d6d5b6858170512d232b0d3c6 for tiled and pair experiments; earlier naive checks use bec1483300f5d052a31db3a5be75e1496742c7d0. The runner SHA256 stayed ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. Rust 1.99.1, native CPU flags plus pclmulqdq, 32 workers, CPUs 0-63, four Cargo build jobs. Build/test budget 96 GiB, benchmark budget 16 GiB and host reserve 40 GiB. The shared Xeon Gold 6230R host is not a dedicated benchmark host. RSS is sampled process-group memory, not cgroup isolation. Source/binary/runner hashes and exact commands remain in receipts. The formatting mutation receipt is intentionally false because source hashes changed during cargo fmt, not because a semantic test failed.

Build through current Yukon with cargo build --locked --release -p rec_aggregation --example closed_tree, then run the frozen control/candidate executables at --depth 1 --chain 16 and --depth 3 --chain 16 in the archived alternating order. Use fresh output directories. The wrappers bind sources and executable hashes. The target differs from the screen only in formatting and compile-time guards inactive on this host. Exact original source patches are preserved.

The archive excludes compiler caches and executable binaries. Run python3 verify-archive.py for member/digest verification. results.json contains every admitted row; raw-evidence.tar.gz includes logs, receipts, rejected patches, scripts, the predeclared plan and excluded smoke. The broader persistent performance goal remains active; implementation tests do not settle the formal composition proof or official recursion.fast integration.
