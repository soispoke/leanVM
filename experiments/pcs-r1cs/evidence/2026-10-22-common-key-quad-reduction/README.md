# Common-key witness and wider-reduction research

Retained the four-element PCLMUL/AVX2 reduction after seven independent eight-leaf pairs.

The control is the previously accepted [two-element kernel](../2026-10-22-common-key-encoding-search/README.md), source c22831cf. Measurements below compare fresh controls and candidates within each pair. They do not establish a new matched comparison against leanVM or Flock. Chain16 leaves use the same common circuit at every level.

## Two-leaf screens

Three alternating fresh-process pairs, three certificates per process. Positive paired reductions mean faster; paired ratios and independent medians are different statistics.

| Candidate | Total control / candidate (s) | Total reduction | All creation reduction | Root creation reduction |
| --- | ---: | ---: | ---: | ---: |
| Parallel connector products | 7.955 / 7.950 | -0.99% (1/3 wins) | -1.32% | -1.87% |
| Four-element AVX2 reduction | 7.846 / 7.615 | +4.06% (3/3 wins) | +3.88% | +7.28% |

Parallel connector products replaced the serial helper-value loop with a flat map_collect over independent group/block pairs. It retained full F192 arithmetic and passed all 76 native tests, including malformed connector-limb rejection. The added temporary vector and dispatch did not produce a whole-workload gain; the patch was rejected and restored.

The retained kernel still uses scalar carry-less multiply instructions, so it works on this host without VPCLMULQDQ. Four products are packed into low/high AVX2 vectors and reduced together by shifts and XORs. The two-element kernel handles pairs and non-AVX2 hosts, and scalar arithmetic handles an odd tail. Existing VPCLMUL and ARM paths are unchanged. Encoder scalar-reference tests cover odd and non-power-of-two lane counts.

## Independent eight-leaf confirmation

Seven new alternating pairs, 15 locally verified certificates per process. Total includes setup, every leaf and internal creation, explicit verification, serialization/reporting and wrong-root/height rejection. Creation includes recording, child prechecks, witness preparation and proving. Timed jobs are serial.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| Whole process | 24.786 | 24.044 | +3.52% | 6/7 | [+0.78, +3.76]% |
| All creation | 21.726 | 21.062 | +3.73% | 7/7 | [+0.96, +3.93]% |
| Root creation | 1.406 | 1.378 | +2.18% | 5/7 | [-0.86, +5.33]% |
| Setup | 2.721 | 2.735 | -0.24% | 3/7 | [-3.54, +2.19]% |

Decision: retain. The frozen rule requires at least 3% paired median reduction in total or all creation, at least 6/7 target wins, positive paired bootstrap 95% interval and no companion regression over 1%. Every key, shape, statement and per-position certificate length, scalar count and Merkle phase count matches both variants and the original common-key baseline. The independent Python validator recomputes all leaf/node statements.

## Validation and provenance

Final gates pass: 76 native tests, 43 active PCS tests (one existing ignored), Clippy with tests/examples and warnings denied, formatting, strict rustdoc and x86 checks covering AVX-512 VPCLMUL, AVX2 VPCLMUL, VPCLMUL without AVX2 and PCLMUL without AVX2. Cross-feature checks type-check those arms; only the native host arm was executed.

All loops use current Yukon, isolated at 83ae1385bfcc5c93f26d117c65f42984cf711028. The control build just before the phase refresh used ab2cc2e. Runner SHA256 is unchanged at ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. Rust 1.99.1, native CPU plus pclmulqdq flags, 32 workers and CPUs 0-63. Build/test budget 96 GiB, benchmark budget 16 GiB, host reserve 40 GiB and four Cargo jobs. The Xeon Gold 6230R host is shared. RSS is a sampled process-group measure, not cgroup isolation. Exact commands, source/build/binary hashes and raw receipts are retained. The formatting mutation receipt reports false because cargo fmt changed source hashes, not because a test failed.

An initial witness-extension edit used the wrong cwd and failed before changing source. It unintentionally launched a check before the correct edit; that attempt was terminated and excluded. Its replacement bound the edited source correctly, waited for the build lock and passed all 76 native tests. The excluded receipt is preserved and does not support any timing claim.

For reproduction, build closed_tree through current Yukon with the recorded flags, then run frozen control/candidate binaries at --depth 1 --chain 16 and --depth 3 --chain 16 in alternating order under the source-bound archived wrappers. Use new output paths. Rejected/retained source patches and the predeclared retention plan are in raw-evidence.tar.gz. Run python3 verify-archive.py here to check every archived member hash without extraction. Compiler caches and executable binaries are excluded. The persistent optimization goal remains active; native tests do not settle the formal composition proof or official recursion.fast integration.
