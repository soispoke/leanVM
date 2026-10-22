# Common-key memory and recording search

No candidate met the predeclared complete-workload retention rule. The common-key implementation published at `d2930534` remains unchanged. All experimental patches are preserved, and none is enabled on the research branch.

Each small screen uses three alternating fresh-process pairs, two distinct leaves, 16 BLAKE2s chain steps per leaf and 32 workers on CPUs 0-63. Every process creates one common setup, three certificates, explicit verification and adversarial root/height checks. Control sources are the published closure tree. Exact source and executable hashes bind every process. Total is complete child-process elapsed time; all creation includes recording, witness preparation, proving and internal-node child prechecks; root is creation of the final certificate alone.

| Candidate | Control / candidate total (s) | Paired total reduction | All-creation reduction | Root reduction | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Stack hash-input bytes | 8.401 / 8.776 | -2.12% | -0.82% | -3.06% | Reject |
| Fine parallel initialization | 8.054 / 8.103 | -0.87% | +1.02% | +5.00% | Reject |
| Coarse parallel initialization | 8.258 / 8.169 | +1.48% | +2.09% | +3.31% | Reject |

Reductions are medians of individual paired ratios, not ratios of the independent medians. Positive means faster. The first candidate assembles each scalar's hash bytes on the stack and reserves the combined byte buffer once. It passes all 76 native tests but does not improve the workload. The second skips a zero-fill pass over arithmetic commitment storage and initializes spare capacity in small parallel chunks. The third changes that initialization to whole limb-column chunks. Both initialize every value and canonical padding word before exposing the vector length; an equal-column-length guard and rejection test protect that memory-safety condition. No circuit equation, layout, public value, security parameter or proof format changes.

The coarse version won all three small pairs but its total and all-creation gains remained below the 3% threshold. Its root screen improved 3.31%, so seven independent eight-leaf pairs were run as a scaling diagnostic, with the same workload rule kept intact. This is not a post-hoc acceptance of a root-only gain.

| Eight leaves, seven pairs | Control / candidate median | Paired reduction | Paired bootstrap 95% interval | Wins |
| --- | ---: | ---: | ---: | ---: |
| Total process (s) | 25.602 / 25.590 | +0.85% | -0.11% to +2.20% | 5/7 |
| All creation (s) | 22.561 / 22.412 | +1.28% | -0.06% to +2.78% | 5/7 |
| Root creation (s) | 1.475 / 1.442 | +2.33% | +0.32% to +3.49% | 6/7 |

Retention requires at least 3% paired median improvement in total or all creation, a positive paired-bootstrap interval, at least six wins in seven target pairs and no material companion regression. The target misses both the size and robustness requirements for those complete-workload metrics. Its smaller root gain does not justify retention. Intervals use 20,000 deterministic resamples of paired reductions; this shared-host screen has no multiple-comparison correction. The full metrics, including setup, verification, CPU and RSS, are in [results.json](results.json).

## Validation

The audit independently recomputes all BLAKE2s leaf/node statements and validates 32 fresh processes containing 264 locally verified certificates. Every key, exact shape and per-position certificate length/scalar count/Merkle phase count matches both its control and the published closure baseline. Root certificates remain 329,852 bytes for two leaves and 330,044 bytes for eight leaves, including the 36-byte certificate header. The audit also checks that all timed measurement intervals are serial.

The hashing candidate passed 76 native tests. Fine initialization passed the 76-test suite and six targeted native layout/safety tests after adding its guard, plus release Clippy. Coarse initialization passed all 77 native tests and the release build. Each candidate's release executable was built through Yukon before measurement. Formatting mutations are explicitly recorded as source-changed receipts and are not interpreted as test failures or as successful immutable checks. No rejected source is merged. No Lean source changed. These tests do not establish formal soundness or official recursion.fast acceptance.

## Tooling and next experiment

The current upstream Yukon revision is `34331e85f931c5bffa85a1200f11429a3e00a499`. The shared stack advanced during research; an isolated clean worktree at `/root/yukon-autoresearch/workspaces/yukon-latest-20261022` pins the new revision for subsequent loops. The benchmark runner stayed byte-identical at `ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e`. Raw receipts retain the revision actually reported for each run. The earlier closure checkpoint includes revision `034f7e7` and some later checks/screens at `34331e8`; its baseline timings are unchanged. The new experiment advisor passes its 22 portable tests. Its planning scores are not prover speedups.

Rust 1.99.1 uses native CPU features plus pclmul, four Cargo build jobs, a 40 GiB host reserve, 96 GiB build/test budget and 16 GiB benchmark budget. Sampled process RSS is not cgroup isolation. Runs use a shared Xeon Gold 6230R host; fresh alternating controls matter more than comparing absolute timings across phases.

The next higher-value hypothesis is fusing the lane-major transpose with commitment encoding's first NTT pass, removing a full intermediate write/read sweep. It is a proposed mechanism, with no accepted code or measured gain yet. The long-running optimization goal remains active.

## Evidence

`raw-evidence.tar.gz` contains every new build/test/measurement receipt and raw log, the three rejected patches, scripts and the retention protocol. Its internal manifest binds every member. Executable binaries and compiler caches are excluded. Run `python3 verify-archive.py` here to validate archive checksums without extraction. Historical scripts retain their original paths; use adapted paths and fresh output directories for reruns, starting from the published closure tree and applying one archived patch at a time.
