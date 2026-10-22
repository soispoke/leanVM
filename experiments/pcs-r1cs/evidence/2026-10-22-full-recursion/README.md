# Full-length recursion checkpoint (incomplete)

These preserved runs use 16,384 tagged BLAKE2s steps per leaf and the witness-schedule native baseline. Global memory admission interrupted the requested full set. The subsequent request prioritizes small experiments, so the missing full-length cases have not been resumed. This directory is a partial checkpoint, not a completed comparison.

| Leaves | Native trials | Native process (s) | Native root prep + prove (s) | leanVM trials | leanVM process (s) | leanVM root prep + prove (s) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 3 | 28.581 | 1.316 | 3 | 52.639 | 1.126 |
| 4 | 3 | 49.135 | 1.036 | 0 | Pending | Pending |
| 8 | 2 | 87.245 | 1.018 | 0 | Pending | Pending |

Times are medians of completed successful trials. The eight-leaf native row has only two measured trials. Whole-process timers include setup, all proofs, verification and negative checks, plus up to about 0.5 s of exit-observation delay. Root timers exclude setup and child proving. Trial ordering changed as memory pressure prevented larger VM jobs; these are shared-host measurements, not an architectural ranking.

For two leaves, native/VM root proving alone is 1.236/1.084 s, root verification is 5.69/12.08 ms and complete root proofs are 337,880/317,968 bytes. Native setup totals 7.962 s and leaf proving is 9.282 s per leaf. VM setup totals 0.432 s and leaf proving is 23.900 s per leaf. See [partial-summary.json](partial-summary.json) for all available totals, shapes, peaks and raw trial paths.

## VM comparison adjustment

The frozen original VM cannot aggregate the full-length leaves: its wrapper rejects `log_committed = 30` with `ChildOutOfRange`. The separately built comparison changes only the wrapper dispatch ceiling from 28 to 30, already supported by the core PCS. [leanvm-mu30.patch](leanvm-mu30.patch), [inputs.json](inputs.json), the successful release build and all three targeted tree tests are retained. This is an expanded-dispatch comparison, not the unmodified VM baseline. Native source and executable remain the published witness-schedule baseline.

## Flock context

The [published Flock BLAKE2s baseline](../2026-10-22-flock-blake2s-baseline/README.md) uses a different sequential tower of eight 256-step segments. Its median complete tower creation is 209.422 s; root online preparation, proving and inline checks are 13.392 s; root proving alone is 1.893 s; complete consumer verification is 10.337 s; the complete proof bundle is 414,354 bytes. These are contextual figures with different workload and timing boundaries, so no cross-workload speedup is claimed.

The fresh Flock rerun in this directory was stopped by the global memory reserve after 534.413 s. Its first tower completed and verified (222.671 s creation, 10.456 s consumer verification and unchanged proof lengths), but the three-trial process did not finish. It is not counted as a successful repeated benchmark. `run_flock-interrupted.py` preserves the exact initial script; `run_flock.py` is the corrected retry script and no successful retry is claimed.

## Audit and scope

[audit_partial.py](audit_partial.py) revalidates every completed measured tree, independent statement digests, guard/log hashes and stable per-backend circuit geometry, without filling in missing cases. [audit.py](audit.py) remains the original complete-set gate and intentionally cannot pass until the missing cases exist. Build and test receipts, unsuccessful attempts, exact executable/source hashes, measurement scripts and the Yukon runner snapshot are preserved. Executables and build caches are not committed. The scripts refer to original absolute workspaces and need path adaptation on another machine.

Separate trusted keys per level, recursive closure, a standalone protocol specification and a formal proof of the new composition remain open. These local Rust measurements are not an official recursion.fast result. [MANIFEST.json](MANIFEST.json) hashes all retained evidence files except itself.
