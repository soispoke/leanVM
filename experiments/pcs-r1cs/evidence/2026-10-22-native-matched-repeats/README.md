# Repeated native recursion and leanVM measurements

These local development runs use the same tagged BLAKE2s hash-chain tree, Rust 1.99.1, 16 workers, CPU affinity 0-15 and an Intel Xeon Gold 6230R shared host. Each backend verifies its own child proofs. Every resulting statement is independently recomputed with Python's BLAKE2s. These are implementation measurements, not official recursion.fast scores or an architectural ranking.

## Current candidate

Source `f1b6626fc546956085f4512d8210f715e6dd256b`; leanVM reference source `bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47`. The native joint WHIR rate is 1/4 and its index rate is 1/16; leanVM uses its default 1/2. Parameters and transcript labels remain fixed within each backend.

All leaves contain 16 hash-chain steps. Parent creation includes symbolic recording, trace lowering, witness preparation and proving. It excludes setup and child proving. Full verification and proof size include auxiliary records. KB means 1,000 bytes.

| Leaves / aggregation levels | Trials per backend | Candidate root creation (s) | leanVM root creation (s) | Candidate / leanVM verification (ms) | Candidate / leanVM proof (KB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 / 1 | 7 | 1.042 | 1.097 | 5.61 / 11.51 | 325.4 / 284.4 |
| 4 / 2 | 3 | 1.700 | 1.097 | 5.89 / 15.46 | 338.3 / 318.4 |
| 8 / 3 | 3 | 1.581 | 1.100 | 6.34 / 18.78 | 336.2 / 324.1 |

These are medians of fresh-process trials, alternating execution order, after one excluded warmup process per backend and workload. At two leaves, root creation ranges are 1.006-1.080 s for the candidate and 1.051-1.234 s for leanVM. All seven adjacent pairs favor the candidate; the median paired speedup is 1.070x. The ratio of the two medians is 1.053x. These are different summaries of the same seven pairs.

The shallow candidate matches leanVM's performance range in this series. Deeper native roots remain slower. The VM wrapper forwards authenticated deferred records at each level, and the root verifies all of them. Its growing verification time is not an inherent cost of upstream leanVM's fixed-program recursion.

| Leaves | Candidate whole process (s) | leanVM whole process (s) | Candidate / leanVM maximum process RSS (GiB) |
| --- | ---: | ---: | ---: |
| 2 | 2.006 | 2.007 | 3.08 / 2.53 |
| 4 | 6.017 | 4.515 | 6.61 / 3.48 |
| 8 | 11.539 | 9.525 | 7.64 / 3.52 |

Whole-process time includes setup, leaf proofs, intermediate proofs, verification and negative checks. The process monitor adds up to approximately 0.5 s of completion-poll delay; do not use the two approximately 2 s process measurements to claim precise equality. Peak RSS is a process high-water mark, not hardware-isolated memory accounting. Every run stayed within the 32 GiB guard and preserved at least 40 GiB global memory headroom.

## Rechecking the earlier diagnostic

`matched-kernels-seven` repeats the previously quoted candidate at source `926264e3e9da1e8b92cd41ef2239a60049aa917a`, with seven alternating trials and one excluded warmup per backend. Its median two-child creation time is 1.231 s versus leanVM's 1.081 s, about 14% slower. This confirms that the original single diagnostic run was not evidence of parity. The newer candidate adds dense compiler membership tables, cached immutable lowering analysis and direct compact witness preparation.

## Evidence and checks

Each directory contains complete stdout, stderr, process receipts, exact commands, source/binary hashes and the validated `summary.json`. The `*-guard` records contain Yukon runner receipts and source manifests. Frozen executable hashes and exact schedules are retained beside them; executables themselves are not committed. The schedules contain the original machine's absolute paths. For another machine, build the named revisions, substitute their paths and preserve new hashes and receipts.

- `matched-compact-plan-seven/summary.json`: seven shallow pairs.
- `matched-compact-plan-depth2/summary.json`: three four-leaf pairs.
- `matched-compact-plan-depth3/summary.json`: three eight-leaf pairs.
- `matched-kernels-seven/summary.json`: seven pairs for the earlier diagnostic candidate.
- `main-compact-plan-tests`: all 70 native release library tests passed, including malformed connector proofs and compact-limb/transcript equivalence.
- `main-compact-plan-clippy`: all-target Clippy passed for the native and aggregation crates with warnings denied.
- `main-compact-plan-vm-tests`: three matched VM wrapper tests passed, including deferred-record adversarial controls.
- `main-compact-plan-upstream`: upstream two-to-one recursion regression passed.
- The 20 independent Python evidence-validator controls and formatting passed.

The first repeat series used Yukon `82641ef8233a4c5ac3065093335c472160a09fbd`; the current candidate series used `e7b766b5d13a2c11b0307f83a8808e401282846e`. Both used the identical benchmark runner hash `47c306c9564f159c56aab5a871e95d889f98f74e4025c07d45ac2cff34164ab6`. No Lean source or accelerator was involved.

## Scope

This candidate uses native GF(2^192) arithmetic constraints, batched BLAKE2s and WHIR. It extends the earlier Boolean format and is not a measurement of arbitrary R1CS. There is a separate trusted circuit and setup key per level. Recursive closure under one submitted verifier, a concrete composition security certificate and zero knowledge are not established. Existing quotient/R1CS Lean theorems do not certify this implementation. Flock adapted to BLAKE2s is a separate baseline and is not included in these matched tree measurements.
