# Arch measurements of the optimization round

Host: `arch-fv-autoresearch-01` (Debian 13 host, kernel `6.12.85+deb13-cloud-amd64`, Ubuntu 24.04 Core container), 64 vCPUs of a `QEMU Virtual CPU version 2.5+`, 251.7 GiB. Toolchain `rustc 1.99.1`, the version the earlier Mac evidence records. The virtual CPU exposes AVX-512 but not `pclmulqdq`, `vpclmulqdq` or `gfni`, so binary-field multiplication runs leanVM's portable fallback, roughly 200 times slower than on the Mac. **Every wall time in these files is therefore unrepresentative and is not reported as a result.** Cycle counts, committed sizes, bytecode sizes, execution gas, tampering outcomes and acceptance decisions are deterministic and exact.

The host was shared with another mission. Our jobs kept total memory use at least 30 GiB below capacity: each job started only if current use plus 1.3 times its expected peak stayed within 170 GiB, and a watchdog would have stopped our job if available memory fell below 35 GiB (it never fired). The first eight-application run was stopped after its PCS sample because a linear extrapolation put the 2^30 Keccak R1CS proof near 170 GiB; the four-application proof peaked at only 45 GiB, so the eight-application R1CS proof was then run alone (`fan8-r1cs`, `--r1cs`) and peaked at 84 GiB.

## Results

`python3 summarize.py` rebuilds `summary.json` and this table from `runs/`. Every row was proved. `batch --dry-run` executes a batch and computes the exact committed layout without proving; at four and eight applications its rows (`dry4`, `dry8`) agree with the proofs for both interfaces.

| Batch | Interface | VM cycles per app | log2 committed | Bytecode | Proved here |
| ---: | --- | ---: | ---: | ---: | --- |
| 1 | pcs | 797,207 | 24.884 | 35,312 | yes |
| 1 | r1cs-vm | 797,964 | 24.884 | 36,246 | yes |
| 1 | r1cs | 2,189,442 | 26.238 | 261,201 | yes |
| 2 | r1cs-vm | 798,194 | 25.883 | 36,273 | yes |
| 4 | pcs | 797,282 | 26.882 | 35,353 | yes |
| 4 | r1cs-vm | 798,172 | 26.882 | 36,288 | yes |
| 4 | r1cs | 2,189,519 | 28.234 | 261,244 | yes |
| 8 | pcs | 797,197 | 27.881 | 35,381 | yes |
| 8 | r1cs-vm | 798,123 | 27.881 | 36,316 | yes |
| 8 | r1cs | 2,189,434 | 29.234 | 261,272 | yes |

Application execution gas is 10,971 per PCS application and 61 per R1CS application on either transcript. Every proved run applied its tampering checks: 30 single-application cases for the Keccak and BLAKE2s R1CS paths and 15 for PCS (`cmp1`, `vm1`), and order, count and duplicate substitution for batches; all were rejected.

## Provenance

| Files | Built from |
| --- | --- |
| `cmp1`, `fan8` | `0a5f7b21` (optimized Keccak, 2^30 window) |
| `vm1` | `f2172f17`'s transcript code before formatting, semantically identical |
| `fan8-vm`, `fan4-pcs`, `fan4-vm`, `fan2-vm`, `fan4` | `f2172f17` plus the `--pcs` flag committed in `0a7ef8ef` |
| `fan8-r1cs` | `0e829ab7` plus the `--r1cs` flag committed in `baf355e4` |
| `dry4`, `dry8` | `0a7ef8ef` |
| `pilot/*` | evaluator at `0a7ef8ef`, reference and candidates built from `8fbcfe33` and the pilot candidate commits |

The Keccak guest is the same in every build: later commits add the BLAKE2s variant and drivers without changing the Keccak emission, and the per-application cycle counts agree across files.

## Track A pilot

Two-application batches, with the reference built from `8fbcfe33` and fresh hidden workloads per evaluation (`pilot/`).

| Candidate | Change | Outcome |
| --- | --- | --- |
| Baseline, PCS and R1CS | none | accepted; repetitions differ by 28% (PCS) and 22% (R1CS) under host load |
| C2 | drops the PIOP's nonzero check in the guest generator | rejected before building: edit outside the prover crates |
| C3 | proves at rate 1 whatever the caller asks | rejected: the proof verifies (`verified: true`, 45% larger) but the reference pins rate 2 |
| C1 | a comment in an editable prover crate | first rejected by an exact proof-size limit (pruned paths differ by 32 bytes between workloads), then accepted with the 1% limit |

Scoring against a stored baseline (`c1-pcs.json`, `c1-r1cs.json`) made the no-op C1 look 1.20 times faster on PCS and 1.29 times faster on R1CS, because host load differed between the sessions. On R1CS that exceeded the rule's 20% noise threshold, so on a host with valid timing it would have counted as an improvement. The evaluator now alternates baseline and candidate repetitions within one session. Rerun that way (`c1-pcs-paired.json`), C1's paired speedups are 0.89, 1.01 and 1.17, median 1.01, and it does not count. Within one session the two proofs have identical sizes.

## Regressions

`regressions/` holds the upstream suites rerun on this branch: the `pcs`, `flock`, `fiat_shamir`, `leanvm_core`, `evm` and `primitives` tests (179 passed, including the Python verifier's regenerated WHIR table), the quotient tests with ignored ones (including `oracles_do_not_cross`), the default two-to-one recursion test (`aggregate_two_to_one`, whose guest keeps the 2^28 window), and the standalone opening regression with its recursive proofs and negative checks.
