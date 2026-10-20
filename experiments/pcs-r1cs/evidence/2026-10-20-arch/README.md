# Arch measurements of the optimization round

Host: `arch-fv-autoresearch-01` (Debian 13 host, kernel `6.12.85+deb13-cloud-amd64`, Ubuntu 24.04 Core container), 64 vCPUs of a `QEMU Virtual CPU version 2.5+`, 251.7 GiB. Toolchain `rustc 1.99.1`, the version the earlier Mac evidence records. The virtual CPU exposes AVX-512 but not `pclmulqdq`, `vpclmulqdq` or `gfni`, so binary-field multiplication runs leanVM's portable fallback, roughly 200 times slower than on the Mac. **Every wall time in these files is therefore unrepresentative and is not reported as a result.** Cycle counts, committed sizes, bytecode sizes, execution gas, tampering outcomes and acceptance decisions are deterministic and exact.

The host was shared with another mission. Our jobs kept total memory use at least 30 GiB below capacity: each job started only if current use plus 1.3 times its expected peak stayed within 170 GiB, and a watchdog would have stopped our job if available memory fell below 35 GiB (it never fired). For that reason the eight-application Keccak R1CS proof (2^30 committed, about 170 GiB) was stopped after its PCS sample and reported from its exact dry-run shape instead.

## Results

`python3 summarize.py` rebuilds `summary.json` and this table from `runs/`. "Shape only" rows come from `batch --dry-run`, which executes the batch and computes the exact committed layout without proving; at four and eight applications its PCS rows agree with the proved ones to three decimals of the committed log.

SUMMARY_TABLE_PLACEHOLDER

Application execution gas is 10,971 per PCS application and 61 per R1CS application on either transcript. Every proved run applied its tampering checks: 30 single-application cases for the Keccak and BLAKE2s R1CS paths and 15 for PCS (`cmp1`, `vm1`), and order, count and duplicate substitution for batches; all were rejected.

## Provenance

| Files | Built from |
| --- | --- |
| `cmp1`, `fan8` | `0a5f7b21` (optimized Keccak, 2^30 window) |
| `vm1` | `f2172f17`'s transcript code before formatting, semantically identical |
| `fan8-vm`, `fan4-pcs`, `fan4-vm`, `fan2-vm`, `fan4` | `f2172f17` plus the `--pcs` flag committed in `0a7ef8ef` |
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
| C1 | a comment in an editable prover crate | first rejected by an exact proof-size limit (pruned paths differ by 32 bytes between workloads), then accepted with the 1% limit; its 20% apparent speedup did not count, the gate requiring more than 24% |

PILOT_R1CS_PLACEHOLDER
