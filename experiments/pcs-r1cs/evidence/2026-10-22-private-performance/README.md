# Private recursion performance, 22 October

This checkpoint improves the private native-field/Flock prototype. Three alternating paired processes show a 1.55× speedup for a four-leaf, two-level tree, with about one-third less peak memory. A matched 2→1 comparison still finds leanVM faster to prove. These are shared-host development measurements, not an architectural ranking or a formal security result.

## Paired implementation improvement

Four fresh 16-step chains, seven verified proofs per process, 16 workers pinned to logical CPUs 0–15. Baseline and candidate processes alternate within each of three pairs. No warmup or cache flush. Every pair favours the candidate (1.55×, 1.55×, 1.60×).

| Metric | Previous implementation | Compact stacks and rate-¼ joint opening |
| --- | ---: | ---: |
| Complete process, median | 15.54 s | 10.03 s |
| Peak RSS, maximum of three | 15.59 GiB | 10.27 GiB |
| Root proving, median | 3.898 s | 3.365 s |
| Root Rust verification, median | 8.77 ms | 7.76 ms |
| Root proof, all serialized data | 634,080 B | 516,112 B |

Whole-process time includes all seven proofs, preprocessing and symbolic recording. Root proving excludes preprocessing and symbolic recording. Preparation was not separately instrumented in the preserved baseline executable; it is included in both whole-process times. [Validated records](optimization.json), [paired gains](paired-gains.json), [source hashes](source-sha256.json), [schedule](measure.py) and [configuration](config.json) retain the accounting.

## Same statement through leanVM

Two fresh 16-step leaves and one parent. Each parent verifies both actual child proofs. Three fresh processes per configuration, with the order rotated. Same tagged statement, hardware, affinity, workers, compiler flags and seed. The VM rates and the native joint/index rates use the existing production WHIR parameter search; this does not establish a bound for the new native composition.

| Backend | Parent preparation + proving | Parent proving | Rust verification | Total proof | Complete process | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native prototype, joint rate ¼ / index ½ | 2.176 s | 2.103 s | 7.22 ms | 487.1 KB | 3.51 s | 4.72 GiB |
| leanVM, rate ½ (upstream default) | 1.072 s | 1.038 s | 11.13 ms | 284.4 KB | 2.00 s | 2.52 GiB |
| leanVM, rate ¼ | 1.119 s | 1.088 s | 10.63 ms | 196.4 KB | 2.00 s | 2.49 GiB |

Timings are medians; peak RSS is the maximum process peak. KB is decimal. Proof size includes the VM deferred records and serialization framing. Root verification checks all deferred polynomial evaluations and includes serialization for the size cap. Native rows and VM cycles are different units and are not divided into speedup ratios. [All timings and ranges](matched.json).

Both wrappers use a different authorized key at every level. The VM wrapper forwards older fixed-polynomial claims, authenticated by its public digest, and the root discharges them against their authorized programs. Its metadata grows with tree size, so deeper wrapper timings do not represent the upstream closed fixed-point design. The 2→1 comparison has one deferred record and is the primary comparison. The VM statement adapter uses straightforward bit decomposition for byte shifts; it is not an optimized VM lower bound.

## Full-size leaves

The candidate also completed eight 16,384-step leaves and three recursion levels: all 15 proofs verified, 111.81 s complete process, 31.47 GiB peak, root 3.116 s proving / 8.40 ms verification / 516,336 B. This is one process, not repeated trials, and no matched full-leaf VM run was attempted. [Full record](../2026-10-22-private-optimized-full-depth3/summary.json).

## Changes and rejected alternatives

The kept changes reuse evaluation tables, parallelize witness preparation, omit authenticated zero lanes, store three live field limbs instead of four slots per column, lower only used bits, and precompute hash blocks only when all operands are explicitly fixed by the circuit. Compacting changes the commitment layout; both native and recorded verifiers use the same mapping. The private bridge transcript is versioned and binds its opening profile.

One four-thread smoke found that retaining the larger logical domain made the proof smaller but proving slower, so that layout was not kept. In separate one-process depth-three tests on 16 workers, compact joint rates ½, ¼ and ⅛ took 27.59 s, 22.07 s and 25.57 s; the rate-⅛ root was smaller but slower. These are tuning probes, not repeated performance claims. Profiles and negative results remain in the adjacent evidence directories and [lane reports](../2026-10-22-perf-lanes/).

## Checks and scope

The integrated native build passed 59 release library tests, including actual malformed connector proofs, and all-target Clippy. The VM wrapper passed three tests including seven real proofs and 11 record/key/serialization attacks; the upstream 2→1 regression passed. The Python accounting suite passed 20 tests. Independent Python BLAKE2s recomputation checks every logged statement and root; the summarizer rejects missing/duplicate proofs, altered provenance, failed runs and resource violations.

The original quotient/structured-R1CS Lean theorems were unchanged. They do not certify the native arithmetic argument, private bridge, compiler, concrete PCS or Rust implementation. No new numerical composition bound, zero knowledge, closed fixed-shape recursion, or official recursion.fast result is claimed. The proof-system oracle adapter, composition/extractor certificate and closed verifier remain open.

Yukon was checked against upstream at `86b1153`, `3e10413`, then `db14697` during this phase. The new guarded benchmark adapter was used for builds and release checks. Receipts identify the adapter hash and actual tooling revision; the existing recursion runner retains runtime command, binary hash, source revision, CPU affinity, worker settings and memory admission. No Lean source changed or accelerator was used.
