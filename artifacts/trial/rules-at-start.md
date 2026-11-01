---
type: research
tags: [privacy, zk, pq, proving, eip-8288, r1cs]
status: draft
updated: 2026-10-23
---

# leanR1CS Challenge

## TL;DR

Can a frozen circuit format (leanR1CS) serve EIP-8288 as well as RISC-V leanVM under identical rules, and how much would Ethereum have to freeze to get there? Wallets prove two applications. Mempool nodes merge proofs of different applications two at a time, and merge merged proofs, under one aggregate key fixed before the applications are known. The final verifier then settles each application's circuit claims. Both systems use Keccak-f[1600] as their only hash and are measured by one harness on the same machine. This is a trial specification for a non-zero-knowledge performance screen: no decision-grade winner exists yet, and a win would be evidence about performance, not a decision between circuits and programs.

## Status

The rules below are in a three-hour trial run that tests the harness, calibrates the gates and checks the key and claim model ([[research/experiments/reviews/leanr1cs-challenge/2026-10-23-v2-draft/2026-10-23-adversarial-review-astra|second audit]]). The 1 s merge gate is enforced only once both systems have a matched Keccak-protocol implementation. Until then, merges are measured and reported under both the BLAKE2s protocol and the Keccak protocol.

## Fixed setting

| Parameter | Value |
|---|---|
| Hash | Keccak-f[1600] for the Fiat-Shamir transcript (with grinding), commitment Merkle trees, claim and identity hashing, and the hash rows or instruction applications use; Keccak-256 with Ethereum padding |
| Commitments | WHIR over the existing binary-field stack; rate 1/4 at leaves; any other layer's rate identical for both systems and declared |
| Security | 128 bits classical for every proof, merge and composition, under the coordinator's calculator, which states the regime (proven or conjectured list decoding), query counts, grinding bits, extension field, completeness error and the composition budget over the declared maximum depth and claim count |
| Merges | Two children; one aggregate key for first-level (wallet + wallet) and node (merged + merged) merges, frozen before held-out applications are revealed |
| Trial bounds | Up to 2 real applications and 2 merge-circuit identities per tree, depth 2 or more |
| Privacy | Zero knowledge is not required; entries report whether proofs are ZK, and a privacy-ready result needs a separate ZK pass |

## Objects and identities

The **generator** is the canonical bytes of an application's circuit description, and its **application ID** is Keccak-256 of those bytes. The **application key** is derived from the generator by a deterministic, protocol-fixed procedure that every verifier re-runs or authenticates; it is never supplied by the application or prover. A fork may change how keys are derived, but application IDs never change. The **aggregate key** is one fixed key for every merge, whichever applications are inside. Each merged proof commits to a **statement digest**, the ordered list of (application ID, public-input hash) it covers. Reordering children changes the digest, and a proof whose digest does not match its children is rejected. EIP-8288 deduplicates and sorts dependencies at the block level. The ordered digest here only fixes what each proof covers.

## Deferred claims

A merge checks both children but does not recompute an application's circuit description. It carries a claim about it instead, folds claims for the same identity, and the root settles each remaining claim once. Each entry publishes its claim schema: which evaluations are claimed, their dimensions, the transcript order in which they are bound, how inherited and fresh claims combine, and the claims the merge circuits themselves leave. It also states the invariant the harness tests: an accepted root implies that every covered wallet proof, application claim and merge-circuit claim is valid.

## Workloads

The statements are fixed in `keccak-statements.md`, published with test vectors and identical for both systems:

- **A: shielded spend, Keccak edition.** 2 inputs, 2 outputs, a depth-20 tree, every hash Keccak-256.
- **B: Falcon-512 verification.** Round-3 encodings parsed inside the proof, including the compressed signature and public key, HashToPoint with SHAKE256, sampler bounds, canonicality and the norm check. A version taking decoded coefficients may be used during the trial only, labelled as a reduced relation.
- **Held-out applications.** At least two, drawn by the coordinator after the aggregate key is frozen, from a pool such as leanXMSS, a Keccak Merkle path and the MPT storage proof. Each must be admitted under the frozen key and merged with A and B in first-level and node merges.

Inputs are fresh seeded instances drawn after submission, with an independent witness per child. Known-answer vectors only check correctness.

## Measurement

One external harness runs both systems on 12 pinned physical cores (no SMT siblings, no swap), alternating systems and cases for at least five rounds, and publishes medians and every sample. Time runs from receiving inputs to emitting the complete serialized proof, including witness construction and decoding. RAM is the peak resident set of the whole process tree, including key loading. Bytes are the complete certificate a node would forward, including carried claims and any sidecar. Setup may read only public generator bytes, includes generator compilation, and must finish before inputs are revealed; its time, peak RAM and retained key bytes are reported. Each case runs cold (a fresh process with only the retained setup artifacts) and warm (public preprocessing kept in memory), and both are reported.

## Gates

| Gate | Limit |
|---|---|
| Merge, first-level and node, mixed applications | 1 s median (enforced once both systems run the Keccak protocol) |
| Root acceptance (decoding, identity authentication, every application and merge-circuit claim) | 10 ms per identity, total reported, at 1, 2 and 3 applications |
| Wallet | 1 GiB peak RAM and 300,000 bytes per proof |
| Admission check of an incoming proof | 20 ms |
| Setup per application | 60 s and 64 MiB of retained key |
| Rejection suite (coordinator's, prover prechecks bypassed) | Rejects tampered proofs, wrong statements, invalid spends or signatures, false carried evaluations, substituted or unauthenticated keys, omitted or duplicated claims, duplicate identities with different claims, wrong child kinds, children reordered against an unchanged digest, malformed shapes and generators, transcript mutations and cross-version keys |
| Upgrade drill | The coordinator's reference backend, an independent hashed binary with bit-level gates and no lookups or hash rows, proves the unchanged generators within 1 hour and 64 GiB, with the same application IDs and rejections, and rejects downgraded or cross-version proofs |

After the trial, each gate is marked binding, non-binding or uncalibrated. A failed gate makes an entry ineligible for the score but is still reported. The rejection suite is regression evidence, not a proof of soundness.

## Score

Lower is better: **wallet A + wallet B + first-level mixed merge (A + B) + node merge ((A + B) + (A + held-out))**. The sum is a convenience. Entries also publish the full cost vector: every time, RAM and byte count, admission and root time, setup, and the throughput and 95th-percentile latency of repeated node merges at EIP-8288's 1,000 ms aggregation interval. Comparisons use the vector.

## What entries may change

Entries may change how circuits are built and proven:

- general CCS constraints;
- one shared lookup table set of at most 2^18 rows with fixed contents, no per-application tables, and a lookup argument sound in characteristic two whose equations, columns, multiplicity encoding and transcript binding are published (the 2^18 byte tables tried so far were a net loss);
- native Keccak rows for every Keccak call;
- padding;
- the proving protocol around the constraints (sumcheck and GKR variants, the hash reduction, how claims are carried), using published techniques with a citation and a note on any adaptation;
- the merge circuits;
- the generator language's word-level primitives.

Generators state what to compute, not how to prove it. Each entry adds a short soundness note for any change to what is proven, and reports its **frozen surface** with counted sizes: constraint system, hash rows, tables (rows and columns), lookup argument, generator grammar, primitives and decoder, and the claim schema.

## Fairness

leanVM is measured by the same harness under the same rules: Keccak everywhere, the same rates, an application-independent aggregate key and the same settlement accounting. leanVM entries may make the equivalent changes (prover, recursion, hash instruction) in the same window.

## What a result means

A leanR1CS win shows that circuits can meet EIP-8288's performance needs under these rules. It does not by itself decide circuits versus programs, which also depends on whether the frozen surface is meaningfully smaller than leanVM's and on each application's circuit-correctness burden ([[research/privacy/Circuit Claims vs PCS_open vs RISC-V]]).

## Reference points

All at 12 threads, from [[research/experiments/leanR1CS vs leanVM Results]] and the lane reports on [soispoke/leanVM `research/r1cs-recursive-verifier`](https://github.com/soispoke/leanVM/tree/research/r1cs-recursive-verifier) (`65745ca1`). Each row is labelled matched (three-round ABAB medians), single run, or projection.

| | RISC-V leanVM | leanR1CS |
|---|---:|---:|
| Shielded spend, BLAKE2s edition and protocol | 0.151 s, 190 MiB, matched | 0.042 s sparse R1CS, matched |
| Shielded spend, Keccak edition, BLAKE2s protocol | 0.450 s with a Keccak instruction, matched | 0.43 to 0.48 s, single runs |
| Shielded spend, Keccak edition and protocol | in progress | 0.775 s, 958 MiB, single run |
| Falcon-512, decoded inputs on the leanR1CS side | 0.53 s, 0.57 GiB, matched | 5.88 s, 13.4 GiB with Keccak rows, matched |
| First-level mixed merge, BLAKE2s protocol | 0.40 to 0.42 s, key fixed to one pair | 0.75 to 0.98 s, application-independent key, matched |
| Node merge, BLAKE2s protocol | 0.37 to 0.59 s, same program | 0.94 to 0.97 s, application-independent key, matched |
| Merges, Keccak protocol | in progress | in progress; about 2x the BLAKE2s merge work, projection |
| Root acceptance, BLAKE2s protocol | not measured | 21 ms total, at most 8.1 ms per identity, matched |

## Open questions

- Where the circuit check should happen in EIP-8288 (final verifier, builder or mempool node); dynamic key recursion is unbenchmarked. Related: [[research/privacy/Enshrined Proof Verification and Aggregation in the Mempool]], [[research/privacy/Paying Proof Aggregation Without Weakening FOCIL]].
- Whether the frozen surface stays meaningfully smaller than leanVM's once Keccak rows or tables are added ([[research/privacy/R1CS plus Lookups Interface]]).
- Zero knowledge and its cost.

## Reviews

The first review pass on `a26e51c7` ([[research/experiments/reviews/leanr1cs-challenge/2026-10-23-a26e51c7/2026-10-23-synthesis-claude|synthesis]]) found v1 not ready to launch. This version answers it. The second audit ([[research/experiments/reviews/leanr1cs-challenge/2026-10-23-v2-draft/2026-10-23-adversarial-review-astra]]) found the v2 draft ready to publish and trial-run but not decision-grade. Its required changes are applied above, except the measured Keccak-protocol merge and the trial calibration, which the trial run produces.

## See also

- [[research/experiments/leanR1CS vs leanVM Results]]
- [[research/privacy/R1CS plus Lookups Interface]]
- [[research/privacy/Circuit Claims vs PCS_open vs RISC-V]]
- [[research/privacy/Enshrined Proof Verification and Aggregation in the Mempool]]
- [[research/privacy/Paying Proof Aggregation Without Weakening FOCIL]]
- [[research/experiments/leanPCS and leanR1CS Autoresearch Challenge]]
- [[research/experiments/Auto-Research Harness]]
