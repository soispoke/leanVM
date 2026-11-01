# leanR1CS Challenge v2 referee report

Trial window: **2026-10-23 18:01:45 to 21:01:45 UTC**. Calibration only, not competition. No push was authorized or performed. Harness: `trial-ref/experiments/challenge/`; raw artifacts and this report: `artifacts/trial/`. The rules and audit were read before the entry interface was published at 18:05 UTC, within the first 30 minutes.

## Verdict

**Neither system has an eligible scalar score.** The required `((A+B)+(A+held-out))` tree is unavailable under the full challenge contract. Baseline R1CS native-Keccak A/B wallets do not compose with its sparse child format; its measured merge controls use shielded+Merkle. VM first merges A+B under a pair-specific tree, but its node repeats one child instead of composing independent AB and AH children. Later R1CS entries demonstrate one-key first/node reuse and selected held-out applications, but still exclude Falcon. Security certification, complete coordinator rejections and the independent upgrade backend remain unavailable. No control sum is substituted for the score.

Machine-readable gate status, prerequisites and full observed cost vectors are in [scoreboard.json](scoreboard.json), generated from [score-evidence.json](score-evidence.json). A scalar requires ten distinct complete raw receipts for each required component, at least five rounds, matching medians, independent merge children and unchanged forwarded files. Protocol/security/identity eligibility still requires referee audit; this is not untrusted-host attestation.

## Primary baseline scoreboard

External warm medians on cores 36-47, 12 threads. First/node/root columns are **scope-labelled controls**, not the missing score. Root is complete two-real-application control acceptance, including decoding and claim settlement.

| Protocol | System | Wallet A s | Wallet B s | First control s | Node control s | Complete root ms | Eligible score |
|---|---|---:|---:|---:|---:|---:|---|
| blake2s | r1cs | 0.535 | 6.869 | 0.688 | 0.874 | 31.53 | Not measurable |
| blake2s | vm | 0.427 | 0.404 | 0.357 | 0.352 | 23.64 | Not measurable |
| keccak | r1cs | 0.747 | 10.350 | 3.212 | 4.223 | 51.84 | Not measurable |
| keccak | vm | 0.384 | 0.379 | 2.278 | 2.619 | 41.87 | Not measurable |

Each primary wallet protocol has 80 successful requests: ten samples per system/application/mode, five rotating A/B rounds. Each complete merge protocol has ten first, ten node and ten root samples per system, plus 60 cadence requests per system and one VM child-preparation receipt. VM certificates now include ordered claims. R1CS first/node controls use different matrix keys; VM is fixed to its program pair and leaf shapes. Sparse recursion uses rate 1/4, VM recursion 1/2; both wallet witness rates are 1/4, with R1CS auxiliary index rate 1/16. These are not matched security/parameter profiles.

### Wallet cold boundary and resources

Cold below is a fresh combined process, including compilation/setup. It is an upper-bound control, **not** independently reloadable retained-key-only cold. RSS is maximum observed across both cold and warm samples; bytes include complete public envelope/output sidecars. GiB means 2^30 bytes.

| Protocol | System | A cold s | B cold s | A max GiB | B max GiB | A max bytes | B max bytes |
|---|---|---:|---:|---:|---:|---:|---:|
| blake2s | r1cs | 30.635 | 14.248 | 0.955 | 13.527 | 295,536 | 369,704 |
| blake2s | vm | 0.519 | 0.558 | 0.503 | 0.543 | 220,197 | 225,347 |
| keccak | r1cs | 28.445 | 18.286 | 0.946 | 13.526 | 290,704 | 364,888 |
| keccak | vm | 0.479 | 0.507 | 0.505 | 0.540 | 215,719 | 220,609 |

R1CS reduced Falcon fails both wallet caps in both protocols. Observed primary VM wallets fit the caps. R1CS A is close to the 1 GiB cap; polling limitations prevent claiming an exact peak. B remains a decoded-input reduced relation on R1CS. VM parses compressed key/signature payloads with scheme headers implied by fixed code, a narrower interface than unrestricted round-3 encoded inputs.

### Repeated process-cold merge controls

Five rounds and ten samples per row, same complete envelopes. These include setup, internal child preparation and a small Python stdin transport process in the RSS/time boundary. They do not isolate retained-key loading.

| Protocol | System | First cold s | Node cold s |
|---|---|---:|---:|
| blake2s | r1cs | 3.744 | 8.149 |
| blake2s | vm | 0.827 | 0.815 |
| keccak | r1cs | 9.364 | 24.165 |
| keccak | vm | 4.909 | 5.174 |

## One-second cadence

FCFS arrivals at 1,000 ms for 60 seconds; latency includes queue delay, and throughput includes draining. Fixed-child controls, not the required independent three-application node.

| Protocol | System | Drain s | Throughput /s | p95 service s | p95 arrival-to-completion s | Unfinished at 60 s |
|---|---|---:|---:|---:|---:|---:|
| blake2s | r1cs | 60.00 | 1.000 | 0.927 | 0.927 | 0 |
| blake2s | vm | 60.00 | 1.000 | 0.405 | 0.405 | 0 |
| keccak | r1cs | 254.08 | 0.236 | 4.346 | 185.348 | 46 |
| keccak | vm | 155.32 | 0.386 | 2.695 | 91.613 | 38 |

The earlier R1CS BLAKE control run had p95 latency 1.236 s and one completion beyond 60 s, despite a 0.930 s warm node median. The complete-envelope rerun sustained the cadence. Both observations are retained. Full-Keccak controls clearly accumulate backlog. A sub-second median alone does not define cadence success.

## Admission and roots

Complete wallet admission with retained public setup, ten samples per row. External times include file decoding and request completion; internal verifier medians are shown separately. These check authenticated proof/output commitments, not an unspecified consumer transaction-validity policy.

| Protocol | System | A external ms | A internal ms | B external ms | B internal ms |
|---|---|---:|---:|---:|---:|
| blake2s | r1cs | 22.29 | 18.68 | 22.16 | 19.41 |
| blake2s | vm | 23.82 | 20.96 | 23.50 | 20.76 |
| keccak | r1cs | 21.86 | 19.17 | 23.19 | 20.64 |
| keccak | vm | 23.62 | 20.88 | 24.22 | 21.06 |

The 20 ms target is binding on observed external medians. The rule specifies no statistic for admission/root, unlike the merge median, and full merge admission semantics remain incomplete. Thus these are observed target failures, not a claim that the entire admission gate has been calibrated.

### One/two/three local applications under one aggregate key

Entry 2 BLAKE2s shielded/Merkle/hash3 control, five samples per count/mode. One aggregate identity is counted in addition to real applications. This is not the required A/B/held-out workload.

| Real applications | Matrix identities | Cold root ms | Warm root ms |
|---:|---:|---:|---:|
| 1 | 2 | 995.18 | 19.66 |
| 2 | 3 | 1164.96 | 21.28 |
| 3 | 4 | 1340.72 | 21.10 |

Counting the aggregate identity gives total budgets 20/30/40 ms; counting only real applications gives 10/20/30 ms. These produce different verdicts. The earlier complete three-local-application warm root median was 35.46 ms, versus 21.10 ms in the later sweep; neither is discarded. Shared-host load, caching and timing variation are not isolated enough to attribute that difference to one cause.

### Entrant-published compact root series (external evidence)

Entry 8 published fifteen fresh four-leaf trees, five per application count, on entrant cores 0–11 with one warm public server per tree. These are separate from referee-core medians and use A/Keccak-1KiB/MPT, without Falcon. A separate profiling request reports settlement costs. The hash-checked publication is retained in `external-entry8-root-snapshot/`.

| Real applications | Identities including aggregate | External root ms | Internal root ms |
|---:|---:|---:|---:|
| 1 | 2 | 44.92 | 29.30 |
| 2 | 3 | 44.18 | 29.31 |
| 3 | 4 | 57.68 | 40.72 |

## Entrants, freezes and held-out applications

Every revised executable, decoder, retained surface or key gets a separate snapshot and draw. Declared setup dependencies, canonical descriptions and interface notes are copied and hashed, not merely the 32-byte digest. SHA-256 authenticates artifacts; it does not replace required Keccak application IDs. The finite pool and earlier reveals are public, so selecting a precompiled decoder demonstrates finite-pool reuse, not arbitrary future-generator universality.

| Entry | Scope and result | Eligibility |
|---|---|---|
| 0 / 1 | Partial interface; entry 1 frozen before its Keccak-1KiB/MPT draw, but no runnable held-out composition. About 366 MiB aggregate retained state. | Ineligible |
| 2 | Twenty frozen objects; 90 successful local three-application tree requests. Post-draw MPT/Keccak attempts fail as unsupported decoders, not verifier rejection passes. About 366 MiB aggregate plus 275 MiB application retained files. | Ineligible |
| 3 | Fixed-padded encoded Falcon diagnostic; six direct verifier-target mutations rejected. No reusable aggregate key or fresh raw-byte scoring adapter. | Ineligible |
| 4 | Aggregate retained 1100.86 MiB; 93 receipts, 0 recorded failures; 10 completed trees across five cold and five warm rounds; draw mpt, keccak1k. No Falcon composition. | Ineligible |
| 5 | Aggregate retained 941.28 MiB; 93 receipts, 0 recorded failures; 10 completed trees across five cold and five warm rounds; draw mpt, keccak1k. No Falcon composition. | Ineligible |
| 7 | Aggregate retained 53.07 MiB; 93 receipts, 0 recorded failures; 10 completed trees across five cold and five warm rounds; draw mpt, merkle-keccak. No Falcon composition. | Ineligible |
| 8 | Aggregate retained 53.07 MiB; 93 receipts, 0 recorded failures; 10 completed trees across five cold and five warm rounds; draw mpt, keccak1k. No Falcon composition. | Ineligible |
| 6 | Independently encoded novel post-freeze native graph admitted; four independent witnesses, two first merges, node and root under the frozen key. External witness construction is upstream and unscored. | Ineligible |

### Observed entrant control costs

Wallet rows pool the indicated local/held-out applications and are not A/B score components. Complete node bytes include root-finalization sidecars.

| Entry | First warm s | Node warm s | Root cold ms | Root warm ms | Node admission warm ms | Max complete node bytes |
|---|---:|---:|---:|---:|---:|---:|
| entry-2 | 1.046 | 1.685 | 1431.53 | 35.46 | 15.79 | 190231 |
| entry-4 | 7.620 | 9.942 | 4814.58 | 75.15 | 17.67 | 224199 |
| entry-5 | 4.658 | 6.710 | 3968.87 | 45.14 | 14.35 | 217639 |
| entry-7 | 4.541 | 6.477 | 13891.44 | 44.59 | 15.44 | 217287 |
| entry-8 | 4.574 | 6.473 | 15098.37 | 44.55 | 13.27 | 217287 |

Entry 4 completed all ten independent A/MPT/Keccak trees, with every frozen object unchanged. Its public A/MPT/Keccak setup times were 4.436/8.012/3.617 s, but retained application files were 454,789,453 / 631,446,065 / 421,884,905 bytes, each above 64 MiB. Cold wallet RSS reached 8.712 GiB and the shared warm wallet process 10.327 GiB. Key setup derivation was public and finished before fresh private seeds. This establishes those selected A/held-out trees only; Falcon admission remains unavailable. Entry 7 tests canonical-only retention and regeneration, not a retroactive correction to entry 4.

entry-5 observed per-application retained files: keccak1k 323,580,905 bytes, shielded 356,485,453 bytes, mpt 533,142,065 bytes.
entry-7 observed per-application retained files: shielded 11,155,468 bytes, merkle 29,772 bytes, mpt 39,195,260 bytes.
entry-8 observed per-application retained files: keccak1k 1,747,596 bytes, shielded 11,155,468 bytes, mpt 39,195,260 bytes.

### Compact retention and cold regeneration

Entries 7 and 8 retain canonical traces and keys, then regenerate public matrices/caches. Cold first/node medians include this work; warm processes retain regenerated state in RAM. Warm wallet RSS below is the shared multi-application process, not an isolated per-wallet attribution.

| Entry | First cold s | Node cold s | Wallet cold max GiB | Shared warm wallet max GiB |
|---|---:|---:|---:|---:|
| entry-7 | 18.105 | 19.950 | 4.916 | 6.239 |
| entry-8 | 19.434 | 21.934 | 5.072 | 6.480 |

## Fresh shared-statement supplement

Both supplemental protocols completed 80 shared-input Falcon/MPT samples. Full-Keccak guests use the native instruction and commit the exact shared 64-byte circuit statement. BLAKE2s supplemental VM guests use software Keccak and are explicitly not the primary instruction-enabled baseline.

| Full Keccak | Falcon warm s | MPT warm s | Falcon max GiB / bytes | MPT max GiB / bytes |
|---|---:|---:|---|---|
| r1cs | 9.904 | 2.542 | 13.508 / 365,752 | 3.479 / 327,816 |
| vm | 0.396 | 0.394 | 0.546 / 220,768 | 0.702 / 219,335 |

R1CS bounded MPT also fails both wallet caps; observed native-Keccak VM cases fit them. The software-Keccak VM MPT control exceeds 1 GiB. Fresh statement equality is observed, not a formal equivalence theorem, and Falcon still differs in parsing obligations. No supplement supplies a VM application-independent key or the required node. Sources: `exact-wallet-{blake2s,keccak}/`, published L6/L7 reports and the hash-checked `protocol-published-snapshots/`. Published lane results are labelled external evidence, never silently mixed with referee-core medians.

## Gate calibration

| Gate | Calibration | Evidence and practical limit |
|---|---|---|
| First/node mixed merge, 1 s median | Observed Keccak target binding; matched eligibility uncalibrated | Both primary Keccak controls exceed 1 s; exact required tree, common key and rates remain mismatched. |
| Root, 10 ms per identity at 1/2/3 apps | Uncalibrated | Complete roots and local series measured; identity denominator and actual A/B/held-out series missing. |
| Wallet RAM, 1 GiB | Binding for R1CS Falcon/MPT; non-binding for observed primary/native VM | Process-group sampled RSS; exact cgroup peak unavailable. Sparse universal padding is also over cap. |
| Wallet bytes, 300,000 | Binding for R1CS Falcon/MPT; non-binding for observed VM | Complete envelope and sidecars counted; early proof-only samples superseded. |
| Admission, 20 ms | Binding on primary external medians; full scope uncalibrated | Internal/external values differ near cutoff; statistic, transaction semantics and all merge cases unspecified. |
| Public application setup, 60 s | Non-binding for observed entry-4 setups; baseline full scope uncalibrated | Three public derivations below 8.1 s; Falcon setup isolation/retained-key reload incomplete. |
| Application retained files, 64 MiB | Binding for cache-heavy entrants; compact policy separately tested | Entry 4 per-application files fail; shared aggregate versus application accounting ambiguous. Entry 7 retained application files each fit 64 MiB and regenerates caches on cold startup; this does not imply RAM or cold-time compliance. |
| Coordinator rejection suite | Uncalibrated | Partial direct regression coverage; no full soundness claim or full coordinator corpus. |
| Independent bit-level upgrade | Uncalibrated | No independent hashed reference backend, complete interchange or cross-version corpus supplied. |

The coordinator security calculator, classical regime, query/grinding composition budget and independent upgrade drill are not replaced by source constants or historical tests. ZK is not claimed.

## Rejections

Direct post-proof tests cover wallet proof/statement changes, root ordered-claim omission/duplication/order and identity substitutions. Existing sparse root/recorder probes cover false carried evaluations, keys, child kinds and claim mutations. Auxiliary encoded-Falcon and VM deferred-checker scopes are listed separately. Generator-parser probes, if present, test public derivation admission and do not imply graceful service rejection.

Cases with no runnable direct evidence in either system: invalid spend, unauthenticated key, cross-version key, downgraded proof. Full suite remains **not measurable**. [rejection-coverage.json](rejection-coverage.json) lists every coordinator case, evidence path and limited scope. Regression rejection is not a soundness theorem.

## Harness integrity and reproducibility

All timed children use `taskset -c 36-47` and both thread variables set to 12; adapters assert the custom pool size. Builds and preparation use cores 48-63 with four Cargo jobs. Host receipts verify distinct physical cores, no SMT siblings in the set, no swap and read-only cgroup v2. The fallback polls simultaneous process-group RSS, recording actual gaps; shared pages can be overcounted, short-lived or escaped descendants missed. A concurrent-child allocation probe exercises group accounting. Shared memory bandwidth/frequency and other calibration lanes are not isolated. A read-only freeze-hash audit at approximately 20:37:30–20:37:57 UTC overlapped entry 8 cold measurements; those samples are retained without causal attribution or silent filtering.

Raw receipts retain argv, executable hashes, timing boundary, process-group RSS, exit status, stdout/stderr and every forwarded file size/hash. Persistent public preprocessing is distinguished from fresh processes; wallet witness decoding, quotient-hint reconstruction and complete serialization are inside corrected timers. Earlier `wallet-abab/` samples omitted R1CS quotient-hint construction and full transport and are preserved only as incomplete-boundary calibration. No eligible result uses them.

Four integrity tests pass: a missing key prevents the draw, mutation of a frozen binary prevents the draw, a missing component/nonexistent receipt prevents eligibility, and existing arbitrary files cannot authenticate a fabricated complete score. Remaining limitations include unsupplied prerequisites, declared-dependency completeness and a shared writable local environment; hashes do not prove soundness.


Retained-artifact audit checked 1,352 raw receipts and 1,291 forwarded-file references: 0 size/hash findings and 0 receipts finishing beyond the deadline. See `final-receipt-audit.json`; this is artifact integrity only.
Warm spread from `wallet-complete-abab`: r1cs A 0.433 to 0.662 s; r1cs B 6.076 to 7.546 s; vm A 0.374 to 0.511 s; vm B 0.367 to 0.494 s.
Warm spread from `wallet-keccak-complete-abab`: r1cs A 0.676 to 0.868 s; r1cs B 9.818 to 10.637 s; vm A 0.357 to 0.481 s; vm B 0.352 to 0.463 s.

The same R1CS Falcon adapter measured 6.869 s warm in the primary BLAKE run and 5.777 s in the later shared-input supplement; Keccak measured 10.350 s and 9.904 s. Inputs, surrounding application portfolio and host conditions differ, so these are repeatability limits, not pooled estimates or an attributed optimization. Every individual sample remains available.

## Ranked rules feedback

The highest-impact fixes are below. The full 31-item tagged and ranked list, with stable finding IDs and proposed fixes, is [rules-feedback.md](rules-feedback.md).

| Rank | ID | Tag | Finding | Proposed fix |
|---|---|---|---|---|
| 1 | F01 | ambiguous | The score's ((A+B)+(A+held-out)) tree has three real applications, but trial bounds allow two. Root gates also request three applications. | Raise the declared maximum to three and supply a compatible reference schema, or define separate pairwise held-out admission and a two-app scored tree. |
| 2 | F10 | missing | Existing R1CS sparse child verifier accepts sparse R1CS envelopes, while the measured A/B native Keccak bridge emits a different proof format. Wallet and merge numbers cannot be added as though those proofs compose. | Require a common certificate contract and an executable wallet-to-first-to-node-to-root test before admitting a scalar score. |
| 3 | F09 | ambiguous | The page requires one aggregate key for first and node merges but permits two merge-circuit identities. Existing code uses distinct first/node verification keys. | Define whether a frozen bundle of both keys is permitted and freeze the full bundle, shape metadata and authentication procedure before revelation. |
| 4 | F02 | ambiguous | Root 10 ms per identity can mean individual settlement, total divided by identity count, or application-only cost. Wrapper claims and shared decoding change the verdict. | Require full root time plus each settlement, count wrapper identities explicitly, and state whether the cap is total <=10 ms times identities or every individual component. |
| 5 | F24 | gameable | The entrant's complete root sidecar folds two claims for the same aggregate identity before settlement; a timer ending before sidecar construction omits work and a root using only the outer proof leaves claims unsettled. | Require finalization sidecars in complete forwarded bytes, charge their construction to the producing merge, and test missing, mutated and extra-scalar sidecars at the final verifier. |
| 6 | F07 | unmeasurable | The coordinator security calculator and independent hashed bit-level upgrade backend are not supplied by the page. | Publish versioned binaries, parameter manifest and test corpus before entry eligibility; keep unavailable gates uncalibrated. |
| 7 | F17 | ambiguous | Entry 1 declares a 32-byte aggregate key plus about 366 MiB of retained cache/setup/trace. The cap says setup per application, while aggregate setup is shared. | Define separate per-application and shared aggregate setup budgets, count every required retained file, and specify whether reconstructible public caches are optional or part of cold retained state. |
| 8 | F29 | ambiguous | Compact entry 7 retains only canonical descriptions and a 53 MiB aggregate trace, rebuilding larger public caches after cold startup. Earlier cache-heavy entries fail 64 MiB while an equivalent retained surface can fit. | Define the retained-file budget independently of transient derived state, charge all regeneration to the cold boundary and resident caches to RAM, and do not infer an intrinsic key-size lower bound from one caching policy. |
| 9 | F03 | unmeasurable | An application-specific aggregate key can be recomputed after revelation unless exact retained bytes and their dependencies are committed. Existing reports are retrospective evidence. | Before the random draw, snapshot key bytes, executable/decoder hashes, protocol version, shape bounds and derivation; check key bytes after every admission and merge. |
| 10 | F06 | gameable | Proof bytes may omit carried public claims, key authentication material or sidecars. | Measure the complete forwarded directory and require a separate verifier to accept using only it and frozen public setup. |
| 11 | F16 | gameable | The first fresh R1CS adapter consumed Boolean inputs already containing Falcon quotient hints generated before the timer. Its proof stage therefore omitted part of witness construction. | Specify raw relation inputs (decoded h/message/nonce/s2 for the reduced track), reconstruct s1 and quotient hints after receipt, and label earlier samples as incomplete-boundary calibration. The complete-certificate adapter implements this correction. |
| 12 | F18 | gameable | VM merge proofs carry a statement digest but the ordered external program/output claims used by `verify_claims` are omitted from the proof-only forwarded file. | Include the ordered claims in the forwarded certificate and verify from that envelope plus frozen setup. The complete merge adapter adds this transport. |

Reproduction and audit entry points: `ENTRY-FORMAT.md`, `host.json`, `source-worktrees.json`, `receipt-inventory.json`, `entry-audit.json`, `heldout-admission.md`, `scoreboard.json`, `rejection-coverage.json`, and each run's `provenance.json`, `index.json`, `summary.json`, `done.json` and raw receipts. Harness source and build logs are retained locally. No competition winner is declared. No push was performed.
