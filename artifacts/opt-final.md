# O4 final optimization report

Round: 2026-10-23 23:31 to 2026-10-24 02:31 UTC. Timed children used cores 0-11, 12 threads; build/test lane cores 48-63, CARGO_BUILD_JOBS=4. Five warm rounds, ten samples per component, original trial transport boundaries, fresh wallet proofs and frozen VM ELFs.

Report generated 2026-10-24T02:31:19.516260+00:00.

## Publication

Last remotely verified R1CS publication: `afa94ae5e30ef6539865deec9434cd7a84bd13b9` on `publish/research/r1cs-recursive-verifier`, fast-forward only. VM was never pushed. Published chain includes opt-in L6 Keccak, O1 layout/packed witness/SIMD, O2 quaternary cap and canonical routing. Canonical publication status: Fully gated and exact compatibility7/7; canonical code published3b4ee58b, final evidence afa94ae5.

Publication checkpoints: `9d2ac6d442a31cf12d3e2d149721d5e4452114b3` (L6/default compatibility), `014f6adf3698cfc6cb04738b91e999888cc9e814` (O1), `f7432c1403ea504bbd9b3b314d05edc3e35dc9ce` (fully validated quad integration plus evidence).

## Best observed completed pass

| System | Commit | Trial first/node s | Best first/node s | Reductions vs trial | Gaps above 1 s | Pass |
|---|---|---|---|---|---|---|
| r1cs | `062eb3c4a071aacf271ac657e2ed13e6f12099e5` | 3.21 / 4.22 | 1.4630 / 2.1915 | 54.4% / 48.1% | 0.4630 / 1.1915 s | r155-final-canonical-streaming |
| vm | `096437a8e89edcd857fab8c9c57dcc53d5ac3f71` | 2.28 / 2.62 | 1.0809 / 1.2468 | 52.6% / 52.4% | 0.0809 / 0.2468 s | r155-final-canonical-streaming |

Best pass is selected by lowest first+node median sum solely for reporting. Differences between passes do not isolate causal wins. Matched ABAB3 comparisons are separate; all chronological passes remain in opt-scoreboard.md.

## Latest completed pass: r155-final-canonical-streaming

| System | First/node s | Root s | Shielded/Falcon wallet s | Complete shielded/Falcon admission ms | First/node certificate bytes |
|---|---|---|---|---|---|
| r1cs | 1.4630 / 2.1915 | 0.0499 | 0.7014 / 10.0226 | 16.4417 / 22.6030 | [221192] / [237965] |
| vm | 1.0809 / 1.2468 | 0.0321 | 0.3969 / 0.3707 | 16.9016 / 21.6814 | [292493] / [293523] |

| System | Cadence /s | Drain s | p95 latency s | Backlog at 60 s |
|---|---:|---:|---:|---:|
| r1cs | 0.445632 | 134.640 | 71.150 | 34 |
| vm | 0.758990 | 79.052 | 18.687 | 15 |

The cadence controls completed 60 arrivals at one per second, including drain. Neither system sustains the required one-per-second service. Final shielded admission medians are below 20 ms, while Falcon medians remain above 20 ms for both systems. Earlier full-pass shielded medians also exceeded 20 ms. Core verification is not substituted for admission.

## Integration decisions and validation

Matched quad versus binary cap: first 2.073950 to 2.006933 s (3.2% lower), node 4.729100 to 2.710722 s (42.7% lower). Matched canonical versus quad: first 1.882178 to 1.658940 s (11.9% lower), node 2.593368 to 2.546450 s (1.8% lower, variable). Fast and regular virtual-prefix integrations regressed node latency and were rejected. Subsequent O1/VM prototypes without a matched combined-workload win were not integrated. Later O2 compact aa1d59a1, alias3c3ae330 and q-first cb891af8 profiles have their own original-control comparisons and tests; they were not integrated or claimed faster than the published stack because an incremental O4 comparison and full combined gates were not completed within this round.

Published quad passed the full default 79/112/43 suites, supported feature suites, native quaternary checks, six Flock Keccak tests, fmt and both Clippy configurations, seven reference reconciliations, and exact default compatibility for seven application circuits (key, shape, statement, certificate length and SHA256). Publication guard checked clean HEAD, code-tree identity to immutable validated source, successful terminal gate status, exact compatibility and fast-forward ancestry, then verified the remote hash. Canonical also passed defaults79/112/43, supported features79/10/71/31, native9/44, Flock6, fmt/both Clippy, seven reconciliations and corrected exact compatibility7/7 before publication.

Defaults and existing default keys/shapes/certificates were preserved. Fixed Keccak, rates, query counts, grinding, extension/security settings and application statements were unchanged. Additional legacy aggregation tests with hardcoded BLAKE guests are unsupported under the shared Keccak feature; 15 failures are preserved in O4/feature-scope.md, not represented as passed. No verifier checks or tests were disabled.

## Scope and remaining limits

These are trial controls: R1CS shielded+Merkle with independent children; VM A+B first and duplicated-child node. They do not establish the eligible AB+AH scalar, arbitrary repeated node closure, a new formal security proof, or a one-second result. Proof/admission/root and sustained-cadence requirements remain separate. Matched soundness/mutation tests and artifact integrity are bounded evidence, not a complete coordinator rejection corpus.

The initial O1 push preceded the full integrated gate; subsequent full gate and exact default checks passed and are archived in O4/published-O1-validation. A local accidental prefix apply/revert was immediately reverted and remains unpublished. Initial quad/canonical compatibility attempts mistakenly referenced an earlier binary; they were cancelled and retained under invalid-binary-path directories, and corrected checks execute candidate binaries. Invalid attempts never authorized a push.

Evidence: opt-scoreboard.md, opt-O4.md, O4/state.json; per-run receipt-audit.json (261 samples, 221 forwarded references, zero findings); O4/build-* manifests and adapter snapshots; matched comparison receipts; candidate gate and exact compatibility directories.

Round closed at 2026-10-24T02:31:20.071498+00:00. Final remote verification: `afa94ae5e30ef6539865deec9434cd7a84bd13b9`; published worktree clean, code tree identical to gated canonical source. Final objective audit verifies six complete optimization passes, both final candidate gates and exact comparisons.
