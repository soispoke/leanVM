# Trial entry format v1

Published 2026-10-23 18:05 UTC. Trial start 18:01:45 UTC; stop 21:01:45 UTC. Calibration only. No pushes.

Submit a directory `P/artifacts/trial/entries/<id>/` containing `manifest.json` and all referenced artifacts. P is `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022`. Commands are JSON argv arrays, never shell strings. Absolute paths are allowed for this local trial; include SHA-256 of every executable and source commit. Report missing capabilities explicitly; partial entries remain useful calibration evidence.

Required manifest fields:

- `id`, `system`, `source_commit`, `protocol_hash`, `relation_B` (full Falcon or decoded-input reduced), `zk`.
- `binaries`: list of `{path, sha256}`; `generators`: mapping application name to `{path, sha256, application_id_keccak256, grammar_version}`. Retain exact canonical generator bytes, not merely a source filename.
- `aggregate_key`: `{path, sha256, derivation, max_applications, max_depth}`. The referee records its bytes and hash before drawing any held-out application. Also freeze executable hashes, generator decoder, derivation rules and protocol version. Subsequent key changes create a new entry and require a new draw. SHA-256 here authenticates files; protocol application IDs remain Keccak-256.
- `setup`: argv, public-only input contract, output directory, retained artifact list. Setup includes compilation and must end before private input revelation. Report wall time, process-tree peak RAM and sum of retained key file bytes.
- `commands`: map `wallet`, `merge_first`, `merge_node`, `admission`, `root`, `reject` to argv. Use literal placeholders `{input}`, `{output}`, `{setup}`, `{case}`, `{seed}`. Inputs/outputs are files. Commands must exit nonzero on failure. Proof output is a directory containing every forwarded byte, including claims, sidecars and required metadata. Log files must be outside it. State if current binaries cannot expose this boundary.
- `input_contract`: how seeded fresh application instances are consumed, child order, public statement, independent child witnesses, and valid/invalid case encoding. Generating a seed without consuming it does not satisfy freshness.
- `claim_schema`: path describing evaluations, dimensions, binding transcript order, inherited/fresh combination, application and wrapper claims, and the accepted-root invariant.
- `frozen_surface`: path with counted constraint system, hash rows, table dimensions/contents, lookup argument, grammar/primitives/decoder and claim schema.
- `soundness_note`: path with changes, citations/adaptations, field, rates, query/grinding counts, security regime, completeness/composition budget, maximum depth/claim count, and known limitations.
- `rejections`: case-to-command mapping and verifier entrypoint; state which tests bypass prover prechecks. Unsupported cases are not measurable, never passing.
- `warm`: optional persistent-process argv and request protocol retaining only public preprocessing. Repeated fresh processes are not warm runs.

Cold means a fresh process retaining only declared setup artifacts. OS page cache remains uncontrolled and is labelled; it is not claimed disk cold. Warm means one live process retaining public preprocessing, with fresh witnesses per request. Both include input decoding, witness generation and serialization. Timed commands use cores 36-47 and 12 threads. Builds use cores 48-63 and four Cargo jobs.

Held-out draw occurs only after the referee writes a timestamped immutable snapshot of aggregate-key bytes and executable hashes. Admission tests cover at least two drawn applications with A and B at leaf and node levels. Key hash equality is checked after each case; public application keys may be derived under the frozen procedure, but no aggregate-key regeneration is allowed. The rules' two-application tree bound conflicts with the score's three-application tree; report both scopes separately pending calibration feedback.

Every measurement includes raw samples and boundary/coverage labels. Missing setup, complete serialized bytes, persistent warm mode, security calculator or root boundary yields not measurable, not a fabricated estimate. No scalar score is eligible while a required gate fails or remains unmeasured.
