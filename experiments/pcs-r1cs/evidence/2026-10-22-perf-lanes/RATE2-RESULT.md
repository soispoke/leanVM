# Candidate: rate-quarter WHIR joint opening

Date: 2026-10-22. Candidate commit `81678ab23c6d99a331a910da8ef1187f36622194`, base `0e245352`. Yukon latest local/upstream checked at `3e10413e639215af6e1577681839ea057d2c1966`; no Lean edits.

Changes only `private_bridge.rs`, `private_verifier.rs`, plus the explicit-rate lane-opening helper in `verifier.rs`. Native index and standalone verifier opening profiles remain rate1/2. Joint commitment, native verification and symbolic verification use `config_for_rate(log_n,2)`, meaning code rate1/4. Production128-bit parameter derivation, not hand-selected query counts. Native and symbolic transcripts bind domainv2 and explicit joint inverse-rate-log2.

## Config shape

At jointlog26 the production query schedule changes `[224,56,32,23,18]` to `[112,45,28,21,16]`; at log29 `[225,56,32,23,18,14]` becomes `[113,45,28,21,16,14]`. Grinding budget remains unchanged. Initial encoding/codeword length doubles for a fixed witness shape, so fewer queries need not improve proving time.

## Validation

57 release library tests passed (including actual malformedproof rejection and concrete/symbolic verifier agreement). Configgate covers jointlog18,22,26,29. All-targetreleaseClippy passed with `-D warnings` (6.48s wholecommand). All seven proofs in the depth2/chain16 tree verified; wrong root statements were rejected by the existing example. Fullsize workloads were not run in this lane.

## One process, four threads on CPUs48-51

| Level | Proofs | Padded native rows | Compressions | Median proving | Median verify | Total proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| Small leaf |4|16,384|17|68.2ms|5.39ms|290,880-294,320|
| Parent1 |2|2,097,152|27,295|5.422s|7.34ms|470,200-470,744|
| Root |1|4,194,304|42,803|10.191s|7.85ms|501,248|

Whole process24.387s; sampled aggregate RSS11.95GiB. The firstparent shape reduction does not persist at the second level: the Flock batch crosses another power-of-two boundary. This is a size/time tradeoff candidate, not a demonstrated speedup. No matched rate1 benchmark was launched here. The root owner is separately evaluating the combination with compact stack layout.

## Receipts

- `rate2-profile-config/`: original guarded configgate.
- `rate2-tests-v2/`: successful new-adapter57-testgate (5.82s whole command).
- `rate2-build/`: isolated releasebuild (47.20s).
- `rate2-tree-depth2/`: clean candidate, all tracked Rust/TOML/Cargo.lock hashes and actual binary hash, pinned affinity, raw logs/events and resource receipts.
- `rate2-summary.json`: extracted per-level measurements; these are medians across distinct proofs in one process, not repeated trials.
- `rate2-clippy/`: all-targetreleaseClippy receipt.

`rate2-tests/` intentionally preserves a failed harness invocation: the new adapter resolved cargo's rustup symlink and accidentally invoked rustup under the wrong name. Using the actual toolchaincargo path fixed it; no source/proof failure occurred.

These checks do not supply a new Lean theorem, tagged challengeROM adapter, fixed-shape recursive verifier, zero-knowledge claim or official recursion.fast score.
