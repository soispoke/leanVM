# Validation

Three checks were completed before publication:

1. **Code:** 76 circuit-suite tests and 8 packed-backend tests passed. The final comparison-helper tests, quotient regressions, EVM verifier regression and upstream two-to-one recursion test passed. Clippy passed for all targets of the three affected packages; Rust formatting passed. The Falcon carry-cache regression, valid/invalid fixtures and known-answer checks passed. Four pre-existing circuit tests and the EVM gas-report test remain ignored by their normal test commands.
2. **Evidence:** all 82 planned jobs completed with validated output. The run reports 1,095 tampering rejections. Every measured packed proof is verified, as are the recursive aggregate proofs. Unsupported quotient sizes and packed Poseidon's memory admission are explicit records. Minimum sampled system memory available was 159.3 GiB. The measured source/library hashes and all five binary hashes were checked independently; the unmeasured export helper gained membership output after timing.
3. **Presentation:** the independent review checked displayed client/aggregate time units and medians, gas, identical circuit identities, paired statements and local documentation links. Optimized interfaces' different transcript hashes, prototype gas accounting, implementation limits and formal-proof scope are stated. The saved Lean 4.34.0 circuit-statement build matches the current theorem and root-module hashes; no Lean sources changed.

Logs are retained here as compressed text. [`review.json`](review.json) records the independent checks. Regenerate tables with `summarize_full.py`; check this run with `review_full.py`. This is implementation validation, not an independent cryptographic audit.
