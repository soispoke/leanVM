# Private index rate audit

Date: 2026-10-22. Read-only source audit; no new benchmarks, source edits, or security proof.

## Verdict

No blocker found in propagation of the selected index rate, concrete/symbolic transcript agreement, or fixed child-key and statement binding. The candidate retains the production 128-bit round-by-round WHIR parameter checks. This is not a new Lean proof of the native composition or a verified whole-system 128-bit security claim.

## Revisions and scope

- Audited candidate: `c3f7c8f12c4f3703d9c1fc40764c94dc741d2f74`, clean worktree `private-index-rate2/`.
- Parent integration observed at `02954a12ed7876085b0869bb859f086cd25a2ac8`: same rate propagation and v4 label present. Parent owns final integrated gates and measurements.
- Yukon local and upstream HEAD both `8e19ffca7f1ed46a111f81cef61b06e51604a27e`, checked at this audit's start. Shared dirty files preserved. No Lean accelerator or Lean edit used.
- Audited native index construction/openings, native symbolic recorder, private bridge/recorder, recursive Setup and child binding, WHIR production config derivation and validation.

## Rate propagation and transcript binding

| Object | Selected inverse-rate exponent | Code rate |
| --- | ---: | ---: |
| Standalone native witness | 1 | 1/2 |
| Standalone default native index | 1 | 1/2 |
| Private joint arithmetic/hash stack | 2 | 1/4 |
| Private circuit index | 3 | 1/8 |

`Index::new_with_rate` validates the permitted exponent, commits the sigma index with it and stores it. Both concrete index opening paths and the symbolic opening path consume the stored exponent. The private joint commitment and its concrete/symbolic openings consistently use exponent 2. No hardcoded default rate remains on an index-opening call site. The unchanged standalone witness opening intentionally keeps exponent 1.

The default native label remains v1; nondefault indexes use v2 with an explicit rate word. Concrete and symbolic private labels both use `format-private-bridge-v4` and serialize the same ordered fields: child index root, caller context, Flock R1CS digest, row/public dimensions, block count and dimensions, connector and q offsets, joint-stack dimension, joint rate, stored index rate, public length, complete public field elements. Thus the profile participates in the transcript before challenges.

The rate is trusted verifier/setup metadata, not a field chosen in serialized proofs. Rust exposes mutable Index metadata publicly; changing it changes the trusted verifier configuration. Existing mutation tests require the old proof to fail after a rate change. Making these fields private could harden the API, but no adversarial proof-input bypass was found here.

## Production parameter checks

`whir::config_for_rate` calls `WhirSecurityConfig::derive_config_with_log_inv_rate`, adding the fixed packing dimension. Derivation fixes `SECURITY_BITS = 128` and `QUERY_GRINDING_BITS = 17`, derives queries/OOD/eta for the exact dimension and rate, and calls `validate`. Conversion to the prover/verifier configuration validates again. Concrete and symbolic opening paths use this production derivation.

Validation checks ladder geometry, permitted rates, finite eta in the Johnson range, OOD presence and error, query error after grinding, proximity-gap error, list-unioned algebraic checks and per-level targets. The optimization does not lower the security target or manually drop queries.

These are numerical production **round-by-round** parameter checks, using floating-point formulas and a 1e-12 comparison tolerance. They are not an independently certified Lean proof of those formulas, the native composition, or the inherited quotient theorem's exact `(Q + 3) / 2^128` bound.

Size coverage distinction: native index log rows range 13 through 24, giving index opening `log_n` 15 through 26. Existing broad production regression explicitly tests log_n 22 through 30 for all permitted rates. Bridge profile assertions additionally test 18, 22, 26, 29; the alternate-index proof/recorder test uses the minimum native shape. Every actual opening derives and validates its exact configuration. This audit therefore finds no unchecked runtime fallback, but does not claim an explicit blanket regression over every size 15 through 26.

## Statement and key binding

`private_recursion::Setup` fixes the program, context and fixed public values. Proving lowers against that program and checks its complete public values. Appending child verification fixes the child index root as circuit constants, fixes context/public constants, substitutes only the claimed child output words, hashes the full profile label, records the complete verifier and requires transcript completion. Node construction checks both ordered children and hashes their tagged digests into the parent statement. Leaf statements remain tagged chain/leaf hashes. Serialized proofs have the existing 1 MiB cap, fixed integer parser and trailing-byte rejection.

New rate profiles regenerate keys and change transcript identity. There is no prover-selected rate or authorized arbitrary child key. The separate dynamic-root recorder still requires callers to authorize its root; the recursive Setup uses the fixed-root path.

## Existing evidence inspected

- `index-rate3-tests-v2/result.json`: ok; 60 library tests passed.
- `index-rate3-clippy/result.json`: ok; all-target release Clippy.
- `index-rate3-build/result.json`: ok.
- `index-rate3-depth2/result.json`: ok; four leaves, two parents and root verified in one process.
- `INDEX-RATES-RESULT.md` and `index-rates-summary.json`: existing timing/size tradeoff record, not a repeated or matched leanVM comparison.

The added alternate-index test checks shape preservation, changed root, successful concrete/symbolic verification, and rejection after trusted-rate mutation. Private bridge tests exercise malformed connector proofs with prover prechecks bypassed. The intentionally invalidated `index-rate3-tests/` receipt is superseded by the frozen successful `index-rate3-tests-v2/` receipt.

## Remaining boundaries

Separate externally supplied circuit/key per recursive level; recursive closure under one submitted verifier has not been established. The challenge need not mandate a single fixed circuit shape or key: one submitted verifier can authenticate variable shapes and keys. Existing untagged BLAKE2s proof-system ROM, with challenge adapter pending. No new Lean native/PCS composition certificate, zero-knowledge claim, official recursion.fast score, end-to-end Rust verification, or architectural superiority established by this audit. Parent's matched/full runs remain the source for performance conclusions.
