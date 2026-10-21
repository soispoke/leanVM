# Every size: the quotient format, formally

Date: 2026-10-21. Toolchain: `leanprover/lean4:v4.34.0` (Lean 4.34.0, commit `293d5d0c0c3f3dded4688b3ccd6a33939ac5102b`), `lake-manifest.json` unchanged (ArkLib `db7005f84a9dbad7ff2abbbb4e8feeeac6f4dfd8`), prebuilt `.lake` reused; no `lake update` or cache download. Base commit `9edcb7c3` on branch `suite-lean`.

Command, in `formal/quotient`: `LEAN_NUM_THREADS=16 lake build`. Result: **`Build completed successfully (9160 jobs)`, exit 0.** The [compressed log](lake-build.log.gz) is the full output; the only warnings from the new file are eight `if_pos`/`if_neg` deprecations, the same as in the code it adapts. The root module `QuotientSecurity.lean` imports the new `QuotientSecurity/Format.lean` and has 28 new `#guard_msgs` axiom guards, each checking `[propext, Classical.choice, Quot.sound]` exactly. A guard was deliberately broken once to confirm that a mismatch fails the build, then restored. No `sorry`, no new axiom. No existing theorem or definition was changed.

Source hashes (sha256): `QuotientSecurity/Format.lean` `18fd12bcddf3dacf0adc3f43dd9810f91a6e3de2fb5a0c9122d79c7c10a067e0`, `QuotientSecurity.lean` `53cbffd545b3181edfcfb877ee405a9abcece85b094291d90486e074299b7672`, `lake-manifest.json` `e7c38c49792a422026d190f4afbea974fb5afe4ccfd9d4bcdd6c885b396e7b17`.

## What is proved

Soundness `(Q + 3) / 2^128` over any field of `2^192` elements for the **format**: `2^n` rows (`N = 2^(n+2)` cells), every `9 ≤ n ≤ 29`, any Cantor basis of `n + 2` vectors, any wiring, any public weights, eight public words. This is the same idealized model as the `n = 20` theorems: ideal binding commitments and a random oracle.

The range arithmetic, with `q = 2^192`:

* First challenge: `(2 N^2 + 4 N + 8) / q ≤ 2^-128` iff `2^(2n+5) + 2^(n+4) + 8 ≤ 2^64` iff `n ≤ 29` (`firstRound_fits_iff`). At `n = 29`, `2^63 + 2^33 + 8 ≤ 2^64`. At `n = 30`, `2^65 + 2^34 + 8 > 2^64`, and `rbrError_first_gt` shows that the protocol's own first-round error then exceeds `2^-128`.
* Second challenge: `d / q`, where `d = 2 (cell + sigma + 1) + cells + rows + quotient + pub + 4 cell`. Here `cell = 3 + 4 * 2^(n+1)`, `sigma = cells = 2^(n+2)`, `rows = 2^n`, `quotient = 2^(n+4)` and `pub = 2^(n+2) + 9 * 2^10`, so `d = 81 * 2^n + 9236` exactly (`Params.ofCantor_identity_eq`). That is `≤ 2^(n+7)` for `n ≥ 8` (`2^27` at `n = 20`) and `≤ 2^64` for `n ≤ 57`, so it is not binding.
* Third challenge: `3 / q`.
* Lower end: the public region has 11 bits (coordinates 0 to 10), so `n + 2 ≥ 11`. The verifier's public weight then has degree `(2^(n+2) - 2^11) + 11 * 2^10 = 2^(n+2) + 9 * 2^10` (`natDegree_membershipPub_le_n`). Soundness needs nothing more. Completeness has a stricter lower end: the honest copy quotient's bound `12 * 2^n + 9249` fits the `2^(n+4)` table iff `n ≥ 12`, which is Rust's `m > REGION + 2`. `InstanceN.honest_legal` and `InstanceN.honest_messages_fit` therefore assume `12 ≤ n`. Rust's `m + 3 ≤ BASIS = 28` (`n ≤ 23`) is an implementation limit.

Fixed: eight public words, the 11-bit region, the field of `2^192` elements. Still at `n = 20` only: `zkError_ofCantor` and `completeness_ofCantor` (`ConcreteZK.lean`). Their counterparts at every size are `InstanceN.zero_knowledge` and `InstanceN.completeness`. `AdderCircuit.determined` and `cells_determined` were already for any `Params`.

## New theorems, exact elaborated statements

Output of `#check` on each, after the build (`pp.fieldNotation false`):

```
QuotientSecurity.firstRound_fits_iff (n : ℕ) :
  (2 * (2 ^ (n + 2)) ^ 2 + 4 * 2 ^ (n + 2) + 8) * 2 ^ 128 ≤ 2 ^ 192 ↔ n ≤ 29
QuotientSecurity.rbrError_le_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F] [SampleableType F]
  (P : Params F) (B : Params.Bounds P) {n : ℕ} (hq : Fintype.card F = 2 ^ 192) (hN : Params.nCells P = 2 ^ (n + 2))
  (hn : n ≤ 29) (hw : Params.words P = 8) (hd : Params.Bounds.identity B ≤ 2 ^ 64)
  (i : ProtocolSpec.ChallengeIdx (pSpec P B)) : rbrError P B i ≤ 1 / 2 ^ 128
QuotientSecurity.rbrError_first_gt {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F] [SampleableType F]
  (P : Params F) (B : Params.Bounds P) {n : ℕ} (hq : Fintype.card F = 2 ^ 192) (hN : Params.nCells P = 2 ^ (n + 2))
  (hn : 30 ≤ n) (hw : Params.words P = 8) : 1 / 2 ^ 128 < rbrError P B ⟨⟨1, ⋯⟩, ⋯⟩
QuotientSecurity.knowledgeSoundness_bits_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] (P : Params F) (B : Params.Bounds P) {n : ℕ} (hq : Fintype.card F = 2 ^ 192)
  (hN : Params.nCells P = 2 ^ (n + 2)) (hn : n ≤ 29) (hw : Params.words P = 8) (hd : Params.Bounds.identity B ≤ 2 ^ 64)
  (adv : OracleComp (OracleSpec.ofFn (Answer P B)) (QuotientSecurity.Proof P B)) (Q : ℕ)
  (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure (Prod.snd r = true ∧ ¬Params.Sat P (Proof.stmt (Prod.fst r)) (Params.cells P ↑(Proof.g (Prod.fst r))))]
      {True} ≤
    ↑(Q + 3) * ↑(1 / 2 ^ 128)
QuotientSecurity.Params.ofCantor_identity_eq {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (σ : Equiv.Perm (Fin (n + 2) → Bool))
  (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F) (pub : F → Polynomial F)
  (hPub :
    ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
      ∑ x, Polynomial.eval (CantorBasis.point B x) (pub γ) * w x = ∑ J, γ ^ ↑J * (wordSum J) w)
  (hd : ∀ (γ : F), Polynomial.natDegree (pub γ) ≤ 2 ^ (n + 2) + 9 * 2 ^ 10) :
  Params.Bounds.identity (Params.ofCantorBounds B hm σ 8 wordSum pub hPub (2 ^ (n + 2) + 9 * 2 ^ 10) hd) =
    81 * 2 ^ n + 9236
QuotientSecurity.Params.ofCantor_identity_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (σ : Equiv.Perm (Fin (n + 2) → Bool))
  (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F) (pub : F → Polynomial F)
  (hPub :
    ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
      ∑ x, Polynomial.eval (CantorBasis.point B x) (pub γ) * w x = ∑ J, γ ^ ↑J * (wordSum J) w)
  (hd : ∀ (γ : F), Polynomial.natDegree (pub γ) ≤ 2 ^ (n + 2) + 9 * 2 ^ 10) (h8 : 8 ≤ n) :
  Params.Bounds.identity (Params.ofCantorBounds B hm σ 8 wordSum pub hPub (2 ^ (n + 2) + 9 * 2 ^ 10) hd) ≤ 2 ^ (n + 7)
QuotientSecurity.Params.ofCantor_identity_le_64 {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (σ : Equiv.Perm (Fin (n + 2) → Bool))
  (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F) (pub : F → Polynomial F)
  (hPub :
    ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
      ∑ x, Polynomial.eval (CantorBasis.point B x) (pub γ) * w x = ∑ J, γ ^ ↑J * (wordSum J) w)
  (hd : ∀ (γ : F), Polynomial.natDegree (pub γ) ≤ 2 ^ (n + 2) + 9 * 2 ^ 10) (hn : n ≤ 29) :
  Params.Bounds.identity (Params.ofCantorBounds B hm σ 8 wordSum pub hPub (2 ^ (n + 2) + 9 * 2 ^ 10) hd) ≤ 2 ^ 64
QuotientSecurity.knowledgeSoundness_ofCantor_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (σ : Equiv.Perm (Fin (n + 2) → Bool))
  (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F) (pub : F → Polynomial F)
  (hPub :
    ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
      ∑ x, Polynomial.eval (CantorBasis.point B x) (pub γ) * w x = ∑ J, γ ^ ↑J * (wordSum J) w)
  (hd : ∀ (γ : F), Polynomial.natDegree (pub γ) ≤ 2 ^ (n + 2) + 9 * 2 ^ 10) (hq : Fintype.card F = 2 ^ 192)
  (hn : n ≤ 29)
  (adv :
    OracleComp
      (OracleSpec.ofFn
        (Answer (Params.ofCantor B hm σ 8 wordSum pub hPub)
          (Params.ofCantorBounds B hm σ 8 wordSum pub hPub (2 ^ (n + 2) + 9 * 2 ^ 10) hd)))
      (QuotientSecurity.Proof (Params.ofCantor B hm σ 8 wordSum pub hPub)
        (Params.ofCantorBounds B hm σ 8 wordSum pub hPub (2 ^ (n + 2) + 9 * 2 ^ 10) hd)))
  (Q : ℕ) (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              ¬Params.Sat (Params.ofCantor B hm σ 8 wordSum pub hPub) (Proof.stmt (Prod.fst r))
                  (Params.cells (Params.ofCantor B hm σ 8 wordSum pub hPub) ↑(Proof.g (Prod.fst r))))]
      {True} ≤
    ↑(Q + 3) * ↑(1 / 2 ^ 128)
QuotientSecurity.exists_instance_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  (hq : Fintype.card F = 2 ^ 192) (n : ℕ) (hn : n ≤ 29) :
  ∃ B,
    ∀ (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F),
      ∃ pub,
        (∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
            ∑ x, Polynomial.eval (CantorBasis.point B x) (pub γ) * w x = ∑ J, γ ^ ↑J * (wordSum J) w) ∧
          ∀ (γ : F), Polynomial.natDegree (pub γ) ≤ 2 ^ (n + 2) + 9 * 2 ^ 10
QuotientSecurity.membershipPub_hPub_n.{u_1} {F : Type u_1} [Field F] [CharP F 2] {N : ℕ} (B : CantorBasis F N) {m : ℕ}
  (b c : ℕ → F) (hm : m ≤ N) (hR : 11 ≤ m) (hb0 : b 0 = 1)
  (hb : ∀ (d : ℕ), 1 ≤ d → d < 11 → ∑ e ∈ Finset.range (d + 1), b e * CantorBasis.β B (d - e) = 0) (γ : F)
  (w : (Fin m → Bool) → F) :
  ∑ x, Polynomial.eval (CantorBasis.point B x) (pubProd b (regionMu c) 11 m γ) * w x =
    ∑ J, γ ^ ↑J * (weightedSum (regionWeightN c J)) w
QuotientSecurity.natDegree_membershipPub_le_n.{u_1} {F : Type u_1} [Field F] [CharP F 2] {m : ℕ} (b c : ℕ → F)
  (hR : 11 ≤ m) (γ : F) : Polynomial.natDegree (pubProd b (regionMu c) 11 m γ) ≤ 2 ^ m + 9 * 2 ^ 10
QuotientSecurity.knowledgeSoundness_membership_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F]
  [SampleableType F] {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (hR : 11 ≤ n + 2)
  (σ : Equiv.Perm (Fin (n + 2) → Bool)) (b c : ℕ → F) (hb0 : b 0 = 1)
  (hb : ∀ (d : ℕ), 1 ≤ d → d < 11 → ∑ e ∈ Finset.range (d + 1), b e * CantorBasis.β B (d - e) = 0)
  (hq : Fintype.card F = 2 ^ 192) (hn : n ≤ 29)
  (adv :
    OracleComp
      (OracleSpec.ofFn (Answer (membershipParamsN B hm hR σ b c hb0 hb) (membershipBoundsN B hm hR σ b c hb0 hb)))
      (QuotientSecurity.Proof (membershipParamsN B hm hR σ b c hb0 hb) (membershipBoundsN B hm hR σ b c hb0 hb)))
  (Q : ℕ) (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              ¬Params.Sat (membershipParamsN B hm hR σ b c hb0 hb) (Proof.stmt (Prod.fst r))
                  (Params.cells (membershipParamsN B hm hR σ b c hb0 hb) ↑(Proof.g (Prod.fst r))))]
      {True} ≤
    ↑(Q + 3) * ↑(1 / 2 ^ 128)
QuotientSecurity.membership_target_n {F : Type} [Field F] [DecidableEq F] [CharP F 2] {N n : ℕ} (B : CantorBasis F N)
  (hm : n + 2 ≤ N) (hR : 11 ≤ n + 2) (σ : Equiv.Perm (Fin (n + 2) → Bool)) (b c : ℕ → F) (hb0 : b 0 = 1)
  (hb : ∀ (d : ℕ), 1 ≤ d → d < 11 → ∑ e ∈ Finset.range (d + 1), b e * CantorBasis.β B (d - e) = 0) (s : Fin 4 → F)
  (γ : F) :
  Params.target (membershipParamsN B hm hR σ b c hb0 hb) ![s 0, s 1, s 2, s 3, 1, 0, 0, 0] γ =
    s 0 + γ * s 1 + γ ^ 2 * (s 2 + γ * s 3) + γ ^ 4
QuotientSecurity.regionWeightN_twenty.{u_1} {F : Type u_1} [Field F] [CharP F 2] (c : ℕ → F) (J : Fin 8)
  (x : Fin (20 + 2) → Bool) : regionWeightN c J x = regionWeight c J x
QuotientSecurity.zkError_le_n {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2] [Fintype E]
  [Fintype K] [DecidableEq K] [FiniteDimensional K E] [SampleableType K] [SampleableType E] {P : Params E} {n : ℕ}
  (hq : Fintype.card E = 2 ^ 192) (hN : Params.nCells P = 2 ^ (n + 2)) (hn : n ≤ 29) (van : Polynomial K)
  (hdeg : Polynomial.natDegree van ≤ 2 ^ n) : zkError P van ≤ 1 / 2 ^ 128
QuotientSecurity.InstanceN (F : Type) [Field F] [CharP F 2] (n : ℕ) : Type
QuotientSecurity.InstanceN.Relation {F : Type} [Field F] [CharP F 2] {n : ℕ} (I : InstanceN F n) (stmt : Fin 8 → F)
  (w : (Fin (n + 2) → Bool) → F) : Prop
QuotientSecurity.InstanceN.sat_iff {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)
  (stmt : Fin 8 → F) (w : ↥(Params.T (InstanceN.params I)) × Fin 4 → F) :
  Params.Sat (InstanceN.params I) stmt w ↔ InstanceN.Relation I stmt fun x => w ((InstanceN.cellEquiv I) x)
QuotientSecurity.InstanceN.soundness {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)
  [Fintype F] [SampleableType F] (hq : Fintype.card F = 2 ^ 192) (adv : InstanceN.Adversary I) (Q : ℕ)
  (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              ¬InstanceN.Relation I (Proof.stmt (Prod.fst r)) (InstanceN.cellsOf I ↑(Proof.g (Prod.fst r))))]
      {True} ≤
    (↑Q + 3) / 2 ^ 128
QuotientSecurity.InstanceN.exists_instance {F : Type} [Field F] [CharP F 2] [Fintype F] (hq : Fintype.card F = 2 ^ 192)
  (n : ℕ) (h9 : 9 ≤ n) (h29 : n ≤ 29) (wiring : Equiv.Perm (Fin (n + 2) → Bool)) (c : ℕ → F) :
  ∃ I, InstanceN.wiring I = wiring ∧ InstanceN.c I = c
QuotientSecurity.InstanceN.r1cs_iff_relation {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}
  (I : InstanceN F n) (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) :
  InstanceN.R1CSSatisfies I stmt w (InstanceN.r1csAux I w) ↔ InstanceN.Relation I stmt w
QuotientSecurity.InstanceN.exists_r1cs_iff_relation {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}
  (I : InstanceN F n) (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) :
  (∃ a, InstanceN.R1CSSatisfies I stmt w a) ↔ InstanceN.Relation I stmt w
QuotientSecurity.InstanceN.r1cs_aux_unique {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)
  (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) (a : (Fin n → Bool) → StructuredR1CS.Aux F)
  (h : InstanceN.R1CSSatisfies I stmt w a) : a = InstanceN.r1csAux I w
QuotientSecurity.InstanceN.r1cs_soundness {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)
  [Fintype F] [SampleableType F] (hq : Fintype.card F = 2 ^ 192) (adv : InstanceN.Adversary I) (Q : ℕ)
  (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              ¬InstanceN.R1CSSatisfies I (Proof.stmt (Prod.fst r)) (InstanceN.cellsOf I ↑(Proof.g (Prod.fst r)))
                  (InstanceN.r1csAux I (InstanceN.cellsOf I ↑(Proof.g (Prod.fst r)))))]
      {True} ≤
    (↑Q + 3) / 2 ^ 128
QuotientSecurity.InstanceN.honest_legal {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)
  (h12 : 12 ≤ n) (g : Fin 4 → Polynomial F) (hg : ∀ (j : Fin 4), Polynomial.natDegree (g j) ≤ 2 ^ n + 2) (α β γ : F) :
  Polynomial.natDegree (Params.Quotients.h₀ (Params.honest (InstanceN.params I) g α β γ)) ≤ 2 ^ (n + 4) ∧
    Polynomial.natDegree (Params.Quotients.hHigh (Params.honest (InstanceN.params I) g α β γ)) ≤ 2 ^ (n + 4) ∧
      Polynomial.natDegree (Params.Quotients.q (Params.honest (InstanceN.params I) g α β γ)) ≤ 2 ^ (n + 4) ∧
        Polynomial.natDegree (Params.Quotients.qGate (Params.honest (InstanceN.params I) g α β γ)) ≤ 2 ^ (n + 4) ∧
          Polynomial.natDegree (Params.Quotients.junk (Params.honest (InstanceN.params I) g α β γ)) ≤ 2 ^ (n + 4)
QuotientSecurity.InstanceN.zero_knowledge {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2]
  [Fintype E] [Fintype K] [DecidableEq K] [FiniteDimensional K E] [SampleableType K] [SampleableType E] {H : Type}
  [SampleableType H] [Fintype H] [DecidableEq H] {n : ℕ} (I : InstanceN E n) (h3 : Module.finrank K E = 3)
  (hq : Fintype.card E = 2 ^ 192) (c₀ : InstanceN.Table H I) (stmt : Fin 8 → E) (U : Finset H)
  (hU : ∀ c₁ ∉ U, Fresh c₀ stmt c₁) (gK : Fin 4 → Polynomial K)
  (hsat : InstanceN.Relation I stmt (InstanceN.witnessCells I gK)) (S : InstanceN.View H I → Prop) :
  𝒟[do
          let o ← InstanceN.real I c₀ stmt gK
          pure (S o)]
        {True} ≤
      𝒟[do
            let o ← InstanceN.sim K I c₀ stmt
            pure (S o)]
          {True} +
        (1 / 2 ^ 128 + ↑(Finset.card U) / ↑(Fintype.card H)) ∧
    𝒟[do
          let o ← InstanceN.sim K I c₀ stmt
          pure (S o)]
        {True} ≤
      𝒟[do
            let o ← InstanceN.real I c₀ stmt gK
            pure (S o)]
          {True} +
        (1 / 2 ^ 128 + ↑(Finset.card U) / ↑(Fintype.card H))
QuotientSecurity.InstanceN.completeness {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2]
  [Fintype E] [Fintype K] [DecidableEq K] [FiniteDimensional K E] [SampleableType K] [SampleableType E] {H : Type}
  [SampleableType H] [Fintype H] [DecidableEq H] {n : ℕ} (I : InstanceN E n) (hq : Fintype.card E = 2 ^ 192)
  (c₀ : InstanceN.Table H I) (stmt : Fin 8 → E) (U : Finset H) (hU : ∀ c₁ ∉ U, Fresh c₀ stmt c₁)
  (gK : Fin 4 → Polynomial K) (hdeg : ∀ (j : Fin 4), Polynomial.natDegree (gK j) ≤ 2 ^ n)
  (hsat : InstanceN.Relation I stmt (InstanceN.witnessCells I gK)) :
  𝒟[do
        let o ← InstanceN.real I c₀ stmt gK
        pure (Outcome.verdict (Prod.fst o) = false)]
      {True} ≤
    2 / 2 ^ 128 + ↑(Finset.card U) / ↑(Fintype.card H)
QuotientSecurity.InstanceN.honest_messages_fit {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E]
  [CharP E 2] [Fintype E] [Fintype K] [DecidableEq K] [FiniteDimensional K E] [SampleableType K] [SampleableType E]
  {n : ℕ} (I : InstanceN E n) (h12 : 12 ≤ n) (gK : Fin 4 → Polynomial K)
  (hdeg : ∀ (j : Fin 4), Polynomial.natDegree (gK j) ≤ 2 ^ n) (m : Fin 4 → Fin 3 → K) (α β γ : E) :
  ∃ g R, ↑g = committed gK (digitPoly n) m ∧ ↑R = Params.honest (InstanceN.params I) (↑g) α β γ
QuotientSecurity.Instance.relation_toN {F : Type} [Field F] [CharP F 2] [DecidableEq F] (I : Instance F) :
  InstanceN.Relation (Instance.toN I) = Instance.Relation I
QuotientSecurity.Instance.cellsOf_toN {F : Type} [Field F] [CharP F 2] [DecidableEq F] (I : Instance F) :
  InstanceN.cellsOf (Instance.toN I) = Instance.cellsOf I
```

## Tail of the build log

```

Note: This linter can be disabled with `set_option linter.unusedVariables false`
⚠ [9158/9160] Replayed QuotientSecurity.Format
warning: QuotientSecurity/Format.lean:203:8: `if_pos` has been deprecated: Use `ite_eq_left` instead
warning: QuotientSecurity/Format.lean:208:12: `if_pos` has been deprecated: Use `ite_eq_left` instead
warning: QuotientSecurity/Format.lean:208:28: `if_pos` has been deprecated: Use `ite_eq_left` instead
warning: QuotientSecurity/Format.lean:209:12: `if_neg` has been deprecated: Use `ite_eq_right` instead
warning: QuotientSecurity/Format.lean:209:40: `if_neg` has been deprecated: Use `ite_eq_right` instead
warning: QuotientSecurity/Format.lean:211:63: `if_neg` has been deprecated: Use `ite_eq_right` instead
warning: QuotientSecurity/Format.lean:213:8: `if_pos` has been deprecated: Use `ite_eq_left` instead
warning: QuotientSecurity/Format.lean:216:57: `if_pos` has been deprecated: Use `ite_eq_left` instead
✔ [9159/9160] Built QuotientSecurity (8.2s)
Build completed successfully (9160 jobs).
exit 0
```
