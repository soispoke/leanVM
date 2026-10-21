import QuotientSecurity.R1CS

/-!
# Every size: the format, not one circuit

The headline theorems elsewhere are at `2^20` rows. Here the size is a parameter: `2^n` rows of
four cells, `2^(n+2)` cells, for every `n` with `9 ≤ n ≤ 29`, any Cantor basis of `n + 2`
vectors, any wiring of the cells and eight public words over a field of `2^192` elements, with
the same bound `(Q + 3) / 2^128`.

**The range.** With `N = 2^(n+2)` cells and `q = 2^192`:
* the first challenge's error is `(2 N^2 + 4 N + 8) / q`, at most `2^-128` exactly when `n ≤ 29`
  (`firstRound_fits_iff`; at `n = 29` it is `2^63 + 2^33 + 8 ≤ 2^64`, at `n = 30` it is
  `2^65 + ... > 2^64`, `rbrError_first_gt`);
* the second's is `d / q`, `d` the degree of the identities: on a Cantor basis with the public
  weight of degree at most `2^(n+2) + 9 * 2^10` it is exactly `81 * 2^n + 9236`
  (`Params.ofCantor_identity_eq`), which is at most `2^(n+7)` from `n = 8` on (for `n = 20`, the
  `2^27` of `Params.ofCantor_identity`) and at most `2^64` up to `n = 57`; not the binding one;
* the third's is `3 / q`;
* the lower end `9 ≤ n` is the public region's: the verifier's public weight reads coordinates
  0 to 10 of a cell, so the cells need at least 11 bits, `n + 2 ≥ 11`. Its degree is then
  `2^(n+2) + 9 * 2^10` (`natDegree_membershipPub_le_n`).

The Rust prover asks more (`m > REGION + 2`, that is `n ≥ 12`, so the honest copy quotient fits
its table, and `m + 3 ≤ BASIS = 28`, that is `n ≤ 23`, its basis's length); those are about the
honest prover and the implementation, not about soundness.
-/

set_option linter.unusedSectionVars false

open OracleSpec OracleComp Polynomial Module NNReal Finset

namespace QuotientSecurity

/-! ## The range of sizes -/

/-- **The first challenge is the binding one**: its error at `2^(n+2)` cells and eight words is at
most `2^-128` over `2^192` elements exactly when `n ≤ 29`. -/
theorem firstRound_fits_iff (n : ℕ) :
    (2 * (2 ^ (n + 2)) ^ 2 + 4 * 2 ^ (n + 2) + 8) * 2 ^ 128 ≤ 2 ^ 192 ↔ n ≤ 29 := by
  constructor
  · intro h
    by_contra hn
    have h32 : 2 ^ 32 ≤ 2 ^ (n + 2) := Nat.pow_le_pow_right (by norm_num) (by omega)
    have h1 : (2 * (2 ^ 32) ^ 2 + 4 * 2 ^ 32 + 8) * 2 ^ 128
        ≤ (2 * (2 ^ (n + 2)) ^ 2 + 4 * 2 ^ (n + 2) + 8) * 2 ^ 128 := by gcongr
    have := h1.trans h
    norm_num at this
  · intro hn
    have h31 : 2 ^ (n + 2) ≤ 2 ^ 31 := Nat.pow_le_pow_right (by norm_num) (by omega)
    calc (2 * (2 ^ (n + 2)) ^ 2 + 4 * 2 ^ (n + 2) + 8) * 2 ^ 128
        ≤ (2 * (2 ^ 31) ^ 2 + 4 * 2 ^ 31 + 8) * 2 ^ 128 := by gcongr
      _ ≤ 2 ^ 192 := by norm_num

section Bits

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F] [SampleableType F]
variable (P : Params F) (B : P.Bounds)

/-- **128 bits of round-by-round soundness, at every size up to `2^29` rows.** -/
theorem rbrError_le_n {n : ℕ} (hq : Fintype.card F = 2 ^ 192) (hN : P.nCells = 2 ^ (n + 2))
    (hn : n ≤ 29) (hw : P.words = 8) (hd : B.identity ≤ 2 ^ 64)
    (i : (pSpec P B).ChallengeIdx) : rbrError P B i ≤ 1 / 2 ^ 128 := by
  have hpos : 0 < Fintype.card F := Fintype.card_pos
  unfold rbrError
  split
  · exact div_le_two_pow hpos (by rw [hq, hN, hw]; exact (firstRound_fits_iff n).mpr hn)
  · exact div_le_two_pow hpos (by
      rw [hq]; exact (Nat.mul_le_mul_right (2 ^ 128) hd).trans (by norm_num))
  · exact div_le_two_pow hpos (by rw [hq]; norm_num)

/-- **And not beyond**: from `2^30` rows on, the first challenge's error exceeds `2^-128`. -/
theorem rbrError_first_gt {n : ℕ} (hq : Fintype.card F = 2 ^ 192)
    (hN : P.nCells = 2 ^ (n + 2)) (hn : 30 ≤ n) (hw : P.words = 8) :
    (1 / 2 ^ 128 : ℝ≥0) < rbrError P B ⟨⟨1, by norm_num⟩, rfl⟩ := by
  have h : 2 ^ 192 < (2 * (2 ^ (n + 2)) ^ 2 + 4 * 2 ^ (n + 2) + 8) * 2 ^ 128 :=
    not_le.mp fun h => by have := (firstRound_fits_iff n).mp h; omega
  show (1 / 2 ^ 128 : ℝ≥0)
    < ((2 * P.nCells ^ 2 + 4 * P.nCells + P.words : ℕ) : ℝ≥0) / (Fintype.card F : ℝ≥0)
  rw [hN, hw, hq, div_lt_div_iff₀ (by positivity) (by positivity), one_mul]
  exact_mod_cast h

/-- **128 bits, at every size.** For parameters with `2^(n+2)` cells, `n ≤ 29`, eight public
words and identities of degree at most `2^64`, over a field of `2^192` elements, an adversary
making `Q` queries wins with probability at most `(Q + 3) / 2^128`. -/
theorem knowledgeSoundness_bits_n {n : ℕ} (hq : Fintype.card F = 2 ^ 192)
    (hN : P.nCells = 2 ^ (n + 2)) (hn : n ≤ 29) (hw : P.words = 8) (hd : B.identity ≤ 2 ^ 64)
    (adv : OracleComp (ofFn (Answer P B)) (Proof P B)) (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ ¬ P.Sat r.1.stmt (P.cells r.1.g.1)]
      ≤ ((Q + 3 : ℕ) : ENNReal) * (((1 / 2 ^ 128 : ℝ≥0) : ℝ≥0) : ENNReal) := by
  refine (knowledgeSoundness adv Q hQ).trans ?_
  gcongr
  have h1 := rbrError_le_n P B hq hN hn hw hd ⟨⟨1, by norm_num⟩, rfl⟩
  have h3 := rbrError_le_n P B hq hN hn hw hd ⟨⟨3, by norm_num⟩, rfl⟩
  have h5 := rbrError_le_n P B hq hN hn hw hd ⟨⟨5, by norm_num⟩, rfl⟩
  exact max_le (max_le h1 h3) h5

end Bits

/-! ## The instance on a Cantor basis, at every size -/

section OfCantor

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F] [SampleableType F]
variable {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N)
  (σ : Equiv.Perm (Fin (n + 2) → Bool))
  (wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F) (pub : F → F[X])
  (hPub : ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
    ∑ x, (pub γ).eval (B.point x) * w x = ∑ J : Fin 8, γ ^ (J : ℕ) * wordSum J w)
  (hd : ∀ γ, (pub γ).natDegree ≤ 2 ^ (n + 2) + 9 * 2 ^ 10)

/-- **The degree of the identities, at every size**: `81 * 2^n + 9236`. -/
theorem Params.ofCantor_identity_eq :
    (Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd).identity = 81 * 2 ^ n + 9236 := by
  simp only [Params.Bounds.identity, Params.Bounds.denominator, Params.Bounds.cell,
    Params.ofCantorBounds, pow_succ]
  ring

/-- From `2^8` rows on, the degree of the identities is at most `2^(n+7)`; at `n = 20` this is the
`2^27` of `Params.ofCantor_identity`. -/
theorem Params.ofCantor_identity_n (h8 : 8 ≤ n) :
    (Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd).identity ≤ 2 ^ (n + 7) := by
  rw [Params.ofCantor_identity_eq, pow_add]
  have : 2 ^ 8 ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) h8
  omega

theorem Params.ofCantor_identity_le_64 (hn : n ≤ 29) :
    (Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd).identity ≤ 2 ^ 64 := by
  rw [Params.ofCantor_identity_eq]
  have : 2 ^ n ≤ 2 ^ 29 := Nat.pow_le_pow_right (by norm_num) hn
  omega

/-- **128 bits on the instance, at every size.** With `2^n` rows, `n ≤ 29`, any Cantor basis of
at least `n + 2` vectors, any wiring of the `2^(n+2)` cells, eight public words over a field of
`2^192` elements and a public weight of degree at most `2^(n+2) + 9 * 2^10`, an adversary making
`Q` queries wins with probability at most `(Q + 3) / 2^128`. -/
theorem knowledgeSoundness_ofCantor_n (hq : Fintype.card F = 2 ^ 192) (hn : n ≤ 29)
    (adv : OracleComp (ofFn (Answer (Params.ofCantor B hm σ 8 wordSum pub hPub)
      (Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd)))
      (Proof (Params.ofCantor B hm σ 8 wordSum pub hPub)
        (Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd)))
    (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ ¬ (Params.ofCantor B hm σ 8 wordSum pub hPub).Sat r.1.stmt
          ((Params.ofCantor B hm σ 8 wordSum pub hPub).cells r.1.g.1)]
      ≤ ((Q + 3 : ℕ) : ENNReal) * (((1 / 2 ^ 128 : NNReal) : NNReal) : ENNReal) :=
  knowledgeSoundness_bits_n (P := Params.ofCantor B hm σ 8 wordSum pub hPub)
    (B := Params.ofCantorBounds B hm σ 8 wordSum pub hPub _ hd) hq
    (Params.ofCantor_nCells B hm σ 8 wordSum pub hPub) hn rfl
    (Params.ofCantor_identity_le_64 B hm σ wordSum pub hPub hd hn) adv Q hQ

omit [SampleableType F] in
/-- **The instance exists at every size** up to `2^29` rows, in every field of `2^192` elements. -/
theorem exists_instance_n (hq : Fintype.card F = 2 ^ 192) (n : ℕ) (hn : n ≤ 29) :
    ∃ B : CantorBasis F (n + 2), ∀ wordSum : Fin 8 → ((Fin (n + 2) → Bool) → F) →ₗ[F] F,
      ∃ pub : F → F[X], (∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
          ∑ x, (pub γ).eval (B.point x) * w x = ∑ J : Fin 8, γ ^ (J : ℕ) * wordSum J w) ∧
        ∀ γ, (pub γ).natDegree ≤ 2 ^ (n + 2) + 9 * 2 ^ 10 := by
  obtain ⟨B⟩ := exists_cantorBasis_big hq (n + 2) (by omega) (by omega)
  refine ⟨B, fun wordSum => ?_⟩
  obtain ⟨pub, h1, h2⟩ := exists_pub B le_rfl 8 wordSum
  exact ⟨pub, h1, fun γ => (h2 γ).trans (by omega)⟩

end OfCantor

/-! ## The verifier's public weight, at every size

The region is fixed: 11 bits, eight words of up to 256 bits. Only the bits past it grow. -/

section Membership

variable {F : Type*} [Field F] [CharP F 2]
variable {N : ℕ} (B : CantorBasis F N) {m : ℕ} (b c : ℕ → F)

theorem sum_Ico_two_pow (a : ℕ) : ∀ k, ∑ j ∈ Finset.Ico a (a + k), 2 ^ j + 2 ^ a = 2 ^ (a + k)
  | 0 => by simp
  | k + 1 => by
    rw [← add_assoc, Finset.sum_Ico_succ_top (by omega), add_right_comm, sum_Ico_two_pow a k,
      pow_succ]
    ring

/-- The word a cell of the region belongs to, at any number of bits. -/
def wordOfN (x : Fin m → Bool) : Fin 8 :=
  ⟨(bitAt x 8).toNat + 2 * (bitAt x 9).toNat + 4 * (bitAt x 10).toNat, by
    cases bitAt x 8 <;> cases bitAt x 9 <;> cases bitAt x 10 <;> decide⟩

/-- The weight of a cell in word `J`, at any number of bits: the product of the weights of its
set bits below 8, on the cells of the region (bits from 11 on zero) that belong to the word. -/
def regionWeightN (J : Fin 8) (x : Fin m → Bool) : F :=
  if (∀ j : Fin m, 11 ≤ (j : ℕ) → x j = false) ∧ wordOfN x = J
  then ∏ k ∈ Finset.range 8, (if bitAt x k then c k else 1) else 0

/-- At `2^20` rows it is `regionWeight`. -/
theorem regionWeightN_twenty (J : Fin 8) (x : Fin (20 + 2) → Bool) :
    regionWeightN c J x = regionWeight c J x := rfl

theorem region_weights_n (γ : F) (x : Fin m → Bool) :
    (if ∀ j : Fin m, 11 ≤ (j : ℕ) → x j = false
      then ∏ k ∈ Finset.range 11, (if bitAt x k then regionMu c k γ else 1) else 0)
      = ∑ J : Fin 8, γ ^ (J : ℕ) * regionWeightN c J x := by
  by_cases h : ∀ j : Fin m, 11 ≤ (j : ℕ) → x j = false
  · rw [if_pos h]
    have hw : ∀ J, regionWeightN c J x = if wordOfN x = J
        then ∏ k ∈ Finset.range 8, (if bitAt x k then c k else 1) else 0 := fun J => by
      unfold regionWeightN
      by_cases hJ : wordOfN x = J
      · rw [if_pos ⟨h, hJ⟩, if_pos hJ]
      · rw [if_neg (fun h' => hJ h'.2), if_neg hJ]
    simp only [hw]
    rw [Finset.sum_eq_single (wordOfN x) (fun J _ hJ => by rw [if_neg (Ne.symm hJ), mul_zero])
      fun h' => absurd (Finset.mem_univ _) h']
    rw [if_pos rfl, Finset.prod_range_succ, Finset.prod_range_succ, Finset.prod_range_succ]
    have h8 : ∏ k ∈ Finset.range 8, (if bitAt x k then regionMu c k γ else 1)
        = ∏ k ∈ Finset.range 8, (if bitAt x k then c k else 1) :=
      Finset.prod_congr rfl fun k hk => by rw [regionMu, if_pos (Finset.mem_range.mp hk)]
    rw [h8]
    cases h8' : bitAt x 8 <;> cases h9' : bitAt x 9 <;> cases h10' : bitAt x 10 <;>
      simp [wordOfN, regionMu, h8', h9', h10'] <;> ring
  · simp [h, regionWeightN]

/-- **The verifier's product is a public weight** for the eight words of the region, at any
number `m ≥ 11` of bits. -/
theorem membershipPub_hPub_n (hm : m ≤ N) (hR : 11 ≤ m) (hb0 : b 0 = 1)
    (hb : ∀ d, 1 ≤ d → d < 11 → ∑ e ∈ Finset.range (d + 1), b e * B.β (d - e) = 0) :
    ∀ (γ : F) (w : (Fin m → Bool) → F),
      ∑ x, (pubProd b (regionMu c) 11 m γ).eval (B.point x) * w x
        = ∑ J : Fin 8, γ ^ (J : ℕ) * weightedSum (regionWeightN c J) w :=
  hPub_of_weights B _ _ fun γ x => by
    rw [pubProd_point B b _ hm hR hb0 hb, region_weights_n]

/-- **Its degree is `2^m + 9 * 2^10`** at any number `m ≥ 11` of bits. -/
theorem natDegree_membershipPub_le_n (hR : 11 ≤ m) (γ : F) :
    (pubProd b (regionMu c) 11 m γ).natDegree ≤ 2 ^ m + 9 * 2 ^ 10 := by
  refine (natDegree_pubProd_le b _ γ).trans ?_
  have h := sum_Ico_two_pow 11 (m - 11)
  rw [show 11 + (m - 11) = m by omega] at h
  norm_num
  omega

end Membership

section MembershipSizes

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] [Fintype F] [SampleableType F]
variable {N n : ℕ} (B : CantorBasis F N) (hm : n + 2 ≤ N) (hR : 11 ≤ n + 2)
  (σ : Equiv.Perm (Fin (n + 2) → Bool)) (b c : ℕ → F) (hb0 : b 0 = 1)
  (hb : ∀ d, 1 ≤ d → d < 11 → ∑ e ∈ Finset.range (d + 1), b e * B.β (d - e) = 0)

/-- The parameters of `flock::quotient` at `2^n` rows: the cells of a Cantor basis, a wiring, the
eight public words of the region, and the public weight the verifier evaluates. -/
noncomputable def membershipParamsN : Params F :=
  Params.ofCantor B hm σ 8 (fun J => weightedSum (regionWeightN c J))
    (pubProd b (regionMu c) 11 (n + 2)) (membershipPub_hPub_n B b c hm hR hb0 hb)

omit [Fintype F] [SampleableType F] in
theorem membershipParamsN_wordSum (J : Fin 8)
    (w : (membershipParamsN B hm hR σ b c hb0 hb).T × Fin 4 → F) :
    (membershipParamsN B hm hR σ b c hb0 hb).wordSum J w
      = ∑ x, regionWeightN c J x * w (cantorCells (n := n) B hm x) := by
  exact weightedSum_apply (regionWeightN c J) (LinearMap.funLeft F F (cantorCells (n := n) B hm) w)

noncomputable def membershipBoundsN : (membershipParamsN B hm hR σ b c hb0 hb).Bounds :=
  Params.ofCantorBounds B hm σ 8 _ _ (membershipPub_hPub_n B b c hm hR hb0 hb) _
    (natDegree_membershipPub_le_n b c hR)

/-- **128 bits for `flock::quotient`, at every size.** With `2^n` rows, `9 ≤ n ≤ 29`, over a
field of `2^192` elements, with the cells, the public weight and the public words of the verifier
and any wiring, an adversary making `Q` queries wins with probability at most `(Q + 3) / 2^128`. -/
theorem knowledgeSoundness_membership_n (hq : Fintype.card F = 2 ^ 192) (hn : n ≤ 29)
    (adv : OracleComp (ofFn (Answer (membershipParamsN B hm hR σ b c hb0 hb)
      (membershipBoundsN B hm hR σ b c hb0 hb)))
      (Proof (membershipParamsN B hm hR σ b c hb0 hb) (membershipBoundsN B hm hR σ b c hb0 hb)))
    (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ ¬ (membershipParamsN B hm hR σ b c hb0 hb).Sat r.1.stmt
          ((membershipParamsN B hm hR σ b c hb0 hb).cells r.1.g.1)]
      ≤ ((Q + 3 : ℕ) : ENNReal) * (((1 / 2 ^ 128 : NNReal) : NNReal) : ENNReal) :=
  knowledgeSoundness_ofCantor_n B hm σ _ _ (membershipPub_hPub_n B b c hm hR hb0 hb)
    (natDegree_membershipPub_le_n b c hR) hq hn adv Q hQ

omit [Fintype F] [SampleableType F] in
/-- The verifier's target, at every size: the statement's four words, then `(1, 0, 0, 0)`. -/
theorem membership_target_n (s : Fin 4 → F) (γ : F) :
    (membershipParamsN B hm hR σ b c hb0 hb).target ![s 0, s 1, s 2, s 3, 1, 0, 0, 0] γ
      = s 0 + γ * s 1 + γ ^ 2 * (s 2 + γ * s 3) + γ ^ 4 := by
  show ∑ J : Fin 8, γ ^ (J : ℕ) * (![s 0, s 1, s 2, s 3, 1, 0, 0, 0] : Fin 8 → F) J = _
  simp [Fin.sum_univ_eight]
  ring

end MembershipSizes

/-- The size, as an opaque proof. -/
theorem leN (n : ℕ) : n + 2 ≤ n + 2 := Nat.le_refl _

/-! ## A circuit of the format

`Instance` at any size in the range. -/

/-- **A circuit of the format**: `2^n` rows of four cells, `9 ≤ n ≤ 29`, a cell being named by
`n + 2` bits; a Cantor basis of `n + 2` vectors, a wiring of the cells, and the weights `c k` of
bits `k < 8` in the eight public words. `Instance` is the case `n = 20`
(`Instance.toN`). -/
structure InstanceN (F : Type) [Field F] [CharP F 2] (n : ℕ) where
  basis : CantorBasis F (n + 2)
  wiring : Equiv.Perm (Fin (n + 2) → Bool)
  c : ℕ → F
  /-- The public region of 11 bits fits in the cells. -/
  low : 9 ≤ n
  /-- The first challenge's error is at most `2^-128` (`firstRound_fits_iff`). -/
  high : n ≤ 29

namespace InstanceN

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} (I : InstanceN F n)

theorem region (I : InstanceN F n) : 11 ≤ n + 2 := by have := I.low; omega

/-- The protocol's parameters on this circuit. -/
noncomputable def params : Params F :=
  membershipParamsN I.basis (leN n) I.region I.wiring (invSeq I.basis.β) I.c (invSeq_zero _)
    fun d hd _ => invSeq_sum I.basis.β I.basis.zero d hd

/-- The degrees a proof's polynomials may have: the sizes of the tables they are committed in. -/
noncomputable def bounds : I.params.Bounds :=
  membershipBoundsN I.basis (leN n) I.region I.wiring (invSeq I.basis.β) I.c (invSeq_zero _)
    fun d hd _ => invSeq_sum I.basis.β I.basis.zero d hd

/-- **The relation**, as `Instance.Relation`: every row satisfies the gate, wired cells are
equal, and each of the eight public words is the weighted sum of its cells of the region. -/
def Relation (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) : Prop :=
  (∀ y : Fin n → Bool, gate (I.basis.β 1) (w (cellBits (y, 0))) (w (cellBits (y, 1)))
      (w (cellBits (y, 2))) (w (cellBits (y, 3))) = 0) ∧
    (∀ x, w (I.wiring x) = w x) ∧
    ∀ J : Fin 8, ∑ x, regionWeightN I.c J x * w x = stmt J

/-- **The cells a first message holds**: its witness polynomial at each cell's point. -/
noncomputable def cellsOf (g : Fin 4 → F[X]) (x : Fin (n + 2) → Bool) : F :=
  (Instance.witnessPoly g).eval (I.basis.point x)

/-- A statement with a proof of it. -/
abbrev Proof := QuotientSecurity.Proof I.params I.bounds

/-- An adversary: a computation that asks the random oracle and outputs a statement with a
proof. -/
abbrev Adversary := OracleComp (ofFn (Answer I.params I.bounds)) I.Proof

/-- The cells, by their bits. -/
noncomputable def cellEquiv : (Fin (n + 2) → Bool) ≃ I.params.T × Fin 4 :=
  cantorCells (n := n) I.basis (leN n)

theorem cellsOf_eq (g : Fin 4 → F[X]) (x : Fin (n + 2) → Bool) :
    I.cellsOf g x = I.params.cells g (I.cellEquiv x) := by
  have h := Params.cellPoly_zero_eval_pt I.params g (I.cellEquiv x)
  have hp : I.params.pt (I.cellEquiv x) = I.basis.point x :=
    cantorCells_point (n := n) I.basis (leN n) x
  rw [← h, hp]
  unfold cellsOf Instance.witnessPoly Params.cellPoly
  congr 1
  refine Finset.sum_congr rfl fun j _ => ?_
  simp [shift]

theorem cells_eq (g : Fin 4 → F[X]) :
    (fun x => I.params.cells g (I.cellEquiv x)) = I.cellsOf g :=
  funext fun x => (I.cellsOf_eq g x).symm

/-- **The model's relation is `Relation`**, on cells indexed by bits, at every size. -/
theorem sat_iff (stmt : Fin 8 → F) (w : I.params.T × Fin 4 → F) :
    I.params.Sat stmt w ↔ I.Relation stmt fun x => w (I.cellEquiv x) := by
  set e := I.cellEquiv with he
  have hrow : ∀ (y : Fin n → Bool) (c : Fin 4),
      e (cellBits (y, c)) = (cantorRows (n := n) I.basis (leN n) y, c) := by
    intro y c
    rw [he]
    show (Equiv.prodCongr _ _) (cellBits.symm (cellBits (y, c))) = _
    rw [Equiv.symm_apply_apply]
    rfl
  have hσ : ∀ x, I.params.σ (e x) = e (I.wiring x) := fun x => by
    show (e.permCongr I.wiring) (e x) = _
    simp [Equiv.permCongr_apply]
  have hword : ∀ J : Fin 8, I.params.wordSum J w = ∑ x, regionWeightN I.c J x * w (e x) :=
    fun J => membershipParamsN_wordSum I.basis (leN n) I.region I.wiring _ I.c _ _ J w
  unfold Params.Sat Relation
  refine and_congr ⟨fun h y => ?_, fun h x => ?_⟩ (and_congr ⟨fun h x => ?_, fun h i => ?_⟩
    (forall_congr' fun J => by rw [hword J]))
  · have := h (cantorRows (n := n) I.basis (leN n) y)
    simp only [hrow]
    exact this
  · obtain ⟨y, rfl⟩ := (cantorRows (n := n) I.basis (leN n)).surjective x
    have := h y
    simp only [hrow] at this
    exact this
  · have := h (e x)
    rwa [hσ x] at this
  · obtain ⟨x, rfl⟩ := e.surjective i
    rw [hσ x]
    exact h x

theorem relation_of_sat (stmt : Fin 8 → F) (g : Fin 4 → F[X])
    (h : I.params.Sat stmt (I.params.cells g)) : I.Relation stmt (I.cellsOf g) :=
  (I.cells_eq g) ▸ (I.sat_iff stmt _).mp h

theorem pub_hPub : ∀ (γ : F) (w : (Fin (n + 2) → Bool) → F),
    ∑ x, (pubProd (invSeq I.basis.β) (regionMu I.c) 11 (n + 2) γ).eval (I.basis.point x) * w x
      = ∑ J : Fin 8, γ ^ (J : ℕ) * weightedSum (regionWeightN I.c J) w :=
  membershipPub_hPub_n I.basis (invSeq I.basis.β) I.c (leN n) I.region (invSeq_zero _)
    fun d hd _ => invSeq_sum I.basis.β I.basis.zero d hd

theorem nCells : I.params.nCells = 2 ^ (n + 2) :=
  Params.ofCantor_nCells I.basis (leN n) I.wiring 8 _ _ I.pub_hPub

/-- **Knowledge soundness, at every size.** For a circuit of the format over a field of `2^192`
elements, for every adversary making at most `Q` oracle queries, the probability that the
verifier accepts while the cells the proof's first message holds do not satisfy the relation is
at most `(Q + 3) / 2^128`. -/
theorem soundness [Fintype F] [SampleableType F] (hq : Fintype.card F = 2 ^ 192)
    (adv : I.Adversary) (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ ¬ I.Relation r.1.stmt (I.cellsOf r.1.g.1)]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 := by
  have h := knowledgeSoundness_membership_n I.basis (leN n) I.region I.wiring _ I.c (invSeq_zero _)
    (fun d hd _ => invSeq_sum I.basis.β I.basis.zero d hd) hq I.high adv Q hQ
  rw [bound_eq] at h
  exact le_trans (prEvent_mono _ _ _ fun r hr =>
    ⟨hr.1, fun hsat => hr.2 (I.relation_of_sat _ _ hsat)⟩) h

/-- **Every size in the range has circuits**: over every field of `2^192` elements, for every
`9 ≤ n ≤ 29`, any wiring and any weights. -/
theorem exists_instance {F : Type} [Field F] [CharP F 2] [Fintype F]
    (hq : Fintype.card F = 2 ^ 192) (n : ℕ) (h9 : 9 ≤ n) (h29 : n ≤ 29)
    (wiring : Equiv.Perm (Fin (n + 2) → Bool)) (c : ℕ → F) :
    ∃ I : InstanceN F n, I.wiring = wiring ∧ I.c = c := by
  obtain ⟨B⟩ := exists_cantorBasis_big hq (n + 2) (by omega) (by omega)
  exact ⟨⟨B, wiring, c, h9, h29⟩, rfl, rfl⟩

/-! ### The structured R1CS, at every size -/

/-- A full R1CS assignment: the committed cells and five wires per row. -/
def R1CSSatisfies (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F)
    (a : (Fin n → Bool) → StructuredR1CS.Aux F) : Prop :=
  (∀ y, StructuredR1CS.Row (I.basis.β 1)
    (w (cellBits (y, 0))) (w (cellBits (y, 1)))
    (w (cellBits (y, 2))) (w (cellBits (y, 3))) (a y)) ∧
  (∀ x, (w (I.wiring x) - w x) * 1 = 0) ∧
  ∀ J : Fin 8, (∑ x, regionWeightN I.c J x * w x) * 1 = stmt J

/-- Canonical extraction of the eliminated wires from the committed cells. -/
def r1csAux (w : (Fin (n + 2) → Bool) → F) (y : Fin n → Bool) : StructuredR1CS.Aux F :=
  StructuredR1CS.extend (I.basis.β 1) (w (cellBits (y, 0)))
    (w (cellBits (y, 1))) (w (cellBits (y, 2)))

theorem r1cs_iff_relation (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) :
    I.R1CSSatisfies stmt w (I.r1csAux w) ↔ I.Relation stmt w := by
  simp only [R1CSSatisfies, r1csAux, StructuredR1CS.row_extend_iff,
    mul_one, sub_eq_zero, Relation]

theorem exists_r1cs_iff_relation (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F) :
    (∃ a, I.R1CSSatisfies stmt w a) ↔ I.Relation stmt w := by
  constructor
  · rintro ⟨a, hg, hc, hp⟩
    refine ⟨fun y => (StructuredR1CS.row_iff _ _ _ _ _).mp ⟨a y, hg y⟩, ?_, ?_⟩
    · simpa only [mul_one, sub_eq_zero] using hc
    · simpa only [mul_one] using hp
  · intro h
    exact ⟨I.r1csAux w, (I.r1cs_iff_relation stmt w).mpr h⟩

theorem r1cs_aux_unique (stmt : Fin 8 → F) (w : (Fin (n + 2) → Bool) → F)
    (a : (Fin n → Bool) → StructuredR1CS.Aux F) (h : I.R1CSSatisfies stmt w a) :
    a = I.r1csAux w := by
  funext y
  exact StructuredR1CS.aux_unique _ _ _ _ _ (a y) (h.1 y)

/-- **R1CS soundness, at every size**: accepted proofs whose committed cells fail the extracted
R1CS constraints have probability at most `(Q + 3) / 2^128`. -/
theorem r1cs_soundness [Fintype F] [SampleableType F] (hq : Fintype.card F = 2 ^ 192)
    (adv : I.Adversary) (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
      r.2 = true ∧ ¬ I.R1CSSatisfies r.1.stmt (I.cellsOf r.1.g.1)
        (I.r1csAux (I.cellsOf r.1.g.1))]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 := by
  refine le_trans (prEvent_mono _ _ _ ?_) (I.soundness hq adv Q hQ)
  intro r hr
  exact ⟨hr.1, fun h => hr.2 ((I.r1cs_iff_relation _ _).mpr h)⟩

/-! ### The honest prover's messages fit their tables, from `2^12` rows on -/

/-- **The honest second message fits its table, at every size from `2^12` rows.** For a first
message of degree at most `2^n + 2`, which a masked witness has, the honest prover's five
polynomials have degree at most `2^(n+4)`, the size of the quotient table. The copy quotient has
degree up to `12 * 2^n + 9249`, so this needs `2^n ≥ 2313`, that is `n ≥ 12`: the Rust prover's
`m > REGION + 2`. -/
theorem honest_legal (h12 : 12 ≤ n) (g : Fin 4 → F[X]) (hg : ∀ j, (g j).natDegree ≤ 2 ^ n + 2)
    (α β γ : F) :
    (Params.honest I.params g α β γ).h₀.natDegree ≤ 2 ^ (n + 4) ∧
      (Params.honest I.params g α β γ).hHigh.natDegree ≤ 2 ^ (n + 4) ∧
      (Params.honest I.params g α β γ).q.natDegree ≤ 2 ^ (n + 4) ∧
      (Params.honest I.params g α β γ).qGate.natDegree ≤ 2 ^ (n + 4) ∧
      (Params.honest I.params g α β γ).junk.natDegree ≤ 2 ^ (n + 4) := by
  classical
  have h2n : 2 ^ 12 ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) h12
  have e2 : 2 ^ (n + 2) = 4 * 2 ^ n := by rw [pow_add]; ring
  have e4 : 2 ^ (n + 4) = 16 * 2 ^ n := by rw [pow_add]; ring
  let B' : I.params.Bounds := { I.bounds with witness := 2 ^ n + 2 }
  let gm : B'.Msg₁ := ⟨g, hg⟩
  have hcell : ∀ c, (Params.cellPoly I.params g c).natDegree ≤ 4 * 2 ^ n + 11 := fun c =>
    (Params.natDegree_cellPoly_le B' gm c).trans (by
      show 3 + (2 ^ n + 2) * 4 ≤ 4 * 2 ^ n + 11
      omega)
  have hgate : (Params.gatePoly I.params g).natDegree ≤ 16 * 2 ^ n + 44 :=
    (Params.natDegree_gatePoly_le B' gm).trans (by
      show 4 * (3 + (2 ^ n + 2) * 4) ≤ 16 * 2 ^ n + 44
      omega)
  have hσ : I.params.sigmaPoly.natDegree ≤ 4 * 2 ^ n := I.bounds.hSigma.trans (by
    show 2 ^ (n + 2) ≤ 4 * 2 ^ n
    omega)
  have hpub : (I.params.pub γ).natDegree ≤ 4 * 2 ^ n + 9216 := (I.bounds.hPub γ).trans (by
    show 2 ^ (n + 2) + 9 * 2 ^ 10 ≤ 4 * 2 ^ n + 9216
    omega)
  have hE : I.params.Exact := Params.ofCantor_exact I.basis (leN n) I.wiring 8 _ _ I.pub_hPub
  have hcmon : I.params.vCells.Monic := (digitPoly_monic_natDegree (n + 2)).1
  have hcdeg : I.params.vCells.natDegree = 4 * 2 ^ n :=
    (digitPoly_monic_natDegree (F := F) (n + 2)).2.trans e2
  have hrmon : I.params.vRows.Monic := by
    rw [hE.rows]; exact monic_prod_of_monic _ _ fun i _ => monic_X_sub_C _
  have hrdeg : I.params.vRows.natDegree = 2 ^ n := by
    rw [hE.rows, natDegree_prod_of_monic _ _ fun i _ => monic_X_sub_C _]
    simp only [natDegree_X_sub_C, Finset.sum_const, Finset.card_univ, smul_eq_mul, mul_one]
    exact card_cantorT (n := n) I.basis (leN n)
  have hh : (Lagrange.interpolate Finset.univ I.params.pt
      (Params.sumValue I.params g α β γ)).natDegree ≤ 4 * 2 ^ n := by
    refine natDegree_le_of_degree_le (le_of_lt (lt_of_lt_of_eq
      (Lagrange.degree_interpolate_lt _ I.params.pt_injective.injOn) ?_))
    rw [Finset.card_univ]
    exact_mod_cast I.nCells.trans e2
  have hall := Params.natDegree_honest_le I.params g α β γ (4 * 2 ^ n + 11) (4 * 2 ^ n + 9216)
    (4 * 2 ^ n) hcell hσ hpub hcmon hcdeg (by omega) (by omega) hh
  rw [e4]
  refine ⟨hh.trans (by omega), by simp [Params.honest], hall.1.trans (by omega), ?_,
    by simp [Params.honest]⟩
  refine (Params.natDegree_honest_qGate_le I.params g α β γ hrmon).trans ?_
  rw [hrdeg]
  omega

end InstanceN

/-- The zero knowledge error, at every size up to `2^29` rows. -/
theorem zkError_le_n {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2]
    [Fintype E] [Fintype K] [DecidableEq K] [FiniteDimensional K E] [SampleableType K]
    [SampleableType E] {P : Params E} {n : ℕ} (hq : Fintype.card E = 2 ^ 192)
    (hN : P.nCells = 2 ^ (n + 2)) (hn : n ≤ 29) (van : K[X]) (hdeg : van.natDegree ≤ 2 ^ n) :
    zkError P van ≤ 1 / 2 ^ 128 := by
  unfold zkError
  refine div_le_two_pow Fintype.card_pos ?_
  rw [hq, hN]
  have h1 : 2 ^ (n + 2) ≤ 2 ^ 31 := Nat.pow_le_pow_right (by norm_num) (by omega)
  have h2 : 2 ^ n ≤ 2 ^ 29 := Nat.pow_le_pow_right (by norm_num) hn
  calc (2 * 2 ^ (n + 2) + 4 * van.natDegree) * 2 ^ 128
      ≤ (2 * 2 ^ 31 + 4 * 2 ^ 29) * 2 ^ 128 := by gcongr; exact hdeg.trans h2
    _ ≤ 2 ^ 192 := by norm_num

namespace InstanceN

/-! ### Zero knowledge and completeness, at every size -/

section Experiments

variable {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2] [Fintype E]
variable [Fintype K] [DecidableEq K] [FiniteDimensional K E]
variable [SampleableType K] [SampleableType E] {H : Type} [SampleableType H]
variable {n : ℕ} (I : InstanceN E n)

variable (H) in
/-- The oracle's table: what it has answered so far. -/
abbrev Table := (ofFn (ZAnswer I.params H)).QueryCache

variable (H) in
/-- What an experiment outputs. -/
abbrev View := Outcome (E := E) H × I.Table H

/-- The cells of a witness given by four polynomials over `K`. -/
noncomputable def witnessCells (gK : Fin 4 → K[X]) : (Fin (n + 2) → Bool) → E :=
  I.cellsOf fun j => (gK j).map (algebraMap K E)

/-- The real experiment: the honest prover on the witness `gK`, masked by the digit `w_n`. -/
noncomputable def real (c₀ : I.Table H) (stmt : Fin 8 → E) (gK : Fin 4 → K[X]) :
    ProbComp (I.View H) :=
  realNI c₀ stmt gK (digitPoly n)

variable (K) in
/-- The simulator. -/
noncomputable def sim (c₀ : I.Table H) (stmt : Fin 8 → E) : ProbComp (I.View H) :=
  simNI (K := K) c₀ stmt

variable [CharP K 2] [Fintype H] [DecidableEq H]

theorem exact : I.params.Exact :=
  Params.ofCantor_exact I.basis (leN n) I.wiring 8 _ _ I.pub_hPub

theorem sat_of_relation (stmt : Fin 8 → E) (g : Fin 4 → E[X])
    (h : I.Relation stmt (I.cellsOf g)) : I.params.Sat stmt (I.params.cells g) :=
  (I.sat_iff stmt _).mpr ((I.cells_eq g).symm ▸ h)

theorem mask_vanishes (x : I.params.T) :
    aeval (rowPoly.eval (x : E)) (digitPoly n : K[X]) = 0 := by
  obtain ⟨y, -, hy⟩ := Finset.mem_image.mp x.2
  rw [← eval_map_algebraMap, digitPoly_map, digitPoly_eval, rowPoly_eval,
    ← Function.iterate_add_apply, ← hy]
  exact I.basis.iterate_point (leN n) _

theorem zkBound_le (hq : Fintype.card E = 2 ^ 192) (U : Finset H) :
    zkBound I.params (digitPoly n : K[X]) U ≤ 1 / 2 ^ 128 + U.card / Fintype.card H := by
  have he : zkError I.params (digitPoly n : K[X]) ≤ 1 / 2 ^ 128 :=
    zkError_le_n hq I.nCells I.high _ (digitPoly_monic_natDegree n).2.le
  unfold zkBound
  rw [← coe_bit]
  exact add_le_add_left (ENNReal.coe_le_coe.mpr he) _

set_option linter.deprecated false in
theorem real_event (c₀ : I.Table H) (stmt : Fin 8 → E) (gK : Fin 4 → K[X])
    (S : I.View H → Prop) :
    Pr{let o ← I.real c₀ stmt gK}[S o] = Pr[S | realNI c₀ stmt gK (digitPoly n)] :=
  prEvent_eq_probEvent _ S

set_option linter.deprecated false in
theorem sim_event (c₀ : I.Table H) (stmt : Fin 8 → E) (S : I.View H → Prop) :
    Pr{let o ← I.sim K c₀ stmt}[S o] = Pr[S | simNI (K := K) c₀ stmt] :=
  prEvent_eq_probEvent _ S

theorem witnessCells_eq (gK : Fin 4 → K[X]) :
    I.witnessCells gK = I.cellsOf (committed gK (digitPoly n) 0) := by
  unfold witnessCells
  congr 1
  funext j
  simp [committed, maskPoly]

end Experiments

section ZeroKnowledge

variable {K E : Type} [Field K] [Field E] [Algebra K E] [DecidableEq E] [CharP E 2] [Fintype E]
variable [Fintype K] [DecidableEq K] [FiniteDimensional K E]
variable [SampleableType K] [SampleableType E]
variable {H : Type} [SampleableType H] [Fintype H] [DecidableEq H]
variable {n : ℕ} (I : InstanceN E n)

/-- **Zero knowledge, at every size**: as `Instance.zero_knowledge`, for a circuit of the
format, the bound `1 / 2^128 + |U| / |H|`. -/
theorem zero_knowledge (h3 : finrank K E = 3) (hq : Fintype.card E = 2 ^ 192)
    (c₀ : I.Table H) (stmt : Fin 8 → E) (U : Finset H)
    (hU : ∀ c₁, c₁ ∉ U → Fresh c₀ stmt c₁) (gK : Fin 4 → K[X])
    (hsat : I.Relation stmt (I.witnessCells gK)) (S : I.View H → Prop) :
    Pr{let o ← I.real c₀ stmt gK}[S o]
        ≤ Pr{let o ← I.sim K c₀ stmt}[S o] + (1 / 2 ^ 128 + U.card / Fintype.card H) ∧
      Pr{let o ← I.sim K c₀ stmt}[S o]
        ≤ Pr{let o ← I.real c₀ stmt gK}[S o] + (1 / 2 ^ 128 + U.card / Fintype.card H) := by
  have : CharP K 2 := RingHom.charP (algebraMap K E) (algebraMap K E).injective 2
  have hsat' := I.sat_of_relation stmt _ (I.witnessCells_eq gK ▸ hsat)
  have h := zeroKnowledge h3 I.exact c₀ stmt U hU gK (digitPoly n)
    (digitPoly_monic_natDegree n).1.ne_zero I.mask_vanishes hsat' S
  have hle := I.zkBound_le (K := K) hq U
  rw [I.real_event, I.sim_event]
  exact ⟨h.1.trans (add_le_add_right hle _), h.2.trans (add_le_add_right hle _)⟩

/-- **Completeness, at every size**: as `Instance.completeness`, for a witness of degree at most
`2^n`, the verdict is false with probability at most `2 / 2^128 + |U| / |H|`. -/
theorem completeness (hq : Fintype.card E = 2 ^ 192)
    (c₀ : I.Table H) (stmt : Fin 8 → E) (U : Finset H)
    (hU : ∀ c₁, c₁ ∉ U → Fresh c₀ stmt c₁) (gK : Fin 4 → K[X])
    (hdeg : ∀ j, (gK j).natDegree ≤ 2 ^ n)
    (hsat : I.Relation stmt (I.witnessCells gK)) :
    Pr{let o ← I.real c₀ stmt gK}[o.1.verdict = false]
      ≤ 2 / 2 ^ 128 + U.card / Fintype.card H := by
  have : CharP K 2 := RingHom.charP (algebraMap K E) (algebraMap K E).injective 2
  have hsat' := I.sat_of_relation stmt _ (I.witnessCells_eq gK ▸ hsat)
  have hvdeg : (digitPoly n : K[X]).natDegree = 2 ^ n := (digitPoly_monic_natDegree n).2
  have hn1 : 2 ^ n + 2 ≤ 2 ^ (n + 1) := by
    have : 2 ≤ 2 ^ n := by
      have := I.low
      calc 2 = 2 ^ 1 := by norm_num
        _ ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) (by omega)
    rw [pow_succ]; omega
  have hg : ∀ m j, (committed (E := E) gK (digitPoly n) m j).natDegree ≤ I.bounds.witness := by
    intro m j
    refine (natDegree_committed_le gK _ m j).trans (max_le ((hdeg j).trans ?_) ?_)
    · show 2 ^ n ≤ 2 ^ (n + 1)
      omega
    · rw [hvdeg]
      exact hn1
  have h := completeness_prob I.exact c₀ stmt U hU gK (digitPoly n)
    (digitPoly_monic_natDegree n).1.ne_zero I.mask_vanishes hsat'
    (I.cellEquiv fun _ => false) I.bounds hg
  have hid : I.bounds.identity ≤ 2 ^ 64 :=
    Params.ofCantor_identity_le_64 I.basis (leN n) I.wiring _ _ I.pub_hPub
      (natDegree_membershipPub_le_n _ I.c I.region) I.high
  have hpos : 0 < Fintype.card E := Fintype.card_pos
  have e2 : (I.bounds.identity : ENNReal) / (Fintype.card E : ENNReal) ≤ 1 / 2 ^ 128 := by
    have hle := div_le_two_pow hpos (a := I.bounds.identity) (by
      rw [hq]; exact (Nat.mul_le_mul_right (2 ^ 128) hid).trans (by norm_num))
    have hc : (I.bounds.identity : ENNReal) / (Fintype.card E : ENNReal)
        = (((I.bounds.identity : ℝ≥0) / (Fintype.card E : ℝ≥0) : ℝ≥0) : ENNReal) := by
      rw [ENNReal.coe_div (by exact_mod_cast hpos.ne')]
      simp
    rw [hc, ← coe_bit]
    exact ENNReal.coe_le_coe.mpr hle
  rw [I.real_event]
  refine (h.trans (add_le_add (I.zkBound_le (K := K) hq U) e2)).trans (le_of_eq ?_)
  rw [show (2 : ENNReal) / 2 ^ 128 = 1 / 2 ^ 128 + 1 / 2 ^ 128 by
    rw [ENNReal.div_add_div_same]; norm_num]
  ring

/-- **The honest prover's messages are legal, at every size from `2^12` rows**: for a witness of
degree at most `2^n`, whatever the masks and the challenges. -/
theorem honest_messages_fit (h12 : 12 ≤ n) (gK : Fin 4 → K[X])
    (hdeg : ∀ j, (gK j).natDegree ≤ 2 ^ n) (m : Fin 4 → Fin 3 → K) (α β γ : E) :
    ∃ (g : I.bounds.Msg₁) (R : I.bounds.Msg₂), g.1 = committed gK (digitPoly n) m ∧
      R.1 = Params.honest I.params g.1 α β γ := by
  have : CharP K 2 := RingHom.charP (algebraMap K E) (algebraMap K E).injective 2
  have hvdeg : (digitPoly n : K[X]).natDegree = 2 ^ n := (digitPoly_monic_natDegree n).2
  have hg : ∀ j, (committed (E := E) gK (digitPoly n) m j).natDegree ≤ 2 ^ n + 2 := by
    intro j
    refine (natDegree_committed_le gK _ m j).trans (max_le ((hdeg j).trans (by omega)) ?_)
    rw [hvdeg]
  have h2 : 2 ≤ 2 ^ n := by
    calc 2 = 2 ^ 1 := by norm_num
      _ ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) (by omega)
  refine ⟨⟨_, fun j => (hg j).trans ?_⟩, ⟨_, I.honest_legal h12 _ hg α β γ⟩, rfl, rfl⟩
  show 2 ^ n + 2 ≤ 2 ^ (n + 1)
  rw [pow_succ]; omega

end ZeroKnowledge

end InstanceN

/-! ## `Instance` is the format at `2^20` rows -/

namespace Instance

variable {F : Type} [Field F] [CharP F 2]

/-- The circuit `I`, as a circuit of the format with `n = 20`. -/
def toN (I : Instance F) : InstanceN F 20 := ⟨I.basis, I.wiring, I.c, by norm_num, by norm_num⟩

/-- Its relation is the same. -/
theorem relation_toN [DecidableEq F] (I : Instance F) : I.toN.Relation = I.Relation := rfl

/-- Its cells are the same. -/
theorem cellsOf_toN [DecidableEq F] (I : Instance F) : I.toN.cellsOf = I.cellsOf := rfl

end Instance

end QuotientSecurity
