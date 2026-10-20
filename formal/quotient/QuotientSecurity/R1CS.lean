import QuotientSecurity.Statement

/-!
# Structured R1CS lowering and soundness

Six rank-one equations replace each quotient gate. Five auxiliary values are eliminated,
not separately committed: the extracted R1CS witness extends the committed cells canonically.
Copy equations and the eight weighted public word equations are preserved unchanged.
This is the comparison's structured full-adder format, not a compiler for arbitrary R1CS.
The commitment, random-oracle and implementation limitations of `Statement.lean` still apply.
-/

open OracleSpec OracleComp Polynomial

namespace QuotientSecurity
namespace StructuredR1CS

variable {F : Type} [Field F]

/-- The five local wires eliminated by the quotient backend. -/
structure Aux (F : Type) where
  u : F
  w : F
  t : F
  p : F
  q : F
  deriving DecidableEq

/-- Each equation is a product of two affine forms equal to an affine form.
The constant wire is implicit and fixed to one. -/
def Row (θ x y c v : F) (a : Aux F) : Prop :=
  x * (θ * x + θ * θ) = a.u ∧
  y * (θ * y + θ * θ) = a.w ∧
  c * (c + 1) = a.t ∧
  a.u * a.w = a.p ∧
  a.t * (a.u + a.w) = a.q ∧
  (v + a.u + a.w + a.t + θ * (a.p + a.q)) * 1 = 0

/-- Deterministic extension of the original four cells. -/
def extend (θ x y c : F) : Aux F :=
  let u := x * (θ * x + θ * θ)
  let w := y * (θ * y + θ * θ)
  let t := c * (c + 1)
  ⟨u, w, t, u * w, t * (u + w)⟩

/-- The first five equations force every auxiliary wire, even for adversarial assignments. -/
theorem aux_unique (θ x y c v : F) (a : Aux F) (h : Row θ x y c v a) :
    a = extend θ x y c := by
  rcases a with ⟨u, w, t, p, q⟩
  rcases h with ⟨hu, hw, ht, hp, hq, _⟩
  dsimp at hu hw ht hp hq
  subst u; subst w; subst t; subst p; subst q
  rfl

/-- Exact elimination: no relaxation of the gate and no extra gate restriction. -/
theorem row_extend_iff (θ x y c v : F) :
    Row θ x y c v (extend θ x y c) ↔ gate θ x y c v = 0 := by
  have ht : c * (c + 1) = c * c + c := by ring
  simp [Row, extend, gate, ht]

/-- An arbitrary satisfying auxiliary assignment exists exactly when the gate holds. -/
theorem row_iff (θ x y c v : F) :
    (∃ a, Row θ x y c v a) ↔ gate θ x y c v = 0 := by
  constructor
  · rintro ⟨a, ha⟩
    rw [aux_unique θ x y c v a ha] at ha
    exact (row_extend_iff θ x y c v).mp ha
  · intro h
    exact ⟨extend θ x y c, (row_extend_iff θ x y c v).mpr h⟩

end StructuredR1CS

namespace Instance

variable {F : Type} [Field F] [CharP F 2] (I : Instance F)

/-- A full R1CS assignment retains the committed cells and adds five wires per row.
Copy and public equations are rank-one equations with second factor one. -/
def R1CSSatisfies (stmt : Fin 8 → F) (w : (Fin (20 + 2) → Bool) → F)
    (a : (Fin 20 → Bool) → StructuredR1CS.Aux F) : Prop :=
  (∀ y, StructuredR1CS.Row (I.basis.β 1)
    (w (cellBits (y, 0))) (w (cellBits (y, 1)))
    (w (cellBits (y, 2))) (w (cellBits (y, 3))) (a y)) ∧
  (∀ x, (w (I.wiring x) - w x) * 1 = 0) ∧
  ∀ J : Fin 8, (∑ x, regionWeight I.c J x * w x) * 1 = stmt J

/-- Canonical extraction of the eliminated wires from the committed cells. -/
def r1csAux (w : (Fin (20 + 2) → Bool) → F) (y : Fin 20 → Bool) :
    StructuredR1CS.Aux F :=
  StructuredR1CS.extend (I.basis.β 1) (w (cellBits (y, 0)))
    (w (cellBits (y, 1))) (w (cellBits (y, 2)))

/-- The lowering preserves the whole relation, including copies and public words. -/
theorem r1cs_iff_relation (stmt : Fin 8 → F) (w : (Fin (20 + 2) → Bool) → F) :
    I.R1CSSatisfies stmt w (I.r1csAux w) ↔ I.Relation stmt w := by
  simp only [R1CSSatisfies, r1csAux, StructuredR1CS.row_extend_iff,
    mul_one, sub_eq_zero, Relation]

/-- No noncanonical auxiliary assignment can enlarge the accepted relation. -/
theorem exists_r1cs_iff_relation (stmt : Fin 8 → F)
    (w : (Fin (20 + 2) → Bool) → F) :
    (∃ a, I.R1CSSatisfies stmt w a) ↔ I.Relation stmt w := by
  constructor
  · rintro ⟨a, hg, hc, hp⟩
    refine ⟨fun y => (StructuredR1CS.row_iff _ _ _ _ _).mp ⟨a y, hg y⟩, ?_, ?_⟩
    · simpa only [mul_one, sub_eq_zero] using hc
    · simpa only [mul_one] using hp
  · intro h
    exact ⟨I.r1csAux w, (I.r1cs_iff_relation stmt w).mpr h⟩

/-- The R1CS extractor does not get to change any of the committed cells. -/
theorem r1cs_aux_unique (stmt : Fin 8 → F) (w : (Fin (20 + 2) → Bool) → F)
    (a : (Fin 20 → Bool) → StructuredR1CS.Aux F) (h : I.R1CSSatisfies stmt w a) :
    a = I.r1csAux w := by
  funext y
  exact StructuredR1CS.aux_unique _ _ _ _ _ (a y) (h.1 y)

variable [DecidableEq F] [Fintype F] [SampleableType F]

/-- Accepted proofs whose committed cells fail the extracted R1CS constraints have the same
soundness error as upstream: at most `(Q + 3) / 2^128`, not an unconditional implication.
No extra cryptographic assumption is introduced by the exact algebraic lowering. -/
theorem r1cs_soundness (hq : Fintype.card F = 2 ^ 192) (adv : I.Adversary) (Q : ℕ)
    (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
      r.2 = true ∧ ¬ I.R1CSSatisfies r.1.stmt (I.cellsOf r.1.g.1)
        (I.r1csAux (I.cellsOf r.1.g.1))]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 := by
  refine le_trans (prEvent_mono _ _ _ ?_) (I.soundness hq adv Q hQ)
  intro r hr
  exact ⟨hr.1, fun h => hr.2 ((I.r1cs_iff_relation _ _).mpr h)⟩

end Instance
end QuotientSecurity
