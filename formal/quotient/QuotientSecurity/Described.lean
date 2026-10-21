import QuotientSecurity.Format
import QuotientSecurity.Circuit

/-!
# From the proof to the circuit's Boolean statement, at every size

`InstanceN.soundness` is about field elements: cells that satisfy the gates, the copies and eight
weighted public words. This file states what that means for a circuit given by its rows, as
`experiments/pcs-r1cs/format/spec/format.py` and `quotient::circuit` define it, with no field and
no proof system: rows of three sources (zero, one, or row `r`), input rows reading themselves and
two zeros, every other row the full adder of its sources' bits and carry. The statement is the
512 bits the public rows read.

* `Desc.WellFormed`: what `Circuit::check_wired` and `format.py`'s `check` check of the rows.
* `Desc.eval`: every row's bit and carry from the input bits (`Circuit::values`, `evaluate`).
* `Desc.statementBits`: the 512 public bits, in `format.py`'s order (byte `i / 8`, bit `i % 8`).
* `Desc.wiringOf`: the wiring `Circuit::from_rows` builds, a cycle per source, its `V` cell then
  its readers in cell order; `Desc.wiringOf_wired`: every reading cell is on its source's cycle.
* `InstanceN.statement_of_relation`: cells satisfying the relation, for the verifier's words
  `(s_0, s_1, s_2, s_3, 1, 0, 0, 0)`, are the circuit's computation on some input bits, and the
  four words are the packing of the 512 statement bits.
* `InstanceN.circuit_soundness`, `InstanceN.circuit_soundness_bits`: so an adversary makes the
  verifier accept a statement that is not the circuit's output on some input with probability at
  most `(Q + 3) / 2^128`.

What is assumed of the weights: `c 1 = 0` (coordinate 1's weight is zero, so only the `X` and `Y`
cells of a public row count, as `quotient::coordinate_weight` sets it) and `Desc.Independent c`:
the 128 weights of a word's bits are independent over `GF(2)` (no nonempty subset sums to zero).
The Rust `bit_weight(j)` are distinct coordinate basis vectors of `F192` over `GF(2)`, which makes
them independent; Lean does not model `F192`'s representation, so this stays a hypothesis.
-/

set_option linter.unusedSectionVars false

open OracleSpec OracleComp Polynomial Finset

namespace QuotientSecurity

deriving instance DecidableEq for Src

namespace Desc

/-! ## Rows -/

/-- A row: the bit of `x`, the bit of `y` and the carry of `c`. -/
structure Row (n : ℕ) where
  x : Src (Fin (2 ^ n))
  y : Src (Fin (2 ^ n))
  c : Src (Fin (2 ^ n))
deriving DecidableEq

/-- A circuit: `2^n` rows, row `r` the `r`-th of `format.py`. -/
abbrev Rows (n : ℕ) := Fin (2 ^ n) → Row n

variable {n : ℕ}

/-- An input row reads its own output and two zeros. -/
def IsInput (rows : Rows n) (r : Fin (2 ^ n)) : Prop := rows r = ⟨.row r, .zero, .zero⟩

instance (rows : Rows n) (r : Fin (2 ^ n)) : Decidable (IsInput rows r) := by
  unfold IsInput; infer_instance

/-- Row `r` reads row `r'`. -/
def Reads (rows : Rows n) (r r' : Fin (2 ^ n)) : Prop :=
  (rows r).x = .row r' ∨ (rows r).y = .row r' ∨ (rows r).c = .row r'

/-- **A well-formed circuit**, what `Circuit::check_wired` checks of the rows (and `format.py`'s
`check` and `decode`): a row that is not an input reads constants or non-public rows, earlier ones
unless it is public (rows `0` to `511`); the public rows read no carry; the cells of words 0 to 3
(rows `0` to `255`) read rows that read one source and two zeros; word 4 is a one and then zeros
(row `256` reads `(one, zero)`), the other public rows read zeros. -/
structure WellFormed (rows : Rows n) : Prop where
  reads : ∀ r, ¬ IsInput rows r → ∀ r', Reads rows r r' →
    512 ≤ r'.val ∧ (r.val < 512 ∨ r'.val < r.val)
  public_carry : ∀ r : Fin (2 ^ n), r.val < 512 → (rows r).c = .zero
  public_bits : ∀ r : Fin (2 ^ n), r.val < 256 → ∀ s, (s = (rows r).x ∨ s = (rows r).y) →
    ∃ r', s = .row r' ∧ (rows r').y = .zero ∧ (rows r').c = .zero
  word_four : ∀ r : Fin (2 ^ n), r.val = 256 → (rows r).x = .one ∧ (rows r).y = .zero
  zeros : ∀ r : Fin (2 ^ n), 256 < r.val → r.val < 512 → (rows r).x = .zero ∧ (rows r).y = .zero

/-- The rank of `check_wired`: the public rows last. -/
def rank (r : Fin (2 ^ n)) : ℕ := if r.val < 512 then 2 ^ n + r.val else r.val

theorem rank_lt {rows : Rows n} (hwf : WellFormed rows) (r : Fin (2 ^ n))
    (hr : ¬ IsInput rows r) (r' : Fin (2 ^ n)) (h : Reads rows r r') : rank r' < rank r := by
  obtain ⟨h1, h2⟩ := hwf.reads r hr r' h
  have := r'.isLt
  unfold rank
  split_ifs <;> omega

/-! ## The Boolean semantics -/

/-- A full adder on the bits of `x` and `y` and the carry of `c`: the sum bit and the carry. -/
def fa (x y c : Bool × Bool) : Bool × Bool :=
  (xor (xor x.1 y.1) c.2, (x.1 && y.1) || (c.2 && xor x.1 y.1))

/-- What a source holds, given every row's bit and carry: the constant one has no carry. -/
def read (v : Fin (2 ^ n) → Bool × Bool) : Src (Fin (2 ^ n)) → Bool × Bool
  | .zero => (false, false)
  | .one => (true, false)
  | .row r => v r

/-- `read` on the rows of lower rank only. -/
def readBelow (r : Fin (2 ^ n)) (v : (r' : Fin (2 ^ n)) → rank r' < rank r → Bool × Bool) :
    Src (Fin (2 ^ n)) → Bool × Bool
  | .zero => (false, false)
  | .one => (true, false)
  | .row r' => if h : rank r' < rank r then v r' h else (false, false)

/-- **The circuit's computation**: each row's bit and carry from the input bits `b` (`b r` is
read at the input rows only), as `Circuit::values` and `format.py`'s `evaluate`. -/
def eval (rows : Rows n) (b : Fin (2 ^ n) → Bool) (r : Fin (2 ^ n)) : Bool × Bool :=
  if IsInput rows r then (b r, false)
  else fa (readBelow r (fun r' _ => eval rows b r') (rows r).x)
    (readBelow r (fun r' _ => eval rows b r') (rows r).y)
    (readBelow r (fun r' _ => eval rows b r') (rows r).c)
termination_by rank r
decreasing_by all_goals assumption

theorem eval_input (rows : Rows n) (b : Fin (2 ^ n) → Bool) (r : Fin (2 ^ n))
    (h : IsInput rows r) : eval rows b r = (b r, false) := by
  rw [eval, if_pos h]

theorem eval_gate {rows : Rows n} (hwf : WellFormed rows) (b : Fin (2 ^ n) → Bool)
    (r : Fin (2 ^ n)) (h : ¬ IsInput rows r) :
    eval rows b r = fa (read (eval rows b) (rows r).x) (read (eval rows b) (rows r).y)
      (read (eval rows b) (rows r).c) := by
  have hb : ∀ s, (∀ r', s = .row r' → Reads rows r r') →
      readBelow r (fun r' _ => eval rows b r') s = read (eval rows b) s := by
    intro s hs
    cases s with
    | zero => rfl
    | one => rfl
    | row r' => simp [readBelow, read, rank_lt hwf r h r' (hs r' rfl)]
  rw [eval, if_neg h, hb _ fun r' h' => Or.inl h', hb _ fun r' h' => Or.inr (Or.inl h'),
    hb _ fun r' h' => Or.inr (Or.inr h')]

/-- A row that reads one source and two zeros has no carry. -/
theorem eval_carry (rows : Rows n) (b : Fin (2 ^ n) → Bool) (r : Fin (2 ^ n))
    (hy : (rows r).y = .zero) (hc : (rows r).c = .zero) : (eval rows b r).2 = false := by
  rw [eval]
  split_ifs
  · rfl
  · rw [hy, hc]; simp [fa, readBelow]

/-! ## Rows and cells -/

/-- The bits of row `r`, low bit first. -/
def rowEquiv : Fin (2 ^ n) ≃ (Fin n → Bool) :=
  finFunctionFinEquiv.symm.trans (Equiv.arrowCongr (Equiv.refl _) finTwoEquiv)

theorem rowEquiv_apply (r : Fin (2 ^ n)) (k : Fin n) :
    rowEquiv r k = decide (r.val / 2 ^ (k : ℕ) % 2 = 1) := by
  have e : ∀ i : Fin 2, finTwoEquiv i = decide (i.val = 1) := by decide
  show finTwoEquiv (finFunctionFinEquiv.symm r k) = _
  rw [e]
  rfl

theorem bitAt_rowEquiv (r : Fin (2 ^ n)) (k : ℕ) :
    bitAt (rowEquiv r) k = decide (r.val / 2 ^ k % 2 = 1) := by
  unfold bitAt
  split_ifs with h
  · exact rowEquiv_apply r ⟨k, h⟩
  · have : r.val / 2 ^ k = 0 := Nat.div_eq_of_lt
      (lt_of_lt_of_le r.isLt (Nat.pow_le_pow_right (by norm_num) (not_lt.mp h)))
    simp [this]

/-- The cell of row `r` with role `role` (`X`, `Y`, `C`, `V`): cell `4 r + role` of Rust. -/
def cellOf (r : Fin (2 ^ n)) (role : Fin 4) : Fin (n + 2) → Bool := cellBits (rowEquiv r, role)

theorem bitAt_cell_zero (y : Fin n → Bool) (role : Fin 4) :
    bitAt (cellBits (y, role) : Fin (n + 2) → Bool) 0 = roleBit0 role := by
  unfold bitAt; rw [dif_pos (by omega)]; rfl

theorem bitAt_cell_one (y : Fin n → Bool) (role : Fin 4) :
    bitAt (cellBits (y, role) : Fin (n + 2) → Bool) 1 = roleBit1 role := by
  unfold bitAt; rw [dif_pos (by omega)]; rfl

theorem bitAt_cell_succ_succ (y : Fin n → Bool) (role : Fin 4) (k : ℕ) :
    bitAt (cellBits (y, role) : Fin (n + 2) → Bool) (k + 1 + 1) = bitAt y k := by
  unfold bitAt
  by_cases h : k < n
  · rw [dif_pos (by omega), dif_pos h]; rfl
  · rw [dif_neg (by omega), dif_neg h]

theorem bitAt_fin {m : ℕ} (x : Fin m → Bool) (j : Fin m) : bitAt x j = x j := by
  simp [bitAt, j.isLt]

/-- Sums over the cells are sums over the rows and their four roles. -/
theorem sum_cells {M : Type*} [AddCommMonoid M] (g : (Fin (n + 2) → Bool) → M) :
    ∑ x, g x = ∑ r : Fin (2 ^ n), ∑ role : Fin 4, g (cellOf r role) := by
  rw [← Equiv.sum_comp (cellBits (n := n)) g, Fintype.sum_prod_type,
    ← Equiv.sum_comp (rowEquiv (n := n))]
  rfl

/-! ## The public words on the rows -/

variable {F : Type} [Field F]

/-- The weight of pair `p` of a word: the product of `c (k + 2)` over the set bits `k` of `p`. -/
def pairWeight (c : ℕ → F) (p : ℕ) : F :=
  ∏ k ∈ Finset.range 6, if p / 2 ^ k % 2 = 1 then c (k + 2) else 1

def roleWeight (c : ℕ → F) (role : Fin 4) : F :=
  (if roleBit0 role then c 0 else 1) * (if roleBit1 role then c 1 else 1)

theorem lt_512_of_bits (r : Fin (2 ^ n))
    (h : ∀ k, 9 ≤ k → r.val / 2 ^ k % 2 = 0) : r.val < 512 := by
  by_contra hr
  push_neg at hr
  have h0 : r.val ≠ 0 := by omega
  obtain ⟨k, hk⟩ : ∃ k, k = Nat.log 2 r.val := ⟨_, rfl⟩
  have h1 : 2 ^ k ≤ r.val := hk ▸ Nat.pow_log_le_self 2 h0
  have h2 : r.val < 2 ^ k * 2 := by
    have := Nat.lt_pow_succ_log_self (by norm_num : 1 < 2) r.val
    rw [← hk, Nat.pow_succ] at this
    exact this
  have hk9 : 9 ≤ k := by
    by_contra hk9
    push_neg at hk9
    have : 2 ^ k ≤ 2 ^ 8 := Nat.pow_le_pow_right (by norm_num) (by omega)
    norm_num at this
    omega
  have hq1 : 1 ≤ r.val / 2 ^ k := (Nat.le_div_iff_mul_le (by positivity)).2 (by omega)
  have hq2 : r.val / 2 ^ k < 2 := (Nat.div_lt_iff_lt_mul (by positivity)).2 (by omega)
  have := h k hk9
  omega

/-- **The weight of a cell in word `J`**, on a row: zero off the public rows of the word, and the
product of its role's and its pair's weights on them. -/
theorem regionWeightN_cellOf (c : ℕ → F) (J : Fin 8) (r : Fin (2 ^ n)) (role : Fin 4) :
    regionWeightN c J (cellOf r role)
      = if r.val < 512 ∧ r.val / 64 = J.val then roleWeight c role * pairWeight c (r.val % 64)
        else 0 := by
  have hbit : ∀ k, bitAt (cellOf r role) (k + 1 + 1) = decide (r.val / 2 ^ k % 2 = 1) :=
    fun k => (bitAt_cell_succ_succ _ _ k).trans (bitAt_rowEquiv r k)
  have hA : (∀ j : Fin (n + 2), 11 ≤ (j : ℕ) → cellOf r role j = false) ↔ r.val < 512 := by
    constructor
    · intro h
      refine lt_512_of_bits r fun k hk => ?_
      by_cases hkn : k < n
      · have h' : bitAt (cellOf r role) (k + 1 + 1) = false := by
          rw [← h ⟨k + 1 + 1, by omega⟩ (by simp; omega)]
          exact bitAt_fin _ ⟨k + 1 + 1, by omega⟩
        rw [hbit] at h'
        simp at h'
        omega
      · have : r.val / 2 ^ k = 0 := Nat.div_eq_of_lt
          (lt_of_lt_of_le r.isLt (Nat.pow_le_pow_right (by norm_num) (not_lt.mp hkn)))
        simp [this]
    · intro h j hj
      obtain ⟨k, hk⟩ : ∃ k, (j : ℕ) = k + 1 + 1 := ⟨j - 2, by omega⟩
      have e : cellOf r role j = bitAt (cellOf r role) (k + 1 + 1) := by rw [← hk, bitAt_fin]
      rw [e, hbit]
      have : r.val / 2 ^ k = 0 := Nat.div_eq_of_lt
        (lt_of_lt_of_le h (le_trans (by norm_num) (Nat.pow_le_pow_right (by norm_num)
          (show 9 ≤ k by omega))))
      simp [this]
  have hB : r.val < 512 → (wordOfN (cellOf r role) = J ↔ r.val / 64 = J.val) := by
    intro h
    have e : ∀ k, (bitAt (cellOf r role) (k + 1 + 1)).toNat = r.val / 2 ^ k % 2 := by
      intro k
      rw [hbit]
      rcases Nat.mod_two_eq_zero_or_one (r.val / 2 ^ k) with h' | h' <;> simp [h']
    rw [Fin.ext_iff]
    show (bitAt (cellOf r role) (6 + 1 + 1)).toNat + 2 * (bitAt (cellOf r role) (7 + 1 + 1)).toNat
        + 4 * (bitAt (cellOf r role) (8 + 1 + 1)).toNat = J.val ↔ _
    rw [e, e, e]
    norm_num
    omega
  have hprod : ∏ k ∈ Finset.range 8, (if bitAt (cellOf r role) k then c k else 1)
      = roleWeight c role * pairWeight c (r.val % 64) := by
    rw [Finset.prod_range_succ', Finset.prod_range_succ']
    unfold cellOf
    rw [bitAt_cell_zero, bitAt_cell_one, roleWeight, pairWeight]
    have hp : ∏ k ∈ Finset.range 6, (if bitAt (cellBits (rowEquiv r, role) : Fin (n + 2) → Bool)
        (k + 1 + 1) then c (k + 1 + 1) else 1)
        = ∏ k ∈ Finset.range 6, if r.val % 64 / 2 ^ k % 2 = 1 then c (k + 2) else 1 := by
      refine Finset.prod_congr rfl fun k hk => ?_
      have hk6 := Finset.mem_range.mp hk
      have hm : r.val % 64 / 2 ^ k % 2 = r.val / 2 ^ k % 2 := by
        interval_cases k <;> norm_num <;> omega
      rw [bitAt_cell_succ_succ, bitAt_rowEquiv, hm]
      by_cases h : r.val / 2 ^ k % 2 = 1 <;> simp [h]
    rw [hp]
    ring
  unfold regionWeightN
  by_cases h : r.val < 512 ∧ r.val / 64 = J.val
  · rw [if_pos ⟨hA.mpr h.1, (hB h.1).mpr h.2⟩, if_pos h, hprod]
  · rw [if_neg h, if_neg]
    rintro ⟨h1, h2⟩
    exact h ⟨hA.mp h1, (hB (hA.mp h1)).mp h2⟩

/-- Row `64 J + p`, pair `p` of word `J`. -/
def pubRow (h9 : 9 ≤ n) (J : Fin 8) (p : Fin 64) : Fin (2 ^ n) :=
  ⟨64 * J.val + p.val, by
    have : 2 ^ 9 ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) h9
    have := J.isLt; have := p.isLt
    omega⟩

theorem sum_region {M : Type*} [AddCommMonoid M] (h9 : 9 ≤ n) (J : Fin 8)
    (g : Fin (2 ^ n) → M) :
    ∑ r : Fin (2 ^ n), (if r.val < 512 ∧ r.val / 64 = J.val then g r else 0)
      = ∑ p : Fin 64, g (pubRow h9 J p) := by
  rw [← Finset.sum_filter]
  refine Finset.sum_nbij' (fun r => (⟨r.val % 64, Nat.mod_lt _ (by norm_num)⟩ : Fin 64))
    (pubRow h9 J) ?_ ?_ ?_ ?_ ?_
  · intros; simp
  · intro p _
    have := J.isLt; have := p.isLt
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, pubRow]
    omega
  · intro r hr
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hr
    ext; simp only [pubRow]; omega
  · intro p _
    have := p.isLt
    ext; simp only [pubRow]; omega
  · intro r hr
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hr
    congr 1
    ext; simp only [pubRow]; omega

/-- A word's sum, on the rows: the `X` cell and `c 0` times the `Y` cell of each pair, each with
its pair's weight. -/
theorem wordSum_eq (h9 : 9 ≤ n) (c : ℕ → F) (hc1 : c 1 = 0) (J : Fin 8)
    (w : (Fin (n + 2) → Bool) → F) :
    ∑ x, regionWeightN c J x * w x
      = ∑ p : Fin 64, pairWeight c p * (w (cellOf (pubRow h9 J p) 0)
          + c 0 * w (cellOf (pubRow h9 J p) 1)) := by
  rw [sum_cells]
  have hrow : ∀ r : Fin (2 ^ n), ∑ role : Fin 4, regionWeightN c J (cellOf r role) * w (cellOf r role)
      = if r.val < 512 ∧ r.val / 64 = J.val then
          pairWeight c (r.val % 64) * (w (cellOf r 0) + c 0 * w (cellOf r 1)) else 0 := by
    intro r
    simp only [regionWeightN_cellOf, Fin.sum_univ_four]
    split_ifs
    · simp [roleWeight, roleBit0, roleBit1, hc1]; ring
    · simp
  rw [Finset.sum_congr rfl fun r _ => hrow r, sum_region h9 J]
  refine Finset.sum_congr rfl fun p _ => ?_
  have : (pubRow h9 J p).val % 64 = p.val := by
    have := p.isLt; simp only [pubRow]; omega
  rw [this]

/-! ## Packing bits into a word -/

/-- **A word from its 128 bits**: bit `2 p + e` has the weight `c 0 ^ e` times pair `p`'s, the
product of the weights of the set bits of its cell's coordinates. -/
def pack (c : ℕ → F) (β : Fin 128 → F) : F :=
  ∑ p : Fin 64, pairWeight c p * (β ⟨2 * p.val, by omega⟩ + c 0 * β ⟨2 * p.val + 1, by omega⟩)

/-- **The weights are independent over `GF(2)`**: no nonempty set of a word's 128 bit weights sums
to zero. In characteristic 2 this is linear independence over `GF(2)`. -/
def Independent (c : ℕ → F) : Prop :=
  ∀ s : Fin 128 → Bool, pack c (fun j => if s j then 1 else 0) = 0 → ∀ j, s j = false

theorem pack_add (c : ℕ → F) (β β' : Fin 128 → F) :
    pack c (fun j => β j + β' j) = pack c β + pack c β' := by
  unfold pack
  rw [← Finset.sum_add_distrib]
  exact Finset.sum_congr rfl fun p _ => by ring

/-- **Packing is injective**, for independent weights: the words determine the bits. -/
theorem pack_injective [CharP F 2] {c : ℕ → F} (hind : Independent c) (s t : Fin 128 → Bool)
    (h : pack c (fun j => if s j then 1 else 0) = pack c (fun j => if t j then 1 else 0)) :
    s = t := by
  have hx : (fun j => if xor (s j) (t j) then (1 : F) else 0)
      = fun j => (if s j then (1 : F) else 0) + (if t j then 1 else 0) := by
    funext j
    cases s j <;> cases t j <;> simp [CharTwo.add_self_eq_zero]
  have h0 := hind (fun j => xor (s j) (t j)) (by rw [hx, pack_add, h, CharTwo.add_self_eq_zero])
  funext j
  have := h0 j
  cases hs : s j <;> cases ht : t j <;> simp_all

theorem pack_ones_ne_zero {c : ℕ → F} (hind : Independent c) : pack c (fun _ => 1) ≠ 0 := by
  intro h
  have := hind (fun _ => true) (by simpa using h) 0
  simp at this

theorem pairWeight_zero (c : ℕ → F) : pairWeight c 0 = 1 := by simp [pairWeight]

/-! ## The statement -/

/-- Word `J < 4` as one of the eight. -/
def wordIdx (J : Fin 4) : Fin 8 := ⟨J.val, by omega⟩

/-- The cell of bit `j` of word `J`: role `j % 2` of row `64 J + j / 2`. -/
def pubCell (h9 : 9 ≤ n) (J : Fin 8) (j : Fin 128) : Fin (n + 2) → Bool :=
  cellOf (pubRow h9 J ⟨j.val / 2, by omega⟩) ⟨j.val % 2, by omega⟩

/-- The source that bit `j` of word `J` reads. -/
def pubSrc (rows : Rows n) (h9 : 9 ≤ n) (J : Fin 8) (j : Fin 128) : Src (Fin (2 ^ n)) :=
  if j.val % 2 = 0 then (rows (pubRow h9 J ⟨j.val / 2, by omega⟩)).x
  else (rows (pubRow h9 J ⟨j.val / 2, by omega⟩)).y

/-- **Bit `j` of public word `J < 4`** on the input bits `b`: the bit of the row its cell reads. -/
def statementBit (rows : Rows n) (b : Fin (2 ^ n) → Bool) (h9 : 9 ≤ n) (J : Fin 4)
    (j : Fin 128) : Bool :=
  (read (eval rows b) (pubSrc rows h9 (wordIdx J) j)).1

theorem wordSum_pack (h9 : 9 ≤ n) (c : ℕ → F) (hc1 : c 1 = 0) (J : Fin 8)
    (w : (Fin (n + 2) → Bool) → F) :
    ∑ x, regionWeightN c J x * w x = pack c (fun j => w (pubCell h9 J j)) := by
  rw [wordSum_eq h9 c hc1 J w]
  refine Finset.sum_congr rfl fun p _ => ?_
  have hp0 : (⟨2 * p.val / 2, by omega⟩ : Fin 64) = p := Fin.ext (by simp)
  have hp1 : (⟨(2 * p.val + 1) / 2, by omega⟩ : Fin 64) = p := Fin.ext (by simp; omega)
  have e0 : pubCell h9 J ⟨2 * p.val, by omega⟩ = cellOf (pubRow h9 J p) 0 :=
    congrArg₂ cellOf (congrArg (pubRow h9 J) hp0) (Fin.ext (by simp))
  have e1 : pubCell h9 J ⟨2 * p.val + 1, by omega⟩ = cellOf (pubRow h9 J p) 1 :=
    congrArg₂ cellOf (congrArg (pubRow h9 J) hp1) (Fin.ext (by simp))
  dsimp only
  rw [e0, e1]

/-! ### Format.py's order of the 512 bits -/

/-- Where bit `j` of word `J` is in the statement's 512 bits (`format.py`'s `decode`: words are
sixteen bytes, big-endian, two words to each 32-byte half). -/
def bitIndex (J : Fin 4) (j : Fin 128) : Fin 512 :=
  ⟨256 * (J.val / 2) + 8 * (16 * (J.val % 2) + 15 - j.val / 8) + j.val % 8, by omega⟩

def wordOfIndex (i : Fin 512) : Fin 4 := ⟨2 * (i.val / 256) + i.val % 256 / 128, by omega⟩

def bitOfIndex (i : Fin 512) : Fin 128 := ⟨8 * (15 - i.val % 256 / 8 % 16) + i.val % 8, by omega⟩

theorem bitIndex_of (i : Fin 512) : bitIndex (wordOfIndex i) (bitOfIndex i) = i := by
  ext; simp only [bitIndex, wordOfIndex, bitOfIndex]; omega

theorem wordOfIndex_bitIndex (J : Fin 4) (j : Fin 128) : wordOfIndex (bitIndex J j) = J := by
  ext; simp only [bitIndex, wordOfIndex]; omega

theorem bitOfIndex_bitIndex (J : Fin 4) (j : Fin 128) : bitOfIndex (bitIndex J j) = j := by
  ext; simp only [bitIndex, bitOfIndex]; omega

/-- **The statement**: the 512 public bits on the input bits `b`, bit `i` being bit `i % 8` of
byte `i / 8` of `format.py`'s `evaluate`. -/
def statementBits (rows : Rows n) (b : Fin (2 ^ n) → Bool) (h9 : 9 ≤ n) (i : Fin 512) : Bool :=
  statementBit rows b h9 (wordOfIndex i) (bitOfIndex i)

/-- The four words 512 bits pack into. -/
def packBits (c : ℕ → F) (β : Fin 512 → Bool) (J : Fin 4) : F :=
  pack c (fun j => if β (bitIndex J j) then 1 else 0)

/-! ## The cells of a value in `GF(4)` -/

/-- A bit and a carry as an element of `GF(4)`: `a + θ b`. -/
def enc (θ : F) (p : Bool × Bool) : F := (if p.1 then 1 else 0) + θ * (if p.2 then 1 else 0)

theorem enc_read (θ : F) (v : Fin (2 ^ n) → Bool × Bool) (s : Src (Fin (2 ^ n))) :
    enc θ (read v s) = s.val (fun r => enc θ (v r)) := by
  cases s with
  | zero => simp [enc, read, Src.val]
  | one => simp [enc, read, Src.val]
  | row r => rfl

variable [CharP F 2] {θ : F}

theorem bitOf_enc (hθ : θ * θ + θ + 1 = 0) (p : Bool × Bool) :
    bitOf θ (enc θ p) = if p.1 then 1 else 0 := by
  have two : (2 : F) = 0 := CharTwo.two_eq_zero
  obtain ⟨a, b⟩ := p
  cases a <;> cases b <;> simp only [enc, bitOf, if_true, if_false, Bool.false_eq_true]
  · ring
  · linear_combination (θ * θ * θ) * two
  · linear_combination hθ - two
  · linear_combination hθ + (θ ^ 3 + θ ^ 2 - 1) * two

theorem carryOf_enc (hθ : θ * θ + θ + 1 = 0) (p : Bool × Bool) :
    carryOf (enc θ p) = if p.2 then 1 else 0 := by
  have two : (2 : F) = 0 := CharTwo.two_eq_zero
  obtain ⟨a, b⟩ := p
  cases a <;> cases b <;> simp only [enc, carryOf, if_true, if_false, Bool.false_eq_true]
  · ring
  · linear_combination hθ - two
  · linear_combination two
  · linear_combination hθ + θ * two

/-- **The full adder satisfies the gate**, on its encoding in `GF(4)`. -/
theorem gate_enc (hθ : θ * θ + θ + 1 = 0) (x y c : Bool × Bool) :
    gate θ (enc θ x) (enc θ y) (enc θ c) (enc θ (fa x y c)) = 0 := by
  have two : (2 : F) = 0 := CharTwo.two_eq_zero
  rw [gate_eq, bitOf_enc hθ, bitOf_enc hθ, carryOf_enc hθ]
  obtain ⟨a, a'⟩ := x
  obtain ⟨b, b'⟩ := y
  obtain ⟨d', d⟩ := c
  cases a <;> cases b <;> cases d <;>
    simp only [enc, fa, if_true, if_false, Bool.false_eq_true, Bool.xor_false, Bool.xor_true,
      Bool.not_false, Bool.not_true, Bool.and_false, Bool.and_true, Bool.or_false, Bool.or_true,
      Bool.false_and, Bool.true_and, Bool.false_or, Bool.true_or, Bool.false_xor, Bool.true_xor] <;>
    first
    | ring1
    | linear_combination two
    | linear_combination (1 + θ) * two
    | linear_combination (2 + 2 * θ) * two

/-- The circuit as an `AdderCircuit`, its rows ranked as `check_wired` ranks them. -/
def adder {rows : Rows n} (hwf : WellFormed rows) : AdderCircuit (Fin (2 ^ n)) where
  x r := (rows r).x
  y r := (rows r).y
  c r := (rows r).c
  rank := rank
  isInput := IsInput rows
  hInput r h := by
    have h' : rows r = ⟨.row r, .zero, .zero⟩ := h
    rw [h']
    exact ⟨rfl, rfl, rfl⟩
  hOrder r hr r' h := rank_lt hwf r hr r' h

/-- The computation satisfies every gate. -/
theorem eval_satisfies (hθ : θ * θ + θ + 1 = 0) {rows : Rows n} (hwf : WellFormed rows)
    (b : Fin (2 ^ n) → Bool) :
    (adder hwf).Satisfies θ (fun r => enc θ (eval rows b r)) := by
  intro r
  show gate θ ((rows r).x.val _) ((rows r).y.val _) ((rows r).c.val _) _ = 0
  rw [← enc_read, ← enc_read, ← enc_read]
  beta_reduce
  by_cases h : IsInput rows r
  · have h' : rows r = ⟨.row r, .zero, .zero⟩ := h
    rw [eval_input rows b r h, h']
    have e : fa (b r, false) (false, false) (false, false) = (b r, false) := by
      cases b r <;> rfl
    have := gate_enc hθ (b r, false) (false, false) (false, false)
    rw [e] at this
    simpa [read, eval_input rows b r h] using this
  · rw [eval_gate hwf b r h]
    exact gate_enc hθ _ _ _

/-! ## The wiring `Circuit::from_rows` builds -/

section Cycle

variable {N : ℕ} {β : Type*} [DecidableEq β] (f : Fin N → β)

/-- The elements of a fiber. -/
def fib (b : β) : Finset (Fin N) := univ.filter fun y => f y = b

/-- The elements of `x`'s fiber after it. -/
def above (x : Fin N) : Finset (Fin N) := (fib f (f x)).filter fun y => x < y

theorem mem_fib {b : β} {y : Fin N} : y ∈ fib f b ↔ f y = b := by simp [fib]

theorem mem_above {x y : Fin N} : y ∈ above f x ↔ f y = f x ∧ x < y := by simp [above, fib]

/-- The next element of `x`'s fiber, the least one after the last. -/
def nextIn (x : Fin N) : Fin N :=
  if h : (above f x).Nonempty then (above f x).min' h
  else (fib f (f x)).min' ⟨x, (mem_fib f).2 rfl⟩

theorem nextIn_pos (x : Fin N) (h : (above f x).Nonempty) : nextIn f x = (above f x).min' h :=
  dif_pos h

theorem nextIn_neg (x : Fin N) (h : ¬ (above f x).Nonempty) :
    nextIn f x = (fib f (f x)).min' ⟨x, (mem_fib f).2 rfl⟩ := dif_neg h

theorem f_nextIn (x : Fin N) : f (nextIn f x) = f x := by
  by_cases h : (above f x).Nonempty
  · rw [nextIn_pos f x h]; exact ((mem_above f).1 (Finset.min'_mem _ h)).1
  · rw [nextIn_neg f x h]; exact (mem_fib f).1 (Finset.min'_mem _ _)

theorem lt_nextIn (x : Fin N) (h : (above f x).Nonempty) : x < nextIn f x := by
  rw [nextIn_pos f x h]; exact ((mem_above f).1 (Finset.min'_mem _ h)).2

theorem nextIn_injective : Function.Injective (nextIn f) := by
  have key : ∀ x x', f x = f x' → x < x' → nextIn f x ≠ nextIn f x' := by
    intro x x' hf hlt heq
    have hmem : x' ∈ above f x := (mem_above f).2 ⟨hf.symm, hlt⟩
    have hne : (above f x).Nonempty := ⟨x', hmem⟩
    have hle : nextIn f x ≤ x' := by rw [nextIn_pos f x hne]; exact Finset.min'_le _ _ hmem
    have hgt : x < nextIn f x := lt_nextIn f x hne
    by_cases h' : (above f x').Nonempty
    · have := lt_nextIn f x' h'
      rw [← heq] at this
      exact absurd hle (not_le.2 this)
    · have : nextIn f x' ≤ x := by
        rw [nextIn_neg f x' h']; exact Finset.min'_le _ _ ((mem_fib f).2 hf)
      rw [← heq] at this
      exact absurd hgt (not_lt.2 this)
  intro x x' heq
  by_contra hne
  have hf : f x = f x' := by
    have h1 := f_nextIn f x
    rw [heq, f_nextIn f x'] at h1
    exact h1.symm
  rcases lt_or_gt_of_ne hne with h | h
  · exact key x x' hf h heq
  · exact key x' x hf.symm h heq.symm

/-- The permutation that takes each element to the next of its fiber, cyclically. -/
noncomputable def fiberPerm : Equiv.Perm (Fin N) :=
  Equiv.ofBijective (nextIn f) (Finite.injective_iff_bijective.mp (nextIn_injective f))

theorem reach_min (x m : Fin N) (hm : f m = f x) (hmin : ∀ y, f y = f x → m ≤ y) :
    ∃ k, (nextIn f)^[k] x = m := by
  induction hc : (above f x).card using Nat.strong_induction_on generalizing x with
  | _ c ih =>
    by_cases h : (above f x).Nonempty
    · have hx1 : f (nextIn f x) = f x := f_nextIn f x
      have hlt := lt_nextIn f x h
      have hsub : above f (nextIn f x) ⊂ above f x := by
        refine (Finset.ssubset_iff_of_subset fun y hy => ?_).2 ⟨nextIn f x, ?_, ?_⟩
        · rw [mem_above] at hy ⊢; exact ⟨hy.1.trans hx1, hlt.trans hy.2⟩
        · rw [mem_above]; exact ⟨hx1, hlt⟩
        · rw [mem_above]; exact fun h => lt_irrefl _ h.2
      obtain ⟨k, hk⟩ := ih _ (hc ▸ Finset.card_lt_card hsub) (nextIn f x) (hm.trans hx1.symm)
        (fun y hy => hmin y (hy.trans hx1)) rfl
      exact ⟨k + 1, by rw [Function.iterate_succ_apply]; exact hk⟩
    · refine ⟨1, ?_⟩
      rw [Function.iterate_one, nextIn_neg f x h]
      exact le_antisymm (Finset.min'_le _ _ ((mem_fib f).2 hm))
        (Finset.le_min' _ _ _ fun y hy => hmin y ((mem_fib f).1 hy))

theorem reach_from_min (y m : Fin N) (hm : f m = f y) (hmin : ∀ z, f z = f y → m ≤ z) :
    ∃ k, (nextIn f)^[k] m = y := by
  induction hc : ((fib f (f y)).filter (· < y)).card using Nat.strong_induction_on
    generalizing y with
  | _ c ih =>
    by_cases h : ((fib f (f y)).filter (· < y)).Nonempty
    · set y' := ((fib f (f y)).filter (· < y)).max' h with hy'
      have hmem := Finset.max'_mem _ h
      rw [← hy', Finset.mem_filter, mem_fib] at hmem
      have hya : y ∈ above f y' := (mem_above f).2 ⟨hmem.1.symm, hmem.2⟩
      have hnext : nextIn f y' = y := by
        rw [nextIn_pos f y' ⟨y, hya⟩]
        refine le_antisymm (Finset.min'_le _ _ hya) (Finset.le_min' _ _ _ fun z hz => ?_)
        rw [mem_above] at hz
        by_contra hzy
        push_neg at hzy
        have : z ∈ (fib f (f y)).filter (· < y) := by
          rw [Finset.mem_filter, mem_fib]; exact ⟨hz.1.trans hmem.1, hzy⟩
        exact absurd (Finset.le_max' _ _ this) (not_le.2 hz.2)
      have hsub : (fib f (f y')).filter (· < y') ⊂ (fib f (f y)).filter (· < y) := by
        refine (Finset.ssubset_iff_of_subset fun z hz => ?_).2 ⟨y', ?_, ?_⟩
        · rw [Finset.mem_filter, mem_fib] at hz ⊢; exact ⟨hz.1.trans hmem.1, hz.2.trans hmem.2⟩
        · rw [Finset.mem_filter, mem_fib]; exact hmem
        · rw [Finset.mem_filter]; exact fun h => lt_irrefl _ h.2
      obtain ⟨k, hk⟩ := ih _ (hc ▸ Finset.card_lt_card hsub) y' (hm.trans hmem.1.symm)
        (fun z hz => hmin z (hz.trans hmem.1)) rfl
      exact ⟨k + 1, by rw [Function.iterate_succ_apply', hk, hnext]⟩
    · refine ⟨0, ?_⟩
      show m = y
      refine le_antisymm (hmin y rfl) ?_
      by_contra hlt
      push_neg at hlt
      exact h ⟨m, by rw [Finset.mem_filter, mem_fib]; exact ⟨hm, hlt⟩⟩

/-- **Two elements of a fiber are on one cycle.** -/
theorem fiberPerm_reach (x y : Fin N) (h : f x = f y) : ∃ k : ℕ, (fiberPerm f ^ k) x = y := by
  set m := (fib f (f x)).min' ⟨x, (mem_fib f).2 rfl⟩
  have hm : f m = f x := (mem_fib f).1 (Finset.min'_mem _ _)
  have hmin : ∀ z, f z = f x → m ≤ z := fun z hz => Finset.min'_le _ _ ((mem_fib f).2 hz)
  obtain ⟨k1, hk1⟩ := reach_min f x m hm hmin
  obtain ⟨k2, hk2⟩ := reach_from_min f y m (hm.trans h) (fun z hz => hmin z (hz.trans h.symm))
  refine ⟨k2 + k1, ?_⟩
  rw [Equiv.Perm.coe_pow]
  show (nextIn f)^[k2 + k1] x = y
  rw [Function.iterate_add_apply, hk1, hk2]

end Cycle

/-- The order of the cells on a cycle: the source's `V` cell first, then the readers in cell
order (`4 r + role`), as `Circuit::from_rows` joins them. -/
def cellKey (p : Fin (2 ^ n) × Fin 4) : ℕ :=
  if p.2 = 3 then p.1.val else 2 ^ n + 3 * p.1.val + p.2.val

theorem cellKey_lt (p : Fin (2 ^ n) × Fin 4) : cellKey p < 4 * 2 ^ n := by
  have := p.1.isLt; have := p.2.isLt
  unfold cellKey
  split_ifs with h
  · omega
  · have : p.2.val ≠ 3 := fun h' => h (Fin.ext h')
    omega

theorem cellKey_injective : Function.Injective (cellKey (n := n)) := by
  rintro ⟨r, a⟩ ⟨s, b⟩ h
  have := r.isLt; have := s.isLt
  fin_cases a <;> fin_cases b <;> simp [cellKey, Prod.ext_iff, Fin.ext_iff] at h ⊢ <;> omega

noncomputable def keyEquiv : Fin (2 ^ n) × Fin 4 ≃ Fin (4 * 2 ^ n) :=
  Equiv.ofBijective (fun p => ⟨cellKey p, cellKey_lt p⟩) (by
    rw [Fintype.bijective_iff_injective_and_card]
    refine ⟨fun p q h => cellKey_injective (Fin.ext_iff.1 h), ?_⟩
    simp [mul_comm])

/-- The cells, in the order of their keys. -/
noncomputable def cellEquiv : Fin (4 * 2 ^ n) ≃ (Fin (n + 2) → Bool) :=
  keyEquiv.symm.trans ((Equiv.prodCongr rowEquiv (Equiv.refl _)).trans cellBits)

theorem cellEquiv_key (r : Fin (2 ^ n)) (role : Fin 4) :
    cellEquiv (keyEquiv (r, role)) = cellOf r role := by
  simp [cellEquiv, cellOf]

/-- The cycle a cell is on: its row's for a `V` cell, its source's for a reading cell. -/
def slot (rows : Rows n) (p : Fin (2 ^ n) × Fin 4) : Src (Fin (2 ^ n)) :=
  if p.2 = 3 then .row p.1 else if p.2 = 0 then (rows p.1).x
  else if p.2 = 1 then (rows p.1).y else (rows p.1).c

/-- **The wiring of the circuit**, as `Circuit::from_rows` builds it: each cell goes to the next
cell of its source's cycle, the source's `V` cell first and then its readers in cell order, the
last back to the first. -/
noncomputable def wiringOf (rows : Rows n) : Equiv.Perm (Fin (n + 2) → Bool) :=
  cellEquiv.permCongr (fiberPerm (slot rows ∘ keyEquiv.symm))

theorem permCongr_pow_apply {α β : Type*} (e : α ≃ β) (σ : Equiv.Perm α) (k : ℕ) (x : β) :
    (e.permCongr σ ^ k) x = e ((σ ^ k) (e.symm x)) := by
  induction k generalizing x with
  | zero => simp
  | succ k ih => rw [pow_succ, Equiv.Perm.mul_apply, ih, pow_succ, Equiv.Perm.mul_apply,
      Equiv.permCongr_apply, Equiv.symm_apply_apply]

theorem wiringOf_reach (rows : Rows n) (p q : Fin (2 ^ n) × Fin 4)
    (h : slot rows p = slot rows q) :
    ∃ k : ℕ, (wiringOf rows ^ k) (cellOf p.1 p.2) = cellOf q.1 q.2 := by
  obtain ⟨k, hk⟩ := fiberPerm_reach (slot rows ∘ keyEquiv.symm) (keyEquiv p) (keyEquiv q)
    (by simp [h])
  refine ⟨k, ?_⟩
  rw [wiringOf, permCongr_pow_apply, ← cellEquiv_key, Equiv.symm_apply_apply, hk, cellEquiv_key]

/-- The constants' anchors: the `X` cells of rows 320 (word 5) and 256 (word 4). -/
def anchor (h9 : 9 ≤ n) (k : ℕ) (hk : k < 512) : Fin (2 ^ n) :=
  ⟨k, lt_of_lt_of_le hk (le_trans (by norm_num) (Nat.pow_le_pow_right (by norm_num) h9))⟩

/-- The cell a source is read from: a row's `V` cell, or a constant's anchor. -/
def target (h9 : 9 ≤ n) : Src (Fin (2 ^ n)) → Fin (n + 2) → Bool
  | .zero => cellOf (anchor h9 320 (by norm_num)) 0
  | .one => cellOf (anchor h9 256 (by norm_num)) 0
  | .row r => cellOf r 3

/-- **Every reading cell is on the cycle of the cell it reads**: the hypothesis `Wired` of
`cells_determined`, on the cells by their bits. -/
def WiredBy (h9 : 9 ≤ n) (rows : Rows n) (σ : Equiv.Perm (Fin (n + 2) → Bool)) : Prop :=
  ∀ r, (∃ k : ℕ, (σ ^ k) (cellOf r 0) = target h9 (rows r).x) ∧
    (∃ k : ℕ, (σ ^ k) (cellOf r 1) = target h9 (rows r).y) ∧
    (∃ k : ℕ, (σ ^ k) (cellOf r 2) = target h9 (rows r).c)

/-- **The wiring `from_rows` builds is wired**, for a well-formed circuit. -/
theorem wiringOf_wired (h9 : 9 ≤ n) {rows : Rows n} (hwf : WellFormed rows) :
    WiredBy h9 rows (wiringOf rows) := by
  have ht : ∀ s, ∃ q : Fin (2 ^ n) × Fin 4, cellOf q.1 q.2 = target h9 s ∧ slot rows q = s := by
    intro s
    cases s with
    | zero =>
      refine ⟨(anchor h9 320 (by norm_num), 0), rfl, ?_⟩
      simp [slot, (hwf.zeros (anchor h9 320 (by norm_num)) (by simp [anchor])
        (by simp [anchor])).1]
    | one =>
      refine ⟨(anchor h9 256 (by norm_num), 0), rfl, ?_⟩
      simp [slot, (hwf.word_four (anchor h9 256 (by norm_num)) (by simp [anchor])).1]
    | row r => exact ⟨(r, 3), rfl, by simp [slot]⟩
  intro r
  refine ⟨?_, ?_, ?_⟩
  · obtain ⟨q, hq, hs⟩ := ht (rows r).x
    rw [← hq]; exact wiringOf_reach rows (r, 0) q (by rw [hs]; simp [slot])
  · obtain ⟨q, hq, hs⟩ := ht (rows r).y
    rw [← hq]; exact wiringOf_reach rows (r, 1) q (by rw [hs]; simp [slot])
  · obtain ⟨q, hq, hs⟩ := ht (rows r).c
    rw [← hq]; exact wiringOf_reach rows (r, 2) q (by rw [hs]; simp [slot])

end Desc

/-! ## The relation is the circuit's statement -/

namespace InstanceN

open Desc

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}

/-- **A satisfying assignment is the circuit's computation, and its words are the statement's.**
For a well-formed circuit whose wiring is the instance's (`WiredBy`, which `wiringOf` meets), with
coordinate 1's weight zero and the bit weights independent: cells that satisfy the relation for
words `(s_0, s_1, s_2, s_3, 1, 0, …)` are the encoding of the computation on some input bits `b`,
and each `s_J` is the packing of the 128 statement bits of word `J`. -/
theorem statement_of_relation (I : InstanceN F n) (rows : Rows n) (hwf : WellFormed rows)
    (hwire : WiredBy I.low rows I.wiring) (hc1 : I.c 1 = 0) (hind : Independent I.c)
    (stmt : Fin 8 → F) (h4 : stmt 4 = 1) (h5 : stmt 5 = 0) (w : (Fin (n + 2) → Bool) → F)
    (hrel : I.Relation stmt w) :
    ∃ b : Fin (2 ^ n) → Bool, ∀ J : Fin 4,
      stmt (wordIdx J) = pack I.c (fun j => if statementBit rows b I.low J j then 1 else 0) := by
  classical
  have h9 := I.low
  set θ := I.basis.β 1 with hθdef
  have hθ : θ * θ + θ + 1 = 0 := cantor_theta I.basis (by omega)
  obtain ⟨hgate, hcopy, hword⟩ := hrel
  have reach : ∀ a a', (∃ k : ℕ, (I.wiring ^ k) a = a') → w a' = w a := by
    rintro a a' ⟨k, rfl⟩; exact copy_iterate I.wiring w hcopy k a
  have hread : ∀ r, w (cellOf r 0) = w (target I.low (rows r).x) ∧
      w (cellOf r 1) = w (target I.low (rows r).y) ∧
      w (cellOf r 2) = w (target I.low (rows r).c) := fun r =>
    ⟨(reach _ _ (hwire r).1).symm, (reach _ _ (hwire r).2.1).symm,
      (reach _ _ (hwire r).2.2).symm⟩
  -- The zero: word 5 is all of its cells.
  have hz : w (target I.low .zero) = 0 := by
    have h := hword 5
    rw [wordSum_eq I.low I.c hc1 5 w, h5] at h
    have hcell : ∀ p : Fin 64, w (cellOf (pubRow I.low 5 p) 0) = w (target I.low .zero) ∧
        w (cellOf (pubRow I.low 5 p) 1) = w (target I.low .zero) := by
      intro p
      have := p.isLt
      obtain ⟨hx, hy⟩ := hwf.zeros (pubRow I.low 5 p) (by simp [pubRow]; omega)
        (by simp [pubRow]; omega)
      exact ⟨(hread _).1.trans (by rw [hx]), (hread _).2.1.trans (by rw [hy])⟩
    have e : ∑ p : Fin 64, pairWeight I.c p * (w (cellOf (pubRow I.low 5 p) 0)
        + I.c 0 * w (cellOf (pubRow I.low 5 p) 1))
        = w (target I.low .zero) * pack I.c (fun _ => 1) := by
      unfold pack
      rw [Finset.mul_sum]
      refine Finset.sum_congr rfl fun p _ => ?_
      rw [(hcell p).1, (hcell p).2]
      ring
    rw [e] at h
    exact (mul_eq_zero.mp h).resolve_right (pack_ones_ne_zero hind)
  -- The one: word 4 is the one and zeros.
  have ho : w (target I.low .one) = 1 := by
    have h := hword 4
    rw [wordSum_eq I.low I.c hc1 4 w, h4] at h
    rw [Finset.sum_eq_single (0 : Fin 64)] at h
    · obtain ⟨hx, hy⟩ := hwf.word_four (pubRow I.low 4 0) (by simp [pubRow])
      rw [(hread _).1, (hread _).2.1, hx, hy, hz] at h
      simpa [pairWeight_zero] using h
    · intro p _ hp
      have hp' : p.val ≠ 0 := fun h => hp (Fin.ext h)
      have := p.isLt
      obtain ⟨hx, hy⟩ := hwf.zeros (pubRow I.low 4 p) (by simp [pubRow]; omega)
        (by simp [pubRow]; omega)
      rw [(hread _).1, (hread _).2.1, hx, hy, hz]
      ring
    · intro h; exact absurd (Finset.mem_univ _) h
  set v : Fin (2 ^ n) → F := fun r => w (cellOf r 3) with hv
  have htarget : ∀ s, w (target I.low s) = s.val v := by
    intro s
    cases s with
    | zero => exact hz
    | one => exact ho
    | row r => rfl
  -- The outputs satisfy the circuit.
  have hsat : (adder hwf).Satisfies θ v := by
    intro r
    have h := hgate (rowEquiv r)
    change gate θ (w (cellOf r 0)) (w (cellOf r 1)) (w (cellOf r 2)) (w (cellOf r 3)) = 0 at h
    rw [(hread r).1, (hread r).2.1, (hread r).2.2, htarget, htarget, htarget] at h
    exact h
  set b : Fin (2 ^ n) → Bool := fun r => decide (v r = 1) with hb
  have hin : ∀ r, (adder hwf).isInput r → v r = enc θ (eval rows b r) := by
    intro r hr
    have h' : rows r = ⟨.row r, .zero, .zero⟩ := hr
    have h := hsat r
    change gate θ ((rows r).x.val v) ((rows r).y.val v) ((rows r).c.val v) (v r) = 0 at h
    rw [h'] at h
    change gate θ (v r) 0 0 (v r) = 0 at h
    rw [eval_input rows b r hr]
    show v r = enc θ (decide (v r = 1), false)
    rcases input_is_bit hθ h with h0 | h1
    · rw [h0]; simp [enc]
    · rw [h1]; simp [enc]
  have hdet := AdderCircuit.determined hθ (adder hwf) v _ hsat (eval_satisfies hθ hwf b) hin
  refine ⟨b, fun J => ?_⟩
  have h := hword (wordIdx J)
  rw [wordSum_pack I.low I.c hc1 _ w] at h
  rw [← h]
  congr 1
  funext j
  -- The cell of bit `j` reads a row with no carry: it holds that row's bit.
  have hj : w (pubCell I.low (wordIdx J) j) = w (target I.low (pubSrc rows I.low (wordIdx J) j)) := by
    unfold pubCell pubSrc
    split_ifs with h2
    · have e : (⟨j.val % 2, by omega⟩ : Fin 4) = 0 := Fin.ext h2
      rw [e]; exact (hread _).1
    · have e : (⟨j.val % 2, by omega⟩ : Fin 4) = 1 := Fin.ext (by simp; omega)
      rw [e]; exact (hread _).2.1
  have hlt : (pubRow I.low (wordIdx J) ⟨j.val / 2, by omega⟩).val < 256 := by
    have := J.isLt; have := j.isLt
    show 64 * J.val + j.val / 2 < 256
    omega
  obtain ⟨r1, hr1, hy1, hc1'⟩ := hwf.public_bits _ hlt (pubSrc rows I.low (wordIdx J) j) (by
    unfold pubSrc; split_ifs <;> simp)
  rw [hj, hr1, htarget]
  show v r1 = _
  rw [(hdet r1).1]
  unfold statementBit
  rw [hr1]
  show enc θ (eval rows b r1) = if (eval rows b r1).1 then 1 else 0
  simp [enc, eval_carry rows b r1 hy1 hc1']

/-- **The statement's bits are the circuit's**: with independent weights, if the four words pack
512 bits `β`, then `β` is the statement of the circuit on some input. -/
theorem statementBits_of_relation (I : InstanceN F n) (rows : Rows n) (hwf : WellFormed rows)
    (hwire : WiredBy I.low rows I.wiring) (hc1 : I.c 1 = 0) (hind : Independent I.c)
    (stmt : Fin 8 → F) (h4 : stmt 4 = 1) (h5 : stmt 5 = 0) (w : (Fin (n + 2) → Bool) → F)
    (hrel : I.Relation stmt w) (β : Fin 512 → Bool)
    (hβ : ∀ J : Fin 4, stmt (wordIdx J) = packBits I.c β J) :
    ∃ b : Fin (2 ^ n) → Bool, statementBits rows b I.low = β := by
  obtain ⟨b, hb⟩ := I.statement_of_relation rows hwf hwire hc1 hind stmt h4 h5 w hrel
  refine ⟨b, funext fun i => ?_⟩
  have h := pack_injective hind _ _ ((hβ (wordOfIndex i)).symm.trans (hb (wordOfIndex i)))
  have := congrFun h (bitOfIndex i)
  simp only [bitIndex_of] at this
  exact this.symm

variable [Fintype F] [SampleableType F]

/-- The statement of a proof, as eight words. -/
def words {I : InstanceN F n} (π : I.Proof) : Fin 8 → F := π.stmt

/-- **End-to-end soundness, at every size.** For a well-formed circuit of `2^n` rows,
`9 ≤ n ≤ 29`, whose wiring is the instance's, over a field of `2^192` elements, with coordinate
1's weight zero and independent bit weights: an adversary making `Q` queries makes the verifier
accept a statement `(s_0, s_1, s_2, s_3, 1, 0, …)` such that no input bits give the circuit
public words `s_0, …, s_3` with probability at most `(Q + 3) / 2^128`. -/
theorem circuit_soundness (I : InstanceN F n) (rows : Rows n) (hwf : WellFormed rows)
    (hwire : WiredBy I.low rows I.wiring) (hc1 : I.c 1 = 0) (hind : Independent I.c)
    (hq : Fintype.card F = 2 ^ 192) (adv : I.Adversary) (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ words r.1 4 = 1 ∧ words r.1 5 = 0 ∧
          ¬ ∃ b : Fin (2 ^ n) → Bool, ∀ J : Fin 4, words r.1 (wordIdx J)
            = pack I.c (fun j => if statementBit rows b I.low J j then 1 else 0)]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 := by
  refine le_trans (prEvent_mono _ _ _ ?_) (I.soundness hq adv Q hQ)
  rintro r ⟨hacc, h4, h5, hno⟩
  exact ⟨hacc, fun hrel => hno (I.statement_of_relation rows hwf hwire hc1 hind _ h4 h5 _ hrel)⟩

/-- **End-to-end soundness on the statement's 512 bits.** The probability that the verifier
accepts words `(s_0, …, s_3, 1, 0, …)` packing 512 bits `β` that are not the circuit's statement
`statementBits rows b` on any input `b` is at most `(Q + 3) / 2^128`. -/
theorem circuit_soundness_bits (I : InstanceN F n) (rows : Rows n) (hwf : WellFormed rows)
    (hwire : WiredBy I.low rows I.wiring) (hc1 : I.c 1 = 0) (hind : Independent I.c)
    (hq : Fintype.card F = 2 ^ 192) (adv : I.Adversary) (Q : ℕ) (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ words r.1 4 = 1 ∧ words r.1 5 = 0 ∧
          ∃ β : Fin 512 → Bool, (∀ J : Fin 4, words r.1 (wordIdx J) = packBits I.c β J) ∧
            ¬ ∃ b : Fin (2 ^ n) → Bool, statementBits rows b I.low = β]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 := by
  refine le_trans (prEvent_mono _ _ _ ?_) (I.soundness hq adv Q hQ)
  rintro r ⟨hacc, h4, h5, β, hβ, hno⟩
  exact ⟨hacc, fun hrel =>
    hno (I.statementBits_of_relation rows hwf hwire hc1 hind _ h4 h5 _ hrel β hβ)⟩

end InstanceN

namespace Desc

variable {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}

/-- **The instance of a circuit**: a Cantor basis of `n + 2` vectors, the wiring `from_rows`
builds, the weights. -/
noncomputable def instanceOf (basis : CantorBasis F (n + 2)) (rows : Rows n) (c : ℕ → F)
    (h9 : 9 ≤ n) (h29 : n ≤ 29) : InstanceN F n :=
  ⟨basis, wiringOf rows, c, h9, h29⟩

/-- Every size in the range, every circuit and every weights have an instance. -/
theorem exists_instanceOf [Fintype F] (hq : Fintype.card F = 2 ^ 192) (h9 : 9 ≤ n)
    (h29 : n ≤ 29) (rows : Rows n) (c : ℕ → F) :
    ∃ basis : CantorBasis F (n + 2), (instanceOf basis rows c h9 h29).wiring = wiringOf rows :=
  ⟨Classical.choice (exists_cantorBasis_big hq (n + 2) (by omega) (by omega)), rfl⟩

variable [Fintype F] [SampleableType F]

/-- **End-to-end soundness for a circuit given by its rows**, at every size `9 ≤ n ≤ 29`: on the
instance `from_rows` builds, the wiring hypothesis is discharged. -/
theorem soundness_ofRows (basis : CantorBasis F (n + 2)) (rows : Rows n) (c : ℕ → F)
    (h9 : 9 ≤ n) (h29 : n ≤ 29) (hwf : WellFormed rows) (hc1 : c 1 = 0) (hind : Independent c)
    (hq : Fintype.card F = 2 ^ 192) (adv : (instanceOf basis rows c h9 h29).Adversary) (Q : ℕ)
    (hQ : IsTotalQueryBound adv Q) :
    Pr{let r ← (simulateQ randomOracle (experiment adv)).run' ∅}[
        r.2 = true ∧ InstanceN.words r.1 4 = 1 ∧ InstanceN.words r.1 5 = 0 ∧
          ∃ β : Fin 512 → Bool, (∀ J : Fin 4, InstanceN.words r.1 (wordIdx J) = packBits c β J) ∧
            ¬ ∃ b : Fin (2 ^ n) → Bool, statementBits rows b h9 = β]
      ≤ (Q + 3 : ENNReal) / 2 ^ 128 :=
  (instanceOf basis rows c h9 h29).circuit_soundness_bits rows hwf (wiringOf_wired h9 hwf) hc1
    hind hq adv Q hQ

end Desc

end QuotientSecurity
