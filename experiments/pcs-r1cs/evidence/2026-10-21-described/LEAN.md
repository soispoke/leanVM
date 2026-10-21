# The circuit's statement, formally, at every size

Date: 2026-10-21. Toolchain: `leanprover/lean4:v4.34.0`. `lake-manifest.json` is unchanged and the prebuilt `.lake` was reused. Branch `suite-lean`, on top of `27acb57d` (the theorems at every size).

Command, in `formal/quotient`: `LEAN_NUM_THREADS=16 lake build`. Result: **`Build completed successfully (9162 jobs)`, exit 0** ([log](lake-build.log.gz)). The new module is `QuotientSecurity/Described.lean` (sha256 `ab0516bcd3151396d13991da903a0c42d9a0441bd063e2608ae4e7d09fcc1e77`). The root `QuotientSecurity.lean` (sha256 `bc108670d4b27609b6f0d69abe5e6efeebfe9c84c005d81d9dbfd9acbae2827c`) imports it and adds 16 axiom guards. Twelve of them are exactly `[propext, Classical.choice, Quot.sound]`. The other four (`eval_gate`, `eval_satisfies`, `gate_enc`, `bitIndex_of`) are exactly `[propext, Quot.sound]`. No `sorry`, no new axiom, no existing theorem changed.

## What is proved

For every `9 ≤ n ≤ 29`, every circuit of `2^n` rows that is `Desc.WellFormed` (the row conditions of `check_wired` and `format.py`'s `check`), on the instance with the wiring `Desc.wiringOf rows` (Lean's `from_rows`), with `c 1 = 0` and `Desc.Independent c`:

* Cells satisfying the relation for words `(s_0, …, s_3, 1, 0, 0, 0)` come from some input bits `b`, and the words pack `statementBits rows b` (`InstanceN.statement_of_relation`, `InstanceN.statementBits_of_relation`).
* The verifier accepts such words packing 512 bits that are not the circuit's output on any input with probability at most `(Q + 3) / 2^128` (`InstanceN.circuit_soundness_bits`, `Desc.soundness_ofRows`).

Hypotheses that remain: `Desc.Independent c`, meaning no nonempty set of a word's 128 bit weights sums to zero, i.e. linear independence over GF(2). It is true of the Rust `bit_weight` by construction, since they are distinct coordinate basis vectors of `F192`, but no Rust test checks independence and Lean does not model `F192`. Rust's `public_weights_are_products_over_coordinates` checks that the weights are the products of coordinate weights that `c` describes. The other hypothesis is `c 1 = 0` (`coordinate_weight(1)`). That the Rust `from_rows`, `values` and `check_wired` are these definitions is by reading. That the concrete circuit is well formed is the Rust test `membership_is_a_wired_loop_free_circuit`.

## Statements (`#check` / `#print`)

```
QuotientSecurity.Desc.WellFormed {n : ℕ} (rows : Desc.Rows n) : Prop
QuotientSecurity.Desc.eval {n : ℕ} (rows : Desc.Rows n) (b : Fin (2 ^ n) → Bool) (r : Fin (2 ^ n)) : Bool × Bool
QuotientSecurity.Desc.statementBits {n : ℕ} (rows : Desc.Rows n) (b : Fin (2 ^ n) → Bool) (h9 : 9 ≤ n) (i : Fin 512) :
  Bool
QuotientSecurity.Desc.pack {F : Type} [Field F] (c : ℕ → F) (β : Fin 128 → F) : F
QuotientSecurity.Desc.packBits {F : Type} [Field F] (c : ℕ → F) (β : Fin 512 → Bool) (J : Fin 4) : F
QuotientSecurity.Desc.Independent {F : Type} [Field F] (c : ℕ → F) : Prop
QuotientSecurity.Desc.bitIndex (J : Fin 4) (j : Fin 128) : Fin 512
QuotientSecurity.Desc.WiredBy {n : ℕ} (h9 : 9 ≤ n) (rows : Desc.Rows n) (σ : Equiv.Perm (Fin (n + 2) → Bool)) : Prop
QuotientSecurity.Desc.wiringOf {n : ℕ} (rows : Desc.Rows n) : Equiv.Perm (Fin (n + 2) → Bool)
QuotientSecurity.Desc.instanceOf {F : Type} [Field F] [CharP F 2] {n : ℕ} (basis : CantorBasis F (n + 2))
  (rows : Desc.Rows n) (c : ℕ → F) (h9 : 9 ≤ n) (h29 : n ≤ 29) : InstanceN F n
QuotientSecurity.Desc.gate_enc {F : Type} [Field F] [CharP F 2] {θ : F} (hθ : θ * θ + θ + 1 = 0) (x y c : Bool × Bool) :
  gate θ (Desc.enc θ x) (Desc.enc θ y) (Desc.enc θ c) (Desc.enc θ (Desc.fa x y c)) = 0
QuotientSecurity.Desc.eval_satisfies {n : ℕ} {F : Type} [Field F] [CharP F 2] {θ : F} (hθ : θ * θ + θ + 1 = 0)
  {rows : Desc.Rows n} (hwf : Desc.WellFormed rows) (b : Fin (2 ^ n) → Bool) :
  AdderCircuit.Satisfies (Desc.adder hwf) θ fun r => Desc.enc θ (Desc.eval rows b r)
QuotientSecurity.Desc.pack_injective {F : Type} [Field F] [CharP F 2] {c : ℕ → F} (hind : Desc.Independent c)
  (s t : Fin 128 → Bool)
  (h : (Desc.pack c fun j => if s j = true then 1 else 0) = Desc.pack c fun j => if t j = true then 1 else 0) : s = t
QuotientSecurity.Desc.wiringOf_wired {n : ℕ} (h9 : 9 ≤ n) {rows : Desc.Rows n} (hwf : Desc.WellFormed rows) :
  Desc.WiredBy h9 rows (Desc.wiringOf rows)
QuotientSecurity.InstanceN.statement_of_relation {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}
  (I : InstanceN F n) (rows : Desc.Rows n) (hwf : Desc.WellFormed rows)
  (hwire : Desc.WiredBy ⋯ rows (InstanceN.wiring I)) (hc1 : InstanceN.c I 1 = 0)
  (hind : Desc.Independent (InstanceN.c I)) (stmt : Fin 8 → F) (h4 : stmt 4 = 1) (h5 : stmt 5 = 0)
  (w : (Fin (n + 2) → Bool) → F) (hrel : InstanceN.Relation I stmt w) :
  ∃ b,
    ∀ (J : Fin 4),
      stmt (Desc.wordIdx J) = Desc.pack (InstanceN.c I) fun j => if Desc.statementBit rows b ⋯ J j = true then 1 else 0
QuotientSecurity.InstanceN.statementBits_of_relation {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ}
  (I : InstanceN F n) (rows : Desc.Rows n) (hwf : Desc.WellFormed rows)
  (hwire : Desc.WiredBy ⋯ rows (InstanceN.wiring I)) (hc1 : InstanceN.c I 1 = 0)
  (hind : Desc.Independent (InstanceN.c I)) (stmt : Fin 8 → F) (h4 : stmt 4 = 1) (h5 : stmt 5 = 0)
  (w : (Fin (n + 2) → Bool) → F) (hrel : InstanceN.Relation I stmt w) (β : Fin 512 → Bool)
  (hβ : ∀ (J : Fin 4), stmt (Desc.wordIdx J) = Desc.packBits (InstanceN.c I) β J) : ∃ b, Desc.statementBits rows b ⋯ = β
QuotientSecurity.InstanceN.circuit_soundness {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} [Fintype F]
  [SampleableType F] (I : InstanceN F n) (rows : Desc.Rows n) (hwf : Desc.WellFormed rows)
  (hwire : Desc.WiredBy ⋯ rows (InstanceN.wiring I)) (hc1 : InstanceN.c I 1 = 0)
  (hind : Desc.Independent (InstanceN.c I)) (hq : Fintype.card F = 2 ^ 192) (adv : InstanceN.Adversary I) (Q : ℕ)
  (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              InstanceN.words (Prod.fst r) 4 = 1 ∧
                InstanceN.words (Prod.fst r) 5 = 0 ∧
                  ¬∃ b,
                      ∀ (J : Fin 4),
                        InstanceN.words (Prod.fst r) (Desc.wordIdx J) =
                          Desc.pack (InstanceN.c I) fun j => if Desc.statementBit rows b ⋯ J j = true then 1 else 0)]
      {True} ≤
    (↑Q + 3) / 2 ^ 128
QuotientSecurity.InstanceN.circuit_soundness_bits {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} [Fintype F]
  [SampleableType F] (I : InstanceN F n) (rows : Desc.Rows n) (hwf : Desc.WellFormed rows)
  (hwire : Desc.WiredBy ⋯ rows (InstanceN.wiring I)) (hc1 : InstanceN.c I 1 = 0)
  (hind : Desc.Independent (InstanceN.c I)) (hq : Fintype.card F = 2 ^ 192) (adv : InstanceN.Adversary I) (Q : ℕ)
  (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              InstanceN.words (Prod.fst r) 4 = 1 ∧
                InstanceN.words (Prod.fst r) 5 = 0 ∧
                  ∃ β,
                    (∀ (J : Fin 4), InstanceN.words (Prod.fst r) (Desc.wordIdx J) = Desc.packBits (InstanceN.c I) β J) ∧
                      ¬∃ b, Desc.statementBits rows b ⋯ = β)]
      {True} ≤
    (↑Q + 3) / 2 ^ 128
QuotientSecurity.Desc.soundness_ofRows {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} [Fintype F]
  [SampleableType F] (basis : CantorBasis F (n + 2)) (rows : Desc.Rows n) (c : ℕ → F) (h9 : 9 ≤ n) (h29 : n ≤ 29)
  (hwf : Desc.WellFormed rows) (hc1 : c 1 = 0) (hind : Desc.Independent c) (hq : Fintype.card F = 2 ^ 192)
  (adv : InstanceN.Adversary (Desc.instanceOf basis rows c h9 h29)) (Q : ℕ) (hQ : OracleComp.IsTotalQueryBound adv Q) :
  𝒟[do
        let r ← StateT.run' (simulateQ OracleSpec.randomOracle (experiment adv)) ∅
        pure
            (Prod.snd r = true ∧
              InstanceN.words (Prod.fst r) 4 = 1 ∧
                InstanceN.words (Prod.fst r) 5 = 0 ∧
                  ∃ β,
                    (∀ (J : Fin 4), InstanceN.words (Prod.fst r) (Desc.wordIdx J) = Desc.packBits c β J) ∧
                      ¬∃ b, Desc.statementBits rows b h9 = β)]
      {True} ≤
    (↑Q + 3) / 2 ^ 128
QuotientSecurity.Desc.exists_instanceOf {F : Type} [Field F] [DecidableEq F] [CharP F 2] {n : ℕ} [Fintype F]
  (hq : Fintype.card F = 2 ^ 192) (h9 : 9 ≤ n) (h29 : n ≤ 29) (rows : Desc.Rows n) (c : ℕ → F) :
  ∃ basis, InstanceN.wiring (Desc.instanceOf basis rows c h9 h29) = Desc.wiringOf rows
structure QuotientSecurity.Desc.WellFormed {n : ℕ} (rows : Desc.Rows n) : Prop
number of parameters: 2
fields:
  QuotientSecurity.Desc.WellFormed.reads : ∀ (r : Fin (2 ^ n)),
      ¬Desc.IsInput rows r → ∀ (r' : Fin (2 ^ n)), Desc.Reads rows r r' → 512 ≤ ↑r' ∧ (↑r < 512 ∨ ↑r' < ↑r)
  QuotientSecurity.Desc.WellFormed.public_carry : ∀ (r : Fin (2 ^ n)), ↑r < 512 → Desc.Row.c (rows r) = Src.zero
  QuotientSecurity.Desc.WellFormed.public_bits : ∀ (r : Fin (2 ^ n)),
      ↑r < 256 →
        ∀ (s : Src (Fin (2 ^ n))),
          s = Desc.Row.x (rows r) ∨ s = Desc.Row.y (rows r) →
            ∃ r', s = Src.row r' ∧ Desc.Row.y (rows r') = Src.zero ∧ Desc.Row.c (rows r') = Src.zero
  QuotientSecurity.Desc.WellFormed.word_four : ∀ (r : Fin (2 ^ n)),
      ↑r = 256 → Desc.Row.x (rows r) = Src.one ∧ Desc.Row.y (rows r) = Src.zero
  QuotientSecurity.Desc.WellFormed.zeros : ∀ (r : Fin (2 ^ n)),
      256 < ↑r → ↑r < 512 → Desc.Row.x (rows r) = Src.zero ∧ Desc.Row.y (rows r) = Src.zero
constructor:
  QuotientSecurity.Desc.WellFormed.mk {n : ℕ} {rows : Desc.Rows n}
    (reads :
      ∀ (r : Fin (2 ^ n)),
        ¬Desc.IsInput rows r → ∀ (r' : Fin (2 ^ n)), Desc.Reads rows r r' → 512 ≤ ↑r' ∧ (↑r < 512 ∨ ↑r' < ↑r))
    (public_carry : ∀ (r : Fin (2 ^ n)), ↑r < 512 → Desc.Row.c (rows r) = Src.zero)
    (public_bits :
      ∀ (r : Fin (2 ^ n)),
        ↑r < 256 →
          ∀ (s : Src (Fin (2 ^ n))),
            s = Desc.Row.x (rows r) ∨ s = Desc.Row.y (rows r) →
              ∃ r', s = Src.row r' ∧ Desc.Row.y (rows r') = Src.zero ∧ Desc.Row.c (rows r') = Src.zero)
    (word_four : ∀ (r : Fin (2 ^ n)), ↑r = 256 → Desc.Row.x (rows r) = Src.one ∧ Desc.Row.y (rows r) = Src.zero)
    (zeros :
      ∀ (r : Fin (2 ^ n)), 256 < ↑r → ↑r < 512 → Desc.Row.x (rows r) = Src.zero ∧ Desc.Row.y (rows r) = Src.zero) :
    Desc.WellFormed rows
def QuotientSecurity.Desc.Independent : {F : Type} → [Field F] → (ℕ → F) → Prop :=
fun {F} [Field F] c =>
  ∀ (s : Fin 128 → Bool), (Desc.pack c fun j => if s j = true then 1 else 0) = 0 → ∀ (j : Fin 128), s j = false
def QuotientSecurity.Desc.WiredBy : {n : ℕ} → 9 ≤ n → Desc.Rows n → Equiv.Perm (Fin (n + 2) → Bool) → Prop :=
fun {n} h9 rows σ =>
  ∀ (r : Fin (2 ^ n)),
    (∃ k, (σ ^ k) (Desc.cellOf r 0) = Desc.target h9 (Desc.Row.x (rows r))) ∧
      (∃ k, (σ ^ k) (Desc.cellOf r 1) = Desc.target h9 (Desc.Row.y (rows r))) ∧
        ∃ k, (σ ^ k) (Desc.cellOf r 2) = Desc.target h9 (Desc.Row.c (rows r))
```

## Tail of the build log

```
macro "push_neg" cfg:optConfig loc:(location)? : tactic =>
  `(tactic| push $cfg:optConfig Not $[$loc]?)
```
✔ [9161/9162] Built QuotientSecurity (8.6s)
Build completed successfully (9162 jobs).
exit 0
```
