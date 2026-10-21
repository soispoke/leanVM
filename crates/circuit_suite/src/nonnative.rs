//! Big integers and prime fields over the adder rows: multiplication, and modular arithmetic by hint and check.
//!
//! # Accumulation
//! Every multi-operand sum is an [`Acc`]: a bag of weighted bits (a column of wires per weight) and a constant,
//! taken modulo `2^width`. [`compress`] reduces it column by column with full-adder rows, each row removing one
//! bit; a row reads two bits and one carry, so the compressor picks its three operands by kind (a row's sum bit
//! or its carry) and by polarity (a negated wire is free when all three are negated: `maj(-a,-b,-c) =
//! -maj(a,b,c)`), paying a conversion row only when no triple fits.
//!
//! # Multiplication
//! A partial product `a_i b_j` is one row either way: as `and` it is a carry, as `xnor` a sum bit. Partial products
//! as carries would leave the compressor a carry for every slot and a conversion for most, so they are sum bits:
//! `a_i b_j 2^(i+j) = (xnor(a_i, b_j) + a_i + b_j - 1) 2^(i+j-1)`, the linear corrections summed per operand bit
//! into a coefficient written in non-adjacent form (two terms per bit). So an `n x n` schoolbook product costs
//! about `2 n^2` rows (`n^2` products and `n^2` compressions) and a square `n^2` (the corrections of a square
//! cancel against its diagonal). Above [`KARATSUBA_MIN`] bits products split by Karatsuba, the three half
//! products materialised as words and recombined in the parent accumulator; squares split into three squares.
//!
//! # Modular arithmetic
//! A congruence `E = sum of products and signed multiples of words + constant = 0 (mod p)` is checked by a hint
//! `q`: the circuit accumulates `E + O p - q p` (the constant `O` makes `E + O p` non-negative, `-q p` is a
//! constant multiplication in non-adjacent form, so `2^256 - 2^32 - 977` costs six copies of `q`) and tests that
//! the accumulator is zero modulo `2^M`, where `M` is chosen from the operands' bounds so that `|E + O p - q p|
//! < 2^M` for every value of the hint. Then zero modulo `2^M` is zero, and `E = (q - O) p`: the congruence holds
//! whatever the hint. A product with a canonical result (`mulmod`) adds the hint `r` and the range check
//! `r < p`; an inverse is a hint `x` with `a x = 1 (mod p)`. Every check is a bit the caller ANDs into its
//! validity bit ([`Nn::valid`]).

use std::cell::RefCell;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::{Ckt, Wire, Word};

/// Products of more bits than this split by Karatsuba (measured: see the tests).
pub const KARATSUBA_MIN: usize = 24;
thread_local! {
    static KARATSUBA: RefCell<usize> = const { RefCell::new(KARATSUBA_MIN) };
}

/// Run `f` with products of more than `min` bits split by Karatsuba (`usize::MAX`: schoolbook only).
pub fn with_karatsuba<T>(min: usize, f: impl FnOnce() -> T) -> T {
    let old = KARATSUBA.with(|k| k.replace(min));
    let out = f();
    KARATSUBA.with(|k| *k.borrow_mut() = old);
    out
}

fn karatsuba_min() -> usize {
    KARATSUBA.with(|k| *k.borrow())
}

/// A full adder on the cheaper polarity: when most of the variable operands are negated, all are flipped and both
/// outputs negated back, so at most one operand needs a positive copy.
pub fn fa(c: &mut Ckt, a: Wire, b: Wire, d: Wire) -> (Wire, Wire) {
    let ops = [a, b, d];
    let vars = ops.iter().filter(|w| w.as_const().is_none()).count();
    let neg = ops.iter().filter(|w| w.is_negated()).count();
    if 2 * neg > vars {
        let (s, k) = c.fa(a.not(), b.not(), d.not());
        (s.not(), k.not())
    } else {
        c.fa(a, b, d)
    }
}

pub fn and(c: &mut Ckt, a: Wire, b: Wire) -> Wire {
    fa(c, a, b, Wire::ZERO).1
}

pub fn or(c: &mut Ckt, a: Wire, b: Wire) -> Wire {
    fa(c, a, b, Wire::ONE).1
}

/// The AND of `bits`: a chain of rows, one a bit, the running result in the carry slot. Bits are grouped by
/// polarity so that each row's operands agree.
pub fn all(c: &mut Ckt, bits: &[Wire]) -> Wire {
    if bits.iter().any(|w| w.as_const() == Some(false)) {
        return Wire::ZERO;
    }
    let vars: Vec<Wire> = bits.iter().copied().filter(|w| w.as_const().is_none()).collect();
    let chain = |c: &mut Ckt, ws: Vec<Wire>| -> Option<Wire> {
        let mut it = ws.into_iter();
        let first = it.next()?;
        Some(it.fold(first, |acc, w| and(c, acc, w)))
    };
    let (neg, pos): (Vec<Wire>, Vec<Wire>) = vars.into_iter().partition(|w| w.is_negated());
    match (chain(c, pos), chain(c, neg)) {
        (None, None) => Wire::ONE,
        (Some(a), None) | (None, Some(a)) => a,
        (Some(a), Some(b)) => and(c, a, b),
    }
}

/// The OR of `bits`.
pub fn any(c: &mut Ckt, bits: &[Wire]) -> Wire {
    let n: Vec<Wire> = bits.iter().map(|w| w.not()).collect();
    all(c, &n).not()
}

/// `x + y + carry` with a ripple of rows, the carry out appended (`max(len) + 1` bits).
pub fn add_words(c: &mut Ckt, x: &[Wire], y: &[Wire]) -> Word {
    let n = x.len().max(y.len());
    let get = |w: &[Wire], i: usize| w.get(i).copied().unwrap_or(Wire::ZERO);
    let mut carry = Wire::ZERO;
    let mut out = Vec::with_capacity(n + 1);
    for i in 0..n {
        let (s, k) = fa(c, get(x, i), get(y, i), carry);
        out.push(s);
        carry = k;
    }
    out.push(carry);
    out
}

/// Whether `x < k` for a constant `k`: the carry out of `x + (2^n - k)`, one row a bit.
pub fn lt_const(c: &mut Ckt, x: &[Wire], k: &BigUint) -> Wire {
    let n = x.len();
    if k.bits() as usize > n {
        return Wire::ONE;
    }
    if k.is_zero() {
        return Wire::ZERO;
    }
    let comp = (BigUint::one() << n) - k;
    let mut carry = Wire::ZERO;
    for (i, &w) in x.iter().enumerate() {
        carry = fa(c, w, Wire::constant(comp.bit(i as u64)), carry).1;
    }
    carry.not()
}

/// Whether two words are equal, bit by bit.
pub fn eq_words(c: &mut Ckt, x: &[Wire], y: &[Wire]) -> Wire {
    let n = x.len().max(y.len());
    let get = |w: &[Wire], i: usize| w.get(i).copied().unwrap_or(Wire::ZERO);
    let d: Vec<Wire> = (0..n).map(|i| c.xor(get(x, i), get(y, i))).collect();
    any(c, &d).not()
}

/// The constant `k` as `len` bits.
pub fn const_word(k: &BigUint, len: usize) -> Word {
    (0..len).map(|i| Wire::constant(k.bit(i as u64))).collect()
}

/// Signed digits of `k` in non-adjacent form: `(position, +1 or -1)`.
pub fn naf(k: &BigInt) -> Vec<(usize, i8)> {
    let mut out = vec![];
    let mut k = k.clone();
    let mut i = 0;
    while !k.is_zero() {
        if k.bit(0) {
            // Odd: digit 2 - (k mod 4), in {1, -1}.
            let m4 = (&k & BigInt::from(3)).to_i64().unwrap();
            let d: i8 = if m4 == 1 { 1 } else { -1 };
            out.push((i, d));
            k -= d as i64;
        }
        k >>= 1;
        i += 1;
    }
    out
}

/// A sum of weighted bits plus a constant, modulo `2^width`.
pub struct Acc {
    pub cols: Vec<Vec<Wire>>,
    pub k: BigInt,
}

impl Acc {
    pub fn new(width: usize) -> Self {
        Self {
            cols: vec![vec![]; width],
            k: BigInt::zero(),
        }
    }

    pub fn width(&self) -> usize {
        self.cols.len()
    }

    /// The number of variable bits held.
    pub fn bits(&self) -> usize {
        self.cols.iter().map(Vec::len).sum()
    }

    /// `+ w 2^pos`.
    pub fn bit(&mut self, w: Wire, pos: usize) {
        if pos >= self.width() {
            return;
        }
        match w.as_const() {
            Some(true) => self.k += BigInt::one() << pos,
            Some(false) => {}
            None => self.cols[pos].push(w),
        }
    }

    /// `- w 2^pos`, as `(not w) 2^pos - 2^pos`.
    pub fn neg_bit(&mut self, w: Wire, pos: usize) {
        if pos >= self.width() {
            return;
        }
        self.bit(w.not(), pos);
        self.k -= BigInt::one() << pos;
    }

    pub fn word(&mut self, w: &[Wire], shift: usize) {
        for (i, &b) in w.iter().enumerate() {
            self.bit(b, shift + i);
        }
    }

    pub fn neg_word(&mut self, w: &[Wire], shift: usize) {
        for (i, &b) in w.iter().enumerate() {
            self.neg_bit(b, shift + i);
        }
    }

    /// `+ k w 2^shift` for a bit `w` and a signed constant `k`, by the digits of `k` in non-adjacent form.
    pub fn scaled_bit(&mut self, w: Wire, shift: usize, k: &BigInt) {
        for (i, d) in naf(k) {
            if d > 0 {
                self.bit(w, shift + i);
            } else {
                self.neg_bit(w, shift + i);
            }
        }
    }

    pub fn konst(&mut self, k: &BigInt) {
        self.k += k;
    }
}

/// Operand classes the compressor tells apart: positive sum bit, positive carry, negated sum bit, negated
/// carry, constant.
fn class(w: Wire) -> usize {
    if w.as_const().is_some() {
        4
    } else {
        (w.is_negated() as usize) * 2 + w.is_carry() as usize
    }
}

/// Rows a full adder on operands of these classes costs, conversions included (cached conversions not known).
fn cost(classes: &[usize]) -> u32 {
    let vars: Vec<usize> = classes.iter().copied().filter(|&k| k != 4).collect();
    if vars.len() <= 1 {
        return 0;
    }
    let neg = vars.iter().filter(|&&k| k >= 2).count();
    let flip = 2 * neg > vars.len();
    let mut rows = 1;
    let mut carries = 0;
    for &k in &vars {
        let negated = (k >= 2) ^ flip;
        if negated {
            rows += 1; // a positive copy, a sum bit
        } else if k % 2 == 1 {
            carries += 1;
        }
    }
    if vars.len() == 3 {
        rows += if carries == 0 { 1 } else { carries - 1 };
    } else if carries == 2 {
        rows += 1;
    }
    rows
}

/// The triples (or pairs) of classes, cheapest first, consuming carries first among equals.
fn plans(n: usize) -> Vec<Vec<usize>> {
    let mut out = vec![];
    for a in 0..5 {
        for b in a..5 {
            if n == 2 {
                out.push(vec![a, b]);
                continue;
            }
            for d in b..5 {
                out.push(vec![a, b, d]);
            }
        }
    }
    out.sort_by_key(|p| {
        let carries = p.iter().filter(|&&k| k == 1 || k == 3).count();
        (cost(p), std::cmp::Reverse(carries))
    });
    out
}

thread_local! {
    static PLANS: (Vec<Vec<usize>>, Vec<Vec<usize>>) = (plans(3), plans(2));
}

/// Reduce `acc` to at most `target` (1 or 2) bits a column, the constant folded in; columns low first.
pub fn compress(c: &mut Ckt, acc: Acc, target: usize) -> Vec<Vec<Wire>> {
    assert!(target == 1 || target == 2);
    let m = acc.width();
    let modulus = BigInt::one() << m;
    let k = ((acc.k % &modulus) + &modulus) % &modulus;
    let k = k.to_biguint().unwrap();
    let mut cols = acc.cols;
    let mut out = Vec::with_capacity(m);
    for w in 0..m {
        let mut pool: [Vec<Wire>; 5] = Default::default();
        for b in std::mem::take(&mut cols[w]) {
            pool[class(b)].push(b);
        }
        if k.bit(w as u64) {
            pool[4].push(Wire::ONE);
        }
        loop {
            let len: usize = pool.iter().map(Vec::len).sum();
            if len <= target {
                break;
            }
            let n = if len == 2 { 2 } else { 3 };
            let plan = PLANS.with(|(p3, p2)| {
                let ps = if n == 3 { p3 } else { p2 };
                ps.iter()
                    .find(|p| (0..5).all(|k| p.iter().filter(|&&x| x == k).count() <= pool[k].len()))
                    .unwrap()
                    .clone()
            });
            let mut ops: Vec<Wire> = plan.iter().map(|&k| pool[k].pop().unwrap()).collect();
            if n == 2 {
                ops.push(Wire::ZERO);
            }
            let (s, carry) = fa(c, ops[0], ops[1], ops[2]);
            if s.as_const() != Some(false) {
                pool[class(s)].push(s);
            }
            if w + 1 < m {
                match carry.as_const() {
                    Some(false) => {}
                    _ => cols[w + 1].push(carry),
                }
            }
        }
        let rest: Vec<Wire> = pool
            .into_iter()
            .flatten()
            .filter(|w| w.as_const() != Some(false))
            .collect();
        out.push(rest);
    }
    out
}

/// The accumulator's value modulo `2^width`, as a word.
pub fn to_word(c: &mut Ckt, acc: Acc) -> Word {
    compress(c, acc, 1)
        .into_iter()
        .map(|col| col.first().copied().unwrap_or(Wire::ZERO))
        .collect()
}

/// Whether the accumulator is zero modulo `2^width`. With the constant lowered by one, the two words `s, t` left by
/// compression must add to `2^width - 1`, which (both being below `2^width`) they do exactly when `s xor t` is all
/// ones: a carry would have to start at a column whose bits are both one, whose sum bit is then zero.
pub fn is_zero(c: &mut Ckt, mut acc: Acc) -> Wire {
    acc.k -= 1;
    let cols = compress(c, acc, 2);
    let bits: Vec<Wire> = cols
        .iter()
        .map(|col| match col.len() {
            0 => Wire::ZERO,
            1 => col[0],
            _ => c.xor(col[0], col[1]),
        })
        .collect();
    all(c, &bits)
}

/// `+ a b 2^shift`, schoolbook: one `xnor` row a partial product, the corrections as coefficients per bit.
pub fn mul_school(c: &mut Ckt, acc: &mut Acc, a: &[Wire], b: &[Wire], shift: usize) {
    let vars = |w: &[Wire]| w.iter().filter(|x| x.as_const().is_none()).count();
    // With a short operand the corrections would cost as much as the products: carries instead.
    let and_form = vars(a).min(vars(b)) <= 2;
    let mut ka = vec![BigInt::zero(); a.len()];
    let mut kb = vec![BigInt::zero(); b.len()];
    let mut k = BigInt::zero();
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            if shift + i + j >= acc.width() {
                break;
            }
            match (x.as_const(), y.as_const()) {
                (Some(false), _) | (_, Some(false)) => {}
                (Some(true), Some(true)) => k += BigInt::one() << (i + j),
                (Some(true), None) => acc.bit(y, shift + i + j),
                (None, Some(true)) => acc.bit(x, shift + i + j),
                (None, None) if i + j == 0 || and_form => {
                    let p = and(c, x, y);
                    acc.bit(p, shift + i + j);
                }
                (None, None) => {
                    let p = c.xor3(x, y, Wire::ONE);
                    acc.bit(p, shift + i + j - 1);
                    let e = BigInt::one() << (i + j - 1);
                    ka[i] += &e;
                    kb[j] += &e;
                    k -= e;
                }
            }
        }
    }
    for (i, &x) in a.iter().enumerate() {
        acc.scaled_bit(x, shift, &ka[i]);
    }
    for (j, &y) in b.iter().enumerate() {
        acc.scaled_bit(y, shift, &kb[j]);
    }
    acc.konst(&(k << shift));
}

/// `+ a^2 2^shift`, schoolbook: `a_i a_j 2^(i+j+1) = (xnor + a_i + a_j - 1) 2^(i+j)` for `i < j`, the diagonal
/// `a_i 2^(2i)` folded into the same coefficients.
pub fn square_school(c: &mut Ckt, acc: &mut Acc, a: &[Wire], shift: usize) {
    let n = a.len();
    let mut ka = vec![BigInt::zero(); n];
    let mut k = BigInt::zero();
    for i in 0..n {
        match a[i].as_const() {
            Some(true) => k += BigInt::one() << (2 * i),
            Some(false) => {}
            None => ka[i] += BigInt::one() << (2 * i),
        }
        for j in i + 1..n {
            if shift + i + j >= acc.width() {
                break;
            }
            let (x, y) = (a[i], a[j]);
            match (x.as_const(), y.as_const()) {
                (Some(false), _) | (_, Some(false)) => {}
                (Some(true), Some(true)) => k += BigInt::one() << (i + j + 1),
                (Some(true), None) => ka[j] += BigInt::one() << (i + j + 1),
                (None, Some(true)) => ka[i] += BigInt::one() << (i + j + 1),
                (None, None) => {
                    let p = c.xor3(x, y, Wire::ONE);
                    acc.bit(p, shift + i + j);
                    let e = BigInt::one() << (i + j);
                    ka[i] += &e;
                    ka[j] += &e;
                    k -= e;
                }
            }
        }
    }
    for (i, &x) in a.iter().enumerate() {
        acc.scaled_bit(x, shift, &ka[i]);
    }
    acc.konst(&(k << shift));
}

fn trim(w: &[Wire]) -> &[Wire] {
    let mut n = w.len();
    while n > 0 && w[n - 1].as_const() == Some(false) {
        n -= 1;
    }
    &w[..n]
}

/// `+ a b 2^shift`: Karatsuba above the threshold. The half products `a0 b0` and `a1 b1`, used twice, are
/// materialised; the middle product `(a0 + a1)(b0 + b1)`, used once, goes straight into `acc`, its operands' top
/// bits (the carries of the two sums) peeled off so that every split halves a power of two.
pub fn mul_into(c: &mut Ckt, acc: &mut Acc, a: &[Wire], b: &[Wire], shift: usize) {
    let (a, b) = (trim(a), trim(b));
    let n = a.len().max(b.len());
    if n <= karatsuba_min().max(3) || a.len().min(b.len()) <= n / 2 {
        return mul_school(c, acc, a, b, shift);
    }
    let h = n.div_ceil(2);
    let pad = |w: &[Wire]| -> Word {
        let mut w = w.to_vec();
        w.resize(n, Wire::ZERO);
        w
    };
    let (a, b) = (pad(a), pad(b));
    let (a0, a1) = a.split_at(h);
    let (b0, b1) = b.split_at(h);
    let z0 = mul(c, a0, b0);
    let z2 = mul(c, a1, b1);
    let sa = add_words(c, a0, a1);
    let sb = add_words(c, b0, b1);
    let (sa0, ca) = (&sa[..h], sa[h]);
    let (sb0, cb) = (&sb[..h], sb[h]);
    mul_into(c, acc, sa0, sb0, shift + h);
    mul_school(c, acc, &[ca], sb0, shift + 2 * h);
    mul_school(c, acc, &[cb], sa0, shift + 2 * h);
    let cc = and(c, ca, cb);
    acc.bit(cc, shift + 3 * h);
    acc.word(&z0, shift);
    acc.word(&z2, shift + 2 * h);
    acc.neg_word(&z0, shift + h);
    acc.neg_word(&z2, shift + h);
}

/// `+ a^2 2^shift`: Karatsuba squaring (three squares) above the threshold, as [`mul_into`].
pub fn square_into(c: &mut Ckt, acc: &mut Acc, a: &[Wire], shift: usize) {
    let a = trim(a);
    let n = a.len();
    if n <= karatsuba_min().max(3) {
        return square_school(c, acc, a, shift);
    }
    let h = n.div_ceil(2);
    let (a0, a1) = a.split_at(h);
    let z0 = square(c, a0);
    let z2 = square(c, a1);
    let sa = add_words(c, a0, a1);
    let (sa0, ca) = (&sa[..h], sa[h]);
    // (sa0 + ca 2^h)^2 = sa0^2 + ca sa0 2^(h+1) + ca 2^(2h).
    square_into(c, acc, sa0, shift + h);
    mul_school(c, acc, &[ca], sa0, shift + 2 * h + 1);
    acc.bit(ca, shift + 3 * h);
    acc.word(&z0, shift);
    acc.word(&z2, shift + 2 * h);
    acc.neg_word(&z0, shift + h);
    acc.neg_word(&z2, shift + h);
}

/// The product `a b`, `len a + len b` bits.
pub fn mul(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    let mut acc = Acc::new(a.len() + b.len());
    mul_into(c, &mut acc, a, b, 0);
    to_word(c, acc)
}

pub fn square(c: &mut Ckt, a: &[Wire]) -> Word {
    let mut acc = Acc::new(2 * a.len());
    square_into(c, &mut acc, a, 0);
    to_word(c, acc)
}

/// `+ k w 2^shift` for a word `w` and a signed constant `k`: shifted copies of `w` by the non-adjacent form of
/// `k`, or, when cheaper, by a window of odd multiples of `w` computed once.
pub fn const_mul_into(c: &mut Ckt, acc: &mut Acc, w: &[Wire], shift: usize, k: &BigInt) {
    let w = trim(w);
    let digits = naf(k);
    let n = w.len();
    // Width-`win` non-adjacent form: digits odd, |d| < 2^(win-1), the table of odd multiples 3w, 5w, ...
    let best = (2..=7)
        .map(|win| {
            let d = wnaf(k, win);
            let table = (1usize << (win - 2)) - 1;
            (table * (n + win) + d.len() * (n + win), win)
        })
        .min()
        .unwrap();
    if best.0 >= digits.len() * n || n == 0 {
        for (i, d) in digits {
            if d > 0 {
                acc.word(w, shift + i);
            } else {
                acc.neg_word(w, shift + i);
            }
        }
        return;
    }
    let win = best.1;
    let d = wnaf(k, win);
    let max_odd = (1i64 << (win - 1)) - 1;
    let mut table: Vec<Word> = vec![w.to_vec()];
    let two: Word = std::iter::once(Wire::ZERO).chain(w.iter().copied()).collect();
    for _ in 1..(max_odd + 1) / 2 {
        let prev = table.last().unwrap().clone();
        let next = add_words(c, &prev, &two);
        table.push(trim(&next).to_vec());
    }
    for (i, dv) in d {
        let t = &table[(dv.unsigned_abs() as usize - 1) / 2];
        if dv > 0 {
            acc.word(t, shift + i);
        } else {
            acc.neg_word(t, shift + i);
        }
    }
}

/// Width-`win` non-adjacent form: odd digits below `2^(win-1)` in absolute value, `(position, digit)`.
pub fn wnaf(k: &BigInt, win: usize) -> Vec<(usize, i64)> {
    let mut out = vec![];
    let mut k = k.clone();
    let mut i = 0;
    let m = BigInt::from(1i64 << win);
    while !k.is_zero() {
        if k.bit(0) {
            let mut d = ((&k % &m + &m) % &m).to_i64().unwrap();
            if d >= 1 << (win - 1) {
                d -= 1 << win;
            }
            out.push((i, d));
            k -= d;
        }
        k >>= 1;
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Integers with bounds and values, and prime fields.

/// A non-negative integer in wires (low bit first), the bound the circuit guarantees for it, and its value when an
/// instance is being computed.
#[derive(Clone, Debug)]
pub struct Int {
    pub w: Word,
    pub max: BigUint,
    pub v: Option<BigUint>,
}

impl Int {
    pub fn constant(k: &BigUint) -> Int {
        Int {
            w: const_word(k, k.bits() as usize),
            max: k.clone(),
            v: Some(k.clone()),
        }
    }

    /// The value, which an instance computation has.
    pub fn val(&self) -> &BigUint {
        self.v.as_ref().expect("no value outside an instance computation")
    }
}

/// A prime modulus.
#[derive(Clone, Debug)]
pub struct Modulus {
    pub p: BigUint,
    /// Bits of a canonical element.
    pub bits: usize,
}

impl Modulus {
    pub fn new(p: BigUint) -> Self {
        let bits = p.bits() as usize;
        Self { p, bits }
    }

    pub fn hex(s: &str) -> Self {
        Self::new(BigUint::parse_bytes(s.as_bytes(), 16).unwrap())
    }
}

/// A term of a congruence `sum of terms = 0 (mod p)`.
pub enum Term<'a> {
    /// `a b 2^shift`.
    Mul(&'a Int, &'a Int, usize),
    /// `a^2 2^shift`.
    Sq(&'a Int, usize),
    /// `k a` for a signed constant `k`.
    Lin(&'a Int, i64),
    /// `k a` for a big signed constant `k`.
    Scaled(&'a Int, BigInt),
    Const(BigInt),
}

/// The circuit under construction, the free inputs an instance computation records, and the checks made so far.
pub struct Nn<'a> {
    pub c: &'a mut Ckt,
    wit: Option<Vec<bool>>,
    checks: Vec<Wire>,
}

impl<'a> Nn<'a> {
    /// Building the circuit alone: values are not computed.
    pub fn new(c: &'a mut Ckt) -> Self {
        Self {
            c,
            wit: None,
            checks: vec![],
        }
    }

    /// Building the circuit and computing an instance: every value is computed and every free input recorded.
    pub fn with_witness(c: &'a mut Ckt) -> Self {
        Self {
            c,
            wit: Some(vec![]),
            checks: vec![],
        }
    }

    pub fn has_values(&self) -> bool {
        self.wit.is_some()
    }

    /// The free inputs recorded.
    pub fn inputs(&self) -> &[bool] {
        self.wit.as_deref().unwrap_or(&[])
    }

    /// `bits` free input bits holding the value `v()` (called only in an instance computation; its bits above
    /// `bits` are dropped).
    pub fn hint(&mut self, bits: usize, v: impl FnOnce() -> BigUint) -> Int {
        let value = self.wit.is_some().then(v).map(|v| v % (BigUint::one() << bits));
        if let (Some(wit), Some(v)) = (&mut self.wit, &value) {
            wit.extend((0..bits).map(|i| v.bit(i as u64)));
        }
        Int {
            w: self.c.inputs(bits),
            max: (BigUint::one() << bits) - 1u32,
            v: value,
        }
    }

    /// Free input bits given as booleans (raw).
    pub fn input_bits(&mut self, bits: &[bool]) -> Word {
        if let Some(wit) = &mut self.wit {
            wit.extend_from_slice(bits);
        }
        self.c.inputs(bits.len())
    }

    /// Record a check.
    pub fn check(&mut self, w: Wire) {
        self.checks.push(w);
    }

    pub fn n_checks(&self) -> usize {
        self.checks.len()
    }

    /// The AND of every check made.
    pub fn valid(&mut self) -> Wire {
        let checks = std::mem::take(&mut self.checks);
        all(self.c, &checks)
    }

    /// The value of a wire in the instance computation, from the values of operands.
    pub fn value_of(&self, f: impl FnOnce() -> BigUint) -> Option<BigUint> {
        self.has_values().then(f)
    }

    /// `a + b` (exact, a ripple).
    pub fn add(&mut self, a: &Int, b: &Int) -> Int {
        let w = add_words(self.c, &a.w, &b.w);
        let max = &a.max + &b.max;
        let w = w[..max.bits() as usize].to_vec();
        Int {
            w,
            v: self.value_of(|| a.val() + b.val()),
            max,
        }
    }

    /// Check `sum of terms = 0 (mod p)` by a quotient hint; returns the check's bit (not recorded).
    ///
    /// Soundness: with `E` the sum, `lo <= E <= hi` from the operands' bounds, and `O = ceil(-lo / p)`, the circuit
    /// tests `V = E + O p - q p = 0 (mod 2^M)` for the hint `q < 2^Q`, where `2^Q > (hi + O p) / p` (so an honest
    /// `q` fits) and `2^M > max(hi + O p, (2^Q - 1) p - lo - O p)` bounds `|V|` for every `q`. So the test passing
    /// means `V = 0`, `E = (q - O) p`.
    pub fn congruence(&mut self, m: &Modulus, terms: &[Term]) -> Wire {
        let p = BigInt::from(m.p.clone());
        let (mut lo, mut hi) = (BigInt::zero(), BigInt::zero());
        let mut add_range = |min: BigInt, max: BigInt| {
            lo += min;
            hi += max;
        };
        for t in terms {
            match t {
                Term::Mul(a, b, s) => add_range(BigInt::zero(), BigInt::from(&a.max * &b.max) << *s),
                Term::Sq(a, s) => add_range(BigInt::zero(), BigInt::from(&a.max * &a.max) << *s),
                Term::Lin(a, k) => {
                    let x = BigInt::from(a.max.clone()) * k;
                    if *k >= 0 {
                        add_range(BigInt::zero(), x)
                    } else {
                        add_range(x, BigInt::zero())
                    }
                }
                Term::Scaled(a, k) => {
                    let x = BigInt::from(a.max.clone()) * k;
                    if !k.is_negative() {
                        add_range(BigInt::zero(), x)
                    } else {
                        add_range(x, BigInt::zero())
                    }
                }
                Term::Const(k) => add_range(k.clone(), k.clone()),
            }
        }
        let o = if lo.is_negative() {
            (-&lo + &p - 1) / &p
        } else {
            BigInt::zero()
        };
        let top = &hi + &o * &p;
        let qbits = ((&top / &p).bits() as usize).max(1);
        let qmax: BigInt = (BigInt::one() << qbits) - 1;
        let neg_end = &qmax * &p - &lo - &o * &p;
        let mbits = top.bits().max(neg_end.bits()) as usize;
        let qv = self.value_of(|| {
            let mut e = &o * &p;
            for t in terms {
                e += match t {
                    Term::Mul(a, b, s) => BigInt::from(a.val() * b.val()) << *s,
                    Term::Sq(a, s) => BigInt::from(a.val() * a.val()) << *s,
                    Term::Lin(a, k) => BigInt::from(a.val().clone()) * k,
                    Term::Scaled(a, k) => BigInt::from(a.val().clone()) * k,
                    Term::Const(k) => k.clone(),
                };
            }
            (e / &p).to_biguint().unwrap_or_default()
        });
        let q = self.hint(qbits, || qv.unwrap());
        let mut acc = Acc::new(mbits);
        for t in terms {
            match t {
                Term::Mul(a, b, s) => mul_into(self.c, &mut acc, &a.w, &b.w, *s),
                Term::Sq(a, s) => square_into(self.c, &mut acc, &a.w, *s),
                Term::Lin(a, k) => const_mul_into(self.c, &mut acc, &a.w, 0, &BigInt::from(*k)),
                Term::Scaled(a, k) => const_mul_into(self.c, &mut acc, &a.w, 0, k),
                Term::Const(k) => acc.konst(k),
            }
        }
        acc.konst(&(&o * &p));
        const_mul_into(self.c, &mut acc, &q.w, 0, &-p);
        is_zero(self.c, acc)
    }

    /// A canonical residue `r < p` given by a hint, range-checked (recorded).
    pub fn residue_hint(&mut self, m: &Modulus, v: impl FnOnce() -> BigUint) -> Int {
        let r = self.hint(m.bits, v);
        let ok = lt_const(self.c, &r.w, &m.p);
        self.check(ok);
        Int { max: &m.p - 1u32, ..r }
    }

    /// The canonical residue of `sum of terms` modulo `p`: a hint `r < p` and the congruence `terms - r = 0`.
    pub fn reduce(&mut self, m: &Modulus, terms: &[Term]) -> Int {
        self.reduce_to(m, terms, true)
    }

    /// A residue of `sum of terms` modulo `p` by a hint and the congruence `terms - r = 0`: canonical (`r < p`
    /// range-checked) or not (`r` any value of `bits` bits: the residue class is still forced).
    pub fn reduce_to(&mut self, m: &Modulus, terms: &[Term], canonical: bool) -> Int {
        let rv = self.value_of(|| eval_terms(terms, &m.p));
        let r = if canonical {
            self.residue_hint(m, || rv.unwrap())
        } else {
            self.hint(m.bits, || rv.unwrap())
        };
        let mut all_terms: Vec<Term> = terms.iter().map(clone_term).collect();
        all_terms.push(Term::Lin(&r, -1));
        let ok = self.congruence(m, &all_terms);
        self.check(ok);
        r
    }

    /// `a b mod p`, canonical.
    pub fn mulmod(&mut self, m: &Modulus, a: &Int, b: &Int) -> Int {
        self.reduce(m, &[Term::Mul(a, b, 0)])
    }

    pub fn sqrmod(&mut self, m: &Modulus, a: &Int) -> Int {
        self.reduce(m, &[Term::Sq(a, 0)])
    }

    /// `a + b mod p`, canonical, for `a, b < p` (no hint): the sum, and `p` taken off when it is at least `p`.
    pub fn addmod(&mut self, m: &Modulus, a: &Int, b: &Int) -> Int {
        debug_assert!(a.max < m.p && b.max < m.p);
        let s = add_words(self.c, &a.w, &b.w);
        self.cond_sub_p(m, s, self.value_of(|| (a.val() + b.val()) % &m.p))
    }

    /// `s - p` when `s >= p`, for `s < 2p` of `bits + 1` bits.
    fn cond_sub_p(&mut self, m: &Modulus, s: Word, v: Option<BigUint>) -> Int {
        let n = m.bits + 1;
        let mut s = s;
        s.resize(n, Wire::ZERO);
        let ge = lt_const(self.c, &s, &m.p).not();
        let comp = (BigUint::one() << n) - &m.p;
        let gated: Word = (0..n)
            .map(|i| if comp.bit(i as u64) { ge } else { Wire::ZERO })
            .collect();
        let r = add_words(self.c, &s, &gated);
        Int {
            w: r[..m.bits].to_vec(),
            max: &m.p - 1u32,
            v,
        }
    }

    /// `a - b mod p`, canonical, for `a, b < p`: `a + (p - b)`, then `p` taken off when at least `p`.
    pub fn submod(&mut self, m: &Modulus, a: &Int, b: &Int) -> Int {
        debug_assert!(a.max < m.p && b.max < m.p);
        // p - b = p + not(b) + 1 - 2^bits, in [1, p].
        let nb: Word =
            b.w.iter()
                .map(|w| w.not())
                .chain(std::iter::repeat(Wire::ONE))
                .take(m.bits)
                .collect();
        let mut acc = Acc::new(m.bits + 1);
        acc.word(&a.w, 0);
        acc.word(&nb, 0);
        acc.konst(&(BigInt::from(m.p.clone()) + 1 - (BigInt::one() << m.bits)));
        let s = to_word(self.c, acc);
        self.cond_sub_p(m, s, self.value_of(|| (a.val() + &m.p - b.val()) % &m.p))
    }

    /// `a^-1 mod p` by a hint `x < p` with `a x = 1 (mod p)` (recorded; fails when `a = 0 mod p`).
    pub fn invmod(&mut self, m: &Modulus, a: &Int) -> Int {
        let xv = self.value_of(|| {
            let e = &m.p - 2u32;
            (a.val() % &m.p).modpow(&e, &m.p)
        });
        let x = self.residue_hint(m, || xv.unwrap());
        let ok = self.congruence(m, &[Term::Mul(a, &x, 0), Term::Const(BigInt::from(-1))]);
        self.check(ok);
        x
    }

    /// Whether `a = b (mod p)` for any bounded `a, b` (a congruence with a small quotient; not recorded).
    pub fn eqmod(&mut self, m: &Modulus, a: &Int, b: &Int) -> Wire {
        self.congruence(m, &[Term::Lin(a, 1), Term::Lin(b, -1)])
    }
}

/// The canonical residue of a sum of terms with values.
pub fn eval_terms(terms: &[Term], p: &BigUint) -> BigUint {
    let p = BigInt::from(p.clone());
    let mut e = BigInt::zero();
    for t in terms {
        e += match t {
            Term::Mul(a, b, s) => BigInt::from(a.val() * b.val()) << *s,
            Term::Sq(a, s) => BigInt::from(a.val() * a.val()) << *s,
            Term::Lin(a, k) => BigInt::from(a.val().clone()) * k,
            Term::Scaled(a, k) => BigInt::from(a.val().clone()) * k,
            Term::Const(k) => k.clone(),
        };
    }
    ((e % &p + &p) % &p).to_biguint().unwrap()
}

fn clone_term<'a>(t: &Term<'a>) -> Term<'a> {
    match t {
        Term::Mul(a, b, s) => Term::Mul(a, b, *s),
        Term::Sq(a, s) => Term::Sq(a, *s),
        Term::Lin(a, k) => Term::Lin(a, *k),
        Term::Scaled(a, k) => Term::Scaled(a, k.clone()),
        Term::Const(k) => Term::Const(k.clone()),
    }
}

/// The secp256k1 base field `2^256 - 2^32 - 977`.
pub fn secp256k1_p() -> Modulus {
    Modulus::hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
}

/// The secp256k1 group order.
pub fn secp256k1_n() -> Modulus {
    Modulus::hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
}

/// The BN254 scalar field.
pub fn bn254_r() -> Modulus {
    Modulus::hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Circuit, PUBLIC_BITS};

    /// A splitmix64 stream.
    pub struct Rng(pub u64);
    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
        pub fn big(&mut self, bits: usize) -> BigUint {
            let words: Vec<u64> = (0..bits.div_ceil(64)).map(|_| self.next()).collect();
            let mut v = BigUint::from_slice(
                &words
                    .iter()
                    .flat_map(|w| [*w as u32, (w >> 32) as u32])
                    .collect::<Vec<_>>(),
            );
            v %= BigUint::one() << bits;
            v
        }
        pub fn below(&mut self, m: &BigUint) -> BigUint {
            self.big(m.bits() as usize + 64) % m
        }
    }

    pub fn bits_of(v: &BigUint, n: usize) -> Vec<bool> {
        (0..n).map(|i| v.bit(i as u64)).collect()
    }

    /// A closed circuit and output words read from its evaluations.
    pub struct Ev {
        pub circuit: Circuit,
        pub outs: Vec<Word>,
        pub rows: usize,
    }

    impl Ev {
        pub fn new(n_in: usize, f: impl FnOnce(&mut Ckt, &[Wire]) -> Vec<Word>) -> Ev {
            let mut c = Ckt::new();
            let ins = c.inputs(n_in);
            let before = c.rows();
            let outs = f(&mut c, &ins);
            let rows = c.rows() - before;
            let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
            circuit.check_wired().unwrap();
            Ev { circuit, outs, rows }
        }
        pub fn eval(&self, inputs: &[bool]) -> Vec<BigUint> {
            let v = self.circuit.values(inputs);
            self.outs
                .iter()
                .map(|w| {
                    w.iter().enumerate().fold(BigUint::zero(), |acc, (i, b)| {
                        if b.value(&v) { acc | (BigUint::one() << i) } else { acc }
                    })
                })
                .collect()
        }
    }

    #[test]
    fn naf_digits_sum_back() {
        let mut rng = Rng(1);
        for _ in 0..200 {
            let k = BigInt::from(rng.big(300)) - BigInt::from(rng.big(300));
            let s: BigInt = naf(&k).iter().map(|&(i, d)| BigInt::from(d) << i).sum();
            assert_eq!(s, k);
            for w in 2..7 {
                let s: BigInt = wnaf(&k, w).iter().map(|&(i, d)| BigInt::from(d) << i).sum();
                assert_eq!(s, k);
            }
        }
    }

    fn check_products(n: usize, m: usize, threshold: usize, trials: usize) -> (usize, usize) {
        with_karatsuba(threshold, || {
            let ev = Ev::new(n + m, |c, ins| vec![mul(c, &ins[..n], &ins[n..])]);
            let sq = Ev::new(n, |c, ins| vec![square(c, ins)]);
            let mut rng = Rng(n as u64 * 1000 + threshold as u64);
            let max_a = (BigUint::one() << n) - 1u32;
            let max_b = (BigUint::one() << m) - 1u32;
            let mut cases = vec![
                (BigUint::zero(), BigUint::zero()),
                (max_a.clone(), max_b.clone()),
                (BigUint::one(), max_b.clone()),
                (max_a.clone(), BigUint::one()),
            ];
            for _ in 0..trials {
                cases.push((rng.big(n), rng.big(m)));
            }
            for (a, b) in cases {
                let mut ins = bits_of(&a, n);
                ins.extend(bits_of(&b, m));
                assert_eq!(ev.eval(&ins)[0], &a * &b, "{n}x{m} t{threshold}: {a} {b}");
                assert_eq!(sq.eval(&bits_of(&a, n))[0], &a * &a, "{n}^2 t{threshold}: {a}");
            }
            (ev.rows, sq.rows)
        })
    }

    #[test]
    fn products_match_bigint() {
        for (n, m) in [
            (1, 1),
            (2, 3),
            (5, 5),
            (8, 8),
            (13, 7),
            (17, 17),
            (33, 33),
            (64, 64),
            (100, 99),
        ] {
            for t in [4, 8, 16, usize::MAX] {
                check_products(n, m, t, 20);
            }
        }
        // Exhaustive at 5 x 5 bits.
        for t in [2, 3, usize::MAX] {
            with_karatsuba(t, || {
                let ev = Ev::new(10, |c, ins| vec![mul(c, &ins[..5], &ins[5..]), square(c, &ins[..5])]);
                for x in 0u32..1024 {
                    let ins: Vec<bool> = (0..10).map(|i| (x >> i) & 1 == 1).collect();
                    let out = ev.eval(&ins);
                    let (a, b) = (x & 31, x >> 5);
                    assert_eq!(out[0], BigUint::from(a * b));
                    assert_eq!(out[1], BigUint::from(a * a));
                }
            });
        }
    }

    #[test]
    fn product_rows_by_threshold() {
        for n in [64, 128, 256] {
            for t in [8, 12, 16, 20, 24, 32, 48, 64, 128, usize::MAX] {
                if t != usize::MAX && t >= n {
                    continue;
                }
                let (m, s) = check_products(n, n, t, 3);
                println!("{n}-bit: karatsuba above {t:>20}: mul {m:>7} rows, square {s:>7} rows");
            }
        }
    }

    /// A closed circuit evaluated on 64 input assignments at once (bit-sliced).
    pub struct Sliced {
        rows: Vec<crate::Row>,
        inputs: Vec<u32>,
        is_input: Vec<bool>,
        pub n_rows: usize,
    }

    impl Sliced {
        pub fn new(circuit: &Circuit) -> Sliced {
            let rows = circuit.rows().to_vec();
            let mut is_input = vec![false; rows.len()];
            let inputs: Vec<u32> = (0..rows.len() as u32)
                .filter(|&r| {
                    let row = rows[r as usize];
                    [row.x, row.y, row.c] == [crate::Src::Row(r), crate::Src::Zero, crate::Src::Zero]
                })
                .collect();
            for &r in &inputs {
                is_input[r as usize] = true;
            }
            Sliced {
                n_rows: rows.len(),
                rows,
                inputs,
                is_input,
            }
        }

        pub fn n_inputs(&self) -> usize {
            self.inputs.len()
        }

        /// `lanes[i]`: input `i` across 64 assignments. Returns each row's (bit, carry) lanes.
        pub fn run(&self, lanes: &[u64]) -> Vec<(u64, u64)> {
            use crate::Src;
            assert_eq!(lanes.len(), self.inputs.len());
            let mut v = vec![(0u64, 0u64); self.rows.len()];
            for (&r, &l) in self.inputs.iter().zip(lanes) {
                v[r as usize] = (l, 0);
            }
            let rd = |v: &[(u64, u64)], s: Src, carry: bool| match s {
                Src::Zero => 0,
                Src::One => u64::MAX,
                Src::Row(r) if carry => v[r as usize].1,
                Src::Row(r) => v[r as usize].0,
            };
            for r in (crate::PUBLIC_ROWS..self.rows.len()).chain(0..crate::PUBLIC_ROWS) {
                if self.is_input[r] {
                    continue;
                }
                let row = self.rows[r];
                let (x, y, c) = (rd(&v, row.x, false), rd(&v, row.y, false), rd(&v, row.c, true));
                v[r] = (x ^ y ^ c, (x & y) | (c & (x ^ y)));
            }
            v
        }

        pub fn wire(v: &[(u64, u64)], w: Wire) -> u64 {
            match (w.as_const(), w.row()) {
                (Some(b), _) => {
                    if b {
                        u64::MAX
                    } else {
                        0
                    }
                }
                (None, Some(r)) => {
                    let (b, k) = v[r as usize];
                    let x = if w.is_carry() { k } else { b };
                    if w.is_negated() { !x } else { x }
                }
                _ => unreachable!(),
            }
        }

        /// A word's value in lane `lane`.
        pub fn word(v: &[(u64, u64)], w: &[Wire], lane: usize) -> u64 {
            w.iter()
                .enumerate()
                .map(|(i, &b)| ((Self::wire(v, b) >> lane) & 1) << i)
                .sum()
        }
    }

    /// Enumerate every assignment of the circuit's inputs (fewer than 32), 64 at a time: `f(assignment, values,
    /// lane)`.
    pub fn exhaust(s: &Sliced, mut f: impl FnMut(u64, &[(u64, u64)], usize)) {
        let n = s.n_inputs();
        assert!(n < 32);
        let total = 1u64 << n;
        let mut base = 0u64;
        while base < total {
            let lanes: Vec<u64> = (0..n)
                .map(|i| (0..64).map(|l| (((base + l) >> i) & 1) << l).sum())
                .collect();
            let v = s.run(&lanes);
            for l in 0..64.min(total - base) as usize {
                f(base + l as u64, &v, l);
            }
            base += 64;
        }
    }

    /// Build a gadget on an [`Nn`] and close it: returns the evaluator and the words `f` returns.
    pub fn gadget(f: impl FnOnce(&mut Nn) -> Vec<Word>) -> (Sliced, Vec<Word>) {
        let mut c = Ckt::new();
        let outs = {
            let mut nn = Nn::new(&mut c);
            let mut outs = f(&mut nn);
            let v = nn.valid();
            outs.push(vec![v]);
            outs
        };
        let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
        circuit.check_wired().unwrap();
        (Sliced::new(&circuit), outs)
    }

    fn small_moduli() -> Vec<(u64, usize)> {
        // (p, operand bits): operands range over all their bits, including values >= p.
        vec![(11, 4), (13, 4), (5, 3), (29, 5)]
    }

    #[test]
    fn mulmod_is_sound_and_complete_for_every_hint() {
        for (p, bits) in small_moduli() {
            for t in [3, usize::MAX] {
                with_karatsuba(t, || {
                    let m = Modulus::new(BigUint::from(p));
                    let (s, outs) = gadget(|nn| {
                        let a = nn.hint(bits, BigUint::zero);
                        let b = nn.hint(bits, BigUint::zero);
                        let r = nn.mulmod(&m, &a, &b);
                        vec![a.w, b.w, r.w]
                    });
                    let mut complete = vec![false; 1 << (2 * bits)];
                    let mut accepted = 0u64;
                    exhaust(&s, |_, v, l| {
                        let get = |k: usize| Sliced::word(v, &outs[k], l);
                        let (a, b, r, ok) = (get(0), get(1), get(2), get(3));
                        if ok == 1 {
                            assert_eq!(r, a * b % p, "p {p}: {a} * {b} accepted with r = {r}");
                            complete[(a | b << bits) as usize] = true;
                            accepted += 1;
                        }
                    });
                    assert!(complete.iter().all(|&x| x), "p {p}: some product has no accepted hint");
                    // Exactly one hint pair (r, q) is accepted per input.
                    assert_eq!(accepted, 1 << (2 * bits));
                    println!(
                        "mulmod p = {p}: {} inputs and hint bits enumerated, rows {}",
                        s.n_inputs(),
                        s.n_rows
                    );
                });
            }
        }
    }

    #[test]
    fn invmod_eqmod_congruence_sound_and_complete() {
        for (p, bits) in small_moduli() {
            let m = Modulus::new(BigUint::from(p));
            // Inverse.
            let (s, outs) = gadget(|nn| {
                let a = nn.hint(bits, BigUint::zero);
                let x = nn.invmod(&m, &a);
                vec![a.w, x.w]
            });
            let mut found = vec![false; 1 << bits];
            exhaust(&s, |_, v, l| {
                let (a, x, ok) = (
                    Sliced::word(v, &outs[0], l),
                    Sliced::word(v, &outs[1], l),
                    Sliced::word(v, &outs[2], l),
                );
                if ok == 1 {
                    assert!(
                        a % p != 0 && a * x % p == 1 && x < p,
                        "p {p}: inverse of {a} accepted as {x}"
                    );
                    found[a as usize] = true;
                }
            });
            for a in 0..1u64 << bits {
                assert_eq!(found[a as usize], a % p != 0, "p {p}: inverse of {a}");
            }
            // Equality modulo p, and a general congruence a b + 3 c - 2 d + 5 = 0.
            let (s, outs) = gadget(|nn| {
                let a = nn.hint(bits, BigUint::zero);
                let b = nn.hint(bits, BigUint::zero);
                let e = nn.eqmod(&m, &a, &b);
                nn.check(e);
                vec![a.w, b.w]
            });
            let mut found = vec![false; 1 << (2 * bits)];
            exhaust(&s, |_, v, l| {
                let (a, b, ok) = (
                    Sliced::word(v, &outs[0], l),
                    Sliced::word(v, &outs[1], l),
                    Sliced::word(v, &outs[2], l),
                );
                if ok == 1 {
                    assert_eq!(a % p, b % p);
                    found[(a | b << bits) as usize] = true;
                }
            });
            for x in 0..1usize << (2 * bits) {
                assert_eq!(found[x], (x as u64 & ((1 << bits) - 1)) % p == (x as u64 >> bits) % p);
            }
            let cb = bits - 1;
            let (s, outs) = gadget(|nn| {
                let a = nn.hint(cb, BigUint::zero);
                let b = nn.hint(cb, BigUint::zero);
                let c = nn.hint(cb, BigUint::zero);
                let d = nn.hint(cb, BigUint::zero);
                let e = nn.congruence(
                    &m,
                    &[
                        Term::Mul(&a, &b, 0),
                        Term::Lin(&c, 3),
                        Term::Lin(&d, -2),
                        Term::Const(BigInt::from(5)),
                    ],
                );
                nn.check(e);
                vec![a.w, b.w, c.w, d.w]
            });
            let mut found = vec![false; 1 << (4 * cb)];
            exhaust(&s, |_, v, l| {
                let g = |k: usize| Sliced::word(v, &outs[k], l) as i64;
                if g(4) == 1 {
                    let e = g(0) * g(1) + 3 * g(2) - 2 * g(3) + 5;
                    assert_eq!(e.rem_euclid(p as i64), 0, "p {p}: congruence accepted wrongly");
                    found[(g(0) | g(1) << cb | g(2) << (2 * cb) | g(3) << (3 * cb)) as usize] = true;
                }
            });
            for x in 0..1usize << (4 * cb) {
                let g = |k: usize| ((x >> (k * cb)) & ((1 << cb) - 1)) as i64;
                let e = g(0) * g(1) + 3 * g(2) - 2 * g(3) + 5;
                assert_eq!(found[x], e.rem_euclid(p as i64) == 0, "p {p}: completeness at {x}");
            }
        }
    }

    #[test]
    fn addmod_submod_lt_exhaustive() {
        for (p, bits) in small_moduli() {
            let m = Modulus::new(BigUint::from(p));
            let (s, outs) = gadget(|nn| {
                let mut a = nn.hint(bits, BigUint::zero);
                let mut b = nn.hint(bits, BigUint::zero);
                let lt_a = lt_const(nn.c, &a.w, &m.p);
                let lt_b = lt_const(nn.c, &b.w, &m.p);
                a.max = &m.p - 1u32;
                b.max = &m.p - 1u32;
                let s = nn.addmod(&m, &a, &b);
                let d = nn.submod(&m, &a, &b);
                vec![a.w, b.w, s.w, d.w, vec![lt_a, lt_b]]
            });
            exhaust(&s, |_, v, l| {
                let g = |k: usize| Sliced::word(v, &outs[k], l);
                let (a, b) = (g(0), g(1));
                assert_eq!(g(4), (a < p) as u64 | ((b < p) as u64) << 1);
                if a < p && b < p {
                    assert_eq!(g(2), (a + b) % p);
                    assert_eq!(g(3), (a + p - b) % p);
                }
            });
        }
    }

    #[test]
    fn mulmod_full_size() {
        // Random and edge operands for the three 256-bit moduli, with the honest hints; then tampered hints.
        for m in [secp256k1_p(), secp256k1_n(), bn254_r()] {
            let p = m.p.clone();
            let mut rng = Rng(p.bits() + 7);
            let mut cases = vec![
                (BigUint::zero(), BigUint::zero()),
                (BigUint::one(), &p - 1u32),
                (&p - 1u32, &p - 1u32),
                (&p - 2u32, BigUint::from(2u32)),
            ];
            for _ in 0..4 {
                cases.push((rng.below(&p), rng.below(&p)));
            }
            let build = |nn: &mut Nn, a: &BigUint, b: &BigUint| -> Vec<Word> {
                let mut x = nn.hint(m.bits, || a.clone());
                let mut y = nn.hint(m.bits, || b.clone());
                x.max = &p - 1u32;
                y.max = &p - 1u32;
                let r = nn.mulmod(&m, &x, &y);
                let s = nn.sqrmod(&m, &x);
                let i = nn.invmod(&m, &y);
                let ad = nn.addmod(&m, &x, &y);
                let sb = nn.submod(&m, &x, &y);
                // Operands of full width, values at or above p included.
                let z = nn.hint(256, || a + &p);
                let zz = nn.mulmod(&m, &z, &z);
                vec![r.w, s.w, i.w, ad.w, sb.w, zz.w]
            };
            let mut rows = 0;
            for (a, b) in &cases {
                let mut c = Ckt::new();
                let (outs, inputs) = {
                    let mut nn = Nn::with_witness(&mut c);
                    let mut outs = build(&mut nn, a, b);
                    let v = nn.valid();
                    outs.push(vec![v]);
                    (outs, nn.inputs().to_vec())
                };
                rows = c.rows();
                let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
                let vals = circuit.values(&inputs);
                let read = |w: &Word| -> BigUint {
                    w.iter().enumerate().fold(BigUint::zero(), |acc, (i, b)| {
                        if b.value(&vals) {
                            acc | (BigUint::one() << i)
                        } else {
                            acc
                        }
                    })
                };
                let invertible = !b.is_zero();
                assert_eq!(read(&outs[6]), BigUint::from(invertible as u32), "valid bit");
                let big = (a + &p) % (BigUint::one() << 256);
                assert_eq!(read(&outs[5]), &big * &big % &p);
                assert_eq!(read(&outs[0]), a * b % &p);
                assert_eq!(read(&outs[1]), a * a % &p);
                if invertible {
                    assert_eq!(read(&outs[2]) * b % &p, BigUint::one());
                }
                assert_eq!(read(&outs[3]), (a + b) % &p);
                assert_eq!(read(&outs[4]), (a + &p - b) % &p);
                // Tamper each free input bit of the hints in turn (a sample): the valid bit must drop.
                let n_ops = 2 * m.bits;
                let mut rng2 = Rng(a.bits() + 99);
                for _ in 0..24 {
                    let i = n_ops + (rng2.next() as usize) % (inputs.len() - n_ops);
                    let mut bad = inputs.clone();
                    bad[i] = !bad[i];
                    let vals = circuit.values(&bad);
                    assert!(!outs[6][0].value(&vals), "flipping hint bit {i} kept valid");
                }
            }
            println!("{:x}: mulmod + sqrmod + invmod + addmod + submod in {rows} rows", p);
        }
    }

    /// Rows of each 256-bit gadget, measured alone (operands are fresh inputs; input rows not counted).
    #[test]
    fn gadget_costs() {
        for (name, m) in [
            ("secp256k1 p", secp256k1_p()),
            ("secp256k1 n", secp256k1_n()),
            ("bn254 r", bn254_r()),
        ] {
            let mut c = Ckt::new();
            let mut nn = Nn::new(&mut c);
            let mut x = nn.hint(m.bits, BigUint::zero);
            let mut y = nn.hint(m.bits, BigUint::zero);
            x.max = &m.p - 1u32;
            y.max = &m.p - 1u32;
            let cost = |nn: &mut Nn, what: &str, f: &mut dyn FnMut(&mut Nn)| {
                let (r0, i0) = (nn.c.rows(), nn.c.n_inputs());
                f(nn);
                let (r1, i1) = (nn.c.rows(), nn.c.n_inputs());
                println!(
                    "{name}: {what:<34} {:>7} rows ({} hint bits)",
                    r1 - r0 - (i1 - i0),
                    i1 - i0
                );
            };
            cost(&mut nn, "product a b (Karatsuba, 512 bits)", &mut |nn| {
                mul(nn.c, &x.w, &y.w);
            });
            cost(&mut nn, "square a^2", &mut |nn| {
                square(nn.c, &x.w);
            });
            cost(&mut nn, "mulmod (hint r, q; r < p)", &mut |nn| {
                nn.mulmod(&m, &x, &y);
            });
            cost(&mut nn, "sqrmod", &mut |nn| {
                nn.sqrmod(&m, &x);
            });
            cost(&mut nn, "invmod (hint, a x = 1)", &mut |nn| {
                nn.invmod(&m, &x);
            });
            cost(&mut nn, "addmod", &mut |nn| {
                nn.addmod(&m, &x, &y);
            });
            cost(&mut nn, "submod", &mut |nn| {
                nn.submod(&m, &x, &y);
            });
            cost(&mut nn, "eqmod (congruence)", &mut |nn| {
                nn.eqmod(&m, &x, &y);
            });
            cost(&mut nn, "range check r < p", &mut |nn| {
                lt_const(nn.c, &x.w, &m.p);
            });
            cost(&mut nn, "q p for a 257-bit q (into an acc)", &mut |nn| {
                let q = nn.c.inputs(257);
                let mut acc = Acc::new(520);
                const_mul_into(nn.c, &mut acc, &q, 0, &-BigInt::from(m.p.clone()));
                let b = acc.bits();
                compress(nn.c, acc, 2);
                println!("   ({b} bits accumulated)");
            });
        }
    }
}
