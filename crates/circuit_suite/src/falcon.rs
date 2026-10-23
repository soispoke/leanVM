//! Falcon-512 signature verification (NIST round 3 / FN-DSA verification) as one adder circuit.
//!
//! # Statement
//!
//! The 64 public bytes (byte `i` bit `j` is public bit `8 i + j`):
//! - bytes `0..32`: the first 32 bytes of `SHAKE256(pk || m)`, where `pk` is the 897-byte NIST/FIPS encoding of the
//!   public key (header byte `0x00 + log n = 0x09`, then the 512 coefficients of `h` on 14 bits each, most
//!   significant bit first) and `m` is the message, of the fixed length [`Params::msg_len`] (32 bytes for
//!   [`Falcon512`]). The digest is computed in the circuit, with the circuit's own Keccak-f[1600].
//! - byte `32` = `valid`, bytes `33..64` = 0.
//!
//! `valid = 1` iff there are a 40-byte nonce `r` and a signature polynomial `s2` (the private inputs) such that
//! 1. every coefficient of `h` is `< q` (the key decodes),
//! 2. `|s2_i| <= 2047` and `sum_i (9 + floor(|s2_i| / 128)) <= 8 * 625` (`s2` has an encoding in the 666-byte
//!    padded signature format of the Falcon specification; the round-3 C decoder's `m > 2047` rule),
//! 3. `c = HashToPoint(r || m)`: SHAKE256 with rejection sampling (16-bit big-endian samples `t < 61445 = 5q`,
//!    coefficient `t mod q`),
//! 4. `s1 = c - s2 h mod (x^512 + 1, q)`, centred in `[-6144, 6144]`, and `||s1||^2 + ||s2||^2 <= 34 034 726`.
//!
//! which is Falcon's verification of the signature `r || compress(s2)`. Deviations, both deliberate:
//! - The signature enters decoded (`s2` as 512 sign-magnitude integers), not as compressed bytes; with check 2,
//!   "there is a valid decoded `s2`" is equivalent to "there is a valid padded compressed signature" (the
//!   encoding is a bijection on the vectors that pass check 2), so the existential statement is the same. Decoding
//!   the variable-length bytes in the circuit is estimated in the report, not built.
//! - HashToPoint reads at most [`Params::squeeze_blocks`] `* 68 = 612` samples (9 SHAKE256 blocks). A signature
//!   whose nonce needs more is rejected (`valid = 0`): `Pr[Bin(612, 4091/65536) > 100] = 7.8e-19 = 2^-60.2` for
//!   a honest nonce. This only costs completeness, never soundness.
//!
//! # Private inputs, in order
//! `h` (512 x 14 bits, low bit first), `m` (bytes, low bit first), `r` (40 bytes), `s2` (512 x (sign, 11-bit
//! magnitude)), the hint `s1` (512 x (sign, 13-bit magnitude)), then per evaluation point a quotient hint
//! (see [`point_check`]).
//!
//! # How it is built
//!
//! 4 022 683 rows (0.959 x 2^22, so the circuit closes on 2^22 rows), 29 760 free inputs; per component
//! (`report_rows`): statement digest 865k, HashToPoint SHAKE256 1 114k, sample tests 9k, compaction 255k, the
//! three NTTs 395k + 400k + 389k, the 512 pointwise checks 343k, range checks and conversions 67k, norm 161k.
//!
//! - **Keccak-f[1600]**: 124 161 rows a permutation, 5120 a round. Chi is never materialised: for each bit one
//!   *pair row* `fa(B[x]', B[x+1]', k_x)` (`'` the wire without its negation, `k_x = !neg(B[x])`) gives in its
//!   carry the and/or chi[x-1] needs (`!b & d` is `(p | r) ^ p`, `p & r`, `!(p | r)` or `p ^ (p & r)` by
//!   polarity) and in its sum the xor chi[x] needs; the next round's theta lane is then one row
//!   `fa(bt, D, K)` (the carry in the carry slot), the column parities five rows a bit from the same terms, `D`
//!   one row. The next absorbed block is xored into the last round's row for free; squeezed bits come out as
//!   positive literals for free; only the needed lanes of a last permutation's last round are computed. 16
//!   permutations: 7 for the digest (897 + 32 bytes), 9 for HashToPoint.
//! - **HashToPoint**: 612 samples; `t >= 61445` is a carry chain. The compaction has no hint: the prefix counts
//!   of rejections are computed and a 7-stage logarithmic left-shifter moves every accepted sample by its count,
//!   least significant stage first (two valid elements never meet, so a stage is a 3-row mux per bit); validity
//!   flags ride along; `ok` needs all 512 outputs valid and fewer than 128 rejections. A coefficient is kept as
//!   the raw sample (any representative modulo `q` will do).
//! - **The product**, hint and check: the prover gives `s1`; the circuit checks `|s1_i| <= (q-1)/2` (which picks
//!   the centred representative: the range holds exactly `q` integers) and `NTT(s2) . NTT(h) = NTT(c - s1)` point
//!   by point. The NTT is a bijection of `Z_q^512`, so this is exactly `s1 = c - s2 h`; no randomness is needed.
//!   Three forward negacyclic NTTs (Cooley-Tukey, 2304 butterflies each) in lazy arithmetic modulo `q`: a value
//!   is a word plus a compile-time constant; `t = w b` is the bit matrix of bit `j` of `b` times a signed-digit
//!   representative of `w 2^j mod q` (fewest digits, then least mass, among `r, r - q, r + q, r - 2q`; 3.4
//!   digits a bit on average) summed by the compressor; `a` is folded modulo `q` once when wider than 16 bits
//!   (shared by both sums), then `a + t` and `a - t` are plain two-operand additions. The outputs that are
//!   multiplied are folded tightly (lightest digits) into two's-complement words (15.7 bits on average). Each
//!   pointwise check is one exact compressor: with two's-complement weights `w`, `v` (weight sums `-1`),
//!   `2 x y = -x - y - sum_(i,j) w_i v_j (x_i ^ y_j)` (an xnor where `w_i v_j < 0`, so every term is a negated
//!   literal), minus `2 z`, minus `q (k' - k0)` for the prover's quotient `k'`; all bits zero is the check
//!   ([`point_check`]).
//! - **The compressor** ([`compress`]): all literals of a sum are first brought to one polarity (a full adder on
//!   complements gives complemented outputs, so either polarity is free; the side needing fewer conversions is
//!   chosen); a column of `B` bit-kind and `C` carry-kind literals then costs `max(B - 1, C)` rows and sends the
//!   fewest carries up (`ceil((B + C - 1) / 2)`), conversions rather than half adders balancing the kinds.
//! - **The norm**: `m^2 = (2^W - 1) m - sum_(i<j) 2^(i+j) (m_i ^ m_j)` for every magnitude, the linear parts summed
//!   first, all in one compressor with `2^L - bound - 1`; the comparison is the top bit.
//!
//! Not built: decoding the compressed signature bytes. With the signature private, the existential statement
//! does not need it (check 2 is the length budget). Were the bytes public, decoding by hint and check would
//! re-encode `s2` and place each code at its offset `9 i + sum_(j<i) floor(|s2_j| / 128)` (the drift at most
//! 392 by check 2): a 9-stage shifter over the 5000 bits, about 5000 x 9 x 18 = 0.81M rows, plus about 20k for
//! the prefix sums and the comparison, so about 4.85M rows in all, 2^23.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::{Ckt, Instance, Kind, PUBLIC_BITS, Wire, Word, Workload, read_u64};

// ---------------------------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------------------------

/// The parameters of the generator. [`Params::falcon512`] is the workload; tests shrink them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    pub log_n: usize,
    pub q: u64,
    /// The message length in bytes.
    pub msg_len: usize,
    /// SHAKE256 output blocks (136 bytes, 68 samples each) HashToPoint may read.
    pub squeeze_blocks: usize,
    /// Stages of the compaction shifter: it moves a sample by at most `2^shift_stages - 1`.
    pub shift_stages: usize,
    /// Magnitude bits of `s2`'s coefficients (`|s2_i| < 2^s2_bits`).
    pub s2_bits: usize,
    pub norm_bound: u64,
    /// The signature's compressed-encoding bit budget, if checked.
    pub max_comp_bits: Option<u64>,
    /// Lazy reduction: word bits of weight `>= 2^fold` are folded back modulo `q` when added.
    pub fold: u32,
}

impl Params {
    pub fn falcon512() -> Self {
        Self {
            log_n: 9,
            q: 12289,
            msg_len: 32,
            squeeze_blocks: 9,
            shift_stages: 7,
            s2_bits: 11,
            norm_bound: 34_034_726,
            max_comp_bits: Some(8 * 625),
            fold: 16,
        }
    }

    pub fn n(&self) -> usize {
        1 << self.log_n
    }

    /// Bits of a public-key coefficient.
    pub fn h_bits(&self) -> usize {
        bitlen(self.q - 1)
    }

    /// Magnitude bits of `s1`'s centred coefficients.
    pub fn s1_bits(&self) -> usize {
        bitlen(self.q / 2)
    }

    pub fn pk_len(&self) -> usize {
        1 + (self.n() * self.h_bits()).div_ceil(8)
    }
}

pub const NONCE_LEN: usize = 40;
const RATE: usize = 136;

fn bitlen(x: u64) -> usize {
    64 - x.leading_zeros() as usize
}

fn bitlen128(x: u128) -> usize {
    128 - x.leading_zeros() as usize
}

// ---------------------------------------------------------------------------------------------------------------
// Literals and the carry-save compressor
// ---------------------------------------------------------------------------------------------------------------

fn is_carry(w: Wire) -> bool {
    matches!(w.kind, Kind::Carry(_))
}

/// `w` with a carry already read as a bit substituted (the polarity is kept).
fn norm(c: &Ckt, w: Wire) -> Wire {
    if let Some(b) = w.as_const() {
        return Wire::constant(b);
    }
    if let Kind::Carry(r) = w.kind
        && let Some(&s) = c.to_sum.get(&r)
    {
        return Wire {
            kind: Kind::Sum(s),
            neg: w.neg,
        };
    }
    w
}

/// A full adder on literals: when most variables are negated, the row adds their complements and both outputs
/// are negated (`fa(!a, !b, !c) = (!s, !k)`), so at most one negation is ever made positive.
fn fa_lit(c: &mut Ckt, a: Wire, b: Wire, d: Wire) -> (Wire, Wire) {
    let ops = [norm(c, a), norm(c, b), norm(c, d)];
    let vars = ops.iter().filter(|w| w.as_const().is_none()).count();
    let negs = ops.iter().filter(|w| w.as_const().is_none() && w.neg).count();
    if 2 * negs > vars {
        let (s, k) = c.fa(ops[0].not(), ops[1].not(), ops[2].not());
        (s.not(), k.not())
    } else {
        c.fa(ops[0], ops[1], ops[2])
    }
}

/// A literal of polarity `neg` with the value of `w`: free if it already has it, else one row (cached).
fn with_polarity(c: &mut Ckt, w: Wire, neg: bool) -> Wire {
    if w.as_const().is_some() || w.neg == neg {
        return w;
    }
    if neg {
        // `w` positive: a positive wire holding `!w`, negated.
        c.positive(w.not()).not()
    } else {
        c.positive(w)
    }
}

/// Whether making `w` of polarity `neg` would cost a row.
fn needs_flip(c: &Ckt, w: Wire, neg: bool) -> bool {
    if w.as_const().is_some() || w.neg == neg {
        return false;
    }
    !c.positive.contains_key(&if neg { w.not() } else { w })
}

/// A bit-kind literal as a carry-kind one (one row, cached).
fn as_carry(c: &mut Ckt, w: Wire) -> Wire {
    let Kind::Sum(r) = w.kind else { return w };
    // Share Ckt's x + 1 conversion: its sum is !x and its carry is x.
    // Ckt::positive also reads this cache, so x + x (sum zero) is incompatible.
    let k = c.flip_row(r);
    Wire {
        kind: Kind::Carry(k),
        neg: w.neg,
    }
}

/// A carry-kind literal as a bit-kind one (one row, cached).
fn as_bit(c: &mut Ckt, w: Wire) -> Wire {
    let Kind::Carry(r) = w.kind else { return w };
    let s = match c.to_sum.get(&r) {
        Some(&s) => s,
        None => {
            let s = c.row(crate::Src::Zero, crate::Src::Zero, crate::Src::Row(r));
            c.to_sum.insert(r, s);
            s
        }
    };
    Wire {
        kind: Kind::Sum(s),
        neg: w.neg,
    }
}

/// Reduce one column of literals of one polarity to a single literal, pushing carries into `next` (dropped in the
/// top column). A full adder takes two bit-kind literals and one carry (or the constant); a column of `B` bits
/// and `C` carries costs `max(B - 1, C)` rows and sends the fewest carries up, `ceil((B + C - 1) / 2)`:
/// conversions balance the kinds rather than half adders.
fn reduce_column(
    c: &mut Ckt,
    mut bits: Vec<Wire>,
    mut carries: Vec<Wire>,
    mut one: bool,
    top: bool,
    next: &mut Vec<Wire>,
) -> Wire {
    loop {
        let e = bits.len() + carries.len() + one as usize;
        match e {
            0 => return Wire::ZERO,
            1 => {
                return if one {
                    Wire::ONE
                } else if let Some(b) = bits.pop() {
                    b
                } else {
                    carries.pop().unwrap()
                };
            }
            2 => {
                let (x, y) = if one {
                    (Wire::ONE, bits.pop().or_else(|| carries.pop()).unwrap())
                } else if !bits.is_empty() && !carries.is_empty() {
                    (bits.pop().unwrap(), carries.pop().unwrap())
                } else if bits.len() == 2 {
                    (bits.pop().unwrap(), bits.pop().unwrap())
                } else {
                    let k = carries.pop().unwrap();
                    (as_bit(c, k), carries.pop().unwrap())
                };
                let (s, k) = fa_lit(c, x, y, Wire::ZERO);
                if !top {
                    next.push(k);
                }
                return s;
            }
            _ => {
                let ops = if !carries.is_empty() && bits.len() >= 2 {
                    [bits.pop().unwrap(), bits.pop().unwrap(), carries.pop().unwrap()]
                } else if one && bits.len() >= 2 {
                    one = false;
                    [bits.pop().unwrap(), bits.pop().unwrap(), Wire::ONE]
                } else if one && bits.len() == 1 && !carries.is_empty() {
                    one = false;
                    [bits.pop().unwrap(), Wire::ONE, carries.pop().unwrap()]
                } else if carries.is_empty() {
                    let b = bits.pop().unwrap();
                    carries.push(as_carry(c, b));
                    continue;
                } else {
                    let k = carries.pop().unwrap();
                    bits.push(as_bit(c, k));
                    continue;
                };
                let (s, k) = fa_lit(c, ops[0], ops[1], ops[2]);
                if !top {
                    next.push(k);
                }
                bits.push(s);
            }
        }
    }
}

/// `sum_k 2^k (sum of the literals of column k)` modulo `2^width`, as a word of literals. All literals are first
/// brought to one polarity (the one needing fewer conversions; a full adder on complemented inputs gives the
/// complemented outputs, so a negated column costs nothing), then each column is reduced by [`reduce_column`].
pub(crate) fn compress(c: &mut Ckt, mut cols: Vec<Vec<Wire>>, width: usize) -> Word {
    cols.resize(width, Vec::new());
    let mut flips = [std::collections::HashSet::new(), std::collections::HashSet::new()];
    for col in &cols {
        for &w in col {
            let w = norm(c, w);
            for (i, neg) in [false, true].into_iter().enumerate() {
                if needs_flip(c, w, neg) {
                    flips[i].insert(w);
                }
            }
        }
    }
    let neg = flips[1].len() < flips[0].len();
    let mut out = Vec::with_capacity(width);
    let mut carry_in: Vec<Wire> = Vec::new();
    let mut ones_in = 0usize;
    for (k, col) in cols.into_iter().enumerate() {
        let top = k + 1 == width;
        let r_start = c.rows();
        let (mut bits, mut carries, mut ones) = (Vec::new(), Vec::new(), ones_in);
        for w in col.into_iter().chain(carry_in.drain(..)) {
            let w = norm(c, w);
            match w.as_const() {
                Some(true) => ones += 1,
                Some(false) => {}
                None => {
                    let w = with_polarity(c, w, neg);
                    let w = norm(c, w);
                    if is_carry(w) { carries.push(w) } else { bits.push(w) }
                }
            }
        }
        ones_in = if top { 0 } else { ones / 2 };
        let mut next = Vec::new();
        let (r_mid, b0, c0) = (c.rows(), bits.len(), carries.len());
        out.push(reduce_column(c, bits, carries, ones % 2 == 1, top, &mut next));
        if std::env::var("FALCON_DEBUG").is_ok() {
            eprintln!(
                "col {k}: B {b0} C {c0} one {} | polarity conv {} | reduce rows {} carries out {}",
                ones % 2,
                r_mid - r_start,
                c.rows() - r_mid,
                next.len()
            );
        }
        carry_in = next;
    }
    out
}

/// An exact integer sum of literals with power-of-two weights, signs, and a constant.
#[derive(Default, Clone)]
pub(crate) struct Acc {
    cols: Vec<Vec<Wire>>,
    /// The largest value of the literal part.
    max: u128,
    konst: i128,
}

impl Acc {
    /// Add `+-w 2^e`; a negative term is `(!w - 1) 2^e`.
    pub(crate) fn lit(&mut self, w: Wire, e: usize, negative: bool) {
        if let Some(b) = w.as_const() {
            if b {
                self.konst += if negative { -(1i128 << e) } else { 1i128 << e };
            }
            return;
        }
        if self.cols.len() <= e {
            self.cols.resize(e + 1, Vec::new());
        }
        if negative {
            self.cols[e].push(w.not());
            self.konst -= 1i128 << e;
        } else {
            self.cols[e].push(w);
        }
        self.max += 1u128 << e;
    }

    pub(crate) fn word(&mut self, x: &[Wire], shift: usize, negative: bool) {
        for (i, &w) in x.iter().enumerate() {
            self.lit(w, i + shift, negative);
        }
    }

    /// The sum modulo `2^width`.
    pub(crate) fn finish(mut self, c: &mut Ckt, width: usize) -> Word {
        let k = self.konst.rem_euclid(1i128 << width);
        if self.cols.len() < width {
            self.cols.resize(width, Vec::new());
        }
        for e in 0..width {
            if (k >> e) & 1 == 1 {
                self.cols[e].push(Wire::ONE);
            }
        }
        self.cols.truncate(width);
        compress(c, self.cols, width)
    }

    /// Whether the sum is `<= bound`, the sum being known non-negative: the top bit of
    /// `sum + 2^L - bound - 1` on `L + 1` bits, `2^L` above the largest sum.
    pub(crate) fn at_most(mut self, c: &mut Ckt, bound: u128) -> Wire {
        let max = (self.max as i128 + self.konst.max(0)) as u128;
        if bound >= max {
            return Wire::ONE;
        }
        let l = bitlen128(max);
        self.konst += (1i128 << l) - bound as i128 - 1;
        let u = self.finish(c, l + 1);
        u[l].not()
    }
}

/// `x >= k` for a word `x`, a carry chain: the carry out of `x + 2^W - k`.
pub(crate) fn geq_const(c: &mut Ckt, x: &[Wire], k: u64) -> Wire {
    let w = x.len();
    if k == 0 {
        return Wire::ONE;
    }
    if w < 64 && k >= 1 << w {
        return Wire::ZERO;
    }
    let add = (1u128 << w) - k as u128;
    let mut carry = Wire::ZERO;
    for (i, &b) in x.iter().enumerate() {
        carry = fa_lit(c, b, Wire::constant((add >> i) & 1 == 1), carry).1;
    }
    carry
}

/// The OR of literals: an or-chain over the positive ones (the chain riding in the carry slot) and an and-chain
/// over the complements of the negated ones.
pub(crate) fn any_lits(c: &mut Ckt, lits: &[Wire]) -> Wire {
    let mut or_acc: Option<Wire> = None;
    let mut and_acc: Option<Wire> = None;
    for &w in lits {
        let w = norm(c, w);
        match w.as_const() {
            Some(true) => return Wire::ONE,
            Some(false) => continue,
            None => {}
        }
        if w.neg {
            let x = w.not();
            and_acc = Some(match and_acc {
                None => x,
                Some(a) => c.and(x, a),
            });
        } else {
            or_acc = Some(match or_acc {
                None => w,
                Some(a) => c.or(w, a),
            });
        }
    }
    match (or_acc, and_acc) {
        (None, None) => Wire::ZERO,
        (Some(o), None) => o,
        (None, Some(a)) => a.not(),
        (Some(o), Some(a)) => c.or(o, a.not()),
    }
}

pub(crate) fn all_lits(c: &mut Ckt, lits: &[Wire]) -> Wire {
    let neg: Vec<Wire> = lits.iter().map(|w| w.not()).collect();
    any_lits(c, &neg).not()
}

// ---------------------------------------------------------------------------------------------------------------
// Keccak-f[1600] and SHAKE256
// ---------------------------------------------------------------------------------------------------------------

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets `ROT[x][y]`.
const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn lane(x: usize, y: usize) -> usize {
    x + 5 * y
}

/// `a ^ (!b & d)` in two rows whatever the polarities: the and (or or) is a carry read in the carry slot.
fn chi_bit(c: &mut Ckt, a: Wire, b: Wire, d: Wire) -> Wire {
    if let Some(bv) = b.as_const() {
        return if bv { a } else { c.xor(a, d) };
    }
    if let Some(dv) = d.as_const() {
        return if dv { c.xor(a, b.not()) } else { a };
    }
    let bp = Wire { neg: false, ..b };
    let dp = Wire { neg: false, ..d };
    match (b.neg, d.neg) {
        // !b & d = d ^ (b & d)
        (false, false) => {
            let t = c.and(bp, dp);
            c.xor3(a, dp, t)
        }
        // b = !bp: bp & dp
        (true, false) => {
            let t = c.and(bp, dp);
            c.xor(a, t)
        }
        // !bp & !dp = !(bp | dp)
        (false, true) => {
            let t = c.or(bp, dp);
            c.xor(a, t).not()
        }
        // bp & !dp = bp ^ (bp & dp)
        (true, true) => {
            let t = c.and(bp, dp);
            c.xor3(a, bp, t)
        }
    }
}

/// The chi output of one bit as `bt ^ k ^ flip`: `bt` a bit-kind literal, `k` a carry (or 0), `flip` a constant.
#[derive(Clone, Copy)]
struct ChiTerm {
    bt: Wire,
    k: Wire,
    flip: bool,
}

/// Chi and iota of a round as terms, never materialised. For each `x`, the pair row
/// `R_x = fa(B[x]', B[x+1]', kappa_x)` (`'` the wire without its negation, `kappa_x = !neg(B[x])`) gives in its
/// carry the and/or that chi[x-1] needs and in its sum `B[x]' ^ B[x+1]' ^ kappa_x`, the xor chi[x] needs when the
/// polarities of `B[x+1]` and `B[x+2]` agree:
/// `!b & d` is `(p | r) ^ p`, `p & r`, `!(p | r)` or `p ^ (p & r)` for the four polarities of `b = p`, `d = r`.
fn chi_terms(c: &mut Ckt, b: &[Word], need: &[bool; 25], rc: u64) -> Vec<Vec<ChiTerm>> {
    let mut pairs: HashMap<(usize, usize, usize), (Wire, Wire, bool)> = HashMap::new();
    let mut pair = |c: &mut Ckt, i: usize, y: usize, z: usize| -> (Wire, Wire, bool) {
        *pairs.entry((i, y, z)).or_insert_with(|| {
            let (u, v) = (b[lane(i, y)][z], b[lane((i + 1) % 5, y)][z]);
            let kappa = !u.neg;
            let (s, k) = c.fa(
                Wire { neg: false, ..u },
                Wire { neg: false, ..v },
                Wire::constant(kappa),
            );
            (s, k, kappa)
        })
    };
    let mut out = vec![Vec::new(); 25];
    for y in 0..5 {
        for x in 0..5 {
            if !need[lane(x, y)] {
                continue;
            }
            out[lane(x, y)] = (0..64)
                .map(|z| {
                    let a = b[lane(x, y)][z];
                    let bb = b[lane((x + 1) % 5, y)][z];
                    let d = b[lane((x + 2) % 5, y)][z];
                    let iota = lane(x, y) == 0 && (rc >> z) & 1 == 1;
                    if [a, bb, d].iter().any(|w| w.as_const().is_some()) {
                        let o = chi_bit(c, a, bb, d);
                        return ChiTerm {
                            bt: o,
                            k: Wire::ZERO,
                            flip: iota,
                        };
                    }
                    let (_, k, _) = pair(c, (x + 1) % 5, y, z);
                    if bb.neg == d.neg {
                        // chi = a ^ p ^ K = sum_x ^ kappa_x ^ neg(a) ^ K.
                        let (sx, _, kx) = pair(c, x, y, z);
                        ChiTerm {
                            bt: sx,
                            k,
                            flip: kx ^ a.neg ^ iota,
                        }
                    } else {
                        // chi = a ^ K, or a ^ K ^ 1 when b is positive and d negated.
                        ChiTerm {
                            bt: Wire { neg: false, ..a },
                            k,
                            flip: a.neg ^ (!bb.neg && d.neg) ^ iota,
                        }
                    }
                })
                .collect();
        }
    }
    out
}

fn rho_pi(t: &[Word]) -> Vec<Word> {
    let mut b: Vec<Word> = vec![Vec::new(); 25];
    for x in 0..5 {
        for y in 0..5 {
            if t[lane(x, y)].is_empty() {
                continue;
            }
            let r = ROT[x][y];
            b[lane(y, (2 * x + 3 * y) % 5)] = (0..64).map(|z| t[lane(x, y)][(z + 64 - r) % 64]).collect();
        }
    }
    b
}

/// Theta's `D[x] = C[x-1] ^ rot(C[x+1], 1)`.
fn theta_d(c: &mut Ckt, cpar: &[Word]) -> Vec<Word> {
    (0..5)
        .map(|x| {
            (0..64)
                .map(|z| c.xor(cpar[(x + 4) % 5][z], cpar[(x + 1) % 5][(z + 63) % 64]))
                .collect()
        })
        .collect()
}

/// Keccak-f[1600] on 25 lanes of 64 literals: the output lanes in `need`, each xored with `xin` if given.
/// Chi's outputs are never materialised: the next theta's lane xor is one row `fa(bt, D, k)`, its column
/// parities five rows a bit from the terms. 5120 rows a round (plus 3200 in the first and last).
pub(crate) fn keccak_f(c: &mut Ckt, a: Vec<Word>, need: &[bool; 25], xin: Option<&[Word]>) -> Vec<Word> {
    if c.native_keccak_enabled() {
        let input: Vec<_> = a.iter().flatten().copied().collect();
        let output = c.keccak_permutation(&input);
        return (0..25)
            .map(|l| {
                if !need[l] {
                    return Vec::new();
                }
                (0..64)
                    .map(|z| match xin {
                        Some(v) => c.xor(output[64 * l + z], v[l][z]),
                        None => output[64 * l + z],
                    })
                    .collect()
            })
            .collect();
    }

    // Theta of the first round from the materialised state.
    let cpar: Vec<Word> = (0..5)
        .map(|x| {
            (0..64)
                .map(|z| {
                    let t = c.xor(a[lane(x, 0)][z], a[lane(x, 1)][z]);
                    let u = c.xor(a[lane(x, 2)][z], a[lane(x, 3)][z]);
                    let v = c.xor(t, u);
                    c.xor(v, a[lane(x, 4)][z])
                })
                .collect()
        })
        .collect();
    let d = theta_d(c, &cpar);
    let mut t: Vec<Word> = (0..25)
        .map(|l| (0..64).map(|z| c.xor(a[l][z], d[l % 5][z])).collect())
        .collect();
    let all = [true; 25];
    for (r, &rc) in RC.iter().enumerate() {
        let b = rho_pi(&t);
        let last = r == 23;
        let terms = chi_terms(c, &b, if last { need } else { &all }, rc);
        if last {
            return (0..25)
                .map(|l| {
                    if !need[l] {
                        return Vec::new();
                    }
                    (0..64)
                        .map(|z| {
                            let ch = terms[l][z];
                            match xin {
                                Some(v) => {
                                    let o = c.xor3(ch.bt, v[l][z], ch.k);
                                    if ch.flip { o.not() } else { o }
                                }
                                // A squeezed bit as a positive literal for free: a complement is the constant 1
                                // in the row's y slot.
                                None if ch.flip ^ ch.bt.neg && ch.k.as_const().is_none() => {
                                    c.fa(Wire { neg: false, ..ch.bt }, Wire::ONE, ch.k).0
                                }
                                None => {
                                    let o = c.xor(ch.bt, ch.k);
                                    if ch.flip { o.not() } else { o }
                                }
                            }
                        })
                        .collect()
                })
                .collect();
        }
        let cpar: Vec<Word> = (0..5)
            .map(|x| {
                (0..64)
                    .map(|z| {
                        let ts: Vec<ChiTerm> = (0..5).map(|y| terms[lane(x, y)][z]).collect();
                        let flip = ts.iter().fold(false, |f, t| f ^ t.flip);
                        let mut u = c.xor3(ts[0].bt, ts[1].bt, ts[0].k);
                        for y in 2..5 {
                            u = c.xor3(u, ts[y].bt, ts[y - 1].k);
                        }
                        u = c.xor(u, ts[4].k);
                        if flip { u.not() } else { u }
                    })
                    .collect()
            })
            .collect();
        let d = theta_d(c, &cpar);
        t = (0..25)
            .map(|l| {
                (0..64)
                    .map(|z| {
                        let ch = terms[l][z];
                        let o = c.xor3(ch.bt, d[l % 5][z], ch.k);
                        if ch.flip { o.not() } else { o }
                    })
                    .collect()
            })
            .collect();
    }
    unreachable!()
}

/// SHAKE256 of a whole number of bytes (literals, byte `i` bit `j` at `8 i + j`), `out_len` output bytes.
pub(crate) fn shake256(c: &mut Ckt, msg: &[Wire], out_len: usize) -> Vec<Wire> {
    shake(c, msg, out_len, RATE)
}

/// SHAKE with a fixed FIPS 202 rate, sharing the Boolean/native permutation hook.
pub(crate) fn shake(c: &mut Ckt, msg: &[Wire], out_len: usize, rate: usize) -> Vec<Wire> {
    assert!(rate == 136 || rate == 168);
    assert_eq!(msg.len() % 8, 0);
    let mlen = msg.len() / 8;
    let total = (mlen / rate + 1) * rate;
    let mut pad = vec![0u8; total - mlen];
    pad[0] ^= 0x1F;
    *pad.last_mut().unwrap() ^= 0x80;
    let mut bits = msg.to_vec();
    bits.extend(
        pad.iter()
            .flat_map(|&b| (0..8).map(move |j| Wire::constant((b >> j) & 1 == 1))),
    );
    let blocks = total / rate;
    let squeezes = out_len.div_ceil(rate);
    let perms = blocks + squeezes - 1;
    let block = |p: usize| -> Vec<Word> {
        (0..25)
            .map(|l| {
                (0..64)
                    .map(|z| {
                        let i = l * 64 + z;
                        if p < blocks && i < rate * 8 {
                            bits[p * rate * 8 + i]
                        } else {
                            Wire::ZERO
                        }
                    })
                    .collect()
            })
            .collect()
    };
    let mut state: Vec<Word> = block(0);
    let mut out = Vec::with_capacity(out_len * 8);
    for p in 0..perms {
        let mut need = [true; 25];
        if p + 1 == perms {
            let remaining = out_len - (squeezes - 1) * rate;
            need = std::array::from_fn(|l| l < remaining.div_ceil(8));
        }
        // The next block is xored into the last round's output for free.
        let next = (p + 1 < blocks).then(|| block(p + 1));
        state = keccak_f(c, state, &need, next.as_deref());
        if p + 1 >= blocks {
            let take = (out_len * 8 - out.len()).min(rate * 8);
            out.extend((0..take).map(|i| state[i / 64][i % 64]));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Lazy arithmetic modulo q
// ---------------------------------------------------------------------------------------------------------------

/// Signed-digit representations of the residues, chosen once.
pub(crate) struct Modq {
    pub q: u64,
    /// For each residue, the fewest (then the lightest) signed digits `(exponent, negative)` of `r` or `r - q`.
    reps: Vec<Vec<(u8, bool)>>,
    slack: usize,
}

fn naf(mut n: i64) -> Vec<(u8, bool)> {
    let neg = n < 0;
    n = n.abs();
    let mut d = Vec::new();
    let mut e = 0u8;
    while n != 0 {
        if n & 1 == 1 {
            let z = 2 - (n & 3);
            n -= z;
            d.push((e, (z < 0) ^ neg));
        }
        n >>= 1;
        e += 1;
    }
    d
}

fn digits_mass(d: &[(u8, bool)]) -> u64 {
    d.iter().map(|&(e, _)| 1u64 << e).sum()
}

impl Modq {
    pub(crate) fn new(q: u64) -> Self {
        Self::with_policy(q, 0)
    }

    /// The lightest (least mass) representations: for folding a word to as few bits as possible.
    pub(crate) fn tight(q: u64) -> Self {
        Self::with_policy(q, 64)
    }

    /// `slack`: a representation may use up to `slack` more digits than the fewest if its mass is smaller.
    pub(crate) fn with_policy(q: u64, slack: usize) -> Self {
        let reps = if q <= 65536 {
            (0..q).map(|r| Self::choose_digits(q, r, slack)).collect()
        } else {
            Vec::new()
        };
        Self { q, reps, slack }
    }
    fn choose_digits(q: u64, r: u64, slack: usize) -> Vec<(u8, bool)> {
        let cands = [
            naf(r as i64),
            naf(r as i64 - q as i64),
            naf(r as i64 + q as i64),
            naf(r as i64 - 2 * q as i64),
        ];
        let fewest = cands.iter().map(Vec::len).min().unwrap();
        cands
            .into_iter()
            .filter(|d| d.len() <= fewest + slack)
            .min_by_key(|d| (digits_mass(d), d.len()))
            .unwrap()
    }
    fn digits(&self, r: u64) -> std::borrow::Cow<'_, [(u8, bool)]> {
        if self.reps.is_empty() {
            std::borrow::Cow::Owned(Self::choose_digits(self.q, r, self.slack))
        } else {
            std::borrow::Cow::Borrowed(&self.reps[r as usize])
        }
    }

    fn mulq(&self, a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % self.q as u128) as u64
    }
}

/// A value modulo `q`: `sum w * coef + k`, the literals `w` with integer coefficients. A word has the
/// coefficients `2^i`; `max` bounds `sum w * coef` for a word.
#[derive(Clone, Debug)]
pub(crate) struct MV {
    pub terms: Vec<(Wire, u64)>,
    pub k: u64,
    pub max: u64,
}

impl MV {
    pub(crate) fn word(bits: &[Wire]) -> MV {
        MV {
            terms: bits.iter().enumerate().map(|(i, &w)| (w, 1u64 << i)).collect(),
            k: 0,
            max: (1u64 << bits.len()) - 1,
        }
    }

    pub(crate) fn bits(&self) -> Word {
        self.terms.iter().map(|t| t.0).collect()
    }
}

/// A linear combination modulo `q` being summed.
pub(crate) struct Lin<'a> {
    m: &'a Modq,
    acc: Acc,
}

impl<'a> Lin<'a> {
    pub(crate) fn new(m: &'a Modq) -> Self {
        Self { m, acc: Acc::default() }
    }

    /// Add `coef * x`. A coefficient `2^i < 2^fold` of `x` with `coef = 1` is kept as the one digit `2^i`; every
    /// other is replaced by the fewest signed digits of a representative of `coef * cf mod q`.
    pub(crate) fn add(&mut self, x: &MV, coef: u64, fold: u32) {
        let q = self.m.q;
        for &(w, cf) in &x.terms {
            if (coef == 1 || coef == q - 1) && cf.is_power_of_two() && (fold >= 64 || cf < 1u64 << fold) {
                self.acc.lit(w, cf.trailing_zeros() as usize, coef != 1);
                continue;
            }
            let r = self.m.mulq(coef, cf % q);
            for &(e, neg) in self.m.digits(r).as_ref() {
                self.acc.lit(w, e as usize, neg);
            }
        }
        self.acc.konst += self.m.mulq(coef, x.k % q) as i128;
    }

    /// Sum into a word. With `absorb` the constant is added into the word (`k = 0`), else it rides along.
    pub(crate) fn finish(mut self, c: &mut Ckt, absorb: bool) -> MV {
        let q = self.m.q as i128;
        let kq = self.acc.konst.rem_euclid(q);
        let (max, k) = if absorb {
            self.acc.konst = kq;
            (self.acc.max + kq as u128, 0)
        } else {
            self.acc.konst = 0;
            (self.acc.max, kq as u64)
        };
        let width = bitlen128(max).max(1);
        let bits = self.acc.finish(c, width);
        let mut mv = MV::word(&bits);
        mv.k = k;
        mv.max = max as u64;
        mv
    }
}

/// A two's-complement word: `value = sum_(i < W-1) b_i 2^i - b_(W-1) 2^(W-1)`, in `[lo, hi]`.
#[derive(Clone, Debug)]
pub struct SWord {
    pub bits: Word,
    pub lo: i128,
    pub hi: i128,
}

impl SWord {
    pub fn read(&self, values: &[u8]) -> i128 {
        let w = self.bits.len();
        let u = self
            .bits
            .iter()
            .enumerate()
            .map(|(i, b)| (b.value(values) as i128) << i)
            .sum::<i128>();
        if u >> (w - 1) & 1 == 1 { u - (1i128 << w) } else { u }
    }
}

impl Lin<'_> {
    /// Sum into a two's-complement word holding an integer congruent to the value, the constant chosen to centre
    /// its range so the word is as narrow as possible.
    pub(crate) fn finish_signed(mut self, c: &mut Ckt) -> SWord {
        let q = self.m.q as i128;
        let k = self.acc.konst.rem_euclid(q);
        let mass = self.acc.max as i128;
        // The narrowest width with a constant k' = k mod q putting [k', k' + mass] inside the signed range.
        let mut w = bitlen128(mass as u128).max(1);
        let konst = loop {
            let lo = -(1i128 << (w - 1));
            let hi_k = (1i128 << (w - 1)) - 1 - mass;
            // The smallest k' >= lo congruent to k.
            let kk = lo + (k - lo).rem_euclid(q);
            if kk <= hi_k {
                // Centre it within the feasible congruent values.
                let mut best = kk;
                let mut t = kk;
                while t <= hi_k {
                    if (t + mass / 2).abs() < (best + mass / 2).abs() {
                        best = t;
                    }
                    t += q;
                }
                break best;
            }
            w += 1;
        };
        self.acc.konst = konst;
        let bits = self.acc.finish(c, w);
        SWord {
            bits,
            lo: konst,
            hi: konst + mass,
        }
    }
}

/// A sign and a magnitude as a value modulo `q`: `(m ^ s) - (2^W - 1) s`.
pub(crate) fn signed_mv(c: &mut Ckt, q: u64, sign: Wire, mag: &[Wire], negate: bool) -> MV {
    let w = mag.len();
    let mut terms = Vec::with_capacity(w + 1);
    for (i, &b) in mag.iter().enumerate() {
        let x = c.xor(b, sign);
        terms.push((x, if negate { (q - (1u64 << i) % q) % q } else { 1u64 << i }));
    }
    let top = ((1u64 << w) - 1) % q;
    terms.push((sign, if negate { top } else { (q - top) % q }));
    MV { terms, k: 0, max: 0 }
}

/// The powers `psi^bitrev(k)` of a primitive `2n`-th root of unity, Cooley-Tukey order.
pub fn zetas(q: u64, log_n: usize) -> Vec<u64> {
    let n = 1usize << log_n;
    let g = (2..q)
        .find(|&g| {
            let mut f = q - 1;
            let mut ok = true;
            let mut p = 2;
            while p * p <= f {
                if f.is_multiple_of(p) {
                    ok &= powmod(g, (q - 1) / p, q) != 1;
                    while f.is_multiple_of(p) {
                        f /= p;
                    }
                }
                p += 1;
            }
            if f > 1 {
                ok &= powmod(g, (q - 1) / f, q) != 1;
            }
            ok
        })
        .unwrap();
    assert_eq!((q - 1) % (2 * n as u64), 0, "q = 1 mod 2n");
    let psi = powmod(g, (q - 1) / (2 * n as u64), q);
    (0..n)
        .map(|k| {
            let br = if log_n == 0 {
                0
            } else {
                (k as u64).reverse_bits() >> (64 - log_n)
            };
            powmod(psi, br, q)
        })
        .collect()
}

pub fn powmod(mut b: u64, mut e: u64, q: u64) -> u64 {
    let mut r = 1u64;
    b %= q;
    while e > 0 {
        if e & 1 == 1 {
            r = (r as u128 * b as u128 % q as u128) as u64;
        }
        b = (b as u128 * b as u128 % q as u128) as u64;
        e >>= 1;
    }
    r
}

/// The forward NTT, then each output folded into a narrow two's-complement word (for the products): bits of
/// weight `>= 2^tight_bits` replaced by their lightest digits modulo `q`.
pub(crate) fn ntt_signed(c: &mut Ckt, m: &Modq, a: Vec<MV>, log_n: usize, fold: u32, tight_bits: u32) -> Vec<SWord> {
    let a = ntt_layers(c, m, a, log_n, fold, log_n);
    let mt = Modq::tight(m.q);
    a.iter()
        .map(|v| {
            let mut l = Lin::new(&mt);
            l.add(v, 1, tight_bits);
            l.finish_signed(c)
        })
        .collect()
}

/// The forward negacyclic NTT (Cooley-Tukey, natural order in, bit-reversed out): `a[i] = f(psi^(2 brv(i) + 1))`.
pub(crate) fn ntt(c: &mut Ckt, m: &Modq, a: Vec<MV>, log_n: usize, fold: u32) -> Vec<MV> {
    ntt_layers(c, m, a, log_n, fold, log_n)
}

/// The first `layers` layers of [`ntt`]. A butterfly is `t = w b`, `y0 = a + t`, `y1 = a - t`; when `a` is wider
/// than `fold` bits it is first folded once (`a mod q` on fewer bits, shared by both sums), so the two sums are
/// plain two-operand additions: a folded bit puts a digit in a low column, and in a two-operand adder an extra
/// low literal costs about a row per column above it.
fn ntt_layers(c: &mut Ckt, m: &Modq, mut a: Vec<MV>, log_n: usize, fold: u32, layers: usize) -> Vec<MV> {
    let n = a.len();
    assert_eq!(n, 1 << log_n);
    let z = zetas(m.q, log_n);
    let mut k = 0;
    let mut len = n / 2;
    for _ in 0..layers {
        for start in (0..n).step_by(2 * len) {
            k += 1;
            for j in start..start + len {
                let (y0, y1) = butterfly(c, m, &a[j], &a[j + len], z[k], fold);
                a[j] = y0;
                a[j + len] = y1;
            }
        }
        len /= 2;
    }
    a
}

/// `a` with its bits of weight `>= 2^fold` folded modulo `q` (unchanged if none).
fn fold_mv(c: &mut Ckt, m: &Modq, a: &MV, fold: u32) -> MV {
    if a.terms.iter().all(|&(_, cf)| cf.is_power_of_two() && cf < 1u64 << fold) {
        return a.clone();
    }
    let mut l = Lin::new(m);
    l.add(a, 1, fold);
    l.finish(c, false)
}

fn butterfly(c: &mut Ckt, m: &Modq, a: &MV, b: &MV, w: u64, fold: u32) -> (MV, MV) {
    let mut l = Lin::new(m);
    l.add(b, w, 0);
    let t = l.finish(c, false);
    let a = fold_mv(c, m, a, fold);
    let mut l = Lin::new(m);
    l.add(&a, 1, 64);
    l.add(&t, 1, 64);
    let y0 = l.finish(c, false);
    let mut l = Lin::new(m);
    l.add(&a, 1, 64);
    l.add(&t, m.q - 1, 64);
    (y0, l.finish(c, false))
}

/// A quotient hint of a pointwise check: `k = (2 x y - 2 z - c0) / q + k0`, read back by the witness generator.
#[derive(Clone, Debug)]
pub struct PointHint {
    pub x: SWord,
    pub y: SWord,
    pub z: Word,
    pub c0: i128,
    pub k0: i128,
    pub first_input: usize,
    pub bits: usize,
}

impl PointHint {
    /// The honest hint value in an evaluation (`None` if the check cannot hold).
    pub fn value(&self, values: &[u8], q: u64) -> Option<u64> {
        let (x, y) = (self.x.read(values), self.y.read(values));
        let z = read_u64(values, &self.z) as i128;
        let d = 2 * x * y - 2 * z - self.c0;
        let q = q as i128;
        (d % q == 0)
            .then(|| (d / q + self.k0) as u64)
            .filter(|&k| k < 1u64 << self.bits)
    }
}

/// Whether `x y = z (mod q)`, for two's-complement words `x`, `y` and a value `z` (word plus constant). The
/// prover gives `k' = k + k0 >= 0` and the circuit checks, as integers,
/// `E = 2 x y - 2 z_word - c0 - (k' - k0) q = 0` (`c0 = 2 z.k`), one compressor holding
/// `2 x y = -x - y - sum_(i,j) w_i v_j (x_i ^ y_j)` (`w`, `v` the two's-complement weights, so the weight sums are
/// `-1`), with every term a negated literal (an xnor where the weight is positive). Returns `E`'s bits, all zero
/// iff the check holds. Sound for every hint: `E = 0` gives `q | 2 (x y - z)`, `q` odd. Complete: the honest
/// `k'` is in `[0, 2^bits)`.
pub(crate) fn point_check(c: &mut Ckt, q: u64, x: &SWord, y: &SWord, z: &MV) -> (Word, PointHint) {
    let q128 = q as i128;
    let (wx, wy) = (x.bits.len(), y.bits.len());
    let zw = z.bits();
    let c0 = 2 * z.k as i128;
    // Range of 2 x y - 2 z_word - c0.
    let prods = [x.lo * y.lo, x.lo * y.hi, x.hi * y.lo, x.hi * y.hi];
    let (pmin, pmax) = (2 * *prods.iter().min().unwrap(), 2 * *prods.iter().max().unwrap());
    let zmax = ((1i128 << zw.len()) - 1).min(z.max as i128);
    let (dmin, dmax) = (pmin - 2 * zmax - c0, pmax - c0);
    let (kmin, kmax) = (dmin.div_euclid(q128), dmax.div_euclid(q128) + 1);
    let k0 = -kmin;
    let bits = bitlen128((kmax - kmin) as u128).max(1);
    let first_input = c.n_inputs();
    let kw = c.inputs(bits);
    let mut acc = Acc::default();
    let weight = |i: usize, w: usize| -> (usize, bool) { (i, i + 1 == w) };
    for i in 0..wx {
        for j in 0..wy {
            let (top_i, top_j) = (weight(i, wx).1, weight(j, wy).1);
            if top_i ^ top_j {
                // + 2^(i+j) xor = - 2^(i+j) xnor + 2^(i+j).
                let t = c
                    .fa(
                        Wire {
                            neg: false,
                            ..x.bits[i]
                        },
                        Wire {
                            neg: false,
                            ..y.bits[j]
                        },
                        Wire::ONE,
                    )
                    .0;
                let t = if x.bits[i].neg ^ y.bits[j].neg { t.not() } else { t };
                acc.lit(t, i + j, true);
                acc.konst += 1i128 << (i + j);
            } else {
                let t = c.xor(x.bits[i], y.bits[j]);
                acc.lit(t, i + j, true);
            }
        }
    }
    // - x - y.
    for (v, w) in [(&x.bits, wx), (&y.bits, wy)] {
        for (i, &b) in v.iter().enumerate() {
            acc.lit(b, i, i + 1 != w);
        }
    }
    // - 2 z_word - c0.
    acc.word(&zw, 1, true);
    acc.konst -= c0;
    // - (k' - k0) q.
    for (b, &w) in kw.iter().enumerate() {
        for e in 0..bitlen(q) {
            if (q >> e) & 1 == 1 {
                acc.lit(w, b + e, true);
            }
        }
    }
    acc.konst += k0 * q128;
    let bound = dmin.abs().max(dmax.abs()) + q128 * ((1i128 << bits) + k0.abs());
    let l = bitlen128(bound as u128) + 1;
    let e = acc.finish(c, l);
    (
        e,
        PointHint {
            x: x.clone(),
            y: y.clone(),
            z: zw,
            c0,
            k0,
            first_input,
            bits,
        },
    )
}

/// The sign-magnitude inputs of a coefficient.
#[derive(Clone, Debug)]
pub(crate) struct SignMag {
    pub sign: Wire,
    pub mag: Word,
}

/// The core relation: every `h_i < q`, every `|s1_i| <= (q - 1) / 2`, and `s1 = c - s2 h` modulo
/// `(x^n + 1, q)`, `c` given as words of any width (any representatives). The quotient hints are taken as free
/// inputs here. Returns the validity bit and the hints.
pub(crate) fn relation(
    c: &mut Ckt,
    m: &Modq,
    log_n: usize,
    fold: u32,
    cpoly: &[Word],
    h: &[Word],
    s2: &[SignMag],
    s1: &[SignMag],
    log: &mut Vec<(&'static str, usize)>,
) -> (Wire, Vec<PointHint>) {
    let q = m.q;
    let mut mark = c.rows();
    let mut lap = |c: &Ckt, name| {
        log.push((name, c.rows() - mark));
        mark = c.rows();
    };
    let n = 1 << log_n;
    assert!(cpoly.len() == n && h.len() == n && s2.len() == n && s1.len() == n);
    let mut ok = Vec::new();
    for hi in h {
        ok.push(geq_const(c, hi, q).not());
    }
    for s in s1 {
        ok.push(geq_const(c, &s.mag, q / 2 + 1).not());
    }
    lap(c, "  h < q and s1 range");
    // d = c - s1, compressed once.
    let d: Vec<MV> = (0..n)
        .map(|i| {
            let mut l = Lin::new(m);
            l.add(&MV::word(&cpoly[i]), 1, fold);
            let ns1 = signed_mv(c, q, s1[i].sign, &s1[i].mag, true);
            l.add(&ns1, 1, fold);
            l.finish(c, false)
        })
        .collect();
    let s2v: Vec<MV> = s2.iter().map(|s| signed_mv(c, q, s.sign, &s.mag, false)).collect();
    let hv: Vec<MV> = h.iter().map(|w| MV::word(w)).collect();
    lap(c, "  s2 and c - s1 as values mod q");
    let tight = bitlen(q) as u32 - 1;
    let fs2 = ntt_signed(c, m, s2v, log_n, fold, tight);
    lap(c, "  NTT(s2)");
    let fh = ntt_signed(c, m, hv, log_n, fold, tight);
    lap(c, "  NTT(h)");
    let fd = ntt(c, m, d, log_n, fold);
    lap(c, "  NTT(c - s1)");
    let mut zero_bits = Vec::new();
    let mut hints = Vec::new();
    for i in 0..n {
        let (e, hint) = point_check(c, q, &fs2[i], &fh[i], &fd[i]);
        zero_bits.extend(e);
        hints.push(hint);
    }
    lap(c, "  pointwise products and quotient checks");
    ok.push(any_lits(c, &zero_bits).not());
    let valid = all_lits(c, &ok);
    lap(c, "  validity");
    (valid, hints)
}

// ---------------------------------------------------------------------------------------------------------------
// HashToPoint: rejection sampling and compaction
// ---------------------------------------------------------------------------------------------------------------

/// Compaction of the accepted samples, in order: `payload[i]` is kept iff `!reject[i]`, the first `n_out` kept
/// ones are returned. `ok` iff at least `n_out` are kept and fewer than `2^stages` are rejected in all (so every
/// prefix count fits the shifter). No hint: the prefix counts are computed, and stage `k` moves an element left by
/// `2^k` iff bit `k` of its count is set. Least significant stage first, two valid elements never meet: for kept
/// `i < i'`, `i' - i > r(i') - r(i) >= (r(i') mod 2^(k+1)) - (r(i) mod 2^(k+1))`.
pub(crate) fn compact(
    c: &mut Ckt,
    payload: &[Word],
    reject: &[Wire],
    n_out: usize,
    stages: usize,
) -> (Vec<Word>, Wire) {
    let n = payload.len();
    assert!(n >= n_out && reject.len() == n);
    let mut pay: Vec<Word> = payload
        .iter()
        .map(|p| p.iter().map(|&w| c.positive(w)).collect())
        .collect();
    let mut valid: Vec<Wire> = reject.iter().map(|&r| c.positive(r.not())).collect();
    // Prefix counts of rejections, on `stages` bits; any carry out is an overflow.
    let mut shift: Vec<Word> = Vec::with_capacity(n);
    let mut r: Word = vec![Wire::ZERO; stages];
    let mut overflow = Vec::new();
    for &rej in reject {
        shift.push(r.clone());
        let mut carry = rej;
        for b in r.iter_mut() {
            let (s, k) = fa_lit(c, *b, carry, Wire::ZERO);
            *b = s;
            carry = k;
        }
        overflow.push(carry);
    }
    let mut lim = n;
    for k in 0..stages {
        let kk = 1usize << k;
        // Positions that may still reach [0, n_out).
        let new_lim = n.min(n_out + (1usize << stages) - (1usize << (k + 1)));
        let src_lim = lim.min(new_lim + kk);
        let m: Vec<Wire> = (0..src_lim).map(|i| c.and(valid[i], shift[i][k])).collect();
        let mut npay = Vec::with_capacity(new_lim);
        let mut nvalid = Vec::with_capacity(new_lim);
        let mut nshift = Vec::with_capacity(new_lim);
        for p in 0..new_lim {
            if p + kk < src_lim {
                let s = m[p + kk];
                npay.push(c.mux_word(s, &pay[p + kk], &pay[p]));
                nshift.push(
                    (0..stages)
                        .map(|b| {
                            if b <= k {
                                Wire::ZERO
                            } else {
                                c.mux(s, shift[p + kk][b], shift[p][b])
                            }
                        })
                        .collect::<Word>(),
                );
                nvalid.push(c.xor3(valid[p], s, m[p]));
            } else {
                npay.push(pay[p].clone());
                nshift.push(shift[p].clone());
                nvalid.push(c.xor(valid[p], m[p]));
            }
        }
        pay = npay;
        valid = nvalid;
        shift = nshift;
        lim = new_lim;
    }
    let all_valid = all_lits(c, &valid[..n_out]);
    let over = any_lits(c, &overflow);
    let ok = c.and(all_valid, over.not());
    pay.truncate(n_out);
    (pay, ok)
}

// ---------------------------------------------------------------------------------------------------------------
// Norm and encoding length
// ---------------------------------------------------------------------------------------------------------------

/// Whether `sum |x|^2 <= bound` over groups of magnitudes: `m^2 = (2^W - 1) m - sum_(i<j) 2^(i+j) (m_i ^ m_j)`,
/// the linear part summed per group first (`(2^W - 1) sum m`).
pub(crate) fn norm_at_most(c: &mut Ckt, groups: &[Vec<Word>], bound: u64) -> Wire {
    let mut acc = Acc::default();
    let mut max: u128 = 0;
    for g in groups {
        if g.is_empty() {
            continue;
        }
        let w = g[0].len();
        let mut lin = Acc::default();
        for m in g {
            assert_eq!(m.len(), w);
            for i in 0..w {
                for j in i + 1..w {
                    let t = c.xor(m[i], m[j]);
                    acc.lit(t, i + j, true);
                }
            }
            lin.word(m, 0, false);
        }
        let smax = g.len() as u128 * ((1u128 << w) - 1);
        let s = lin.finish(c, bitlen128(smax));
        acc.word(&s, w, false);
        acc.word(&s, 0, true);
        max += g.len() as u128 * ((1u128 << w) - 1).pow(2);
    }
    if bound as u128 >= max {
        return Wire::ONE;
    }
    // The sum is exactly the norm, in [0, max].
    let l = bitlen128(max);
    acc.konst += (1i128 << l) - bound as i128 - 1;
    let u = acc.finish(c, l + 1);
    u[l].not()
}

/// Whether `sum_i (9 + floor(|s_i| / 128)) <= bits`: the compressed signature fits.
pub(crate) fn encoding_fits(c: &mut Ckt, mags: &[Word], bits: u64) -> Wire {
    let base = 9 * mags.len() as u64;
    if bits < base {
        return Wire::ZERO;
    }
    let mut acc = Acc::default();
    for m in mags {
        for (i, &w) in m.iter().enumerate().skip(7) {
            acc.lit(w, i - 7, false);
        }
    }
    acc.at_most(c, (bits - base) as u128)
}

// ---------------------------------------------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------------------------------------------

/// What witness generation needs beyond the circuit.
#[derive(Clone, Debug, Default)]
pub struct Handles {
    pub zero: Vec<PointHint>,
    /// Rows used by each component, in build order.
    pub rows: Vec<(&'static str, usize)>,
}

/// The NIST public-key bytes as literals: header `log n`, then `h` on `h_bits` bits a coefficient, MSB first.
fn pk_bits(p: &Params, h: &[Word]) -> Vec<Wire> {
    let hb = p.h_bits();
    let nbytes = p.pk_len();
    let mut bits = vec![Wire::ZERO; nbytes * 8];
    for j in 0..8 {
        bits[j] = Wire::constant((p.log_n >> j) & 1 == 1);
    }
    for (i, hi) in h.iter().enumerate() {
        for (j, &w) in hi.iter().enumerate() {
            let s = hb * i + (hb - 1 - j);
            let (byte, bit) = (1 + s / 8, 7 - s % 8);
            bits[8 * byte + bit] = w;
        }
    }
    bits
}

/// The Falcon verification circuit; returns the public bits and the handles.
pub fn build_falcon(c: &mut Ckt, p: &Params) -> (Vec<Wire>, Handles) {
    let n = p.n();
    let mut hd = Handles::default();
    let mut mark = c.rows();
    let mut lap = |c: &Ckt, hd: &mut Handles, name| {
        hd.rows.push((name, c.rows() - mark));
        mark = c.rows();
    };
    let h: Vec<Word> = (0..n).map(|_| c.inputs(p.h_bits())).collect();
    let msg = c.inputs(8 * p.msg_len);
    let nonce = c.inputs(8 * NONCE_LEN);
    let s2: Vec<SignMag> = (0..n)
        .map(|_| SignMag {
            sign: c.input(),
            mag: c.inputs(p.s2_bits),
        })
        .collect();
    let s1: Vec<SignMag> = (0..n)
        .map(|_| SignMag {
            sign: c.input(),
            mag: c.inputs(p.s1_bits()),
        })
        .collect();
    lap(c, &mut hd, "inputs");

    let mut digest_in = pk_bits(p, &h);
    digest_in.extend_from_slice(&msg);
    let digest = shake256(c, &digest_in, 32);
    lap(c, &mut hd, "statement digest SHAKE256(pk || m)");

    let mut input = nonce.clone();
    input.extend_from_slice(&msg);
    let out = shake256(c, &input, p.squeeze_blocks * RATE);
    lap(c, &mut hd, "HashToPoint SHAKE256");
    let samples: Vec<Word> = (0..p.squeeze_blocks * RATE / 2)
        .map(|i| {
            (0..16)
                .map(|j| {
                    if j < 8 {
                        out[(2 * i + 1) * 8 + j]
                    } else {
                        out[2 * i * 8 + j - 8]
                    }
                })
                .collect()
        })
        .collect();
    let kq = (1u64 << 16) / p.q * p.q;
    let samples: Vec<Word> = samples
        .iter()
        .map(|s| s.iter().map(|&w| c.positive(w)).collect())
        .collect();
    let reject: Vec<Wire> = samples.iter().map(|s| geq_const(c, s, kq)).collect();
    lap(c, &mut hd, "HashToPoint sample tests");
    let (cpoly, h2p_ok) = compact(c, &samples, &reject, n, p.shift_stages);
    lap(c, &mut hd, "HashToPoint compaction");

    let m = Modq::new(p.q);
    let mut log = Vec::new();
    let (rel_ok, hints) = relation(c, &m, p.log_n, p.fold, &cpoly, &h, &s2, &s1, &mut log);
    hd.zero = hints;
    lap(c, &mut hd, "s1 = c - s2 h mod (x^n + 1, q):");
    hd.rows.extend(log);

    let groups = vec![
        s1.iter().map(|s| s.mag.clone()).collect::<Vec<_>>(),
        s2.iter().map(|s| s.mag.clone()).collect::<Vec<_>>(),
    ];
    let norm_ok = norm_at_most(c, &groups, p.norm_bound);
    lap(c, &mut hd, "norm");
    let len_ok = match p.max_comp_bits {
        Some(b) => encoding_fits(c, &groups[1], b),
        None => Wire::ONE,
    };
    let valid = all_lits(c, &[h2p_ok, rel_ok, norm_ok, len_ok]);
    lap(c, &mut hd, "encoding length and validity");

    let mut public = digest;
    public.push(valid);
    public.resize(PUBLIC_BITS, Wire::ZERO);
    (public, hd)
}

/// Falcon-512 verification over a 32-byte message.
pub struct Falcon512;

impl Workload for Falcon512 {
    const NAME: &'static str = "falcon512";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        build_falcon(c, &Params::falcon512()).0
    }

    fn instance(seed: u64) -> Instance {
        let vs = fixtures();
        let v = &vs[seed as usize % vs.len()];
        instance_for(&Params::falcon512(), &v.h, &v.msg, &v.nonce, &v.s2, None)
    }

    /// A signature with one coefficient of `s2` changed (and the honest `s1` for it).
    fn invalid_instance(seed: u64) -> Option<Instance> {
        let vs = fixtures();
        let v = &vs[seed as usize % vs.len()];
        let mut s2 = v.s2.clone();
        let i = (seed as usize * 37) % s2.len();
        s2[i] += 1;
        Some(instance_for(&Params::falcon512(), &v.h, &v.msg, &v.nonce, &s2, None))
    }
}

/// A built circuit, cached per parameters.
pub struct Built {
    pub circuit: crate::Circuit,
    pub srcs: Vec<crate::Src>,
    pub handles: Handles,
    pub used: usize,
    pub n_inputs: usize,
}

pub fn built(p: &Params) -> Arc<Built> {
    static CACHE: OnceLock<Mutex<HashMap<Params, Arc<Built>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(b) = cache.lock().unwrap().get(p) {
        return b.clone();
    }
    let mut c = Ckt::new();
    let (public, handles) = build_falcon(&mut c, p);
    let used = c.rows();
    let n_inputs = c.n_inputs();
    let (circuit, srcs) = c.finish(&public);
    let b = Arc::new(Built {
        circuit,
        srcs,
        handles,
        used,
        n_inputs,
    });
    cache.lock().unwrap().insert(p.clone(), b.clone());
    b
}

/// Free inputs before the quotient hints: `h, m, r, s2, s1`.
pub fn base_inputs(p: &Params, h: &[u64], msg: &[u8], nonce: &[u8], s2: &[i64], s1: &[i64]) -> Vec<bool> {
    let mut v = Vec::new();
    for &x in h {
        v.extend((0..p.h_bits()).map(|j| (x >> j) & 1 == 1));
    }
    for &b in msg.iter().chain(nonce) {
        v.extend((0..8).map(|j| (b >> j) & 1 == 1));
    }
    for (&x, bits) in s2
        .iter()
        .map(|x| (x, p.s2_bits))
        .chain(s1.iter().map(|x| (x, p.s1_bits())))
    {
        let mag = x.unsigned_abs();
        v.push(x < 0);
        v.extend((0..bits).map(|j| (mag >> j) & 1 == 1));
    }
    v
}

/// The witness generator for the quotient hints: evaluate the circuit (the hints do not affect what they divide)
/// and set each hint to its honest value (0 if there is none).
pub fn fill_hints(p: &Params, inputs: &mut Vec<bool>) {
    let b = built(p);
    inputs.resize(b.n_inputs, false);
    let values = b.circuit.values(inputs);
    for z in &b.handles.zero {
        let k = z.value(&values, p.q).unwrap_or(0);
        for j in 0..z.bits {
            inputs[z.first_input + j] = (k >> j) & 1 == 1;
        }
    }
}

/// An instance: inputs (the quotient hints found by evaluating the circuit, the witness generator) and the
/// statement from the reference (`sha3`'s SHAKE256 and [`native::verify`]). `s1` defaults to the honest one.
pub fn instance_for(p: &Params, h: &[u64], msg: &[u8], nonce: &[u8], s2: &[i64], s1: Option<&[i64]>) -> Instance {
    let honest;
    let s1 = match s1 {
        Some(s) => s,
        None => {
            honest = native::s1(p, h, msg, nonce, s2);
            &honest
        }
    };
    // A coefficient out of the input range is replaced by 0: the statement is about inputs that exist.
    let clamp = |x: i64, bits: usize| if x.unsigned_abs() < 1 << bits { x } else { 0 };
    let s2c: Vec<i64> = s2.iter().map(|&x| clamp(x, p.s2_bits)).collect();
    let s1c: Vec<i64> = s1.iter().map(|&x| clamp(x, p.s1_bits())).collect();
    let mut inputs = base_inputs(p, h, msg, nonce, &s2c, &s1c);
    fill_hints(p, &mut inputs);
    let mut statement = [0u8; 64];
    let mut pk_m = native::pk_bytes(p, h);
    pk_m.extend_from_slice(msg);
    statement[..32].copy_from_slice(&native::shake256(&pk_m, 32));
    let valid = s2c.as_slice() == s2 && native::verify(p, h, msg, nonce, s2);
    statement[32] = valid as u8;
    Instance { inputs, statement }
}

// ---------------------------------------------------------------------------------------------------------------
// Reference implementation and fixtures
// ---------------------------------------------------------------------------------------------------------------

/// A signature fixture (from `tprest/falcon.py`, decoded).
#[derive(Clone, Debug)]
pub struct Vector {
    pub h: Vec<u64>,
    pub msg: Vec<u8>,
    pub nonce: Vec<u8>,
    pub s2: Vec<i64>,
    pub s1: Vec<i64>,
    pub c: Vec<u64>,
    pub norm: u64,
    pub sig: Vec<u8>,
}

pub fn fixtures() -> &'static [Vector] {
    static V: OnceLock<Vec<Vector>> = OnceLock::new();
    V.get_or_init(|| {
        let j: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/falcon/falcon512_vectors.json")).unwrap();
        let ints =
            |v: &serde_json::Value| -> Vec<i64> { v.as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect() };
        j.as_array()
            .unwrap()
            .iter()
            .map(|e| Vector {
                h: ints(&e["h"]).iter().map(|&x| x as u64).collect(),
                msg: native::unhex(e["msg"].as_str().unwrap()),
                nonce: native::unhex(e["nonce"].as_str().unwrap()),
                s2: ints(&e["s2"]),
                s1: ints(&e["s1"]),
                c: ints(&e["c"]).iter().map(|&x| x as u64).collect(),
                norm: e["norm"].as_u64().unwrap(),
                sig: native::unhex(e["sig"].as_str().unwrap()),
            })
            .collect()
    })
}

pub mod native {
    //! Falcon verification, natively: schoolbook negacyclic product, `sha3`'s SHAKE256.
    use super::Params;
    use sha3::Shake256;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    pub fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    pub fn shake256(data: &[u8], n: usize) -> Vec<u8> {
        let mut h = Shake256::default();
        h.update(data);
        let mut r = h.finalize_xof();
        let mut out = vec![0u8; n];
        r.read(&mut out);
        out
    }

    /// HashToPoint, unbounded: the coefficients and the 16-bit samples read.
    pub fn hash_to_point(nonce: &[u8], msg: &[u8], n: usize, q: u64) -> (Vec<u64>, usize) {
        let kq = (1u64 << 16) / q * q;
        let mut h = Shake256::default();
        h.update(nonce);
        h.update(msg);
        let mut r = h.finalize_xof();
        let (mut out, mut used) = (Vec::with_capacity(n), 0);
        while out.len() < n {
            let mut two = [0u8; 2];
            r.read(&mut two);
            used += 1;
            let t = (two[0] as u64) << 8 | two[1] as u64;
            if t < kq {
                out.push(t % q);
            }
        }
        (out, used)
    }

    /// `a b mod (x^n + 1, q)`, in `[0, q)`.
    pub fn mul_negacyclic(a: &[i64], b: &[i64], q: i64) -> Vec<i64> {
        let n = a.len();
        let mut r = vec![0i128; n];
        for i in 0..n {
            for j in 0..n {
                let p = a[i] as i128 * b[j] as i128;
                if i + j < n {
                    r[i + j] += p;
                } else {
                    r[i + j - n] -= p;
                }
            }
        }
        r.iter().map(|&x| x.rem_euclid(q as i128) as i64).collect()
    }

    /// Falcon's centring, `(x + q/2) mod q - q/2`, in `[-(q-1)/2, (q-1)/2]`.
    pub fn center(x: i64, q: i64) -> i64 {
        (x + (q >> 1)).rem_euclid(q) - (q >> 1)
    }

    pub fn s1(p: &Params, h: &[u64], msg: &[u8], nonce: &[u8], s2: &[i64]) -> Vec<i64> {
        let q = p.q as i64;
        let (c, _) = hash_to_point(nonce, msg, p.n(), p.q);
        let hs: Vec<i64> = h.iter().map(|&x| x as i64).collect();
        let s2h = mul_negacyclic(s2, &hs, q);
        (0..p.n()).map(|i| center(c[i] as i64 - s2h[i], q)).collect()
    }

    /// Falcon verification of a decoded signature (`|s2_i| < 2^s2_bits`, the encoding budget, the norm).
    pub fn verify(p: &Params, h: &[u64], msg: &[u8], nonce: &[u8], s2: &[i64]) -> bool {
        let n = p.n();
        if h.len() != n || s2.len() != n || h.iter().any(|&x| x >= p.q) {
            return false;
        }
        if s2.iter().any(|&x| x.unsigned_abs() >= 1 << p.s2_bits) {
            return false;
        }
        if let Some(b) = p.max_comp_bits {
            let bits: u64 = s2.iter().map(|&x| 9 + (x.unsigned_abs() >> 7)).sum();
            if bits > b {
                return false;
            }
        }
        let s1 = s1(p, h, msg, nonce, s2);
        let norm: i64 = s1.iter().chain(s2).map(|&x| x * x).sum();
        norm as u64 <= p.norm_bound
    }

    /// The NIST public-key encoding.
    pub fn pk_bytes(p: &Params, h: &[u64]) -> Vec<u8> {
        let hb = p.h_bits();
        let mut out = vec![0u8; p.pk_len()];
        out[0] = p.log_n as u8;
        for (i, &x) in h.iter().enumerate() {
            for j in 0..hb {
                if (x >> j) & 1 == 1 {
                    let s = hb * i + (hb - 1 - j);
                    out[1 + s / 8] |= 1 << (7 - s % 8);
                }
            }
        }
        out
    }

    /// Decode a NIST public key (`None` if malformed or a coefficient is `>= q`).
    pub fn decode_pk(p: &Params, b: &[u8]) -> Option<Vec<u64>> {
        if b.len() != p.pk_len() || b[0] as usize != p.log_n {
            return None;
        }
        let hb = p.h_bits();
        let h: Vec<u64> = (0..p.n())
            .map(|i| {
                (0..hb).fold(0u64, |acc, k| {
                    let s = hb * i + k;
                    acc << 1 | ((b[1 + s / 8] >> (7 - s % 8)) & 1) as u64
                })
            })
            .collect();
        h.iter().all(|&x| x < p.q).then_some(h)
    }

    /// The round-3 reference `comp_decode` (`codec.c`): `None` if invalid.
    pub fn comp_decode(buf: &[u8], n: usize) -> Option<Vec<i64>> {
        let (mut acc, mut acc_len, mut v) = (0u32, 0u32, 0usize);
        let mut x = Vec::with_capacity(n);
        for _ in 0..n {
            if v >= buf.len() {
                return None;
            }
            acc = (acc << 8) | buf[v] as u32;
            v += 1;
            let b = acc >> acc_len;
            let s = b & 128;
            let mut m = b & 127;
            loop {
                if acc_len == 0 {
                    if v >= buf.len() {
                        return None;
                    }
                    acc = (acc << 8) | buf[v] as u32;
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;
                if (acc >> acc_len) & 1 != 0 {
                    break;
                }
                m += 128;
                if m > 2047 {
                    return None;
                }
            }
            if s != 0 && m == 0 {
                return None;
            }
            x.push(if s != 0 { -(m as i64) } else { m as i64 });
        }
        if acc & ((1u32 << acc_len) - 1) != 0 {
            return None;
        }
        Some(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PUBLIC_BITS, Row, Src, build, read_statement};

    #[test]
    fn carry_conversion_and_negation_share_the_same_row() {
        for carry_first in [false, true] {
            let mut c = Ckt::new();
            let x = c.input();
            let (carry, negated) = if carry_first {
                let carry = as_carry(&mut c, x);
                (carry, c.positive(x.not()))
            } else {
                let negated = c.positive(x.not());
                (as_carry(&mut c, x), negated)
            };
            let mut public = vec![carry, negated];
            public.resize(PUBLIC_BITS, Wire::ZERO);
            let (circuit, srcs) = c.finish(&public);
            circuit.check_wired().unwrap();
            for bit in [false, true] {
                let statement = read_statement(&circuit.values(&[bit]), &srcs);
                assert_eq!(statement[0] & 3, if bit { 1 } else { 2 });
            }
        }
    }

    /// A circuit evaluated 64 assignments at a time (bit-sliced), reading any wire.
    struct Sliced {
        rows: Vec<Row>,
        inputs: Vec<u32>,
        used: usize,
    }

    impl Sliced {
        fn new(c: Ckt) -> Sliced {
            let used = c.rows();
            let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
            let rows = circuit.rows()[..used].to_vec();
            let inputs = (0..used as u32)
                .filter(|&r| {
                    let row = rows[r as usize];
                    [row.x, row.y, row.c] == [Src::Row(r), Src::Zero, Src::Zero]
                })
                .collect();
            Sliced { rows, inputs, used }
        }

        /// `lanes[i]`: input `i` across the 64 assignments.
        fn eval(&self, lanes: &[u64], v: &mut Vec<(u64, u64)>) {
            assert_eq!(lanes.len(), self.inputs.len());
            v.clear();
            v.resize(self.used, (0, 0));
            for (&r, &l) in self.inputs.iter().zip(lanes) {
                v[r as usize] = (l, 0);
            }
            let mut next_input = 0;
            for r in crate::PUBLIC_ROWS..self.used {
                if next_input < self.inputs.len() && self.inputs[next_input] as usize == r {
                    next_input += 1;
                    continue;
                }
                let row = self.rows[r];
                let bit = |s: Src, v: &Vec<(u64, u64)>| match s {
                    Src::Zero => 0,
                    Src::One => !0,
                    Src::Row(i) => v[i as usize].0,
                };
                let carry = |s: Src, v: &Vec<(u64, u64)>| match s {
                    Src::Row(i) => v[i as usize].1,
                    _ => 0,
                };
                let (x, y, z) = (bit(row.x, v), bit(row.y, v), carry(row.c, v));
                v[r] = (x ^ y ^ z, (x & y) | (z & (x ^ y)));
            }
        }

        fn wire(v: &[(u64, u64)], w: Wire) -> u64 {
            let x = match w.kind {
                Kind::Const(b) => {
                    if b {
                        !0
                    } else {
                        0
                    }
                }
                Kind::Sum(r) => v[r as usize].0,
                Kind::Carry(r) => v[r as usize].1,
            };
            if w.neg { !x } else { x }
        }

        fn word(v: &[(u64, u64)], w: &[Wire], lane: usize) -> u64 {
            w.iter()
                .enumerate()
                .map(|(i, &b)| ((Self::wire(v, b) >> lane) & 1) << i)
                .sum()
        }
    }

    /// The lanes of the inputs for assignments `64 b .. 64 b + 63` of `n` input bits (assignment `a`: input `i`
    /// is bit `i` of `a`).
    fn lanes(n: usize, b: u64) -> Vec<u64> {
        const P: [u64; 6] = [
            0xAAAA_AAAA_AAAA_AAAA,
            0xCCCC_CCCC_CCCC_CCCC,
            0xF0F0_F0F0_F0F0_F0F0,
            0xFF00_FF00_FF00_FF00,
            0xFFFF_0000_FFFF_0000,
            0xFFFF_FFFF_0000_0000,
        ];
        (0..n)
            .map(|i| {
                if i < 6 {
                    P[i]
                } else if (b >> (i - 6)) & 1 == 1 {
                    !0
                } else {
                    0
                }
            })
            .collect()
    }

    /// Run `f(assignment, values, lane)` over all `2^n` assignments (`n >= 6`), in parallel.
    fn exhaustive(s: &Sliced, n: usize, f: impl Fn(u64, &[(u64, u64)], usize) + Sync) {
        assert!(n >= 6);
        let batches = 1u64 << (n - 6);
        let threads = 32u64.min(batches);
        std::thread::scope(|sc| {
            for t in 0..threads {
                let f = &f;
                sc.spawn(move || {
                    let mut v = Vec::new();
                    let mut b = t;
                    while b < batches {
                        s.eval(&lanes(n, b), &mut v);
                        for l in 0..64 {
                            f(b * 64 + l as u64, &v, l);
                        }
                        b += threads;
                    }
                });
            }
        });
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    // ------------------------------------------------------------------ native NTT, used against the gadget

    fn ntt_native(a: &[u64], q: u64, log_n: usize) -> Vec<u64> {
        let mut a = a.to_vec();
        let n = a.len();
        let z = zetas(q, log_n);
        let (mut k, mut len) = (0, n / 2);
        while len >= 1 {
            for start in (0..n).step_by(2 * len) {
                k += 1;
                for j in start..start + len {
                    let t = z[k] * a[j + len] % q;
                    a[j + len] = (a[j] + q - t) % q;
                    a[j] = (a[j] + t) % q;
                }
            }
            len /= 2;
        }
        a
    }

    // ------------------------------------------------------------------ gadgets against native arithmetic

    /// A random literal holding the value of input `x`: the input, a carry holding it, a negated positive wire of
    /// its complement, or an or with zero (a carry); possibly negated (then it holds `!x`).
    fn random_literal(c: &mut Ckt, rng: &mut Rng, x: Wire) -> (Wire, bool) {
        let w = match rng.below(4) {
            0 => x,
            1 => c.and(x, x),
            2 => c.positive(x.not()).not(),
            _ => c.or(x, Wire::ZERO),
        };
        if rng.below(2) == 1 { (w.not(), true) } else { (w, false) }
    }

    #[test]
    fn compress_and_acc_match_native() {
        let mut rng = Rng(5);
        for trial in 0..300 {
            let n_in = 8 + rng.below(40) as usize;
            let mut c = Ckt::new();
            let ins = c.inputs(n_in);
            let mut acc = Acc::default();
            // (input index or constant, weight exponent, negative, flip)
            let mut terms = Vec::new();
            for _ in 0..(5 + rng.below(80)) {
                let e = rng.below(14) as usize;
                let negative = rng.below(3) == 0;
                if rng.below(10) == 0 {
                    let b = rng.below(2) == 1;
                    acc.lit(Wire::constant(b), e, negative);
                    terms.push((None, e, negative, b));
                } else {
                    let i = rng.below(n_in as u64) as usize;
                    let (l, flip) = random_literal(&mut c, &mut rng, ins[i]);
                    acc.lit(l, e, negative);
                    terms.push((Some(i), e, negative, flip));
                }
            }
            let width = 1 + rng.below(20) as usize;
            let out = acc.finish(&mut c, width);
            let s = Sliced::new(c);
            let lanes_in: Vec<u64> = (0..n_in).map(|_| rng.next()).collect();
            let mut v = Vec::new();
            s.eval(&lanes_in, &mut v);
            for lane in 0..64 {
                let mut sum: i128 = 0;
                for &(i, e, negative, flag) in &terms {
                    let bit = match i {
                        None => flag as i128,
                        Some(i) => (((lanes_in[i] >> lane) & 1) as i128) ^ flag as i128,
                    };
                    sum += if negative { -(bit << e) } else { bit << e };
                }
                let expect = sum.rem_euclid(1 << width) as u64;
                assert_eq!(Sliced::word(&v, &out, lane), expect, "trial {trial} lane {lane}");
            }
        }
    }

    #[test]
    fn geq_and_or_chains_exhaustive() {
        let mut rng = Rng(11);
        for k in 0..=256u64 {
            let mut c = Ckt::new();
            let ins = c.inputs(8);
            let negs: Vec<bool> = (0..8).map(|_| rng.below(2) == 1).collect();
            // A negated literal of a positive wire holding the input's complement holds the input; so these
            // literals hold `input ^ neg`.
            let lits: Vec<Wire> = ins
                .iter()
                .zip(&negs)
                .map(|(&w, &n)| if n { c.positive(w.not()) } else { w })
                .collect();
            let ge = geq_const(&mut c, &lits, k);
            let any = any_lits(&mut c, &lits);
            let all = all_lits(&mut c, &lits);
            let s = Sliced::new(c);
            exhaustive(&s, 8, |a, v, l| {
                let x = (0..8).map(|i| (((a >> i) & 1) ^ negs[i] as u64) << i).sum::<u64>();
                assert_eq!((Sliced::wire(v, ge) >> l) & 1 == 1, x >= k, "k {k} x {x}");
                assert_eq!((Sliced::wire(v, any) >> l) & 1 == 1, x != 0);
                assert_eq!((Sliced::wire(v, all) >> l) & 1 == 1, x == 255);
            });
        }
        // Mixed kinds and polarities in the chains.
        for trial in 0..50 {
            let mut c = Ckt::new();
            let ins = c.inputs(7);
            let mut r2 = Rng(trial + 100);
            let lits: Vec<Wire> = ins.iter().map(|&w| random_literal(&mut c, &mut r2, w).0).collect();
            let any = any_lits(&mut c, &lits);
            let all = all_lits(&mut c, &lits);
            let s = Sliced::new(c);
            let mut v = Vec::new();
            for b in 0..2 {
                s.eval(&lanes(7, b), &mut v);
                for l in 0..64 {
                    let bits: Vec<bool> = lits.iter().map(|&w| (Sliced::wire(&v, w) >> l) & 1 == 1).collect();
                    assert_eq!((Sliced::wire(&v, any) >> l) & 1 == 1, bits.iter().any(|&x| x));
                    assert_eq!((Sliced::wire(&v, all) >> l) & 1 == 1, bits.iter().all(|&x| x));
                }
            }
        }
    }

    #[test]
    fn lin_mod_q_and_signed_words() {
        for q in [12289u64, 17, 97, 5] {
            let m = Modq::new(q);
            let mut rng = Rng(q);
            for trial in 0..60 {
                let mut c = Ckt::new();
                let nw = 1 + rng.below(3) as usize;
                let mut mvs = Vec::new();
                for _ in 0..nw {
                    let w = 1 + rng.below(18) as usize;
                    let ins = c.inputs(w);
                    let lits: Vec<Wire> = ins.iter().map(|&x| random_literal(&mut c, &mut rng, x).0).collect();
                    let mut mv = MV::word(&lits);
                    mv.k = rng.below(q);
                    mvs.push(mv);
                }
                let coefs: Vec<u64> = (0..nw).map(|_| rng.below(q)).collect();
                let fold = rng.below(20) as u32;
                let mut l = Lin::new(&m);
                let mut l2 = Lin::new(&m);
                for (mv, &cf) in mvs.iter().zip(&coefs) {
                    l.add(mv, cf, fold);
                    l2.add(mv, cf, fold);
                }
                let absorb = trial % 2 == 0;
                let out = l.finish(&mut c, absorb);
                let sw = l2.finish_signed(&mut c);
                let n_in = c.n_inputs();
                let s = Sliced::new(c);
                let lanes_in: Vec<u64> = (0..n_in).map(|_| rng.next()).collect();
                let mut v = Vec::new();
                s.eval(&lanes_in, &mut v);
                for lane in 0..64 {
                    let mut expect = 0u128;
                    for (mv, &cf) in mvs.iter().zip(&coefs) {
                        let x: u128 = mv
                            .terms
                            .iter()
                            .map(|&(w, c2)| ((Sliced::wire(&v, w) >> lane) & 1) as u128 * c2 as u128)
                            .sum::<u128>()
                            + mv.k as u128;
                        expect = (expect + x % q as u128 * cf as u128) % q as u128;
                    }
                    let word = Sliced::word(&v, &out.bits(), lane);
                    assert_eq!(
                        (word as u128 + out.k as u128) % q as u128,
                        expect,
                        "q {q} trial {trial}"
                    );
                    assert!(word <= out.max);
                    let w = sw.bits.len();
                    let u = Sliced::word(&v, &sw.bits, lane) as i128;
                    let sv = if (u >> (w - 1)) & 1 == 1 { u - (1 << w) } else { u };
                    assert!(sw.lo <= sv && sv <= sw.hi && sw.lo >= -(1 << (w - 1)) && sw.hi < 1 << (w - 1));
                    assert_eq!(sv.rem_euclid(q as i128) as u128, expect, "signed q {q} trial {trial}");
                }
            }
        }
    }

    #[test]
    fn ntt_gadget_matches_native() {
        for (q, log_n, w) in [(12289u64, 9usize, 14usize), (17, 3, 5), (97, 4, 7), (5, 1, 3)] {
            let m = Modq::new(q);
            let n = 1 << log_n;
            for fold in [bitlen(q) as u32, bitlen(q) as u32 + 2, 64] {
                let mut c = Ckt::new();
                let ins: Vec<Word> = (0..n).map(|_| c.inputs(w)).collect();
                let out = ntt(&mut c, &m, ins.iter().map(|x| MV::word(x)).collect(), log_n, fold);
                let outs = ntt_signed(
                    &mut c,
                    &m,
                    ins.iter().map(|x| MV::word(x)).collect(),
                    log_n,
                    fold,
                    bitlen(q) as u32 - 1,
                );
                let s = Sliced::new(c);
                let mut rng = Rng(q + fold as u64);
                let lanes_in: Vec<u64> = (0..n * w).map(|_| rng.next()).collect();
                let mut v = Vec::new();
                s.eval(&lanes_in, &mut v);
                for lane in [0usize, 17, 63] {
                    let a: Vec<u64> = (0..n)
                        .map(|i| (0..w).map(|j| ((lanes_in[i * w + j] >> lane) & 1) << j).sum::<u64>() % q)
                        .collect();
                    let expect = ntt_native(&a, q, log_n);
                    for i in 0..n {
                        let got = (Sliced::word(&v, &out[i].bits(), lane) + out[i].k) % q;
                        assert_eq!(got, expect[i], "q {q} fold {fold} i {i}");
                        let ww = outs[i].bits.len();
                        let u = Sliced::word(&v, &outs[i].bits, lane) as i128;
                        let sv = if (u >> (ww - 1)) & 1 == 1 { u - (1 << ww) } else { u };
                        assert_eq!(sv.rem_euclid(q as i128) as u64, expect[i]);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ exhaustive soundness at small parameters

    /// The pointwise check alone, every input and every hint: `x, y` from 3-bit words (as two's-complement words
    /// congruent to them), `z` a 4-bit word plus a constant; `q = 17` and `q = 5`.
    #[test]
    fn point_check_exhaustive() {
        for q in [17u64, 5] {
            let m = Modq::new(q);
            for kz in [0u64, 3] {
                let mut c = Ckt::new();
                let xi = c.inputs(3);
                let yi = c.inputs(3);
                let zi = c.inputs(4);
                let mut lx = Lin::new(&m);
                lx.add(&MV::word(&xi), 1, 64);
                let x = lx.finish_signed(&mut c);
                let mut ly = Lin::new(&m);
                ly.add(&MV::word(&yi), 1, 64);
                let y = ly.finish_signed(&mut c);
                let z = MV { k: kz, ..MV::word(&zi) };
                let (e, hint) = point_check(&mut c, q, &x, &y, &z);
                let ok = any_lits(&mut c, &e).not();
                let n = c.n_inputs();
                assert_eq!(n, 10 + hint.bits);
                let s = Sliced::new(c);
                let found: Vec<std::sync::atomic::AtomicBool> = (0..1024).map(|_| Default::default()).collect();
                exhaustive(&s, n.max(6), |a, v, l| {
                    if a >> n != 0 {
                        return;
                    }
                    let (xv, yv, zv) = (a & 7, (a >> 3) & 7, (a >> 6) & 15);
                    let holds = (xv * yv) % q == (zv + kz) % q;
                    if (Sliced::wire(v, ok) >> l) & 1 == 1 {
                        assert!(holds, "q {q}: accepted x {xv} y {yv} z {zv} k {}", a >> 10);
                        found[(a & 1023) as usize].store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
                for a in 0..1024u64 {
                    let (xv, yv, zv) = (a & 7, (a >> 3) & 7, (a >> 6) & 15);
                    let f = found[a as usize].load(std::sync::atomic::Ordering::Relaxed);
                    assert_eq!(f, (xv * yv) % q == (zv + kz) % q, "completeness q {q} a {a}");
                }
                println!("point check q {q}: {} hint bits, all 2^{n} assignments", hint.bits);
            }
        }
    }

    struct SmallRel {
        q: u64,
        log_n: usize,
        cb: usize,
        hb: usize,
        s2b: usize,
        s1b: usize,
    }

    impl SmallRel {
        fn n(&self) -> usize {
            1 << self.log_n
        }
        fn base_bits(&self) -> usize {
            self.n() * (self.cb + self.hb + 1 + self.s2b + 1 + self.s1b)
        }
        /// The relation's circuit (the generator's own [`relation`]), its validity bit and hints.
        fn build(&self, fold: u32) -> (Sliced, Wire, Vec<PointHint>) {
            let m = Modq::new(self.q);
            let n = self.n();
            let mut c = Ckt::new();
            let cw: Vec<Word> = (0..n).map(|_| c.inputs(self.cb)).collect();
            let h: Vec<Word> = (0..n).map(|_| c.inputs(self.hb)).collect();
            let s2: Vec<SignMag> = (0..n)
                .map(|_| SignMag {
                    sign: c.input(),
                    mag: c.inputs(self.s2b),
                })
                .collect();
            let s1: Vec<SignMag> = (0..n)
                .map(|_| SignMag {
                    sign: c.input(),
                    mag: c.inputs(self.s1b),
                })
                .collect();
            let (valid, hints) = relation(&mut c, &m, self.log_n, fold, &cw, &h, &s2, &s1, &mut Vec::new());
            (Sliced::new(c), valid, hints)
        }
        /// Decode the base inputs: c, h, s2, s1.
        fn decode(&self, a: u64) -> (Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
            let n = self.n();
            let mut pos = 0;
            let mut take = |w: usize| {
                let v = (a >> pos) & ((1 << w) - 1);
                pos += w;
                v as i64
            };
            let c: Vec<i64> = (0..n).map(|_| take(self.cb)).collect();
            let h: Vec<i64> = (0..n).map(|_| take(self.hb)).collect();
            let mut sm = |w: usize| -> Vec<i64> {
                (0..n)
                    .map(|_| {
                        let s = take(1);
                        let m = take(w);
                        if s == 1 { -m } else { m }
                    })
                    .collect()
            };
            let s2 = sm(self.s2b);
            let s1 = sm(self.s1b);
            (c, h, s2, s1)
        }
        /// Falcon's relation natively: `h < q`, `s1` centred and `s1 = c - s2 h`.
        fn holds(&self, c: &[i64], h: &[i64], s2: &[i64], s1: &[i64]) -> bool {
            let q = self.q as i64;
            if h.iter().any(|&x| x >= q) {
                return false;
            }
            let s2h = native::mul_negacyclic(s2, h, q);
            (0..self.n()).all(|i| s1[i] == native::center(c[i] - s2h[i], q))
        }
    }

    /// The whole relation of the generator (`h < q`, the `s1` hint centred, three NTTs, the products with their
    /// quotient hints), q = 5, x^2 + 1: all 2^22 inputs and all 2^10 hint values. Soundness: valid implies the
    /// relation; completeness: every input satisfying it has a hint making it valid.
    #[test]
    fn relation_exhaustive_q5() {
        let r = SmallRel {
            q: 5,
            log_n: 1,
            cb: 3,
            hb: 3,
            s2b: 1,
            s1b: 2,
        };
        for fold in [3u32, 64] {
            let (s, valid, hints) = r.build(fold);
            let base = r.base_bits();
            let hint_bits: usize = hints.iter().map(|h| h.bits).sum();
            let n = base + hint_bits;
            let found: Vec<std::sync::atomic::AtomicU64> =
                (0..(1usize << base) / 64).map(|_| Default::default()).collect();
            let accepted = std::sync::atomic::AtomicU64::new(0);
            exhaustive(&s, n, |a, v, l| {
                if (Sliced::wire(v, valid) >> l) & 1 == 1 {
                    let b = a & ((1 << base) - 1);
                    let (c, h, s2, s1) = r.decode(b);
                    assert!(
                        r.holds(&c, &h, &s2, &s1),
                        "unsound: c {c:?} h {h:?} s2 {s2:?} s1 {s1:?} hints {}",
                        a >> base
                    );
                    found[(b / 64) as usize].fetch_or(1 << (b % 64), std::sync::atomic::Ordering::Relaxed);
                    accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
            let mut complete = 0;
            for b in 0..1u64 << base {
                let (c, h, s2, s1) = r.decode(b);
                let f = (found[(b / 64) as usize].load(std::sync::atomic::Ordering::Relaxed) >> (b % 64)) & 1 == 1;
                assert_eq!(
                    f,
                    r.holds(&c, &h, &s2, &s1),
                    "completeness: c {c:?} h {h:?} s2 {s2:?} s1 {s1:?}"
                );
                complete += f as usize;
            }
            println!(
                "relation q 5, x^2 + 1, fold {fold}: {} rows, {base} input + {hint_bits} hint bits, all 2^{n} assignments: \
                 {} accepting, {complete} true statements, each with an accepting hint",
                s.used,
                accepted.into_inner()
            );
        }
    }

    /// The relation at q = 17, x^4 + 1 (two NTT layers): random inputs, every `s1` (2^20), with the honest
    /// quotient hints (found by evaluating, as the witness generator does) and with random wrong ones.
    #[test]
    fn relation_q17_every_s1() {
        let r = SmallRel {
            q: 17,
            log_n: 2,
            cb: 3,
            hb: 5,
            s2b: 1,
            s1b: 4,
        };
        assert!(r.base_bits() < 64);
        let (s, valid, hints) = r.build(6);
        let base = r.base_bits();
        let s1_bits = r.n() * (1 + r.s1b);
        let s1_off = base - s1_bits;
        let n_in = base + hints.iter().map(|h| h.bits).sum::<usize>();
        let mut rng = Rng(1717);
        let total_true = std::sync::atomic::AtomicUsize::new(0);
        for _ in 0..6 {
            let mut fixed = rng.next() & ((1 << s1_off) - 1);
            for i in 0..r.n() {
                let off = r.n() * r.cb + i * r.hb;
                let x = ((fixed >> off) & ((1 << r.hb) - 1)) % 17;
                fixed = (fixed & !(((1 << r.hb) - 1) << off)) | (x << off);
            }
            let (c, h, s2, _) = r.decode(fixed);
            let seed = rng.next();
            std::thread::scope(|sc| {
                for t in 0..16u64 {
                    let (s, r, c, h, s2, hints, total_true) = (&s, &r, &c, &h, &s2, &hints, &total_true);
                    sc.spawn(move || {
                        let mut rng = Rng(seed ^ ((t + 1) * 0x9E37_79B9));
                        let mut v = Vec::new();
                        let mut batch = t;
                        while batch < 1 << (s1_bits - 6) {
                            // Lane l: s1 = 64 batch + l.
                            let mut lanes_in: Vec<u64> = vec![0; n_in];
                            for (i, li) in lanes_in.iter_mut().enumerate().take(s1_off) {
                                *li = if (fixed >> i) & 1 == 1 { !0 } else { 0 };
                            }
                            for j in 0..s1_bits {
                                lanes_in[s1_off + j] = if j < 6 {
                                    lanes(6, 0)[j]
                                } else if ((batch >> (j - 6)) & 1) == 1 {
                                    !0
                                } else {
                                    0
                                };
                            }
                            // Random hints first: nothing false may be accepted.
                            for li in lanes_in.iter_mut().skip(base) {
                                *li = rng.next();
                            }
                            s.eval(&lanes_in, &mut v);
                            let wrong = Sliced::wire(&v, valid);
                            // Honest hints, lane by lane.
                            for li in lanes_in.iter_mut().skip(base) {
                                *li = 0;
                            }
                            s.eval(&lanes_in, &mut v);
                            for l in 0..64 {
                                let vals: Vec<u8> = (0..s.used)
                                    .map(|rw| (((v[rw].0 >> l) & 1) | (((v[rw].1 >> l) & 1) << 1)) as u8)
                                    .collect();
                                for hnt in hints.iter() {
                                    if let Some(k) = hnt.value(&vals, 17) {
                                        for j in 0..hnt.bits {
                                            lanes_in[hnt.first_input + j] |= ((k >> j) & 1) << l;
                                        }
                                    }
                                }
                            }
                            s.eval(&lanes_in, &mut v);
                            let honest = Sliced::wire(&v, valid);
                            for l in 0..64 {
                                let (_, _, _, s1) = r.decode(fixed | ((batch * 64 + l as u64) << s1_off));
                                let holds = r.holds(c, h, s2, &s1);
                                assert_eq!((honest >> l) & 1 == 1, holds, "honest hints, s1 {s1:?}");
                                if !holds {
                                    assert_eq!((wrong >> l) & 1, 0, "a random hint accepted a false s1 {s1:?}");
                                }
                                total_true.fetch_add(holds as usize, std::sync::atomic::Ordering::Relaxed);
                            }
                            batch += 16;
                        }
                    });
                }
            });
        }
        let t = total_true.into_inner();
        println!("relation q 17, x^4 + 1: 6 random (c, h, s2) x 2^{s1_bits} s1 hints: {t} accepted, all true");
        assert!(t > 0);
    }

    /// The compaction, every input: 6 samples of 3 bits, accepted iff `< 5`, 3 outputs, 2 or 1 stages; payload
    /// literals of random polarity.
    #[test]
    fn compaction_exhaustive() {
        let mut rng = Rng(66);
        for stages in [2usize, 1] {
            for _ in 0..3 {
                let mut c = Ckt::new();
                let ins: Vec<Word> = (0..6).map(|_| c.inputs(3)).collect();
                // Literals holding the inputs: some negated wires (of positive wires holding the complement).
                let lits: Vec<Word> = ins
                    .iter()
                    .map(|w| {
                        w.iter()
                            .map(|&x| {
                                if rng.below(2) == 1 {
                                    c.positive(x.not()).not()
                                } else {
                                    x
                                }
                            })
                            .collect()
                    })
                    .collect();
                let reject: Vec<Wire> = lits.iter().map(|w| geq_const(&mut c, w, 5)).collect();
                let (out, ok) = compact(&mut c, &lits, &reject, 3, stages);
                let s = Sliced::new(c);
                exhaustive(&s, 18, |a, v, l| {
                    let xs: Vec<u64> = (0..6).map(|i| (a >> (3 * i)) & 7).collect();
                    let acc: Vec<u64> = xs.iter().copied().filter(|&x| x < 5).collect();
                    let rejects = 6 - acc.len();
                    let expect_ok = acc.len() >= 3 && rejects < 1 << stages;
                    let got_ok = (Sliced::wire(v, ok) >> l) & 1 == 1;
                    assert_eq!(got_ok, expect_ok, "stages {stages} xs {xs:?}");
                    if got_ok {
                        for j in 0..3 {
                            assert_eq!(Sliced::word(v, &out[j], l), acc[j], "xs {xs:?}");
                        }
                    }
                });
            }
        }
    }

    #[test]
    fn norm_and_encoding_exhaustive() {
        // Two groups: 2 magnitudes of 3 bits, 2 of 2 bits; every input, every bound.
        let mut c = Ckt::new();
        let g1: Vec<Word> = (0..2).map(|_| c.inputs(3)).collect();
        let g2: Vec<Word> = (0..2).map(|_| c.inputs(2)).collect();
        let max = 2 * 49 + 2 * 9;
        let checks: Vec<Wire> = (0..=max + 1)
            .map(|b| norm_at_most(&mut c, &[g1.clone(), g2.clone()], b as u64))
            .collect();
        let s = Sliced::new(c);
        exhaustive(&s, 10, |a, v, l| {
            let m: Vec<u64> = vec![a & 7, (a >> 3) & 7, (a >> 6) & 3, (a >> 8) & 3];
            let norm: u64 = m.iter().map(|x| x * x).sum();
            for (b, &w) in checks.iter().enumerate() {
                assert_eq!(
                    (Sliced::wire(v, w) >> l) & 1 == 1,
                    norm <= b as u64,
                    "m {m:?} bound {b}"
                );
            }
        });
        // Encoding budget: 2 magnitudes of 10 bits (high parts 0..7).
        let mut c = Ckt::new();
        let mags: Vec<Word> = (0..2).map(|_| c.inputs(10)).collect();
        let budgets: Vec<u64> = (0..40).collect();
        let checks: Vec<Wire> = budgets.iter().map(|&b| encoding_fits(&mut c, &mags, b)).collect();
        let s = Sliced::new(c);
        exhaustive(&s, 20, |a, v, l| {
            let bits: u64 = [a & 1023, a >> 10].iter().map(|m| 9 + (m >> 7)).sum();
            for (&b, &w) in budgets.iter().zip(&checks) {
                assert_eq!((Sliced::wire(v, w) >> l) & 1 == 1, bits <= b);
            }
        });
    }

    #[test]
    fn keccak_matches_sha3() {
        let mut rng = Rng(99);
        for len in [0usize, 1, 72, 135, 136, 137, 300, 929] {
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            for out_len in [32usize, 136, 200, 9 * 136] {
                let mut c = Ckt::new();
                let ins = c.inputs(8 * len);
                let out = shake256(&mut c, &ins, out_len);
                let s = Sliced::new(c);
                let lanes_in: Vec<u64> = data
                    .iter()
                    .flat_map(|&b| (0..8).map(move |j| if (b >> j) & 1 == 1 { !0 } else { 0 }))
                    .collect();
                let mut v = Vec::new();
                s.eval(&lanes_in, &mut v);
                let got: Vec<u8> = (0..out_len)
                    .map(|i| Sliced::word(&v, &out[8 * i..8 * i + 8], 0) as u8)
                    .collect();
                assert_eq!(got, native::shake256(&data, out_len), "len {len} out {out_len}");
            }
        }
    }

    // ------------------------------------------------------------------ the reference and the fixtures

    /// A known answer of the round-3 submission (`falcon512-KAT.rsp`, counts 0..9 kept): public key, message,
    /// nonce and the encoded signature (header byte then compressed `s2`).
    fn kat(count: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let text = include_str!("../testdata/falcon/falcon512-KAT-0-9.rsp");
        let block = text
            .split("count = ")
            .find(|b| b.starts_with(&format!("{count}\n")))
            .unwrap();
        let field = |name: &str| {
            native::unhex(
                block
                    .lines()
                    .find(|l| l.starts_with(&format!("{name} = ")))
                    .unwrap()
                    .split(" = ")
                    .nth(1)
                    .unwrap(),
            )
        };
        let (pk, sm) = (field("pk"), field("sm"));
        let mlen = field("msg").len();
        // sm = sig_len (2 bytes) || nonce || msg || 0x29 || compressed s2.
        let sig_len = (sm[0] as usize) << 8 | sm[1] as usize;
        let nonce = sm[2..42].to_vec();
        let msg = sm[42..42 + mlen].to_vec();
        let esig = sm[42 + mlen..].to_vec();
        assert_eq!(esig.len(), sig_len);
        assert_eq!(msg, field("msg"));
        (pk, msg, nonce, esig)
    }

    #[test]
    fn native_verifier_on_fixtures_and_kat() {
        let p = Params::falcon512();
        for v in fixtures() {
            assert!(native::verify(&p, &v.h, &v.msg, &v.nonce, &v.s2));
            let (c, used) = native::hash_to_point(&v.nonce, &v.msg, 512, p.q);
            assert_eq!(c, v.c, "HashToPoint agrees with falcon.py");
            assert!(used <= 612);
            assert_eq!(
                native::s1(&p, &v.h, &v.msg, &v.nonce, &v.s2),
                v.s1,
                "s1 agrees with falcon.py"
            );
            let norm: i64 = v.s1.iter().chain(&v.s2).map(|x| x * x).sum();
            assert_eq!(norm as u64, v.norm);
            // falcon.py's signature: header 0x39, nonce, 625 bytes of compressed s2 padded with zeros.
            assert_eq!(v.sig[0], 0x39);
            assert_eq!(&v.sig[1..41], &v.nonce[..]);
            let enc = &v.sig[41..];
            let used_len = enc.iter().rposition(|&b| b != 0).unwrap() + 1;
            assert_eq!(native::comp_decode(&enc[..used_len], 512).unwrap(), v.s2);
            let bits: u64 = v.s2.iter().map(|&x| 9 + (x.unsigned_abs() >> 7)).sum();
            assert!(bits <= 5000);
            let pk = native::pk_bytes(&p, &v.h);
            assert_eq!(native::decode_pk(&p, &pk).unwrap(), v.h);
            // Tampering.
            let mut s2 = v.s2.clone();
            s2[3] += 1;
            assert!(!native::verify(&p, &v.h, &v.msg, &v.nonce, &s2));
            let mut msg = v.msg.clone();
            msg[0] ^= 1;
            assert!(!native::verify(&p, &v.h, &msg, &v.nonce, &v.s2));
            let mut nonce = v.nonce.clone();
            nonce[5] ^= 0x80;
            assert!(!native::verify(&p, &v.h, &v.msg, &nonce, &v.s2));
            let tight = Params {
                norm_bound: v.norm - 1,
                ..p.clone()
            };
            assert!(!native::verify(&tight, &v.h, &v.msg, &v.nonce, &v.s2));
        }
        // The official round-3 known answers, counts 0..9 (messages of 33 (count + 1) bytes).
        for count in 0..10 {
            let (pk, msg, nonce, esig) = kat(count);
            let p = Params {
                msg_len: msg.len(),
                ..Params::falcon512()
            };
            let h = native::decode_pk(&p, &pk).unwrap();
            assert_eq!(esig[0], 0x29);
            let s2 = native::comp_decode(&esig[1..], 512).unwrap();
            assert!(native::verify(&p, &h, &msg, &nonce, &s2), "KAT {count}");
            let mut bad = s2.clone();
            bad[0] -= 1;
            assert!(!native::verify(&p, &h, &msg, &nonce, &bad));
        }
    }

    // ------------------------------------------------------------------ the workload

    fn eval_statement(p: &Params, inputs: &[bool]) -> [u8; 64] {
        let b = built(p);
        let v = b.circuit.values(inputs);
        read_statement(&v, &b.srcs)
    }

    #[test]
    fn falcon512_valid_and_invalid() {
        let (circuit, _, used) = build::<Falcon512>();
        assert!(used + 1024 <= 1 << 22, "fits 2^22 rows");
        assert_eq!(circuit.log_rows, 22);
        circuit.check_wired().unwrap();
        let p = Params::falcon512();
        for seed in 0..fixtures().len() as u64 {
            let inst = Falcon512::instance(seed);
            assert_eq!(inst.statement[32], 1);
            assert_eq!(eval_statement(&p, &inst.inputs), inst.statement, "seed {seed}");
            let bad = Falcon512::invalid_instance(seed).unwrap();
            assert_eq!(bad.statement[32], 0);
            assert_eq!(bad.statement[..32], inst.statement[..32]);
            assert_eq!(eval_statement(&p, &bad.inputs), bad.statement, "invalid seed {seed}");
        }
    }

    #[test]
    fn falcon512_negatives() {
        let p = Params::falcon512();
        let v = &fixtures()[1];
        let honest = instance_for(&p, &v.h, &v.msg, &v.nonce, &v.s2, None);
        assert_eq!(eval_statement(&p, &honest.inputs), honest.statement);
        let check = |inputs: &[bool], what: &str| {
            let st = eval_statement(&p, inputs);
            assert_eq!(st[32], 0, "{what} must be rejected");
            assert_eq!(st[..32], honest.statement[..32], "{what}: same public key and message");
        };
        // Wrong message / nonce: the reference says invalid, and the circuit agrees.
        let mut msg = v.msg.clone();
        msg[7] ^= 4;
        let i = instance_for(&p, &v.h, &msg, &v.nonce, &v.s2, None);
        assert_eq!(i.statement[32], 0);
        assert_eq!(eval_statement(&p, &i.inputs), i.statement);
        let mut nonce = v.nonce.clone();
        nonce[39] ^= 1;
        let i = instance_for(&p, &v.h, &v.msg, &nonce, &v.s2, None);
        assert_eq!(i.statement[32], 0);
        assert_eq!(eval_statement(&p, &i.inputs), i.statement);
        // Tampered s2 coefficient, the honest s1 and hints for it.
        let mut s2 = v.s2.clone();
        s2[100] -= 3;
        let i = instance_for(&p, &v.h, &v.msg, &v.nonce, &s2, None);
        assert_eq!(i.statement[32], 0);
        check(&i.inputs, "tampered s2");
        // Malicious s1 hints: off by one, and magnitudes above q/2 (a congruent one, outside the centred range,
        // does not fit 13 bits for these small coefficients; the exhaustive q = 5 test covers that case).
        for (idx, val) in [
            (0usize, v.s1[0] + 1),
            (77, v.s1[77] - 1),
            (300, 6145),
            (5, -8191),
            (6, 6144 - v.s1[6].signum()),
        ] {
            let mut s1 = v.s1.clone();
            s1[idx] = val;
            if s1 == v.s1 {
                continue;
            }
            let i = instance_for(&p, &v.h, &v.msg, &v.nonce, &v.s2, Some(&s1));
            check(&i.inputs, "wrong s1 hint");
        }
        // Malicious quotient hints: one bit flipped.
        let b = built(&p);
        for z in [0usize, 200, 511] {
            let hint = &b.handles.zero[z];
            for j in [0, hint.bits / 2, hint.bits - 1] {
                let mut inputs = honest.inputs.clone();
                inputs[hint.first_input + j] ^= true;
                check(&inputs, "wrong quotient hint");
            }
        }
        // A key coefficient >= q (h_i + q, still 14 bits): the key does not decode.
        let j = v.h.iter().position(|&x| x + p.q < 1 << 14).unwrap();
        let mut inputs = honest.inputs.clone();
        for k in 0..14 {
            inputs[j * 14 + k] = ((v.h[j] + p.q) >> k) & 1 == 1;
        }
        let st = eval_statement(&p, &inputs);
        assert_eq!(st[32], 0, "h >= q rejected");
        // An s1 coefficient 0 given as negative zero is the same integer: accepted (with its own quotient hints;
        // the old ones are wrong for it).
        let z = v.s1.iter().position(|&x| x == 0).unwrap();
        let at = p.n() * p.h_bits() + 8 * (p.msg_len + NONCE_LEN) + p.n() * (1 + p.s2_bits) + z * (1 + p.s1_bits());
        let mut inputs = honest.inputs.clone();
        inputs[at] = true;
        let st = eval_statement(&p, &inputs);
        fill_hints(&p, &mut inputs);
        assert_eq!(eval_statement(&p, &inputs), honest.statement);
        let _ = st;
    }

    /// The norm bound at the boundary: the generator with the bound set to a signature's norm accepts it, with
    /// the bound one below rejects it.
    #[test]
    fn falcon512_norm_boundary() {
        let v = &fixtures()[0];
        for (bound, ok) in [(v.norm, 1u8), (v.norm - 1, 0)] {
            let p = Params {
                norm_bound: bound,
                ..Params::falcon512()
            };
            let i = instance_for(&p, &v.h, &v.msg, &v.nonce, &v.s2, None);
            assert_eq!(i.statement[32], ok);
            assert_eq!(eval_statement(&p, &i.inputs), i.statement);
        }
    }

    /// The official KAT count 0 (a 33-byte message) through the generator built for 33-byte messages.
    #[test]
    fn falcon512_kat_through_circuit() {
        let (pk, msg, nonce, esig) = kat(0);
        let p = Params {
            msg_len: msg.len(),
            ..Params::falcon512()
        };
        let h = native::decode_pk(&p, &pk).unwrap();
        let s2 = native::comp_decode(&esig[1..], 512).unwrap();
        let i = instance_for(&p, &h, &msg, &nonce, &s2, None);
        assert_eq!(i.statement[32], 1);
        let mut pk_m = pk.clone();
        pk_m.extend_from_slice(&msg);
        assert_eq!(i.statement[..32], native::shake256(&pk_m, 32)[..]);
        assert_eq!(eval_statement(&p, &i.inputs), i.statement);
    }

    #[test]
    fn report_rows() {
        let (rows, inputs) = crate::count::<Falcon512>();
        let mut c = Ckt::new();
        let (_, hd) = build_falcon(&mut c, &Params::falcon512());
        println!(
            "falcon512: {rows} rows ({:.4} x 2^22, padded to 2^22), {inputs} free inputs",
            rows as f64 / (1u64 << 22) as f64
        );
        for (name, r) in &hd.rows {
            println!("  {name:<60} {r:>9}");
        }
        let mut c = Ckt::new();
        let st: Vec<Word> = (0..25).map(|_| c.inputs(64)).collect();
        let r0 = c.rows();
        keccak_f(&mut c, st, &[true; 25], None);
        println!("one Keccak-f[1600]: {} rows", c.rows() - r0);
    }

    #[test]
    fn native_ntt_is_the_negacyclic_product() {
        for (q, log_n) in [(12289u64, 9usize), (17, 2), (5, 1), (97, 4)] {
            let n = 1 << log_n;
            let mut rng = Rng(q * 7 + 1);
            let a: Vec<u64> = (0..n).map(|_| rng.below(q)).collect();
            let b: Vec<u64> = (0..n).map(|_| rng.below(q)).collect();
            let (fa, fb) = (ntt_native(&a, q, log_n), ntt_native(&b, q, log_n));
            let prod = native::mul_negacyclic(
                &a.iter().map(|&x| x as i64).collect::<Vec<_>>(),
                &b.iter().map(|&x| x as i64).collect::<Vec<_>>(),
                q as i64,
            );
            let fp = ntt_native(&prod.iter().map(|&x| x as u64).collect::<Vec<_>>(), q, log_n);
            for i in 0..n {
                assert_eq!(fa[i] * fb[i] % q, fp[i], "q {q} n {n}");
            }
        }
    }
}
