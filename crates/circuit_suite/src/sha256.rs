//! SHA-256 (FIPS 180-4) as rows of full adders, and the workload [`Sha256OneKiB`].
//!
//! # The gadget
//!
//! [`sha256`] hashes a message whose length is fixed when the circuit is built; its bits come in statement order
//! (byte `i`, bit `j` at `8 i + j`, low bit first) and so do the 256 digest bits it returns. The padding and the
//! length are constants, and every constant folds: a block that is all padding costs no message-schedule rows
//! (26,470 rows), and the first block's rounds fold while the state is still the constant IV (35,525 rows for a
//! one-block message). [`add_many`] is the column compressor behind every sum.
//!
//! # Rows per round
//!
//! Words are 32 wires, low bit first. Per round and per bit, with the state's words all variable:
//!
//! | rows/bit | what |
//! |---:|---|
//! | 1 | `Maj(a, b, c)`: one row's carry, with the carry copy of `b` or `c` in the `c` slot |
//! | 2 | `Ch(e, f, g) = maj(g, e ^ g, f)`: a row for `e ^ g`, then the majority's carry, `f`'s carry copy in the `c` slot |
//! | 2 | carry copies: of `a` (half its bits, see [`A_COLOUR`]), of `e`, and of the message word's bits its `σ`s read |
//! | 2 | `Σ0(a)` and `Σ1(e)`: a three-way XOR each, one row, a carry copy in the `c` slot |
//! | 3 | `T1 = h + Σ1 + Ch + W + K`: four variable words, by column compression |
//! | 1 | `e' = d + T1` |
//! | 2 | `a' = T1 + Σ0 + Maj` |
//!
//! that is 13 rows a bit, 416 a round, plus the constant `K_t` (below). The message schedule costs, per new word,
//! `σ0` and `σ1` (32 rows each) and a four-word compression (96 rows); the carry copies its XORs read are made by
//! the rounds' conversion rows at no extra cost. With the feed-forward (8 two-word sums), a compression with a
//! variable chaining value and block takes 36,140 rows (see the `rows_per_compression` test).
//!
//! # Why this is about the floor of the format
//!
//! Each row has one `c` slot, which must hold a carry, and two `x`/`y` slots, which must hold bits; a conversion
//! between the kinds is a row. A three-way XOR of three bits needs one of them as a carry, and the nonlinear
//! `Maj` and `Ch` come out as carries that the sums want as bits: a column compression of `n` words has as many
//! rows in a column as carries arriving from the column below, so a carry among the summands is one too many.
//! The row `fa(x, x, z)` converts both ways at once: its bit is `z` and its carry is `x` ([`Twins`]). So the round
//! pays exactly the 64 conversions `Maj` and `Ch` force (less the low two columns, whose spare `c` slots take them
//! as carries), and every carry copy the XORs and majorities read rides along: half of `a`'s bits (a 2-colouring
//! in which every `Σ0` triple has both colours, so that each `Σ0` row and each `Maj` finds a copy, alternating
//! colours round by round), all of `e`'s, and a minimum hitting set (13 bits) of each message word's `σ0`/`σ1`
//! triples. Then every slot of the 13 rows a bit is used except the `c` slot of `e ^ g`: in the sums every row is
//! a full adder (a column of `v` bits takes `(v - 1) / 2` rows, each full adder removing one bit), `Σ` needs a row
//! per output bit since a row has one XOR output, `Maj` and `Ch` are not XORs so need a carry each, and `Ch` is not
//! a threshold function of `e, f, g` (it is not unate in `e`), so it needs a row before its majority (the
//! majority forms of `Ch` over XORs of its inputs, found exhaustively, all need one XOR with the fresh `e`).
//!
//! The constant costs about one row a column from its lowest set bit at position two or more (the low two
//! columns of a four-word compression have spare slots) up to the top: the compression of four words is exactly
//! tight (seven bits a column, three full adders), so a fifth summand needs a fourth row in every column above
//! it. Every summand of `T1` is fresh in its round, so the constant has to be a fifth summand somewhere, and
//! `T1`, which feeds both new words, is the one place where it is added once. On average this is 28 rows a round,
//! 5% of a compression.
//!
//! Carry-save forms do not help: `T1` feeds two sums, so resolving it once (3 rows a bit) beats feeding its two
//! carry-save words into both (2 + 2 + 3).
//!
//! # The workload
//!
//! [`Sha256OneKiB`]: a private 1,024-byte message; the statement is its SHA-256 digest in bytes 0..32 and zeros
//! in bytes 32..64. Inputs: the 8,192 message bits, byte `i` bit `j` (low first) as input `8 i + j`.

use std::collections::HashMap;

use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload};

pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Copies of wires in the other kind: a carry with the value of a bit, or a bit with the value of a carry.
///
/// A row `fa(x, x, z)` with `x` a bit and `z` a carry makes both at once: its bit is `z` and its carry is `x`. So a
/// carry whose bit will be wanted is registered with [`Twins::want_bit`], and the next conversion of a bit to a
/// carry ([`Twins::carry`]) takes it along in the same row. Each conversion is made once.
#[derive(Default)]
pub struct Twins {
    carry: HashMap<Wire, Wire>,
    bit: HashMap<Wire, Wire>,
    pending: Vec<Wire>,
    /// Conversion rows made, and how many of them converted a carry too.
    pub conversions: usize,
    pub paired: usize,
}

impl Twins {
    pub fn new() -> Self {
        Self::default()
    }

    /// A wire with `w`'s value that fits a `c` slot (negated if `w` is: free in an XOR), if one exists already.
    pub fn carry_known(&self, w: Wire) -> Option<Wire> {
        if w.as_const().is_some() || w.is_carry() {
            return Some(w);
        }
        let (p, neg) = strip(w);
        self.carry.get(&p).map(|&k| if neg { k.not() } else { k })
    }

    /// A wire with `w`'s value that fits a `c` slot, made by a conversion row if none exists; the row also makes
    /// the bit of a carry waiting for one.
    pub fn carry(&mut self, c: &mut Ckt, w: Wire) -> Wire {
        if let Some(k) = self.carry_known(w) {
            return k;
        }
        let (p, neg) = strip(w);
        let mut z = Wire::ZERO;
        while let Some(q) = self.pending.pop() {
            if !self.bit.contains_key(&q) {
                z = q;
                break;
            }
        }
        let (b, k) = c.fa(p, p, z);
        self.conversions += 1;
        self.carry.insert(p, k);
        self.bit.insert(k, p);
        if z != Wire::ZERO {
            self.paired += 1;
            self.bit.insert(z, b);
            self.carry.insert(b, z);
        }
        if neg { k.not() } else { k }
    }

    /// A bit with the value of the carry `z`, if one exists.
    pub fn bit_known(&self, z: Wire) -> Option<Wire> {
        if !z.is_carry() {
            return Some(z);
        }
        let (p, neg) = strip(z);
        self.bit.get(&p).map(|&b| if neg { b.not() } else { b })
    }

    /// Register the carry `z` as wanting a bit copy, to be made by the next conversion row.
    pub fn want_bit(&mut self, z: Wire) {
        if fits_c(z) && !self.bit.contains_key(&z) {
            self.pending.push(z);
        }
    }

    /// Forget the carries still waiting (their consumers have converted them otherwise).
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }
}

/// `w` without its negation, and whether it had one.
fn strip(w: Wire) -> (Wire, bool) {
    if w.is_negated() { (w.not(), true) } else { (w, false) }
}

/// A carry-kind wire that fills a `c` slot as is.
fn fits_c(w: Wire) -> bool {
    w.is_carry() && !w.is_negated()
}

/// A wire that fills an `x` or `y` slot as is.
fn fits_xy(w: Wire) -> bool {
    !w.is_carry() && !w.is_negated()
}

/// Take from `pool` the first wire `f` accepts.
fn take(pool: &mut Vec<Wire>, f: impl Fn(Wire) -> bool) -> Option<Wire> {
    pool.iter().position(|&w| f(w)).map(|i| pool.swap_remove(i))
}

/// Choose the operands of one compression row from a column: a carry for the `c` slot (one with no bit copy
/// first), bits for the others (a carry's bit copy if it has one), a pending constant one where a slot would
/// otherwise need a conversion. Only a column with more carries than rows, or three bits and nothing else, needs a
/// conversion.
fn pick(c: &mut Ckt, pool: &mut Vec<Wire>, one: &mut bool, tw: &mut Twins) -> [Wire; 3] {
    if pool.len() + *one as usize == 2 {
        // A half adder: a carry and a bit fill the `c` and `x` slots, else two bits the `x` and `y` slots.
        let z = take(pool, fits_c).unwrap_or(Wire::ZERO);
        let x = take(pool, |_| true).unwrap();
        let y = if z == Wire::ZERO {
            take(pool, |_| true).unwrap()
        } else {
            Wire::ZERO
        };
        let x = if x.is_carry() { tw.bit_known(x).unwrap_or(x) } else { x };
        return [x, y, z];
    }
    let z = if let Some(z) = take(pool, |w| fits_c(w) && tw.bit_known(w).is_none()) {
        z
    } else if let Some(z) = take(pool, fits_c) {
        z
    } else if *one {
        *one = false;
        Wire::ONE
    } else if let Some(w) = take(pool, |w| tw.carry_known(w).is_some_and(fits_c)) {
        tw.carry_known(w).unwrap()
    } else {
        let w = take(pool, fits_xy).unwrap_or_else(|| pool.pop().unwrap());
        tw.carry(c, w)
    };
    let mut xy = [Wire::ZERO; 2];
    for slot in &mut xy {
        *slot = if let Some(w) = take(pool, fits_xy) {
            w
        } else if let Some(w) = take(pool, |w| tw.bit_known(w).is_some_and(fits_xy)) {
            tw.bit_known(w).unwrap()
        } else if *one {
            *one = false;
            Wire::ONE
        } else {
            pool.pop().unwrap()
        };
    }
    [xy[0], xy[1], z]
}

/// The sum of the words `ops` and the constant `konst`, modulo `2^width`, by column compression: each column is
/// reduced to one bit by full adders (three bits in, a bit out and a carry to the next column), with half adders
/// only where a column's count is even, and constants folded. A column of `v` variable bits costs `(v - 1) / 2`
/// rows (rounded up), which no adder circuit beats: each full adder removes exactly one bit. Operands shorter than
/// `width` are zero-extended. Carries go in `c` slots and bits in `x`/`y` slots, so conversions only happen when
/// a column holds more carries than rows; `tw` supplies copies of the other kind.
pub fn add_many(c: &mut Ckt, tw: &mut Twins, ops: &[&[Wire]], konst: u128, width: usize) -> Word {
    let mut ones = vec![0u32; width + 1];
    for (j, n) in ones.iter_mut().enumerate().take(width.min(128)) {
        *n = ((konst >> j) & 1) as u32;
    }
    let mut cols: Vec<Vec<Wire>> = vec![Vec::new(); width];
    for op in ops {
        for (j, &w) in op.iter().enumerate().take(width) {
            match w.as_const() {
                Some(b) => ones[j] += b as u32,
                None => cols[j].push(w),
            }
        }
    }
    let mut out = Vec::with_capacity(width);
    let mut carries: Vec<Wire> = Vec::new();
    for j in 0..width {
        let top = j + 1 == width;
        let mut pool = std::mem::take(&mut cols[j]);
        pool.append(&mut carries);
        ones[j + 1] += ones[j] / 2;
        let mut one = ones[j] % 2 == 1;
        loop {
            match (pool.len(), one) {
                (0, _) => {
                    out.push(Wire::constant(one));
                    break;
                }
                (1, false) => {
                    out.push(pool[0]);
                    break;
                }
                // x + 1: the bit is not x, the carry is x; no row.
                (1, true) => {
                    out.push(pool[0].not());
                    if !top {
                        carries.push(pool[0]);
                    }
                    break;
                }
                _ => {}
            }
            let [x, y, z] = pick(c, &mut pool, &mut one, tw);
            if top {
                pool.push(c.xor3(x, y, z));
            } else {
                let (s, k) = c.fa(x, y, z);
                pool.push(s);
                match k.as_const() {
                    Some(b) => ones[j + 1] += b as u32,
                    None => carries.push(k),
                }
            }
        }
    }
    out
}

/// The majority of three wires, one row: the operand with a carry copy rides in the `c` slot (`pref` is
/// converted if none has one).
fn maj_tw(c: &mut Ckt, tw: &mut Twins, x: Wire, y: Wire, pref: Wire) -> Wire {
    let ops = [pref, y, x];
    if let Some(i) = ops
        .iter()
        .position(|&w| tw.carry_known(w).is_some_and(|k| fits_c(k) || k.as_const().is_some()))
    {
        let k = tw.carry_known(ops[i]).unwrap();
        let rest: Vec<Wire> = (0..3).filter(|&r| r != i).map(|r| ops[r]).collect();
        return c.maj(rest[0], rest[1], k);
    }
    let k = tw.carry(c, pref);
    c.maj(x, y, k)
}

/// `x ^ y ^ z`, one row, with a carry copy of an operand in the `c` slot.
fn xor3_tw(c: &mut Ckt, tw: &mut Twins, x: Wire, y: Wire, z: Wire) -> Wire {
    let ops = [z, y, x];
    if let Some(i) = ops.iter().position(|&w| tw.carry_known(w).is_some()) {
        let k = tw.carry_known(ops[i]).unwrap();
        let rest: Vec<Wire> = (0..3).filter(|&r| r != i).map(|r| ops[r]).collect();
        return c.xor3(rest[0], rest[1], k);
    }
    // Two bits and a zero need no carry.
    if [x, y, z].iter().any(|w| w.as_const().is_some()) {
        return c.xor3(x, y, z);
    }
    let k = tw.carry(c, z);
    c.xor3(x, y, k)
}

fn rotr(x: &[Wire], n: usize, j: usize) -> Wire {
    x[(j + n) % 32]
}

fn shr(x: &[Wire], n: usize, j: usize) -> Wire {
    if j + n < 32 { x[j + n] } else { Wire::ZERO }
}

pub fn big_sigma0(c: &mut Ckt, tw: &mut Twins, x: &[Wire]) -> Word {
    (0..32)
        .map(|j| xor3_tw(c, tw, rotr(x, 2, j), rotr(x, 13, j), rotr(x, 22, j)))
        .collect()
}

pub fn big_sigma1(c: &mut Ckt, tw: &mut Twins, x: &[Wire]) -> Word {
    (0..32)
        .map(|j| xor3_tw(c, tw, rotr(x, 6, j), rotr(x, 11, j), rotr(x, 25, j)))
        .collect()
}

pub fn small_sigma0(c: &mut Ckt, tw: &mut Twins, x: &[Wire]) -> Word {
    (0..32)
        .map(|j| xor3_tw(c, tw, rotr(x, 7, j), rotr(x, 18, j), shr(x, 3, j)))
        .collect()
}

pub fn small_sigma1(c: &mut Ckt, tw: &mut Twins, x: &[Wire]) -> Word {
    (0..32)
        .map(|j| xor3_tw(c, tw, rotr(x, 17, j), rotr(x, 19, j), shr(x, 10, j)))
        .collect()
}

/// A 2-colouring of the bits of a word in which every `Σ0` triple `{j + 2, j + 13, j + 22}` has both colours:
/// with carry copies of one colour of `a` each round, alternating, every `Σ0` row finds a carry copy, and so does
/// every `Maj` (its `b` and `c` are the last two rounds' `a`, of both colours).
pub const A_COLOUR: u32 = 0b1111_1011_1110_1000_0000_0000_0110_1101;

/// Bits of a message word whose carry copies hit every three-way XOR of `σ0` (`{j + 7, j + 18, j + 3}`, `j < 29`)
/// and of `σ1` (`{j + 17, j + 19, j + 10}`, `j < 22`): minimum hitting sets, found by exhaustive search.
pub const SIGMA_BOTH: u32 = bits_mask(&[3, 8, 11, 13, 19, 20, 21, 22, 24, 25, 27, 29, 30]);
pub const SIGMA0_ONLY: u32 = bits_mask(&[1, 7, 8, 11, 13, 14, 19, 20, 21, 26, 27]);
pub const SIGMA1_ONLY: u32 = bits_mask(&[3, 4, 14, 19, 20, 24, 25, 30, 31]);

const fn bits_mask(bits: &[usize]) -> u32 {
    let mut m = 0;
    let mut i = 0;
    while i < bits.len() {
        m |= 1 << bits[i];
        i += 1;
    }
    m
}

/// The bits of message word `t` that need carry copies: `σ0` reads words 1..=48, `σ1` words 14..=61.
fn schedule_copies(t: usize) -> u32 {
    match (1..=48).contains(&t) as u8 + 2 * (14..=61).contains(&t) as u8 {
        1 => SIGMA0_ONLY,
        2 => SIGMA1_ONLY,
        3 => SIGMA_BOTH,
        _ => 0,
    }
}

/// A word of constant wires.
pub fn const_word(v: u32) -> Word {
    Ckt::constant_word(v as u128, 32)
}

fn word_const(w: &[Wire]) -> Option<u32> {
    w.iter()
        .enumerate()
        .try_fold(0u32, |acc, (i, b)| b.as_const().map(|b| acc | (b as u32) << i))
}

/// Rows spent in a compression, by part (for reports).
#[derive(Default, Clone, Copy, Debug)]
pub struct Breakdown {
    pub schedule: usize,
    pub conversions: usize,
    pub maj: usize,
    pub ch: usize,
    pub sigma: usize,
    pub t1: usize,
    pub new_state: usize,
    pub feed_forward: usize,
}

impl Breakdown {
    pub fn total(&self) -> usize {
        self.schedule
            + self.conversions
            + self.maj
            + self.ch
            + self.sigma
            + self.t1
            + self.new_state
            + self.feed_forward
    }
}

/// One SHA-256 compression: chaining value `h` (eight words) and a block of sixteen words, each low bit first.
pub fn compress(c: &mut Ckt, tw: &mut Twins, h: &[Word], block: &[Word]) -> Vec<Word> {
    compress_counted(c, tw, h, block, &mut Breakdown::default())
}

/// [`compress`], adding its rows to `rows` by part.
pub fn compress_counted(c: &mut Ckt, tw: &mut Twins, h: &[Word], block: &[Word], rows: &mut Breakdown) -> Vec<Word> {
    assert_eq!((h.len(), block.len()), (8, 16));
    let mut mark = c.rows();
    let mut tick = |c: &Ckt, part: &mut usize| {
        *part += c.rows() - mark;
        mark = c.rows();
    };
    let mut w: Vec<Word> = block.to_vec();
    // a[t + 3] is the state's `a` before round t, so a[t], a[t + 1], a[t + 2] are its `d`, `c`, `b`; e likewise.
    let mut a: Vec<Word> = vec![h[3].clone(), h[2].clone(), h[1].clone(), h[0].clone()];
    let mut e: Vec<Word> = vec![h[7].clone(), h[6].clone(), h[5].clone(), h[4].clone()];
    for t in 0..64 {
        let (at, bt, ct, dt) = (a[t + 3].clone(), a[t + 2].clone(), a[t + 1].clone(), a[t].clone());
        let (et, ft, gt, ht) = (e[t + 3].clone(), e[t + 2].clone(), e[t + 1].clone(), e[t].clone());
        // Maj, a carry, with `b`'s or `c`'s carry copy in the `c` slot.
        let maj: Word = (0..32).map(|j| maj_tw(c, tw, at[j], bt[j], ct[j])).collect();
        tick(c, &mut rows.maj);
        // Ch(e, f, g) = maj(g, e ^ g, f), a carry, with `f`'s carry copy in the `c` slot.
        let ch: Word = (0..32)
            .map(|j| {
                let x = c.xor(et[j], gt[j]);
                maj_tw(c, tw, gt[j], x, ft[j])
            })
            .collect();
        tick(c, &mut rows.ch);
        // The additions want Maj and Ch as bits: each conversion row below makes one of them a bit as it makes a
        // carry copy of `a` (the bits of one colour: Σ0, and with the other colour the next two Maj), of `e` (Σ1,
        // and the next Ch) and of the new message word (the bits its σ0 and σ1 read).
        // (Bits 0 and 1 need no copy: the low two columns of the sums have spare `c` slots.)
        for &m in maj[2..].iter().chain(&ch[2..]) {
            tw.want_bit(m);
        }
        for j in (0..32).filter(|j| (A_COLOUR >> j) & 1 == (t as u32 & 1) ^ 1) {
            tw.carry(c, at[j]);
        }
        for &x in &et {
            tw.carry(c, x);
        }
        tick(c, &mut rows.conversions);
        let s0 = big_sigma0(c, tw, &at);
        let s1 = big_sigma1(c, tw, &et);
        tick(c, &mut rows.sigma);
        if t >= 16 {
            let s0 = small_sigma0(c, tw, &w[t - 15]);
            let s1 = small_sigma1(c, tw, &w[t - 2]);
            let wt = add_many(c, tw, &[&s1, &w[t - 7], &s0, &w[t - 16]], 0, 32);
            w.push(wt);
            tick(c, &mut rows.schedule);
        }
        for j in (0..32).filter(|j| (schedule_copies(t) >> j) & 1 == 1) {
            tw.carry(c, w[t][j]);
        }
        tick(c, &mut rows.conversions);
        let t1_ops: Vec<&[Wire]> = vec![&ht, &s1, &ch, &w[t]];
        let variable = t1_ops.iter().filter(|o| word_const(o).is_none()).count();
        let (en, an) = if variable >= 2 {
            let t1 = add_many(c, tw, &t1_ops, K[t] as u128, 32);
            tick(c, &mut rows.t1);
            let en = add_many(c, tw, &[&dt, &t1], 0, 32);
            let an = add_many(c, tw, &[&t1, &s0, &maj], 0, 32);
            (en, an)
        } else {
            // T1 is one word and a constant: add it into both sums rather than once alone.
            let mut e_ops = t1_ops.clone();
            e_ops.push(&dt);
            let en = add_many(c, tw, &e_ops, K[t] as u128, 32);
            let mut a_ops = t1_ops.clone();
            a_ops.push(&s0);
            a_ops.push(&maj);
            let an = add_many(c, tw, &a_ops, K[t] as u128, 32);
            (en, an)
        };
        tick(c, &mut rows.new_state);
        tw.clear_pending();
        a.push(an);
        e.push(en);
    }
    let out: Vec<Word> = (0..8)
        .map(|i| {
            let s = if i < 4 { &a[67 - i] } else { &e[67 - (i - 4)] };
            add_many(c, tw, &[&h[i], s], 0, 32)
        })
        .collect();
    tick(c, &mut rows.feed_forward);
    out
}

/// The bytes of a message of `len` bytes after SHA-256 padding: `Some(i)` the message byte `i`, `None` a constant.
fn padded(len: usize) -> Vec<Result<usize, u8>> {
    let total = (len + 9).div_ceil(64) * 64;
    let bits = (len as u64) * 8;
    (0..total)
        .map(|i| {
            if i < len {
                Ok(i)
            } else if i == len {
                Err(0x80)
            } else if i >= total - 8 {
                Err((bits >> (8 * (total - 1 - i))) as u8)
            } else {
                Err(0)
            }
        })
        .collect()
}

/// The sixteen words of block `b` of a message (statement-order bits, byte `i` bit `j` at `8 i + j`) after padding.
pub fn block_words(msg: &[Wire], b: usize) -> Vec<Word> {
    assert_eq!(msg.len() % 8, 0);
    let bytes = padded(msg.len() / 8);
    let byte_bit = |i: usize, k: usize| -> Wire {
        match bytes[i] {
            Ok(m) => msg[8 * m + k],
            Err(v) => Wire::constant((v >> k) & 1 == 1),
        }
    };
    (0..16)
        .map(|t| (0..32).map(|k| byte_bit(64 * b + 4 * t + 3 - k / 8, k % 8)).collect())
        .collect()
}

/// The number of compressions for a message of `len` bytes.
pub fn blocks(len: usize) -> usize {
    (len + 9).div_ceil(64)
}

/// Statement-order digest bits from the final chaining value: byte `4 i + b` holds bits `24 - 8 b ..` of word `i`.
pub fn digest_bits(h: &[Word]) -> Vec<Wire> {
    (0..256).map(|n| h[n / 32][24 - 8 * ((n / 8) % 4) + n % 8]).collect()
}

/// SHA-256 of a message of fixed length, its bits in statement order; returns the 256 digest bits likewise.
pub fn sha256(c: &mut Ckt, msg: &[Wire]) -> Vec<Wire> {
    sha256_tw(c, &mut Twins::new(), msg)
}

/// [`sha256`] sharing carry copies with the rest of a circuit.
pub fn sha256_tw(c: &mut Ckt, tw: &mut Twins, msg: &[Wire]) -> Vec<Wire> {
    sha256_counted(c, tw, msg, &mut Breakdown::default())
}

/// [`sha256_tw`], adding its rows to `rows` by part.
pub fn sha256_counted(c: &mut Ckt, tw: &mut Twins, msg: &[Wire], rows: &mut Breakdown) -> Vec<Wire> {
    let mut h: Vec<Word> = IV.iter().map(|&v| const_word(v)).collect();
    for b in 0..blocks(msg.len() / 8) {
        let block = block_words(msg, b);
        h = compress_counted(c, tw, &h, &block, rows);
    }
    digest_bits(&h)
}

/// The statement bits of 32 digest bytes followed by 32 zero bytes.
pub fn digest_statement(digest: &[Wire]) -> Vec<Wire> {
    let mut public = digest.to_vec();
    public.resize(PUBLIC_BITS, Wire::ZERO);
    public
}

/// A deterministic byte stream for instances (splitmix64).
pub(crate) fn bytes_from_seed(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed ^ 0x5348_4132_3536_0000;
    (0..n)
        .map(|_| {
            s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

/// Bits of bytes in statement order (byte `i`, bit `j` low first, at `8 i + j`).
pub fn bits_of(bytes: &[u8]) -> Vec<bool> {
    crate::bytes_to_bits(bytes)
}

/// SHA-256 of a private 1,024-byte message. Statement: the digest in bytes 0..32, zeros in bytes 32..64.
pub struct Sha256OneKiB;

pub const ONE_KIB: usize = 1024;

impl Workload for Sha256OneKiB {
    const NAME: &'static str = "sha256-1kib";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        let msg = c.inputs(8 * ONE_KIB);
        let digest = sha256(c, &msg);
        digest_statement(&digest)
    }

    fn instance(seed: u64) -> Instance {
        use sha2::Digest;
        let msg = bytes_from_seed(seed, ONE_KIB);
        let digest: [u8; 32] = sha2::Sha256::digest(&msg).into();
        let mut statement = [0u8; 64];
        statement[..32].copy_from_slice(&digest);
        Instance {
            inputs: bits_of(&msg),
            statement,
        }
    }

    /// A hash has no invalid instance: every message has a digest.
    fn invalid_instance(_seed: u64) -> Option<Instance> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::eval;
    use crate::{build, read_statement};
    use sha2::Digest;

    fn rng(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *seed >> 11
    }

    fn reference_compress(h: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(block);
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = s1.wrapping_add(w[t - 7]).wrapping_add(s0).wrapping_add(w[t - 16]);
        }
        let [mut a, mut b, mut cc, mut d, mut e, mut f, mut g, mut hh] = *h;
        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & cc) ^ (b & cc);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = cc;
            cc = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let s = [a, b, cc, d, e, f, g, hh];
        std::array::from_fn(|i| h[i].wrapping_add(s[i]))
    }

    fn word_bits(v: u32) -> Vec<bool> {
        (0..32).map(|i| (v >> i) & 1 == 1).collect()
    }

    #[test]
    fn carry_copy_sets_cover_their_xors() {
        let mono = |set: u32, r: [usize; 3]| (0..32).any(|j| r.iter().all(|&k| (set >> ((j + k) % 32)) & 1 == 1));
        // Both colours meet every Σ0 triple.
        assert!(!mono(A_COLOUR, [2, 13, 22]) && !mono(!A_COLOUR, [2, 13, 22]));
        let hits = |set: u32, r: [usize; 2], shift: usize| {
            (0..32 - shift).all(|j| {
                r.iter()
                    .map(|&k| (j + k) % 32)
                    .chain([j + shift])
                    .any(|b| (set >> b) & 1 == 1)
            })
        };
        for (set, s0, s1) in [
            (SIGMA_BOTH, true, true),
            (SIGMA0_ONLY, true, false),
            (SIGMA1_ONLY, false, true),
        ] {
            assert!(!s0 || hits(set, [7, 18], 3));
            assert!(!s1 || hits(set, [17, 19], 10));
        }
    }

    #[test]
    fn adder_matches_native() {
        let mut seed = 7u64;
        // Operand kinds: inputs (bits), carries (`and` of an input with itself), negated bits, constants.
        for case in 0..60 {
            let n = 2 + case % 5;
            let width = [32usize, 7, 1, 13][case % 4];
            let kinds: Vec<u64> = (0..n).map(|_| rng(&mut seed) % 5).collect();
            let konst = if case % 3 == 0 { 0 } else { rng(&mut seed) as u128 };
            let vals: Vec<u64> = (0..n).map(|_| rng(&mut seed)).collect();
            let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
            let mut inputs = Vec::new();
            for v in &vals {
                inputs.extend((0..width).map(|i| (v >> i) & 1 == 1));
            }
            let out = eval(
                n * width,
                |c, ins| {
                    let ops: Vec<Word> = (0..n)
                        .map(|k| {
                            let w = &ins[k * width..(k + 1) * width];
                            match kinds[k] {
                                0 => w.to_vec(),
                                1 => w.iter().map(|&x| c.and(x, x)).collect(),
                                2 => w.iter().map(|&x| c.positive(x.not())).collect(),
                                4 => w.iter().map(|&x| x.not()).collect(),
                                _ => const_word((vals[k] & mask) as u32)[..width.min(32)].to_vec(),
                            }
                        })
                        .collect();
                    let refs: Vec<&[Wire]> = ops.iter().map(|o| o.as_slice()).collect();
                    add_many(c, &mut Twins::new(), &refs, konst, width)
                },
                &inputs,
            );
            let mut expect = konst as u64;
            for (k, v) in vals.iter().enumerate() {
                let v = v & mask;
                expect = expect.wrapping_add(match kinds[k] {
                    2 | 4 => !v & mask,
                    3 => v & 0xffff_ffff,
                    _ => v,
                });
            }
            let got: u64 = out.iter().enumerate().map(|(i, &b)| (b as u64) << i).sum();
            assert_eq!(got, expect & mask, "case {case} kinds {kinds:?}");
        }
    }

    #[test]
    fn an_adder_of_four_words_takes_three_rows_a_bit() {
        let mut c = Ckt::new();
        let ops: Vec<Word> = (0..4).map(|_| c.inputs(32)).collect();
        let refs: Vec<&[Wire]> = ops.iter().map(|o| o.as_slice()).collect();
        let before = c.rows();
        add_many(&mut c, &mut Twins::new(), &refs, 0, 32);
        // Columns: 4 bits (3 rows: three bits and no carry need a conversion), 6 (3), then 7 (3) up to the top.
        assert_eq!(c.rows() - before, 96);
    }

    #[test]
    fn sigma_and_choice_match_native() {
        let mut seed = 3u64;
        for _ in 0..20 {
            let (x, y, z) = (rng(&mut seed) as u32, rng(&mut seed) as u32, rng(&mut seed) as u32);
            let inputs: Vec<bool> = [x, y, z].iter().flat_map(|&v| word_bits(v)).collect();
            let out = eval(
                96,
                |c, ins| {
                    let mut tw = Twins::new();
                    let (a, b, d) = (&ins[..32], &ins[32..64], &ins[64..]);
                    let mut o = big_sigma0(c, &mut tw, a);
                    o.extend(big_sigma1(c, &mut tw, a));
                    o.extend(small_sigma0(c, &mut tw, b));
                    o.extend(small_sigma1(c, &mut tw, b));
                    let ch: Word = (0..32)
                        .map(|j| {
                            let x = c.xor(a[j], d[j]);
                            maj_tw(c, &mut tw, d[j], x, b[j])
                        })
                        .collect();
                    o.extend(ch);
                    o.extend(
                        (0..32)
                            .map(|j| maj_tw(c, &mut tw, a[j], b[j], d[j]))
                            .collect::<Vec<_>>(),
                    );
                    o
                },
                &inputs,
            );
            let word = |k: usize| -> u32 { (0..32).map(|i| (out[32 * k + i] as u32) << i).sum() };
            assert_eq!(word(0), x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22));
            assert_eq!(word(1), x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25));
            assert_eq!(word(2), y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3));
            assert_eq!(word(3), y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10));
            assert_eq!(word(4), (x & y) ^ (!x & z));
            assert_eq!(word(5), (x & y) ^ (x & z) ^ (y & z));
        }
    }

    #[test]
    fn compression_matches_native() {
        let mut seed = 11u64;
        for _ in 0..3 {
            let h: [u32; 8] = std::array::from_fn(|_| rng(&mut seed) as u32);
            let block: [u32; 16] = std::array::from_fn(|_| rng(&mut seed) as u32);
            let inputs: Vec<bool> = h.iter().chain(&block).flat_map(|&v| word_bits(v)).collect();
            let out = eval(
                24 * 32,
                |c, ins| {
                    let words: Vec<Word> = ins.chunks(32).map(|w| w.to_vec()).collect();
                    compress(c, &mut Twins::new(), &words[..8], &words[8..]).concat()
                },
                &inputs,
            );
            let expect = reference_compress(&h, &block);
            let got: Vec<u32> = out
                .chunks(32)
                .map(|w| w.iter().enumerate().map(|(i, &b)| (b as u32) << i).sum())
                .collect();
            assert_eq!(got, expect);
        }
    }

    #[test]
    fn hash_matches_sha2_on_every_padding_shape() {
        let mut seed = 5u64;
        for len in [0usize, 1, 3, 32, 33, 55, 56, 63, 64, 65, 119, 120, 128, 200] {
            let msg: Vec<u8> = (0..len).map(|_| rng(&mut seed) as u8).collect();
            let out = eval(8 * len, sha256, &bits_of(&msg));
            let expect: [u8; 32] = sha2::Sha256::digest(&msg).into();
            assert_eq!(out, bits_of(&expect), "length {len}");
        }
    }

    #[test]
    fn rows_per_compression() {
        // Variable chaining value and block: the steady-state cost.
        let mut c = Ckt::new();
        let words: Vec<Word> = (0..24).map(|_| c.inputs(32)).collect();
        let before = c.rows();
        let mut rows = Breakdown::default();
        compress_counted(&mut c, &mut Twins::new(), &words[..8], &words[8..], &mut rows);
        let total = c.rows() - before;
        assert_eq!(total, rows.total());
        println!("one compression, variable state and block: {total} rows {rows:?}");
        // From the IV, a block of padding only (constant schedule).
        let mut c = Ckt::new();
        let h: Vec<Word> = (0..8).map(|_| c.inputs(32)).collect();
        let pad: Vec<Word> = (0..16)
            .map(|t| const_word(if t == 0 { 0x8000_0000 } else { 0 }))
            .collect();
        let before = c.rows();
        compress(&mut c, &mut Twins::new(), &h, &pad);
        println!("one compression, constant block: {} rows", c.rows() - before);
        let mut c = Ckt::new();
        let msg = c.inputs(8 * 55);
        let before = c.rows();
        sha256(&mut c, &msg);
        println!(
            "one compression from the IV (55-byte message): {} rows",
            c.rows() - before
        );
    }

    #[test]
    fn one_kib_workload() {
        let (circuit, srcs, _) = build::<Sha256OneKiB>();
        circuit.check_wired().unwrap();
        let (rows, inputs) = crate::count::<Sha256OneKiB>();
        let mut c = Ckt::new();
        let msg = c.inputs(8 * ONE_KIB);
        let mut parts = Breakdown::default();
        sha256_counted(&mut c, &mut Twins::new(), &msg, &mut parts);
        println!(
            "{}: {rows} rows ({} public rows, {inputs} input rows, {} hash rows), 2^{} padded; {} compressions \
             ({:.0} rows each); by part {parts:?}",
            Sha256OneKiB::NAME,
            crate::PUBLIC_ROWS,
            parts.total(),
            circuit.log_rows,
            blocks(ONE_KIB),
            parts.total() as f64 / blocks(ONE_KIB) as f64,
        );
        assert_eq!(rows, crate::PUBLIC_ROWS + inputs + parts.total());
        for seed in 0..3 {
            let inst = Sha256OneKiB::instance(seed);
            let v = circuit.values(&inst.inputs);
            assert_eq!(read_statement(&v, &srcs), inst.statement, "seed {seed}");
        }
    }
}
