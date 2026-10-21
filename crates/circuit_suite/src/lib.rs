//! Statements written in the one circuit format the quotient argument proves (`flock::quotient`): rows of full
//! adders, a wiring permutation and 512 public bits. Nothing here adds to that format; every circuit is closed by
//! [`Ckt::finish`] into a [`Circuit`] that [`Circuit::check_wired`] holds to the hypotheses of the Lean theorems
//! (`formal/quotient`: `AdderCircuit`, `Wired`, `cells_determined`).
//!
//! A row reads the bits of its `x` and `y` sources and the carry of its `c` source, and outputs their sum bit and
//! their carry. [`Wire`] names one of those two outputs, or a constant, with a free negation, and [`Ckt::fa`]
//! places three wires into a row's slots, adding a conversion row only when a carry must be read as a bit or the
//! other way round. Gadgets are built from that one operation, so a gadget's row count is exact.
//!
//! A statement is a function of the free input bits, its 512 public bits (the 64 bytes of a
//! `flock::membership::Statement`, low bit first in each byte). A check a statement makes is a public bit the
//! verifier fixes, typically a validity bit: the format has no assertion of its own, and needs none.

use std::collections::HashMap;

pub use flock::quotient::circuit::{Builder, Circuit, PUBLIC_ROWS, Row, Src, WORD_BITS, public_words};

pub mod blake2s;
pub mod describe;
pub mod falcon;
pub mod keccak;
pub mod mpt;
pub mod nonnative;
pub mod poseidon;
pub mod secp256k1;
pub mod sha256;
pub mod shielded;

/// The public bits of a statement.
pub const PUBLIC_BITS: usize = 512;
/// The fewest rows a circuit can have: the quotient argument wants `log_rows + 2 > 13`.
pub const MIN_LOG_ROWS: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    Const(bool),
    /// The sum bit of row `r`.
    Sum(u32),
    /// The carry of row `r`.
    Carry(u32),
}

/// A bit of the circuit: a constant, or a row's sum bit or carry, possibly negated.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Wire {
    kind: Kind,
    neg: bool,
}

impl Wire {
    pub const ZERO: Wire = Wire {
        kind: Kind::Const(false),
        neg: false,
    };
    pub const ONE: Wire = Wire {
        kind: Kind::Const(true),
        neg: false,
    };

    pub fn constant(bit: bool) -> Wire {
        if bit { Wire::ONE } else { Wire::ZERO }
    }

    /// Its value if it is a constant.
    pub fn as_const(self) -> Option<bool> {
        match self.kind {
            Kind::Const(b) => Some(b ^ self.neg),
            _ => None,
        }
    }

    /// Its value in an evaluation of the circuit (`Circuit::values`).
    pub fn value(self, values: &[u8]) -> bool {
        self.neg
            ^ match self.kind {
                Kind::Const(b) => b,
                Kind::Sum(r) => values[r as usize] & 1 == 1,
                Kind::Carry(r) => values[r as usize] >> 1 == 1,
            }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Wire {
        Wire { neg: !self.neg, ..self }
    }
}

/// A word of wires, low bit first.
pub type Word = Vec<Wire>;

/// The value of `bits` (low first) as an integer, in an evaluation.
pub fn read_u64(values: &[u8], bits: &[Wire]) -> u64 {
    bits.iter()
        .enumerate()
        .map(|(i, w)| (w.value(values) as u64) << i)
        .sum()
}

/// A circuit under construction.
pub struct Ckt {
    b: Builder,
    /// A carry read as a bit: row `r`'s carry is the bit of row `to_sum[r]`.
    to_sum: HashMap<u32, u32>,
    /// A bit read as a carry: row `r`'s bit is the carry of row `to_carry[r]`.
    to_carry: HashMap<u32, u32>,
    /// A negated wire made positive.
    positive: HashMap<Wire, Wire>,
    /// The input rows, which read their own bit and two zeros.
    input_rows: std::collections::HashSet<u32>,
}

impl Default for Ckt {
    fn default() -> Self {
        Self::new()
    }
}

impl Ckt {
    pub fn new() -> Self {
        Self {
            b: Builder::new(),
            to_sum: HashMap::new(),
            to_carry: HashMap::new(),
            positive: HashMap::new(),
            input_rows: std::collections::HashSet::new(),
        }
    }

    /// Rows so far, the 512 public rows included.
    pub fn rows(&self) -> usize {
        self.b.len()
    }

    /// Free input bits so far.
    pub fn n_inputs(&self) -> usize {
        self.input_rows.len()
    }

    /// A free input bit.
    pub fn input(&mut self) -> Wire {
        let Src::Row(r) = self.b.input() else { unreachable!() };
        self.input_rows.insert(r);
        Wire {
            kind: Kind::Sum(r),
            neg: false,
        }
    }

    pub fn inputs(&mut self, n: usize) -> Word {
        (0..n).map(|_| self.input()).collect()
    }

    fn row(&mut self, x: Src, y: Src, c: Src) -> u32 {
        let Src::Row(r) = self.b.row(x, y, c) else {
            unreachable!()
        };
        r
    }

    /// `w` with no negation: one row when it is negated.
    pub fn positive(&mut self, w: Wire) -> Wire {
        if !w.neg {
            return w;
        }
        if let Kind::Const(b) = w.kind {
            return Wire::constant(!b);
        }
        if let Some(&p) = self.positive.get(&w) {
            return p;
        }
        // The bit of a row reading `w` and a one.
        let r = match w.kind {
            Kind::Sum(r) => self.row(Src::Row(r), Src::One, Src::Zero),
            Kind::Carry(r) => self.row(Src::One, Src::Zero, Src::Row(r)),
            Kind::Const(_) => unreachable!(),
        };
        let p = Wire {
            kind: Kind::Sum(r),
            neg: false,
        };
        self.positive.insert(w, p);
        p
    }

    /// A source for an `x` or `y` slot, from a positive bit or constant.
    fn bit_src(&mut self, w: Wire) -> Src {
        debug_assert!(!w.neg);
        match w.kind {
            Kind::Const(false) => Src::Zero,
            Kind::Const(true) => Src::One,
            Kind::Sum(r) => Src::Row(r),
            Kind::Carry(r) => {
                let s = match self.to_sum.get(&r) {
                    Some(&s) => s,
                    None => {
                        let s = self.row(Src::Zero, Src::Zero, Src::Row(r));
                        self.to_sum.insert(r, s);
                        s
                    }
                };
                Src::Row(s)
            }
        }
    }

    /// A source for a `c` slot, from a positive wire.
    fn carry_src(&mut self, w: Wire) -> Src {
        debug_assert!(!w.neg);
        match w.kind {
            Kind::Const(false) => Src::Zero,
            Kind::Const(true) => self.b.carry_one(),
            Kind::Carry(r) => Src::Row(r),
            Kind::Sum(r) => {
                let c = match self.to_carry.get(&r) {
                    Some(&c) => c,
                    None => {
                        let c = self.row(Src::Row(r), Src::Row(r), Src::Zero);
                        self.to_carry.insert(r, c);
                        c
                    }
                };
                Src::Row(c)
            }
        }
    }

    /// One row computing `a + b + c`: its sum bit and its carry. Constants fold, and a row that would only copy
    /// a wire is not made.
    pub fn fa(&mut self, a: Wire, b: Wire, c: Wire) -> (Wire, Wire) {
        let ops = [a, b, c];
        let consts: Vec<bool> = ops.iter().filter_map(|w| w.as_const()).collect();
        let vars: Vec<Wire> = ops.iter().copied().filter(|w| w.as_const().is_none()).collect();
        let ones = consts.iter().filter(|&&b| b).count();
        match vars.len() {
            0 => return (Wire::constant(ones % 2 == 1), Wire::constant(ones >= 2)),
            // x + k: with k = 0 the sum is x and the carry 0; with k = 2 the sum is x and the carry 1;
            // with k = 1 the sum is not x and the carry x.
            1 => {
                let x = vars[0];
                return match ones {
                    0 => (x, Wire::ZERO),
                    1 => (x.not(), x),
                    _ => (x, Wire::ONE),
                };
            }
            _ => {}
        }
        // The carry of negated operands is not free; the sum's negation is.
        let ops: Vec<Wire> = ops.iter().map(|&w| self.positive(w)).collect();
        // The `c` slot takes a carry if there is one, else a constant, else a bit read as a carry.
        let pick = ops
            .iter()
            .position(|w| matches!(w.kind, Kind::Carry(_)))
            .or_else(|| ops.iter().position(|w| w.as_const() == Some(false)))
            .or_else(|| ops.iter().position(|w| w.as_const().is_some()))
            .unwrap_or(2);
        let mut rest = ops.clone();
        let c = rest.remove(pick);
        let c = self.carry_src(c);
        let x = self.bit_src(rest[0]);
        let y = self.bit_src(rest[1]);
        let r = self.row(x, y, c);
        (
            Wire {
                kind: Kind::Sum(r),
                neg: false,
            },
            Wire {
                kind: Kind::Carry(r),
                neg: false,
            },
        )
    }

    /// `a ^ b ^ c`, the negations free.
    pub fn xor3(&mut self, a: Wire, b: Wire, c: Wire) -> Wire {
        let parity = a.neg ^ b.neg ^ c.neg;
        let strip = |w: Wire| Wire { neg: false, ..w };
        let (s, _) = self.fa(strip(a), strip(b), strip(c));
        if parity { s.not() } else { s }
    }

    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        self.xor3(a, b, Wire::ZERO)
    }

    pub fn and(&mut self, a: Wire, b: Wire) -> Wire {
        self.fa(a, b, Wire::ZERO).1
    }

    pub fn or(&mut self, a: Wire, b: Wire) -> Wire {
        self.fa(a, b, Wire::ONE).1
    }

    /// The majority of three bits.
    pub fn maj(&mut self, a: Wire, b: Wire, c: Wire) -> Wire {
        // maj(-a, -b, -c) = -maj(a, b, c).
        if a.neg && b.neg && c.neg {
            return self.fa(a.not(), b.not(), c.not()).1.not();
        }
        self.fa(a, b, c).1
    }

    /// `s ? a : b`, three rows: `b ^ (s & (a ^ b))`.
    pub fn mux(&mut self, s: Wire, a: Wire, b: Wire) -> Wire {
        if a == b {
            return a;
        }
        let d = self.xor(a, b);
        let t = self.and(s, d);
        self.xor(b, t)
    }

    /// Bitwise `s ? a : b`.
    pub fn mux_word(&mut self, s: Wire, a: &[Wire], b: &[Wire]) -> Word {
        a.iter().zip(b).map(|(&x, &y)| self.mux(s, x, y)).collect()
    }

    pub fn xor_word(&mut self, a: &[Wire], b: &[Wire]) -> Word {
        a.iter().zip(b).map(|(&x, &y)| self.xor(x, y)).collect()
    }

    pub fn and_word(&mut self, a: &[Wire], b: &[Wire]) -> Word {
        a.iter().zip(b).map(|(&x, &y)| self.and(x, y)).collect()
    }

    /// `x + y + carry` on as many bits as `x` has, and the carry out; one row a bit, the carry riding in the
    /// carry slot.
    pub fn add_carry(&mut self, x: &[Wire], y: &[Wire], mut carry: Wire) -> (Word, Wire) {
        assert_eq!(x.len(), y.len());
        let sum = x
            .iter()
            .zip(y)
            .map(|(&a, &b)| {
                let (s, c) = self.fa(a, b, carry);
                carry = c;
                s
            })
            .collect();
        (sum, carry)
    }

    /// `x + y` modulo `2^len`.
    pub fn add(&mut self, x: &[Wire], y: &[Wire]) -> Word {
        self.add_carry(x, y, Wire::ZERO).0
    }

    /// `x - y` modulo `2^len`, and whether no borrow occurred (`x >= y`).
    pub fn sub(&mut self, x: &[Wire], y: &[Wire]) -> (Word, Wire) {
        let ny: Word = y.iter().map(|w| w.not()).collect();
        self.add_carry(x, &ny, Wire::ONE)
    }

    /// Whether `x == y`: the OR tree of the differing bits, negated.
    pub fn eq(&mut self, x: &[Wire], y: &[Wire]) -> Wire {
        let d: Word = x.iter().zip(y).map(|(&a, &b)| self.xor(a, b)).collect();
        self.is_zero(&d)
    }

    pub fn is_zero(&mut self, x: &[Wire]) -> Wire {
        self.any(x).not()
    }

    /// The OR of `x`, one row a bit.
    pub fn any(&mut self, x: &[Wire]) -> Wire {
        let mut level: Word = x.to_vec();
        if level.is_empty() {
            return Wire::ZERO;
        }
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|p| if p.len() == 2 { self.or(p[0], p[1]) } else { p[0] })
                .collect();
        }
        level[0]
    }

    /// The AND of `x`.
    pub fn all(&mut self, x: &[Wire]) -> Wire {
        let neg: Word = x.iter().map(|w| w.not()).collect();
        self.any(&neg).not()
    }

    /// A constant word of `len` bits.
    pub fn constant_word(value: u128, len: usize) -> Word {
        (0..len).map(|i| Wire::constant((value >> i) & 1 == 1)).collect()
    }

    /// Close the circuit: `public` are the statement's 512 bits, byte by byte, low bit first. The rows are the
    /// fewest power of two that holds them, at least `2^MIN_LOG_ROWS`.
    pub fn finish(self, public: &[Wire]) -> (Circuit, Vec<Src>) {
        let log = self.log_rows_for(public);
        self.finish_at(log, public)
    }

    /// The rows [`Ckt::finish`] would close on, without closing.
    pub fn log_rows_for(&self, public: &[Wire]) -> usize {
        // Each public bit may cost up to two rows (a negated wire made positive, then a row dropping the carry).
        let rows = self.b.len() + 2 * public.len();
        rows.next_power_of_two().trailing_zeros().max(MIN_LOG_ROWS as u32) as usize
    }

    /// [`Ckt::finish`] on `2^log_rows` rows. Also returns the public bits' sources, rows whose bit is the public
    /// bit and whose carry is zero.
    pub fn finish_at(mut self, log_rows: usize, public: &[Wire]) -> (Circuit, Vec<Src>) {
        assert_eq!(public.len(), PUBLIC_BITS);
        let mut published = HashMap::new();
        let srcs: Vec<Src> = public
            .iter()
            .map(|&w| {
                if let Some(&s) = published.get(&w) {
                    return s;
                }
                let p = self.positive(w);
                let x = self.bit_src(p);
                let s = match (p.kind, x) {
                    // An input row already reads its own bit and two zeros.
                    (Kind::Sum(r), Src::Row(_)) if self.input_rows.contains(&r) => Src::Row(r),
                    _ => self.b.row(x, Src::Zero, Src::Zero),
                };
                published.insert(w, s);
                s
            })
            .collect();
        let (y, root) = srcs.split_at(256);
        let circuit = self.b.finish(log_rows, &public_words(y, root));
        (circuit, srcs)
    }
}

/// The 64 statement bytes a circuit's public sources hold, in an evaluation.
pub fn read_statement(values: &[u8], srcs: &[Src]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, src) in srcs.iter().enumerate() {
        let bit = match *src {
            Src::Zero => 0,
            Src::One => 1,
            Src::Row(r) => values[r as usize] & 1,
        };
        out[i / 8] |= bit << (i % 8);
    }
    out
}

/// The public wires of 64 statement bytes given as wires, low bit first per byte.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .collect()
}

/// A statement: how it is built, and an instance computed by an independent reference implementation.
pub trait Workload {
    /// A short name, used in reports.
    const NAME: &'static str;
    /// Build the circuit; returns the 512 public bits. Free inputs are taken in the order
    /// [`Workload::instance`]'s inputs list them.
    fn build(c: &mut Ckt) -> Vec<Wire>;
    /// A valid instance from a seed: the free inputs, and the 64 statement bytes a reference computes.
    fn instance(seed: u64) -> Instance;
    /// An invalid instance: inputs whose statement the reference says differ from any valid one's (for a
    /// validity bit, the bit is cleared). `None` if the statement has no notion of invalidity.
    fn invalid_instance(seed: u64) -> Option<Instance>;
}

pub struct Instance {
    pub inputs: Vec<bool>,
    pub statement: [u8; 64],
}

/// Build a workload's circuit, closed on the fewest rows; the row count before padding is `.2`.
pub fn build<W: Workload>() -> (Circuit, Vec<Src>, usize) {
    let mut c = Ckt::new();
    let public = W::build(&mut c);
    let used = c.rows();
    let (circuit, srcs) = c.finish(&public);
    (circuit, srcs, used)
}

/// Count a workload's rows and inputs without closing the circuit.
pub fn count<W: Workload>() -> (usize, usize) {
    let mut c = Ckt::new();
    let public = W::build(&mut c);
    assert_eq!(public.len(), PUBLIC_BITS);
    (c.rows(), c.n_inputs())
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Evaluate a gadget on given inputs: `f` gets the input wires and returns outputs.
    pub fn eval(n_inputs: usize, f: impl FnOnce(&mut Ckt, &[Wire]) -> Vec<Wire>, inputs: &[bool]) -> Vec<bool> {
        let mut c = Ckt::new();
        let ins = c.inputs(n_inputs);
        let out = f(&mut c, &ins);
        let mut public = out.clone();
        public.resize(PUBLIC_BITS, Wire::ZERO);
        let (circuit, srcs) = c.finish(&public);
        circuit.check_wired().unwrap();
        let v = circuit.values(inputs);
        let st = read_statement(&v, &srcs);
        (0..out.len()).map(|i| (st[i / 8] >> (i % 8)) & 1 == 1).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::eval;
    use super::*;

    #[test]
    fn every_three_bit_gadget_on_every_input() {
        // Every combination of negations and kinds: inputs as bits, carries made by and-ing with one.
        for mask in 0..8u32 {
            let inputs: Vec<bool> = (0..3).map(|i| (mask >> i) & 1 == 1).collect();
            for kinds in 0..27u32 {
                for negs in 0..8u32 {
                    let out = eval(
                        3,
                        |c, ins| {
                            // Kind 0 an input's bit, 1 a carry (`and(x, x)`), 2 the bit of another row.
                            let w: Vec<Wire> = (0..3)
                                .map(|i| {
                                    let w = match (kinds / 3u32.pow(i as u32)) % 3 {
                                        0 => ins[i],
                                        1 => c.and(ins[i], ins[i]),
                                        _ => c.positive(ins[i].not()).not(),
                                    };
                                    if (negs >> i) & 1 == 1 { w.not() } else { w }
                                })
                                .collect();
                            let (s, k) = c.fa(w[0], w[1], w[2]);
                            vec![
                                s,
                                k,
                                c.xor3(w[0], w[1], w[2]),
                                c.and(w[0], w[1]),
                                c.or(w[1], w[2]),
                                c.maj(w[0], w[1], w[2]),
                                c.mux(w[0], w[1], w[2]),
                                c.xor(w[2], w[0]),
                            ]
                        },
                        &inputs,
                    );
                    let b: Vec<bool> = (0..3).map(|i| inputs[i] ^ ((negs >> i) & 1 == 1)).collect();
                    let n = b.iter().filter(|&&x| x).count();
                    let expect = [
                        n % 2 == 1,
                        n >= 2,
                        n % 2 == 1,
                        b[0] & b[1],
                        b[1] | b[2],
                        n >= 2,
                        if b[0] { b[1] } else { b[2] },
                        b[2] ^ b[0],
                    ];
                    assert_eq!(out, expect, "inputs {mask:03b} kinds {kinds} negs {negs:03b}");
                }
            }
        }
    }

    #[test]
    fn words_add_subtract_compare() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for _ in 0..200 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let (x, y) = ((rng >> 7) as u16, (rng >> 33) as u16);
            let inputs: Vec<bool> = (0..32).map(|i| ((x as u32 | (y as u32) << 16) >> i) & 1 == 1).collect();
            let out = eval(
                32,
                |c, ins| {
                    let (a, b) = (&ins[..16], &ins[16..]);
                    let mut o = c.add(a, b);
                    let (d, ge) = c.sub(a, b);
                    o.extend(d);
                    o.push(ge);
                    o.push(c.eq(a, b));
                    o.push(c.eq(a, a));
                    o.push(c.is_zero(b));
                    o
                },
                &inputs,
            );
            let word = |k: usize| -> u16 { (0..16).map(|i| (out[16 * k + i] as u16) << i).sum() };
            assert_eq!(word(0), x.wrapping_add(y));
            assert_eq!(word(1), x.wrapping_sub(y));
            assert_eq!(out[32], x >= y);
            assert_eq!(out[33], x == y);
            assert!(out[34]);
            assert_eq!(out[35], y == 0);
        }
    }

    #[test]
    fn an_adder_is_a_row_a_bit() {
        let mut c = Ckt::new();
        let a = c.inputs(32);
        let b = c.inputs(32);
        let before = c.rows();
        c.add(&a, &b);
        assert_eq!(c.rows() - before, 32);
    }
}
