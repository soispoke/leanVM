//! Shielded spend with native compression rows and Boolean rule gates.
use crate::native_hash::{Builder, Word as NativeWord};
use circuit_suite::shielded_blake2s::{DEPTH, INPUT_BYTES};
const NOTE_BYTES: usize = 724;
const NOTES_AT: usize = 136;
const OUTPUTS_AT: usize = 1584;
const OUTPUT_BYTES: usize = 48;
const TAG_PK: u8 = 1;
const TAG_COMMIT: u8 = 2;
const TAG_NULL: u8 = 3;
const TAG_NODE: u8 = 4;
const TAG_INNER: u8 = 5;
const TAG_NK: u8 = 6;
const TAG_OCC: u8 = 7;
const TAG_STATEMENT: u8 = 8;
const PUBLIC_BITS: usize = 512;
#[derive(Clone, Copy)]
pub struct Wire {
    at: NativeWord,
    neg: bool,
}
impl Wire {
    const ZERO: Self = Self {
        at: NativeWord::ZERO,
        neg: false,
    };
    fn not(self) -> Self {
        Self { neg: !self.neg, ..self }
    }
    fn is_negated(&self) -> bool {
        self.neg
    }
}
type Word = Vec<Wire>;
struct Twins;
impl Twins {
    fn new() -> Self {
        Self
    }
}
pub struct Ckt {
    pub builder: Builder,
    input: Word,
}
impl Ckt {
    fn constant_word(value: u128, width: usize) -> Word {
        (0..width)
            .map(|i| {
                let mut w = Wire::ZERO;
                if (value >> i) & 1 != 0 {
                    w = w.not();
                }
                w
            })
            .collect()
    }
    fn inputs(&self, n: usize) -> Word {
        assert_eq!(n, self.input.len());
        self.input.clone()
    }
    fn rows(&self) -> usize {
        self.builder.rows()
    }
    fn pos(&mut self, w: Wire) -> NativeWord {
        if w.neg {
            let one = self.builder.one();
            self.builder.gate(w.at, one, one)
        } else {
            w.at
        }
    }
    fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        let a = self.pos(a);
        let b = self.pos(b);
        let one = self.builder.one();
        Wire {
            at: self.builder.gate(a, one, b),
            neg: false,
        }
    }
    fn and(&mut self, a: Wire, b: Wire) -> Wire {
        let a = self.pos(a);
        let b = self.pos(b);
        let z = self.builder.zero();
        Wire {
            at: self.builder.gate(a, b, z),
            neg: false,
        }
    }
    fn or(&mut self, a: Wire, b: Wire) -> Wire {
        self.and(a.not(), b.not()).not()
    }
}
fn add_many(c: &mut Ckt, _tw: &mut Twins, words: &[&[Wire]], constant: u128, width: usize) -> Word {
    assert_eq!(constant, 0);
    let mut result = vec![Wire::ZERO; width];
    for word in words {
        let mut carry = Wire::ZERO;
        for i in 0..width {
            let a = result[i];
            let b = word.get(i).copied().unwrap_or(Wire::ZERO);
            let x = c.xor(a, b);
            result[i] = c.xor(x, carry);
            let ab = c.and(a, b);
            let xc = c.and(x, carry);
            carry = c.xor(ab, xc);
        }
    }
    result
}
/// The wires of a constant byte, low bit first.
fn tag(t: u8) -> Word {
    Ckt::constant_word(t as u128, 8)
}

/// The OR of `bits`, one row a bit: the accumulator stays a carry in the `c` slot. Negated bits are collected
/// apart (their OR is a negated AND, also a chain) so that no bit needs a row to lose its negation.
pub fn any_bits(c: &mut Ckt, bits: &[Wire]) -> Wire {
    let (neg, pos): (Vec<Wire>, Vec<Wire>) = bits.iter().partition(|w| w.is_negated());
    let chain = |c: &mut Ckt, bits: &[Wire], and: bool| -> Option<Wire> {
        let mut it = bits.iter();
        let mut acc = *it.next()?;
        for &b in it {
            acc = if and { c.and(b, acc) } else { c.or(b, acc) };
        }
        Some(acc)
    };
    let pos_any = chain(c, &pos, false);
    let neg: Vec<Wire> = neg.iter().map(|w| w.not()).collect();
    // Some negated bit is one exactly when not all of their positives are.
    let neg_any = chain(c, &neg, true).map(|w| w.not());
    match (pos_any, neg_any) {
        (Some(a), Some(b)) => c.or(a, b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => Wire::ZERO,
    }
}

/// Whether `x == y`: an XOR row a bit and an OR chain.
pub fn eq_bits(c: &mut Ckt, x: &[Wire], y: &[Wire]) -> Wire {
    assert_eq!(x.len(), y.len());
    let d: Word = x.iter().zip(y).map(|(&a, &b)| c.xor(a, b)).collect();
    any_bits(c, &d).not()
}

/// The children of a Merkle step: `(cur, sib)` when `s` is 0, `(sib, cur)` when it is 1. Four rows a bit pair.
pub fn merkle_children(c: &mut Ckt, s: Wire, cur: &[Wire], sib: &[Wire]) -> (Word, Word) {
    cur.iter()
        .zip(sib)
        .map(|(&x, &y)| {
            let t = c.xor(x, y);
            let u = c.and(s, t);
            (c.xor(x, u), c.xor(y, u))
        })
        .unzip()
}

/// Rows spent, by part (for reports).
#[derive(Default, Debug, Clone, Copy)]
pub struct Breakdown {
    pub compressions: usize,
    pub merkle_swaps: usize,
    pub rules: usize,
}

/// The circuit; returns its 512 public bits. `rows` gets the breakdown.
pub fn build_counted(c: &mut Ckt, rows: &mut Breakdown) -> Vec<Wire> {
    let input = c.inputs(8 * INPUT_BYTES);
    let bytes = |at: usize, n: usize| -> Word { input[8 * at..8 * (at + n)].to_vec() };
    // A big-endian integer of `n` bytes, low bit first.
    let int = |at: usize, n: usize| -> Word { (0..8 * n).map(|k| input[8 * (at + n - 1 - k / 8) + k % 8]).collect() };
    let mut tw = Twins::new();
    let root = bytes(0, 32);
    let domain = bytes(32, 32);
    let public_amount = int(64, 16);
    let fee = int(80, 16);
    let recipient = bytes(96, 20);
    let authorizer = bytes(116, 20);

    let mut ok: Vec<Wire> = Vec::new();
    let mut nullifiers = Vec::new();
    let mut in_values = Vec::new();
    let mut in_nonzero = Vec::new();
    for k in 0..2 {
        let at = NOTES_AT + k * NOTE_BYTES;
        let spend_key = bytes(at, 32);
        let rho = bytes(at + 32, 32);
        let value = int(at + 64, 16);
        let index = int(at + 80, 4);
        let owner = hash(c, &mut tw, rows, TAG_PK, &[&spend_key]);
        let inner = hash(c, &mut tw, rows, TAG_INNER, &[&owner, &rho]);
        let commitment = hash(c, &mut tw, rows, TAG_COMMIT, &[&inner, &bytes(at + 64, 16)]);
        let mut current = commitment.clone();
        for (level, &s) in index.iter().enumerate().take(DEPTH) {
            let sibling = bytes(at + 84 + 32 * level, 32);
            let mark = c.rows();
            let (left, right) = merkle_children(c, s, &current, &sibling);
            rows.merkle_swaps += c.rows() - mark;
            current = hash(c, &mut tw, rows, TAG_NODE, &[&left, &right]);
        }
        let occurrence = hash(c, &mut tw, rows, TAG_OCC, &[&commitment, &bytes(at + 80, 4)]);
        let nullifier_key = hash(c, &mut tw, rows, TAG_NK, &[&domain, &spend_key]);
        nullifiers.push(hash(c, &mut tw, rows, TAG_NULL, &[&nullifier_key, &occurrence]));

        let mark = c.rows();
        // Rule 1: the index is below 2^20.
        ok.push(any_bits(c, &index[DEPTH..]).not());
        // Rule 2: a note with nonzero value opens its path to the root.
        let nonzero = any_bits(c, &value);
        let member = eq_bits(c, &current, &root);
        ok.push(c.or(nonzero.not(), member));
        in_values.push(value);
        in_nonzero.push(nonzero);
        rows.rules += c.rows() - mark;
    }

    let mut commitments = Vec::new();
    let mut out_values = Vec::new();
    for k in 0..2 {
        let at = OUTPUTS_AT + k * OUTPUT_BYTES;
        let inner = bytes(at, 32);
        let value = int(at + 32, 16);
        commitments.push(hash(c, &mut tw, rows, TAG_COMMIT, &[&inner, &bytes(at + 32, 16)]));
        let mark = c.rows();
        // The sinks are 1 and 2 as 32-byte big-endian words: byte 31 holds 1 or 2, every other bit is zero.
        let (b0, b1) = (inner[8 * 31], inner[8 * 31 + 1]);
        let rest: Word = inner
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != 8 * 31 && i != 8 * 31 + 1)
            .map(|(_, &w)| w)
            .collect();
        let high_zero = any_bits(c, &rest).not();
        let (low, other) = if k == 0 { (b0, b1) } else { (b1, b0) };
        let low_only = c.and(low, other.not());
        let own_sink = c.and(high_zero, low_only);
        let one_of = c.xor(b0, b1);
        let is_sink = c.and(high_zero, one_of);
        let nonzero = any_bits(c, &value);
        // Rule 5: a zero output carries its position's sink. Rule 6: a nonzero output carries neither.
        ok.push(c.or(nonzero, own_sink));
        ok.push(c.or(nonzero.not(), is_sink.not()));
        out_values.push(value);
        rows.rules += c.rows() - mark;
    }

    let mark = c.rows();
    // Rule 3: the inputs carry value (two u128 sum to zero only if both are zero).
    ok.push(c.or(in_nonzero[0], in_nonzero[1]));
    // Rule 4: v0 + v1 = o0 + o1 + public_amount + fee over the integers: 130-bit sums, no wraparound.
    let lhs = add_many(c, &mut tw, &[&in_values[0], &in_values[1]], 0, 130);
    let rhs = add_many(
        c,
        &mut tw,
        &[&out_values[0], &out_values[1], &public_amount, &fee],
        0,
        130,
    );
    ok.push(eq_bits(c, &lhs, &rhs));
    // Rule 7: the authorizer is not zero.
    ok.push(any_bits(c, &authorizer));
    // Rule 8: the recipient is zero exactly when the public amount is.
    let amount_nonzero = any_bits(c, &public_amount);
    let recipient_nonzero = any_bits(c, &recipient);
    ok.push(c.xor(amount_nonzero, recipient_nonzero).not());
    // Rules 9 and 10: the nullifiers differ, and so do the output commitments.
    ok.push(eq_bits(c, &nullifiers[0], &nullifiers[1]).not());
    ok.push(eq_bits(c, &commitments[0], &commitments[1]).not());
    let valid = any_bits(c, &ok.iter().map(|w| w.not()).collect::<Vec<_>>()).not();
    rows.rules += c.rows() - mark;

    let digest = hash(
        c,
        &mut tw,
        rows,
        TAG_STATEMENT,
        &[
            &nullifiers[0],
            &nullifiers[1],
            &commitments[0],
            &commitments[1],
            &bytes(0, 136),
        ],
    );
    let mut public = digest;
    public.push(valid);
    public.resize(PUBLIC_BITS, Wire::ZERO);
    public
}

fn hash(c: &mut Ckt, _tw: &mut Twins, rows: &mut Breakdown, t: u8, parts: &[&[Wire]]) -> Word {
    let mut message = tag(t);
    for p in parts {
        message.extend_from_slice(p);
    }
    hash_message(c, rows, &message)
}

fn hash_message(c: &mut Ckt, rows: &mut Breakdown, message: &[Wire]) -> Word {
    let len = message.len() / 8;
    let blocks = len.div_ceil(64).max(1);
    rows.compressions += blocks;
    let iv = flock::hash::param_iv();
    let mut h = std::array::from_fn(|i| {
        c.builder
            .constant(u64::from(iv[2 * i]) | (u64::from(iv[2 * i + 1]) << 32))
    });
    for block in 0..blocks {
        let mut bits = message[(block * 512).min(message.len())..((block + 1) * 512).min(message.len())].to_vec();
        bits.resize(512, Wire::ZERO);
        let m = std::array::from_fn(|i| {
            let bits: Vec<_> = bits[i * 64..i * 64 + 64].iter().map(|&w| c.pos(w)).collect();
            c.builder.pack(&bits)
        });
        let counter = c.builder.constant(if block + 1 == blocks {
            len as u64
        } else {
            (block as u64 + 1) * 64
        });
        let flags = c
            .builder
            .constant(if block + 1 == blocks { u64::from(u32::MAX) } else { 0 });
        h = c.builder.compress(h, m, counter, flags);
    }
    h.into_iter()
        .flat_map(|w| c.builder.bits(w, 64))
        .map(|at| Wire { at, neg: false })
        .collect()
}
/// All witness bits are constrained; the validity bit is fixed to one.
pub fn application(payload: &[u8]) -> Builder {
    application_inner(payload, false).0
}

/// Same final public digest as the leanVM single-spend guest (106 compressions).
pub fn application_vm(payload: &[u8]) -> (Builder, Breakdown) {
    application_inner(payload, true)
}

fn application_inner(payload: &[u8], vm_output: bool) -> (Builder, Breakdown) {
    assert_eq!(payload.len(), INPUT_BYTES);
    let mut builder = Builder::default();
    let input = payload
        .iter()
        .flat_map(|&b| (0..8).map(move |i| u64::from((b >> i) & 1)))
        .map(|b| {
            let at = builder.input(b);
            builder.boolean(at);
            Wire { at, neg: false }
        })
        .collect();
    let mut c = Ckt { builder, input };
    let mut rows = Breakdown::default();
    let public = build_counted(&mut c, &mut rows);
    let valid = c.pos(public[256]);
    let one = c.builder.one();
    c.builder.assert_eq(valid, one);
    let digest = if vm_output {
        hash_message(&mut c, &mut rows, &public[..256])
    } else {
        public[..256].to_vec()
    };
    for bits in digest.chunks(64) {
        let bits: Vec<_> = bits.iter().map(|&w| c.pos(w)).collect();
        let w = c.builder.pack(&bits);
        c.builder.expose(w);
    }
    (c.builder, rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_suite::shielded_blake2s::{generate, leanvm_input, reference};
    #[test]
    fn shapes_and_rejections() {
        for seed in 0..3 {
            let payload = leanvm_input(seed);
            let app = application(&payload);
            assert!(app.satisfied());
            let digest = reference::verify(&payload).unwrap();
            let public = app.public_values();
            let expected: Vec<_> = digest
                .chunks(8)
                .map(|b| primitives::field::F192::new(u64::from_le_bytes(b.try_into().unwrap()), 0, 0))
                .collect();
            assert_eq!(&public[public.len() - 4..], expected.as_slice());
            assert_eq!(app.compressions.len(), 105);
            let (matched, rows) = application_vm(&payload);
            assert!(matched.satisfied());
            assert_eq!(matched.compressions.len(), 106);
            let final_digest = primitives::hash::hash(&digest);
            let expected: Vec<_> = final_digest
                .chunks_exact(8)
                .map(|b| primitives::field::F192::new(u64::from_le_bytes(b.try_into().unwrap()), 0, 0))
                .collect();
            let public = matched.public_values();
            assert_eq!(&public[public.len() - 4..], expected.as_slice());
            if seed == 0 {
                // Independent receipt from leanVM's host/guest run, hometurf-L2/shielded.output.json.
                assert_eq!(
                    expected.iter().map(|v| v.c0).collect::<Vec<_>>(),
                    vec![
                        8148722794000879574,
                        12273388761951158148,
                        13463691297944637417,
                        5783332347444188522
                    ]
                );
                println!(
                    "matched gate rows={} swaps={} rules={} compressions={}",
                    matched.rows(),
                    rows.merkle_swaps,
                    rows.rules,
                    rows.compressions
                );
            }

            let mut bad = payload;
            bad[0] ^= 1;
            assert!(!application(&bad).satisfied());
            bad[0] ^= 1;
            bad[136 + 84] ^= 1;
            assert!(!application(&bad).satisfied());
        }
        for rule in &reference::Rule::ALL[1..] {
            let bad = generate::invalid(7, *rule);
            assert_eq!(reference::verify(&bad), Err(*rule));
            assert!(!application(&bad).satisfied(), "{rule:?}");
        }
    }
}
