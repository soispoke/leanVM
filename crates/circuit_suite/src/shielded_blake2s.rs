//! BLAKE2s edition of the two-input, two-output depth-20 shielded spend.
//! The SHA-256 baseline remains in `shielded`. Public bytes 0..32 are the digest, byte 32 is validity.

use crate::sha256::{Twins, add_many};
use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload};

pub const DEPTH: usize = 20;
pub const INPUT_BYTES: usize = 1680;
const NOTE_BYTES: usize = 32 + 32 + 16 + 4 + 32 * DEPTH;
const NOTES_AT: usize = 136;
const OUTPUTS_AT: usize = NOTES_AT + 2 * NOTE_BYTES;
const OUTPUT_BYTES: usize = 48;

const TAG_PK: u8 = 1;
const TAG_COMMIT: u8 = 2;
const TAG_NULL: u8 = 3;
const TAG_NODE: u8 = 4;
const TAG_INNER: u8 = 5;
const TAG_NK: u8 = 6;
const TAG_OCC: u8 = 7;
const TAG_STATEMENT: u8 = 8;

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
    pub hash_gates: usize,
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

/// BLAKE2s of a tag byte and fields.
fn hash(c: &mut Ckt, tw: &mut Twins, rows: &mut Breakdown, t: u8, parts: &[&[Wire]]) -> Word {
    let mut msg = tag(t);
    for p in parts {
        msg.extend_from_slice(p);
    }
    rows.compressions += (msg.len() / 8).div_ceil(64).max(1);
    let _ = tw;
    let before = c.rows();
    let result = crate::blake2s::blake2s(c, &msg);
    rows.hash_gates += c.rows() - before;
    result
}

/// The shielded transfer: the private 1,680-byte input; statement = the statement digest in bytes 0..32 and the
/// validity bit (rules 1 to 10) in byte 32.
pub struct ShieldedTransfer;

impl Workload for ShieldedTransfer {
    const NAME: &'static str = "shielded-blake2s";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        build_counted(c, &mut Breakdown::default())
    }

    fn instance(seed: u64) -> Instance {
        let payload = leanvm_input(seed as usize);
        instance_of(&payload)
    }

    /// A valid spend mutated to break exactly one rule, rule `1 + seed % 10`.
    fn invalid_instance(seed: u64) -> Option<Instance> {
        let rule = reference::Rule::ALL[1 + (seed % 10) as usize];
        Some(instance_of(&generate::invalid(seed, rule)))
    }
}

/// The statement a reference computes for an input: its digest, and whether it breaks no rule.
pub fn instance_of(payload: &[u8]) -> Instance {
    let (violated, digest) = reference::evaluate(payload);
    let mut statement = [0u8; 64];
    statement[..32].copy_from_slice(&digest.expect("a 1,680-byte input has a digest"));
    statement[32] = violated.is_empty() as u8;
    Instance {
        inputs: crate::bytes_to_bits(payload),
        statement,
    }
}

/// The reference: the challenge's Rust statement (`statement/src/lib.rs`, `verify`), ported, and its Python oracle's
/// `evaluate` (every violated rule, and the digest of any 1,680-byte input). Both are checked against the
/// challenge's public fixtures.
pub mod reference {

    use super::*;

    /// Position-specific inners for zero-value outputs: 1 and 2 as 32-byte words.
    const SINK: [[u8; 32]; 2] = {
        let mut sink = [[0u8; 32]; 2];
        sink[0][31] = 1;
        sink[1][31] = 2;
        sink
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Rule {
        Length,
        IndexRange,
        Membership,
        NonzeroInput,
        Conservation,
        ZeroOutputSink,
        PositiveOutputNotSink,
        AuthorizerNonzero,
        RecipientMatchesAmount,
        DistinctNullifiers,
        DistinctOutputs,
    }

    impl Rule {
        pub const ALL: [Rule; 11] = [
            Rule::Length,
            Rule::IndexRange,
            Rule::Membership,
            Rule::NonzeroInput,
            Rule::Conservation,
            Rule::ZeroOutputSink,
            Rule::PositiveOutputNotSink,
            Rule::AuthorizerNonzero,
            Rule::RecipientMatchesAmount,
            Rule::DistinctNullifiers,
            Rule::DistinctOutputs,
        ];

        pub const fn name(self) -> &'static str {
            match self {
                Rule::Length => "length",
                Rule::IndexRange => "index_range",
                Rule::Membership => "membership",
                Rule::NonzeroInput => "nonzero_input",
                Rule::Conservation => "conservation",
                Rule::ZeroOutputSink => "zero_output_sink",
                Rule::PositiveOutputNotSink => "positive_output_not_sink",
                Rule::AuthorizerNonzero => "authorizer_nonzero",
                Rule::RecipientMatchesAmount => "recipient_matches_amount",
                Rule::DistinctNullifiers => "distinct_nullifiers",
                Rule::DistinctOutputs => "distinct_outputs",
            }
        }
    }

    pub fn digest(message: &[u8]) -> [u8; 32] {
        crate::blake2s::blake2s_native(message)
    }

    fn word(input: &[u8], at: usize) -> [u8; 32] {
        input[at..at + 32].try_into().unwrap()
    }

    fn u128_at(input: &[u8], at: usize) -> u128 {
        u128::from_be_bytes(input[at..at + 16].try_into().unwrap())
    }

    fn same<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
        let mut difference = 0u8;
        for i in 0..N {
            difference |= a[i] ^ b[i];
        }
        difference == 0
    }

    fn hash2(tag: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut message = [0u8; 65];
        message[0] = tag;
        message[1..33].copy_from_slice(a);
        message[33..65].copy_from_slice(b);
        digest(&message)
    }

    fn hash_tail<const N: usize>(tag: u8, a: &[u8; 32], tail: [u8; N]) -> [u8; 32] {
        let mut message = [0u8; 65];
        message[0] = tag;
        message[1..33].copy_from_slice(a);
        message[33..33 + N].copy_from_slice(&tail);
        digest(&message[..33 + N])
    }

    fn node(current: &[u8; 32], sibling: &[u8; 32], bit: u32) -> [u8; 32] {
        let mask = 0u8.wrapping_sub(bit as u8);
        let mut message = [0u8; 65];
        message[0] = TAG_NODE;
        for i in 0..32 {
            let swap = (current[i] ^ sibling[i]) & mask;
            message[1 + i] = current[i] ^ swap;
            message[33 + i] = sibling[i] ^ swap;
        }
        digest(&message)
    }

    /// The commitment of input note `k` and the root its path leads to.
    fn note_root(input: &[u8], k: usize) -> ([u8; 32], [u8; 32]) {
        let at = NOTES_AT + k * NOTE_BYTES;
        let spend_key = word(input, at);
        let rho = word(input, at + 32);
        let value = u128_at(input, at + 64);
        let index = u32::from_be_bytes(input[at + 80..at + 84].try_into().unwrap());
        let mut owner_message = [0u8; 33];
        owner_message[0] = TAG_PK;
        owner_message[1..].copy_from_slice(&spend_key);
        let owner = digest(&owner_message);
        let inner = hash2(TAG_INNER, &owner, &rho);
        let commitment = hash_tail::<16>(TAG_COMMIT, &inner, value.to_be_bytes());
        let mut current = commitment;
        for level in 0..DEPTH {
            let sibling = word(input, at + 84 + 32 * level);
            current = node(&current, &sibling, (index >> level) & 1);
        }
        (commitment, current)
    }

    /// The Rust reference's `verify`: the statement digest, or the first violated rule.
    pub fn verify(input: &[u8]) -> Result<[u8; 32], Rule> {
        if input.len() != INPUT_BYTES {
            return Err(Rule::Length);
        }
        let root = word(input, 0);
        let domain = word(input, 32);
        let public_amount = u128_at(input, 64);
        let fee = u128_at(input, 80);
        let recipient: [u8; 20] = input[96..116].try_into().unwrap();
        let authorizer: [u8; 20] = input[116..136].try_into().unwrap();

        let mut nullifiers = [[0u8; 32]; 2];
        let mut values = [0u128; 2];
        for k in 0..2 {
            let at = NOTES_AT + k * NOTE_BYTES;
            let spend_key = word(input, at);
            let value = u128_at(input, at + 64);
            let index = u32::from_be_bytes(input[at + 80..at + 84].try_into().unwrap());
            if index >= 1 << DEPTH {
                return Err(Rule::IndexRange);
            }
            let (commitment, current) = note_root(input, k);
            if !(same(&current, &root) | (value == 0)) {
                return Err(Rule::Membership);
            }
            let occurrence = hash_tail::<4>(TAG_OCC, &commitment, index.to_be_bytes());
            let nullifier_key = hash2(TAG_NK, &domain, &spend_key);
            nullifiers[k] = hash2(TAG_NULL, &nullifier_key, &occurrence);
            values[k] = value;
        }

        let mut commitments = [[0u8; 32]; 2];
        let mut outputs = [0u128; 2];
        for k in 0..2 {
            let at = OUTPUTS_AT + k * OUTPUT_BYTES;
            let inner = word(input, at);
            let value = u128_at(input, at + 32);
            let is_sink = same(&inner, &SINK[0]) | same(&inner, &SINK[1]);
            if !((value != 0) | same(&inner, &SINK[k])) {
                return Err(Rule::ZeroOutputSink);
            }
            if !((value == 0) | !is_sink) {
                return Err(Rule::PositiveOutputNotSink);
            }
            commitments[k] = hash_tail::<16>(TAG_COMMIT, &inner, value.to_be_bytes());
            outputs[k] = value;
        }

        let (inputs_low, inputs_carry) = values[0].overflowing_add(values[1]);
        let inputs_high = inputs_carry as u32;
        let mut outputs_low = 0u128;
        let mut outputs_high = 0u32;
        for part in [outputs[0], outputs[1], public_amount, fee] {
            let (sum, carry) = outputs_low.overflowing_add(part);
            outputs_low = sum;
            outputs_high += carry as u32;
        }
        if (inputs_low == 0) & (inputs_high == 0) {
            return Err(Rule::NonzeroInput);
        }
        if !((inputs_low == outputs_low) & (inputs_high == outputs_high)) {
            return Err(Rule::Conservation);
        }
        if same(&authorizer, &[0u8; 20]) {
            return Err(Rule::AuthorizerNonzero);
        }
        if (public_amount == 0) != same(&recipient, &[0u8; 20]) {
            return Err(Rule::RecipientMatchesAmount);
        }
        if same(&nullifiers[0], &nullifiers[1]) {
            return Err(Rule::DistinctNullifiers);
        }
        if same(&commitments[0], &commitments[1]) {
            return Err(Rule::DistinctOutputs);
        }
        Ok(statement_digest(input, &nullifiers, &commitments))
    }

    fn statement_digest(input: &[u8], nullifiers: &[[u8; 32]; 2], commitments: &[[u8; 32]; 2]) -> [u8; 32] {
        let mut statement = [0u8; 265];
        statement[0] = TAG_STATEMENT;
        statement[1..33].copy_from_slice(&nullifiers[0]);
        statement[33..65].copy_from_slice(&nullifiers[1]);
        statement[65..97].copy_from_slice(&commitments[0]);
        statement[97..129].copy_from_slice(&commitments[1]);
        statement[129..265].copy_from_slice(&input[..136]);
        digest(&statement)
    }

    /// The Python oracle's `evaluate`: every violated rule in rule order, and the digest of any 1,680-byte input.
    pub fn evaluate(input: &[u8]) -> (Vec<Rule>, Option<[u8; 32]>) {
        if input.len() != INPUT_BYTES {
            return (vec![Rule::Length], None);
        }
        let mut violated = Vec::new();
        let root = word(input, 0);
        let domain = word(input, 32);
        let public_amount = u128_at(input, 64);
        let fee = u128_at(input, 80);
        let mut nullifiers = [[0u8; 32]; 2];
        let mut total_in = 0u128;
        let mut total_in_high = 0u32;
        for (k, nullifier) in nullifiers.iter_mut().enumerate() {
            let at = NOTES_AT + k * NOTE_BYTES;
            let spend_key = word(input, at);
            let value = u128_at(input, at + 64);
            let index = u32::from_be_bytes(input[at + 80..at + 84].try_into().unwrap());
            if index >= 1 << DEPTH {
                violated.push(Rule::IndexRange);
            }
            let (commitment, current) = note_root(input, k);
            if value != 0 && current != root {
                violated.push(Rule::Membership);
            }
            let occurrence = hash_tail::<4>(TAG_OCC, &commitment, index.to_be_bytes());
            let nullifier_key = hash2(TAG_NK, &domain, &spend_key);
            *nullifier = hash2(TAG_NULL, &nullifier_key, &occurrence);
            let (s, carry) = total_in.overflowing_add(value);
            total_in = s;
            total_in_high += carry as u32;
        }
        if total_in == 0 && total_in_high == 0 {
            violated.push(Rule::NonzeroInput);
        }
        let mut commitments = [[0u8; 32]; 2];
        let mut total_out = 0u128;
        let mut total_out_high = 0u32;
        for k in 0..2 {
            let at = OUTPUTS_AT + k * OUTPUT_BYTES;
            let inner = word(input, at);
            let value = u128_at(input, at + 32);
            if value == 0 && inner != SINK[k] {
                violated.push(Rule::ZeroOutputSink);
            }
            if value != 0 && (inner == SINK[0] || inner == SINK[1]) {
                violated.push(Rule::PositiveOutputNotSink);
            }
            commitments[k] = hash_tail::<16>(TAG_COMMIT, &inner, value.to_be_bytes());
            let (s, carry) = total_out.overflowing_add(value);
            total_out = s;
            total_out_high += carry as u32;
        }
        for part in [public_amount, fee] {
            let (s, carry) = total_out.overflowing_add(part);
            total_out = s;
            total_out_high += carry as u32;
        }
        if (total_in, total_in_high) != (total_out, total_out_high) {
            violated.push(Rule::Conservation);
        }
        if input[116..136].iter().all(|&b| b == 0) {
            violated.push(Rule::AuthorizerNonzero);
        }
        if (public_amount == 0) != input[96..116].iter().all(|&b| b == 0) {
            violated.push(Rule::RecipientMatchesAmount);
        }
        if nullifiers[0] == nullifiers[1] {
            violated.push(Rule::DistinctNullifiers);
        }
        if commitments[0] == commitments[1] {
            violated.push(Rule::DistinctOutputs);
        }
        violated.sort_by_key(|r| *r as u8);
        violated.dedup();
        (violated, Some(statement_digest(input, &nullifiers, &commitments)))
    }
}

/// Spends for instances, after the oracle's builder: real notes are leaves of one sparse tree whose other
/// subtrees are pseudo-random stand-ins.
pub mod generate {
    use std::collections::HashMap;

    use super::reference::{Rule, digest, evaluate};
    use super::*;

    const U128_TOP: u128 = u128::MAX;

    /// A seeded byte source (splitmix64).
    pub struct Rng(u64);

    impl Rng {
        pub fn new(seed: u64) -> Self {
            Rng(seed ^ 0x5350_454e_4400_0000)
        }

        pub fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next_u64() as u8)
        }

        pub fn below(&mut self, n: u128) -> u128 {
            let r = (self.next_u64() as u128) << 64 | self.next_u64() as u128;
            r % n
        }

        /// Nonzero bytes that are not a sink.
        pub fn nonzero<const N: usize>(&mut self) -> [u8; N] {
            loop {
                let v: [u8; N] = self.bytes();
                let sink = N == 32 && v[..31].iter().all(|&b| b == 0) && (v[31] == 1 || v[31] == 2);
                if v.iter().any(|&b| b != 0) && !sink {
                    return v;
                }
            }
        }
    }

    #[derive(Clone)]
    pub struct Note {
        pub spend_key: [u8; 32],
        pub rho: [u8; 32],
        pub value: u128,
        pub index: u32,
        pub siblings: Vec<[u8; 32]>,
    }

    #[derive(Clone)]
    pub struct Spend {
        pub root: [u8; 32],
        pub domain: [u8; 32],
        pub public_amount: u128,
        pub fee: u128,
        pub recipient: [u8; 20],
        pub authorizer: [u8; 20],
        pub inputs: [Note; 2],
        pub outputs: [([u8; 32], u128); 2],
    }

    impl Spend {
        pub fn encode(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(INPUT_BYTES);
            out.extend_from_slice(&self.root);
            out.extend_from_slice(&self.domain);
            out.extend_from_slice(&self.public_amount.to_be_bytes());
            out.extend_from_slice(&self.fee.to_be_bytes());
            out.extend_from_slice(&self.recipient);
            out.extend_from_slice(&self.authorizer);
            for n in &self.inputs {
                out.extend_from_slice(&n.spend_key);
                out.extend_from_slice(&n.rho);
                out.extend_from_slice(&n.value.to_be_bytes());
                out.extend_from_slice(&n.index.to_be_bytes());
                for s in &n.siblings {
                    out.extend_from_slice(s);
                }
            }
            for (inner, value) in &self.outputs {
                out.extend_from_slice(inner);
                out.extend_from_slice(&value.to_be_bytes());
            }
            assert_eq!(out.len(), INPUT_BYTES);
            out
        }
    }

    fn tagged(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = vec![tag];
        for p in parts {
            m.extend_from_slice(p);
        }
        digest(&m)
    }

    pub fn commitment(n: &Note) -> [u8; 32] {
        let owner = tagged(TAG_PK, &[&n.spend_key]);
        let inner = tagged(TAG_INNER, &[&owner, &n.rho]);
        tagged(TAG_COMMIT, &[&inner, &n.value.to_be_bytes()])
    }

    /// A depth-20 tree holding a few leaves; every other subtree is a pseudo-random stand-in.
    struct SparseTree {
        seed: [u8; 16],
        leaves: HashMap<u32, [u8; 32]>,
        memo: HashMap<(usize, u32), [u8; 32]>,
    }

    impl SparseTree {
        fn node(&mut self, level: usize, pos: u32) -> [u8; 32] {
            if let Some(&v) = self.memo.get(&(level, pos)) {
                return v;
            }
            let (lo, hi) = ((pos as u64) << level, ((pos as u64) + 1) << level);
            let v = if !self.leaves.keys().any(|&i| lo <= i as u64 && (i as u64) < hi) {
                let mut m = self.seed.to_vec();
                m.push(level as u8);
                m.extend_from_slice(&pos.to_be_bytes());
                digest(&m)
            } else if level == 0 {
                self.leaves[&pos]
            } else {
                let (l, r) = (self.node(level - 1, 2 * pos), self.node(level - 1, 2 * pos + 1));
                tagged(TAG_NODE, &[&l, &r])
            };
            self.memo.insert((level, pos), v);
            v
        }

        fn path(&mut self, index: u32) -> Vec<[u8; 32]> {
            (0..DEPTH)
                .map(|level| self.node(level, ((index & 0xf_ffff) >> level) ^ 1))
                .collect()
        }
    }

    #[derive(Default, Clone, Copy)]
    pub struct Shape {
        pub dummy: [bool; 2],
        pub indices: Option<[u32; 2]>,
        pub same_key: bool,
        pub same_note: bool,
        pub same_body: bool,
    }

    /// A spend whose real inputs are members of one tree.
    pub fn build(
        rng: &mut Rng,
        in_values: [u128; 2],
        out_values: [u128; 2],
        public_amount: u128,
        fee: u128,
        shape: Shape,
    ) -> Spend {
        let mut indices = shape.indices.unwrap_or_else(|| {
            let i0 = rng.below(1 << DEPTH) as u32;
            let mut i1 = rng.below(1 << DEPTH) as u32;
            while i1 == i0 && !shape.same_note {
                i1 = rng.below(1 << DEPTH) as u32;
            }
            [i0, i1]
        });
        let mut keys = [rng.bytes::<32>(), rng.bytes::<32>()];
        let mut rhos = [rng.bytes::<32>(), rng.bytes::<32>()];
        if shape.same_key || shape.same_note || shape.same_body {
            keys[1] = keys[0];
        }
        if shape.same_note || shape.same_body {
            rhos[1] = rhos[0];
        }
        if shape.same_note {
            indices[1] = indices[0];
        }
        let mut notes: [Note; 2] = std::array::from_fn(|k| Note {
            spend_key: keys[k],
            rho: rhos[k],
            value: in_values[k],
            index: indices[k],
            siblings: vec![],
        });
        let leaves: HashMap<u32, [u8; 32]> = (0..2)
            .filter(|&k| !shape.dummy[k])
            .map(|k| (notes[k].index, commitment(&notes[k])))
            .collect();
        let any_leaf = !leaves.is_empty();
        let mut tree = SparseTree {
            seed: rng.bytes(),
            leaves,
            memo: HashMap::new(),
        };
        for (k, note) in notes.iter_mut().enumerate() {
            note.siblings = if shape.dummy[k] {
                (0..DEPTH).map(|_| rng.bytes()).collect()
            } else {
                tree.path(note.index)
            };
        }
        let root = if any_leaf { tree.node(DEPTH, 0) } else { rng.bytes() };
        let sink = |k: usize| {
            let mut s = [0u8; 32];
            s[31] = k as u8 + 1;
            s
        };
        let outputs =
            std::array::from_fn(|k| (if out_values[k] == 0 { sink(k) } else { rng.nonzero() }, out_values[k]));
        let recipient = if public_amount != 0 { rng.nonzero() } else { [0u8; 20] };
        Spend {
            root,
            domain: rng.bytes(),
            public_amount,
            fee,
            recipient,
            authorizer: rng.nonzero(),
            inputs: notes,
            outputs,
        }
    }

    /// A random valid spend: shapes and values vary with the seed (a funded pair, a withdrawal, one dummy input
    /// either side, values up to `2^128 - 1`).
    pub fn spend(seed: u64) -> Spend {
        let mut rng = Rng::new(seed);
        let dummy = [[false, false], [false, true], [true, false], [false, false]][(seed % 4) as usize];
        let big = seed % 3 == 2;
        let draw = |rng: &mut Rng| {
            if big {
                U128_TOP - rng.below(1 << 20)
            } else {
                1 + rng.below(1 << 64)
            }
        };
        let in_values: [u128; 2] = std::array::from_fn(|k| if dummy[k] { 0 } else { draw(&mut rng) });
        // The total, up to 2^129 - 2, as a carry and a low word.
        let (total, carry) = in_values[0].overflowing_add(in_values[1]);
        let small = |rng: &mut Rng, bits: u32| rng.below((1u128 << bits).min(total / 4 + 1));
        let public_amount = if seed % 2 == 1 { small(&mut rng, 40) } else { 0 };
        let fee = small(&mut rng, 20);
        // The rest goes to the two outputs, each below 2^128.
        let (rest, borrow0) = total.overflowing_sub(public_amount);
        let (rest, borrow1) = rest.overflowing_sub(fee);
        let high = carry as u8 - borrow0 as u8 - borrow1 as u8;
        let (o0, o1) = if high == 1 {
            // 2^128 + rest = (2^128 - 1) + (rest + 1).
            (U128_TOP, rest + 1)
        } else {
            let cut = rng.below(rest + 1);
            (cut, rest - cut)
        };
        build(
            &mut rng,
            in_values,
            [o0, o1],
            public_amount,
            fee,
            Shape {
                dummy,
                ..Shape::default()
            },
        )
    }

    /// The bytes of a valid spend from a seed; the reference accepts it.
    pub fn valid(seed: u64) -> Vec<u8> {
        let payload = spend(seed).encode();
        let (violated, _) = evaluate(&payload);
        assert!(violated.is_empty(), "seed {seed}: {violated:?}");
        payload
    }

    /// A valid spend mutated to break exactly `rule`.
    pub fn invalid(seed: u64, rule: Rule) -> Vec<u8> {
        let mut rng = Rng::new(seed ^ 0xbad);
        let base = |rng: &mut Rng| build(rng, [700, 300], [600, 350], 0, 50, Shape::default());
        let s = match rule {
            Rule::IndexRange => {
                let mut s = base(&mut rng);
                s.inputs[(seed % 2) as usize].index |= 1 << (DEPTH + (seed as usize % 12));
                s
            }
            Rule::Membership => {
                let mut s = base(&mut rng);
                let (k, level) = ((seed % 2) as usize, (seed as usize / 2) % DEPTH);
                s.inputs[k].siblings[level][(seed as usize) % 32] ^= 1 << (seed % 8);
                s
            }
            Rule::NonzeroInput => build(
                &mut rng,
                [0, 0],
                [0, 0],
                0,
                0,
                Shape {
                    dummy: [true, true],
                    ..Shape::default()
                },
            ),
            Rule::Conservation => {
                let mut s = base(&mut rng);
                s.outputs[0].1 += 1;
                s
            }
            Rule::ZeroOutputSink => {
                let mut s = build(&mut rng, [700, 300], [0, 950], 0, 50, Shape::default());
                s.outputs[0].0[31] = 2;
                s
            }
            Rule::PositiveOutputNotSink => {
                let mut s = base(&mut rng);
                s.outputs[(seed % 2) as usize].0 = [0u8; 32];
                s.outputs[(seed % 2) as usize].0[31] = 1 + (seed / 2 % 2) as u8;
                s
            }
            Rule::AuthorizerNonzero => {
                let mut s = base(&mut rng);
                s.authorizer = [0u8; 20];
                s
            }
            Rule::RecipientMatchesAmount => {
                let mut s = base(&mut rng);
                s.recipient = rng.nonzero();
                s
            }
            Rule::DistinctNullifiers => build(
                &mut rng,
                [500, 500],
                [900, 50],
                0,
                50,
                Shape {
                    same_note: true,
                    ..Shape::default()
                },
            ),
            Rule::DistinctOutputs => {
                let mut s = build(&mut rng, [700, 300], [500, 500], 0, 0, Shape::default());
                s.outputs[1].0 = s.outputs[0].0;
                s
            }
            Rule::Length => panic!("the length is structural"),
        };
        let payload = s.encode();
        let (violated, _) = evaluate(&payload);
        assert_eq!(violated, vec![rule], "seed {seed}");
        payload
    }
}

use std::collections::BTreeMap;
pub fn leanvm_input(i: usize) -> Vec<u8> {
    let mut draw = Draw::new(i);

    // Two notes, each owned by its own key: values below 2^64, so every sum fits.
    let keys: [[u8; 32]; 2] = [draw.bytes(), draw.bytes()];
    let rhos: [[u8; 32]; 2] = [draw.bytes(), draw.bytes()];
    let mut values = [u128::from(draw.u64() >> 1), u128::from(draw.u64() >> 1)];
    // Two distinct leaves of the 2^20.
    let index_0 = draw.u64() as u32 % (1 << DEPTH);
    let index_1 = (index_0 + 1 + draw.u64() as u32 % ((1 << DEPTH) - 1)) % (1 << DEPTH);

    // The shape decides what leaves the pool, and which notes are empty.
    let shape = i % 3;
    if shape == 2 {
        values[1] = 0;
    }
    let total = values[0] + values[1];
    let fee = total / 1000;
    let public_amount = if shape == 1 { total / 2 } else { 0 };
    let out_0 = total - fee - public_amount;
    let outputs: [(u128, [u8; 32]); 2] = match shape {
        // The withdrawal's second output is empty: its inner part is its sink, 2.
        1 => [(out_0, draw.bytes()), (0, sink(1))],
        _ => [(out_0 - out_0 / 3, draw.bytes()), (out_0 / 3, draw.bytes())],
    };
    let recipient: [u8; 20] = if public_amount == 0 { [0; 20] } else { draw.bytes() };
    let authorizer: [u8; 20] = draw.bytes();
    let domain: [u8; 32] = draw.bytes();

    // Both inputs in one tree, whatever their values.
    let commitments = [0, 1].map(|k| note_commitment(&keys[k], &rhos[k], values[k]));
    let (root, paths) = tree([(index_0, commitments[0]), (index_1, commitments[1])]);

    // Laid out at the specification's offsets.
    let mut input = [0; INPUT_BYTES];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        input[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&root);
    put(&domain);
    put(&public_amount.to_be_bytes());
    put(&fee.to_be_bytes());
    put(&recipient);
    put(&authorizer);
    for (k, index) in [index_0, index_1].into_iter().enumerate() {
        put(&keys[k]);
        put(&rhos[k]);
        put(&values[k].to_be_bytes());
        put(&index.to_be_bytes());
        paths[k].iter().for_each(|sibling| put(sibling));
    }
    for (value, inner) in outputs {
        put(&inner);
        put(&value.to_be_bytes());
    }
    assert_eq!(at, INPUT_BYTES);
    input.to_vec()
}

/// BLAKE2s-256 of a tag byte, then the parts: every hash of the specification.
fn tagged(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut message = vec![tag];
    for part in parts {
        message.extend_from_slice(part);
    }
    crate::blake2s::blake2s_native(&message)
}

/// A note's commitment, from its spend key, randomness and value.
fn note_commitment(spend_key: &[u8; 32], rho: &[u8; 32], value: u128) -> [u8; 32] {
    let owner = tagged(1, &[spend_key]);
    let inner = tagged(5, &[&owner, rho]);
    tagged(2, &[&inner, &value.to_be_bytes()])
}

/// The root of a depth-20 tree holding `leaves` and nothing else, and each leaf's siblings, the leaf's first.
///
/// An empty leaf is 32 zero bytes, and an empty subtree the hash of two empty ones.
fn tree(leaves: [(u32, [u8; 32]); 2]) -> ([u8; 32], [[[u8; 32]; DEPTH]; 2]) {
    let mut empty = [0; 32];
    // The nodes present at the current level, by position.
    let mut level: BTreeMap<u32, [u8; 32]> = leaves.into_iter().collect();
    // Each level's siblings of the two leaves' paths, the leaf level first.
    let mut siblings = Vec::with_capacity(DEPTH);
    for depth in 0..DEPTH {
        // A sibling is present, or an empty subtree.
        siblings.push(leaves.map(|(index, _)| *level.get(&((index >> depth) ^ 1)).unwrap_or(&empty)));
        // One level up: each parent from its two children.
        let parents: BTreeMap<u32, [u8; 32]> = (level.keys())
            .map(|&position| {
                let child = |p: u32| *level.get(&p).unwrap_or(&empty);
                let left = position & !1;
                (position >> 1, tagged(4, &[&child(left), &child(left | 1)]))
            })
            .collect();
        level = parents;
        empty = tagged(4, &[&empty, &empty]);
    }
    let paths = [0, 1].map(|k| std::array::from_fn(|depth| siblings[depth][k]));
    (level[&0], paths)
}

/// The inner part an empty output in position `k` must have: `k + 1` as a 32-byte big-endian word.
const fn sink(k: usize) -> [u8; 32] {
    let mut inner = [0; 32];
    inner[31] = k as u8 + 1;
    inner
}

/// A deterministic stream of bytes: BLAKE2s of a label, the spend's index and a counter.
struct Draw {
    /// The spend's index.
    spend: u64,
    /// Draws made so far.
    count: u64,
}

impl Draw {
    const fn new(spend: usize) -> Self {
        Self {
            spend: spend as u64,
            count: 0,
        }
    }

    /// The next `N` bytes, at most 32.
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        self.count += 1;
        let block = tagged(
            0xFF,
            &[b"shielded", &self.spend.to_le_bytes(), &self.count.to_le_bytes()],
        );
        block[..N].try_into().unwrap()
    }

    /// The next 64 bits.
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }
}
