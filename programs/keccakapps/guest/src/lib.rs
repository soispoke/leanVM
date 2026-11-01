//! Exact L6 Keccak application predicates; reference verification ported without changing rules.
#![no_std]
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
    let mut words = [0u64; 34];
    assert!(message.len() <= words.len() * 8);
    for (i, &byte) in message.iter().enumerate() {
        words[i / 8] |= (byte as u64) << (8 * (i % 8));
    }
    let lanes = leanvm_guest::keccak::keccak256(&words, message.len());
    let mut bytes = [0; 32];
    for (slot, word) in bytes.chunks_exact_mut(8).zip(lanes) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    bytes
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

/// The exact 64-byte circuit-suite public statement: digest then validity byte.
pub fn shielded_statement(input: &[u8; INPUT_BYTES]) -> [u64; 8] {
    let (digest, valid) = match verify(input) {
        Ok(digest) => (digest, true),
        Err(_) => {
            let mut nullifiers = [[0; 32]; 2];
            let domain = word(input, 32);
            for (k, nullifier) in nullifiers.iter_mut().enumerate() {
                let at = NOTES_AT + k * NOTE_BYTES;
                let (commitment, _) = note_root(input, k);
                let index = input[at + 80..at + 84].try_into().unwrap();
                let occurrence = hash_tail::<4>(TAG_OCC, &commitment, index);
                let key = hash2(TAG_NK, &domain, &word(input, at));
                *nullifier = hash2(TAG_NULL, &key, &occurrence);
            }
            let commitments = core::array::from_fn(|k| {
                let at = OUTPUTS_AT + k * OUTPUT_BYTES;
                hash_tail::<16>(
                    TAG_COMMIT,
                    &word(input, at),
                    input[at + 32..at + 48].try_into().unwrap(),
                )
            });
            (statement_digest(input, &nullifiers, &commitments), false)
        }
    };
    let mut statement = [0; 8];
    for i in 0..4 {
        statement[i] = u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap());
    }
    statement[4] = u64::from(valid);
    statement
}

/// Leaf 32 bytes, then 16 sibling/Boolean-path records (5 words each).
pub fn merkle_root(input: &[u64; 84]) -> Option<[u64; 4]> {
    let mut current = leanvm_guest::keccak::keccak256(&input[..4], 32);
    for level in 0..16 {
        let at = 4 + level * 5;
        let bit = input[at + 4];
        if bit > 1 {
            return None;
        }
        let mut pair = [0; 8];
        let (left, right) = if bit == 1 {
            (&current[..], &input[at..at + 4])
        } else {
            (&input[at..at + 4], &current[..])
        };
        pair[..4].copy_from_slice(left);
        pair[4..].copy_from_slice(right);
        current = leanvm_guest::keccak::keccak256(&pair, 64);
    }
    Some(current)
}
