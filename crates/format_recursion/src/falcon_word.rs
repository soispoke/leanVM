//! Falcon integer relation over the application-independent byte lowering.
//! Callers must bind all supplied words to the SHAKE and input frontend.
use crate::{native_hash::Word, word_lowering::Lowering};
const Q: u64 = 12289;
pub struct Signed {
    pub magnitude: Vec<Word>,
    pub sign: Word,
}
pub struct Stage {
    pub name: &'static str,
    pub rows: usize,
    pub queries: usize,
}
fn mark(c: &Lowering, rows: &mut usize, queries: &mut usize, stages: &mut Vec<Stage>, name: &'static str) {
    stages.push(Stage {
        name,
        rows: c.b.rows() - *rows,
        queries: c.query_count() - *queries,
    });
    *rows = c.b.rows();
    *queries = c.query_count();
}
fn residue(c: &mut Lowering, value: &Signed) -> Vec<Word> {
    c.b.boolean(value.sign);
    let negative = c.sub_mod(&[Word::ZERO; 2], &value.magnitude, Q);
    value
        .magnitude
        .iter()
        .zip(negative)
        .map(|(&positive, negative)| c.b.select(value.sign, positive, negative))
        .collect()
}
/// Assert the modular product relation and norm for already decoded inputs.
/// Compaction, encoding budget and digest binding remain frontend obligations.
pub fn relation(
    c: &mut Lowering,
    h: &[Vec<Word>],
    s1: &[Signed],
    s2: &[Signed],
    challenge: &[Vec<Word>],
) -> Vec<Stage> {
    let n = h.len();
    assert!(n.is_power_of_two() && n == s1.len() && n == s2.len() && n == challenge.len());
    let mut stages = Vec::new();
    let (mut rows, mut queries) = (c.b.rows(), c.query_count());
    for value in h {
        c.assert_less_than(value, Q);
    }
    for value in s1 {
        c.assert_less_than(&value.magnitude, Q / 2 + 1);
    }
    for value in s2 {
        c.assert_less_than(&value.magnitude, 2048);
    }
    mark(c, &mut rows, &mut queries, &mut stages, "bounds");
    let s2v: Vec<_> = s2.iter().map(|v| residue(c, v)).collect();
    let s1v: Vec<_> = s1.iter().map(|v| residue(c, v)).collect();
    let d: Vec<_> = challenge
        .iter()
        .zip(s1v)
        .map(|(cc, s1)| {
            let reduced = c.remainder(cc, Q);
            c.sub_mod(&reduced, &s1, Q)
        })
        .collect();
    mark(c, &mut rows, &mut queries, &mut stages, "modular conversion");
    let roots = circuit_suite::falcon::zetas(Q, n.trailing_zeros() as usize);
    let fs2 = c.ntt(s2v, &roots, Q);
    mark(c, &mut rows, &mut queries, &mut stages, "NTT(s2)");
    let fh = c.ntt(h.to_vec(), &roots, Q);
    mark(c, &mut rows, &mut queries, &mut stages, "NTT(h)");
    let fd = c.ntt(d, &roots, Q);
    mark(c, &mut rows, &mut queries, &mut stages, "NTT(c-s1)");
    for ((x, y), z) in fs2.iter().zip(&fh).zip(&fd) {
        let product = c.mul_mod(x, y, Q);
        let left = c.pack(&product);
        let right = c.pack(z);
        c.b.assert_eq(left, right);
    }
    mark(c, &mut rows, &mut queries, &mut stages, "pointwise products");
    let mut sum = vec![Word::ZERO; 5];
    for value in s1.iter().chain(s2) {
        let mut square = c.mul(&value.magnitude, &value.magnitude);
        square.resize(5, Word::ZERO);
        let (next, carry) = c.add(&sum, &square);
        c.b.assert_eq(carry, Word::ZERO);
        sum = next;
    }
    c.assert_less_than(&sum, 34034726 + 1);
    mark(c, &mut rows, &mut queries, &mut stages, "norm");
    stages
}

fn shake(c: &mut Lowering, input: &[Word], output_len: usize) -> Vec<Word> {
    let mut padded = input.to_vec();
    padded.push(c.b.constant(31));
    padded.resize(padded.len().next_multiple_of(136), Word::ZERO);
    let last = padded.len() - 1;
    let flag = c.b.constant(128);
    padded[last] = c.b.gate(padded[last], c.b.one(), flag);
    let mut state = [Word::ZERO; 25];
    for block in padded.chunks_exact(136) {
        for (i, word) in block.chunks_exact(8).enumerate() {
            let packed = c.pack(word);
            state[i] = c.b.gate(state[i], c.b.one(), packed);
        }
        state = c.b.keccak_f(state);
    }
    let mut out = Vec::with_capacity(output_len);
    while out.len() < output_len {
        for &lane in &state[..17] {
            if out.len() >= output_len {
                break;
            }
            out.extend(c.unpack(lane, 8));
        }
        if out.len() < output_len {
            state = c.b.keccak_f(state);
        }
    }
    out.truncate(output_len);
    out
}
fn compact(c: &mut Lowering, mut payload: Vec<Vec<Word>>) -> Vec<Vec<Word>> {
    let n = payload.len();
    let cutoff = [c.b.constant(61445 & 255), c.b.constant(61445 >> 8)];
    let mut reject = Vec::new();
    let mut valid = Vec::new();
    let one = c.b.one();
    for sample in &payload {
        let (_, no_borrow) = c.subtract(sample, &cutoff);
        reject.push(no_borrow);
        valid.push(c.b.gate(no_borrow, one, one));
    }
    let mut count = Word::ZERO;
    let mut shift = Vec::new();
    for &rej in &reject {
        shift.push(c.b.bits(count, 7));
        let (next, carry) = c.add8(count, rej, Word::ZERO);
        c.b.assert_eq(carry, Word::ZERO);
        count = next;
    }
    c.b.bits(count, 7);
    let mut lim = n;
    for k in 0..7 {
        let distance = 1usize << k;
        let new_lim = n.min(512 + 128 - (1usize << (k + 1)));
        let src_lim = lim.min(new_lim + distance);
        let moving: Vec<_> = (0..src_lim)
            .map(|i| c.b.gate(valid[i], shift[i][k], Word::ZERO))
            .collect();
        let mut new_payload = Vec::new();
        let mut new_valid = Vec::new();
        let mut new_shift = Vec::new();
        for i in 0..new_lim {
            let mut v = c.b.gate(valid[i], one, moving[i]);
            if i + distance < src_lim {
                let selector = moving[i + distance];
                new_payload.push(
                    payload[i]
                        .iter()
                        .zip(&payload[i + distance])
                        .map(|(&a, &b)| c.b.select(selector, a, b))
                        .collect(),
                );
                new_shift.push(
                    (0..7)
                        .map(|bit| {
                            if bit <= k {
                                Word::ZERO
                            } else {
                                c.b.select(selector, shift[i][bit], shift[i + distance][bit])
                            }
                        })
                        .collect(),
                );
                v = c.b.gate(v, one, selector);
            } else {
                new_payload.push(payload[i].clone());
                new_shift.push(shift[i].clone());
            }
            new_valid.push(v);
        }
        payload = new_payload;
        shift = new_shift;
        valid = new_valid;
        lim = new_lim;
    }
    for &v in &valid[..512] {
        c.b.assert_eq(v, one);
    }
    payload.truncate(512);
    payload
}
/// Fixed decoded Falcon-512 statement with native SHAKE and shared byte tables.
/// The returned witness still needs `Lowering::setup` and its joint proof.
pub fn application(fixture: &circuit_suite::falcon::Vector, identity: [u8; 32]) -> (Lowering, Vec<Stage>) {
    let mut c = Lowering::default();
    let (mut rows, mut queries) = (0, 0);
    let mut stages = Vec::new();
    let h: Vec<_> = fixture
        .h
        .iter()
        .map(|&v| {
            let w = c.b.input(v);
            c.unpack(w, 2)
        })
        .collect();
    let msg: Vec<_> = fixture.msg.iter().map(|&v| c.byte(v)).collect();
    let nonce: Vec<_> = fixture.nonce.iter().map(|&v| c.byte(v)).collect();
    let mut signed = |values: &[i64]| {
        values
            .iter()
            .map(|&v| {
                let w = c.b.input(v.unsigned_abs());
                let magnitude = c.unpack(w, 2);
                let sign = c.b.input(u64::from(v < 0));
                Signed { magnitude, sign }
            })
            .collect::<Vec<_>>()
    };
    let s1 = signed(&fixture.s1);
    let s2 = signed(&fixture.s2);
    mark(&c, &mut rows, &mut queries, &mut stages, "inputs");
    let mut pkbits = Vec::new();
    for value in &h {
        let packed = c.pack(value);
        let bits = c.b.bits(packed, 14);
        pkbits.extend(bits.into_iter().rev());
    }
    let mut pk = vec![c.b.constant(9)];
    for bits in pkbits.chunks_exact(8) {
        let reversed: Vec<_> = bits.iter().copied().rev().collect();
        pk.push(c.b.pack(&reversed));
    }
    pk.extend_from_slice(&msg);
    let digest = shake(&mut c, &pk, 32);
    let mut hash_input = nonce;
    hash_input.extend(msg);
    let sample_bytes = shake(&mut c, &hash_input, 1224);
    mark(
        &c,
        &mut rows,
        &mut queries,
        &mut stages,
        "SHAKE and input serialization",
    );
    let samples = sample_bytes.chunks_exact(2).map(|b| vec![b[1], b[0]]).collect();
    let challenge = compact(&mut c, samples);
    mark(&c, &mut rows, &mut queries, &mut stages, "sampling and compaction");
    let integer = relation(&mut c, &h, &s1, &s2, &challenge);
    stages.extend(integer);
    rows = c.b.rows();
    queries = c.query_count();
    let mut budget = vec![Word::ZERO; 2];
    for s in &s2 {
        let packed = c.pack(&s.magnitude);
        let bits = c.b.bits(packed, 11);
        let length = c.b.pack(&bits[7..]);
        let (next, carry) = c.add(&budget, &[length, Word::ZERO]);
        c.b.assert_eq(carry, Word::ZERO);
        budget = next;
    }
    c.assert_less_than(&budget, 393);
    mark(&c, &mut rows, &mut queries, &mut stages, "encoding budget");
    let mut statement = digest;
    statement.push(c.b.one());
    statement.resize(64, Word::ZERO);
    let mut message: Vec<_> = identity
        .chunks_exact(8)
        .map(|b| c.b.constant(u64::from_le_bytes(b.try_into().unwrap())))
        .collect();
    for half in statement.chunks_exact(16) {
        let reversed: Vec<_> = half.iter().copied().rev().collect();
        for word in reversed.chunks_exact(8) {
            message.push(c.pack(word));
        }
    }
    let claim = c.b.hash_words(&message);
    for word in claim {
        c.b.expose(word);
    }
    mark(&c, &mut rows, &mut queries, &mut stages, "canonical application claim");
    (c, stages)
}
