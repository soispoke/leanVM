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
