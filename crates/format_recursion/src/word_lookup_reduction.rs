//! Sparse, public integer multiplicities for the shared word-table product bus.
//!
//! Counts and fixed-table addresses enter the transcript before fingerprints.
//! The verifier computes the fixed-table product with integer exponents, never
//! additive field multiplicities. Returned query evaluations MUST be bound to
//! the witness commitment; this reduction alone does not accept an application.
use crate::{
    lookup_reduction::Evaluation,
    word_tables::{TOTAL_ROWS, Tuple},
};
use fiat_shamir::transcript::{Challenger, ProverState, Receiver, Transmitter, VerifierState};
use leanvm_core::gkr::{self, RootShape};
use primitives::{field::F192, multilinear::eq_table};

const MAX_QUERY_LOG: usize = 22;
fn fixed_tuple(row: usize) -> Option<Tuple> {
    for table in crate::word_tables::TABLES {
        if (table.offset()..table.offset() + table.rows()).contains(&row) {
            return table.tuple(row - table.offset());
        }
    }
    None
}
fn exponent(mut factor: F192, mut count: u64) -> F192 {
    let mut product = F192::ONE;
    while count != 0 {
        if count & 1 != 0 {
            product *= factor;
        }
        factor = factor.square();
        count >>= 1;
    }
    product
}
fn scalar(value: u64) -> F192 {
    F192::new(value, 0, 0)
}
fn integer(value: F192) -> Option<u64> {
    (value == scalar(value.c0)).then_some(value.c0)
}
fn fingerprint(tuple: &Tuple, alpha: &[F192], beta: F192) -> F192 {
    tuple.iter().zip(alpha).fold(beta, |v, (&x, &a)| v + scalar(x) * a)
}
fn valid_counts(query_log: usize, counts: &[(usize, u64)]) -> bool {
    if !(1..=MAX_QUERY_LOG).contains(&query_log) || counts.is_empty() || counts.len() > TOTAL_ROWS {
        return false;
    }
    let mut previous = None;
    let mut total = 0u64;
    for &(row, count) in counts {
        if row >= TOTAL_ROWS || count == 0 || previous.is_some_and(|p| row <= p) {
            return false;
        }
        previous = Some(row);
        let Some(sum) = total.checked_add(count) else {
            return false;
        };
        total = sum;
    }
    total == 1u64 << query_log
}
fn expected_product(counts: &[(usize, u64)], alpha: &[F192], beta: F192) -> F192 {
    counts.iter().fold(F192::ONE, |p, &(row, count)| {
        p * exponent(fingerprint(&fixed_tuple(row).unwrap(), alpha, beta), count)
    })
}

/// No host membership/multiset precheck: malformed query columns can be proved
/// here for verifier adversarial tests. All six claims require PCS binding.
pub fn prove(
    query_log: usize,
    queries: &[Vec<F192>; 6],
    counts: &[(usize, u64)],
    ps: &mut ProverState,
) -> Option<Vec<Evaluation>> {
    if !valid_counts(query_log, counts) || queries.iter().any(|c| c.len() != 1 << query_log) {
        return None;
    }
    ps.add_scalar(scalar(counts.len() as u64));
    for &(row, count) in counts {
        ps.add_scalar(scalar(row as u64));
        ps.add_scalar(scalar(count));
    }
    let alpha = ps.sample_vec(6);
    let beta = ps.sample();
    let leaves = (0..1 << query_log)
        .map(|row| {
            queries
                .iter()
                .zip(&alpha)
                .fold(beta, |v, (column, &a)| v + column[row] * a)
        })
        .collect();
    let product = gkr::prove_product_triple([leaves, vec![F192::ONE], vec![F192::ONE]], ps, RootShape::Distinct);
    let weights = eq_table(&product.point);
    Some(
        queries
            .iter()
            .map(|column| {
                let value = column
                    .iter()
                    .zip(&weights)
                    .fold(F192::ZERO, |sum, (&v, &w)| sum + v * w);
                ps.add_scalar(value);
                Evaluation {
                    point: product.point.clone(),
                    value,
                }
            })
            .collect(),
    )
}

/// Returns unbound query evaluations, not application acceptance.
pub fn verify(query_log: usize, vs: &mut VerifierState<'_>) -> Option<Vec<Evaluation>> {
    if !(1..=MAX_QUERY_LOG).contains(&query_log) {
        return None;
    }
    let len = usize::try_from(integer(vs.next_scalar().ok()?)?).ok()?;
    if len == 0 || len > TOTAL_ROWS || len > 1 << query_log {
        return None;
    }
    let mut counts = Vec::with_capacity(len);
    for _ in 0..len {
        let row = usize::try_from(integer(vs.next_scalar().ok()?)?).ok()?;
        let count = integer(vs.next_scalar().ok()?)?;
        counts.push((row, count));
    }
    if !valid_counts(query_log, &counts) {
        return None;
    }
    let alpha = vs.sample_vec(6);
    let beta = vs.sample();
    let expected = expected_product(&counts, &alpha, beta);
    let product = gkr::verify_product_triple(query_log, vs, RootShape::Distinct).ok()?;
    if product.roots != [expected, F192::ONE, F192::ONE] || product.values[1..] != [F192::ONE, F192::ONE] {
        return None;
    }
    let mut queries = Vec::with_capacity(6);
    for _ in 0..6 {
        queries.push(Evaluation {
            point: product.point.clone(),
            value: vs.next_scalar().ok()?,
        });
    }
    let leaf = queries
        .iter()
        .zip(&alpha)
        .fold(beta, |v, (query, &a)| v + query.value * a);
    (leaf == product.values[0]).then_some(queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::word_tables::Table;
    use fiat_shamir::transcript::Proof;
    fn columns(tuples: &[Tuple]) -> [Vec<F192>; 6] {
        std::array::from_fn(|c| tuples.iter().map(|t| scalar(t[c])).collect())
    }
    fn run(tuples: &[Tuple], counts: &[(usize, u64)]) -> (Proof, Vec<Evaluation>) {
        let mut ps = ProverState::from_label(b"word-sparse-reduction-test");
        let claims = prove(tuples.len().ilog2() as usize, &columns(tuples), counts, &mut ps).unwrap();
        (ps.into_proof(), claims)
    }
    #[test]
    fn sparse_integer_product_and_verifier_rejections_without_prover_prechecks() {
        parallel::init();
        let add_row = 255 + 256 * 255 + 65536;
        let mul_row = 255 + 256 * 255;
        let add = Table::Add8.tuple(add_row).unwrap();
        let mul = Table::Mul8.tuple(mul_row).unwrap();
        let tuples = [add, add, mul, mul];
        let counts = [(Table::Add8.offset() + add_row, 2), (Table::Mul8.offset() + mul_row, 2)];
        let (proof, claims) = run(&tuples, &counts);
        let mut vs = VerifierState::from_label(b"word-sparse-reduction-test", &proof);
        assert_eq!(verify(2, &mut vs), Some(claims));
        assert!(vs.finish().is_ok());
        // Construct full GKR transcripts for malformed tuples, bypassing host
        // table membership checks. The reduction verifier must reject them.
        for (row, coordinate, value) in [(0, 3, 0), (0, 4, 0), (2, 3, 0), (0, 0, 3), (0, 1, 256), (2, 5, 1)] {
            let mut bad = tuples;
            bad[row][coordinate] = value;
            let (proof, _) = run(&bad, &counts);
            let mut vs = VerifierState::from_label(b"word-sparse-reduction-test", &proof);
            assert!(verify(2, &mut vs).is_none(), "mutation {row}/{coordinate}");
        }
        // Preserve the count total but alter its distribution. Even counts
        // must not disappear as they would in an additive characteristic-two bus.
        let wrong = [(counts[0].0, 1), (counts[1].0, 3)];
        let (proof, _) = run(&tuples, &wrong);
        let mut vs = VerifierState::from_label(b"word-sparse-reduction-test", &proof);
        assert!(verify(2, &mut vs).is_none());
        assert!(!valid_counts(2, &[(0, 2), (0, 2)]));
        assert!(!valid_counts(2, &[(TOTAL_ROWS, 4)]));
        assert!(!valid_counts(2, &[(0, 3)]));
    }
}
