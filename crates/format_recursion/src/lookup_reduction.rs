//! Multiplicity-aware lookup bus reduction over GF(2^192).
//!
//! This is a reduction, not an accepting verifier: callers MUST bind returned
//! query and multiplicity claims to commitments made before these challenges.
//! Integer multiplicities use committed Boolean bits; additive LogUp would
//! discard even multiplicities in this characteristic.
use fiat_shamir::transcript::{Challenger, ProverState, Receiver, Transmitter, VerifierState};
use flock::zerocheck;
use leanvm_core::gkr::{self, RootShape};
use primitives::{
    field::{F64, F192},
    multilinear::eq_table,
};

#[derive(Clone, Debug)]
pub struct Shape {
    pub table_log: usize,
    pub query_log: usize,
    pub count_bits: usize,
}
impl Shape {
    fn group_log(&self) -> usize {
        self.count_bits.next_power_of_two().trailing_zeros() as usize
    }
    pub fn leaf_log(&self) -> usize {
        self.table_log + self.group_log()
    }
    pub fn valid(&self) -> bool {
        self.table_log > 0
            && self.table_log <= 18
            && self.query_log <= self.leaf_log()
            && self.count_bits > 0
            && self.count_bits <= 16
            && self.leaf_log() <= 22
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub point: Vec<F192>,
    pub value: F192,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// One MLE evaluation per query tuple column, in coordinate order.
    pub queries: Vec<Evaluation>,
    /// Two MLE evaluations of the same multiplicity-bit commitment: product
    /// leaf reduction, then Booleanity. Neither may be left unopened.
    pub multiplicities: Vec<Evaluation>,
}
fn zero() -> (F192, F192) {
    (F192::ZERO, F192::ZERO)
}
fn pow2(mut x: F192, n: usize) -> F192 {
    for _ in 0..n {
        x = x.square();
    }
    x
}
fn mle_eval(column: &[F192], point: &[F192]) -> F192 {
    column
        .iter()
        .zip(eq_table(point))
        .fold(F192::ZERO, |sum, (&v, w)| sum + v * w)
}
#[cfg(test)]
fn eval_base(column: &[F64], point: &[F192]) -> F192 {
    let weights = eq_table(point);
    column
        .iter()
        .zip(weights)
        .fold(F192::ZERO, |s, (&x, w)| s + F192::from(x) * w)
}
fn product_factor_eval(shape: &Shape, tables: &[Vec<F64>], alpha: &[F192], beta: F192, point: &[F192]) -> F192 {
    let rows = eq_table(&point[..shape.table_log]);
    let groups = eq_table(&point[shape.table_log..]);
    rows.iter().enumerate().fold(F192::ZERO, |sum, (row, &weight)| {
        let mut factor = tables
            .iter()
            .zip(alpha)
            .fold(beta, |s, (column, &a)| s + a * F192::from(column[row]));
        let mut value = F192::ZERO;
        for &group in groups.iter().take(shape.count_bits) {
            value += group * (factor + F192::ONE);
            factor = factor.square();
        }
        sum + weight * value
    })
}
fn query_leaf_value(shape: &Shape, alpha: &[F192], beta: F192, point: &[F192], query_values: &[F192]) -> F192 {
    let select = point[shape.query_log..]
        .iter()
        .fold(F192::ONE, |p, &r| p * (F192::ONE + r));
    let value = alpha.iter().zip(query_values).fold(beta, |s, (&a, &v)| s + a * v);
    F192::ONE + select * (value + F192::ONE)
}
/// Expand integer counts into a padded bit column. Layout is table rows low,
/// bit number high, matching the GKR product producer.
pub fn bit_witness(shape: &Shape, counts: &[u64]) -> Option<Vec<F64>> {
    if !shape.valid() || counts.len() != 1 << shape.table_log || counts.iter().any(|&v| v >= 1u64 << shape.count_bits) {
        return None;
    }
    let rows = 1usize << shape.table_log;
    let mut bits = vec![F64::ZERO; 1usize << shape.leaf_log()];
    for bit in 0..shape.count_bits {
        for (row, &count) in counts.iter().enumerate() {
            bits[bit * rows + row] = F64((count >> bit) & 1);
        }
    }
    Some(bits)
}
/// Prove the bus and return claims, without accepting them as commitment openings.
pub fn prove(
    shape: &Shape,
    tables: &[Vec<F64>],
    queries: &[Vec<F192>],
    bits: &[F64],
    ps: &mut ProverState,
) -> Option<Claims> {
    if !shape.valid()
        || tables.is_empty()
        || tables.len() != queries.len()
        || tables.iter().any(|c| c.len() != 1 << shape.table_log)
        || queries.iter().any(|c| c.len() != 1 << shape.query_log)
        || bits.len() != 1 << shape.leaf_log()
    {
        return None;
    }
    let alpha = ps.sample_vec(tables.len());
    let beta = ps.sample();
    let rows = 1usize << shape.table_log;
    let n = 1usize << shape.leaf_log();
    let mut query_leaves = vec![F192::ONE; n];
    for (row, leaf) in query_leaves[..1usize << shape.query_log].iter_mut().enumerate() {
        *leaf = queries.iter().zip(&alpha).fold(beta, |s, (c, &a)| s + a * c[row]);
    }
    let factors: Vec<_> = (0..rows)
        .map(|row| {
            tables
                .iter()
                .zip(&alpha)
                .fold(beta, |s, (c, &a)| s + a * F192::from(c[row]))
        })
        .collect();
    let factor_table: Vec<_> = (0..n)
        .map(|i| {
            let bit = i / rows;
            if bit < shape.count_bits {
                pow2(factors[i % rows], bit) + F192::ONE
            } else {
                F192::ZERO
            }
        })
        .collect();
    let multiplicities: Vec<_> = bits.iter().map(|&b| F192::from(b)).collect();
    let producer: Vec<_> = multiplicities
        .iter()
        .zip(&factor_table)
        .map(|(&b, &f)| F192::ONE + b * f)
        .collect();
    let product = gkr::prove_product_triple([query_leaves, producer, vec![F192::ONE]], ps, RootShape::Distinct);
    let mut query_claims = Vec::new();
    for column in queries {
        let value = mle_eval(column, &product.point[..shape.query_log]);
        ps.add_scalar(value);
        query_claims.push(Evaluation {
            point: product.point[..shape.query_log].to_vec(),
            value,
        });
    }
    let (point, a, b, _) = zerocheck::prove_tables(
        multiplicities.clone(),
        factor_table,
        vec![F192::ZERO; n],
        &product.point,
        product.values[1] + F192::ONE,
        &mut |_| zero(),
        ps,
    );
    ps.add_scalar(a);
    ps.add_scalar(b);
    let first = Evaluation { point, value: a };
    let rho = ps.sample_vec(shape.leaf_log());
    let (point, a, _, _) = zerocheck::prove_tables(
        multiplicities.clone(),
        multiplicities.clone(),
        multiplicities,
        &rho,
        F192::ZERO,
        &mut |_| zero(),
        ps,
    );
    ps.add_scalar(a);
    Some(Claims {
        queries: query_claims,
        multiplicities: vec![first, Evaluation { point, value: a }],
    })
}
/// Verify the reduction only. `Some` is NOT proof acceptance until all returned
/// claims are opened against the already-bound native/multiplicity roots.
pub fn verify(shape: &Shape, tables: &[Vec<F64>], vs: &mut VerifierState<'_>) -> Option<Claims> {
    if !shape.valid() || tables.is_empty() || tables.iter().any(|c| c.len() != 1 << shape.table_log) {
        return None;
    }
    let alpha = vs.sample_vec(tables.len());
    let beta = vs.sample();
    let product = gkr::verify_product_triple(shape.leaf_log(), vs, RootShape::Distinct).ok()?;
    if product.roots[0] != product.roots[1] || product.roots[2] != F192::ONE || product.values[2] != F192::ONE {
        return None;
    }
    let mut query_claims = Vec::new();
    for _ in tables {
        query_claims.push(Evaluation {
            point: product.point[..shape.query_log].to_vec(),
            value: vs.next_scalar().ok()?,
        });
    }
    let values: Vec<_> = query_claims.iter().map(|c| c.value).collect();
    if product.values[0] != query_leaf_value(shape, &alpha, beta, &product.point, &values) {
        return None;
    }
    let (point, terminal) = zerocheck::verify_tables(&product.point, product.values[1] + F192::ONE, vs).ok()?;
    let a = vs.next_scalar().ok()?;
    let b = vs.next_scalar().ok()?;
    if terminal != a * b || b != product_factor_eval(shape, tables, &alpha, beta, &point) {
        return None;
    }
    let first = Evaluation { point, value: a };
    let rho = vs.sample_vec(shape.leaf_log());
    let (point, terminal) = zerocheck::verify_tables(&rho, F192::ZERO, vs).ok()?;
    let a = vs.next_scalar().ok()?;
    if terminal != a * a + a {
        return None;
    }
    Some(Claims {
        queries: query_claims,
        multiplicities: vec![first, Evaluation { point, value: a }],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_reads_are_counted_and_bad_counts_reject() {
        parallel::init();
        let shape = Shape {
            table_log: 3,
            query_log: 2,
            count_bits: 3,
        };
        let tables = vec![(0..8).map(F64).collect::<Vec<_>>()];
        let queries = vec![vec![F192::from(F64(2)); 4]];
        let mut counts = vec![0; 8];
        counts[2] = 4;
        let bits = bit_witness(&shape, &counts).unwrap();
        let mut ps = ProverState::from_label(b"lookup-reduction-test");
        let claims = prove(&shape, &tables, &queries, &bits, &mut ps).unwrap();
        let proof = ps.into_proof();
        let mut vs = VerifierState::from_label(b"lookup-reduction-test", &proof);
        assert_eq!(verify(&shape, &tables, &mut vs), Some(claims.clone()));
        assert!(vs.finish().is_ok());
        for (col, c) in queries.iter().zip(&claims.queries) {
            assert_eq!(mle_eval(col, &c.point), c.value);
        }
        for c in &claims.multiplicities {
            assert_eq!(eval_base(&bits, &c.point), c.value);
        }
        // Prove with malformed counts without a host precheck: the verifier checks
        // both products and rejects before asking for commitment openings.
        counts[2] = 3;
        let bad_bits = bit_witness(&shape, &counts).unwrap();
        let mut ps = ProverState::from_label(b"lookup-reduction-test");
        prove(&shape, &tables, &queries, &bad_bits, &mut ps).unwrap();
        let bad = ps.into_proof();
        let mut vs = VerifierState::from_label(b"lookup-reduction-test", &bad);
        assert!(verify(&shape, &tables, &mut vs).is_none());
        let bad_queries = vec![vec![F192::from(F64(8)); 4]];
        let mut ps = ProverState::from_label(b"lookup-reduction-test");
        prove(&shape, &tables, &bad_queries, &bits, &mut ps).unwrap();
        let bad = ps.into_proof();
        let mut vs = VerifierState::from_label(b"lookup-reduction-test", &bad);
        assert!(verify(&shape, &tables, &mut vs).is_none());
    }
}
