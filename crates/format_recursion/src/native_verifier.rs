//! Symbolic verifier for the experimental native-field arithmetic argument.
//! Records every arithmetic, transcript and Merkle verification equation; this
//! is implementation evidence, not a formal proof of the argument.
use crate::{
    native_arithmetic::{ArithmeticShape, Index},
    trace::{self, S, Trace, digest_constant, hash},
    verifier::{Transcript, eq, kernel, powers, verify_basis_opening, verify_basis_opening_lanes_rate},
};
use fiat_shamir::{merkle::Hash, transcript::Proof};
use flock::membership::Scalar;
use primitives::field::F192;

#[derive(Clone)]
pub(crate) struct Claim {
    pub(crate) offset: usize,
    pub(crate) point: Vec<S>,
    pub(crate) value: S,
}
fn eval_poly(coefficients: &[S], at: S) -> S {
    coefficients.iter().rev().fold(S::u(0), |v, &c| c + at * v)
}
fn interpolate(a: S, b: S, x: S) -> S {
    a + x * (a + b)
}
fn read_field(t: &mut Transcript<'_>, l: usize, col: usize, point: &[S], claims: &mut Vec<Claim>) -> S {
    let mut value = S::u(0);
    let mut basis = F192::ONE;
    for limb in 0..3 {
        let v = t.next();
        claims.push(Claim {
            offset: (col * 4 + limb) * (1 << l),
            point: point.to_vec(),
            value: v,
        });
        value = value + S::c(basis) * v;
        basis *= F192::Y;
    }
    value
}
pub(crate) fn opening(t: &mut Transcript<'_>, root: [S; 2], l: usize, claims: &[Claim]) {
    opening_rate(t, root, l, 1, claims)
}
pub(crate) fn opening_rate(t: &mut Transcript<'_>, root: [S; 2], l: usize, log_inv_rate: usize, claims: &[Claim]) {
    let lambda = t.sample();
    let weights = powers(lambda, claims.len());
    let target = claims.iter().zip(&weights).fold(S::u(0), |v, (c, &w)| v + w * c.value);
    let basis = |at: &[S]| {
        claims.iter().zip(&weights).fold(S::u(0), |sum, (c, &w)| {
            let mut value = eq(&c.point, &at[..c.point.len()]);
            let selector = c.offset >> c.point.len();
            for (i, &x) in at[c.point.len()..].iter().enumerate() {
                value = value * if selector >> i & 1 == 1 { x } else { S::u(1) + x };
            }
            sum + w * value
        })
    };
    if log_inv_rate == 1 {
        verify_basis_opening(t, l, root, target, basis);
    } else {
        verify_basis_opening_lanes_rate(
            t,
            l,
            log_inv_rate,
            1 << pcs::whir::INITIAL_FOLDING_FACTOR,
            root,
            target,
            basis,
        );
    }
}
/// Native arithmetic transcript label, binding the trusted index and complete
/// public vector before any prover message or random challenge.
pub(crate) fn label(index: &Index, public: &[S], context: [S; 2]) -> Vec<(S, usize)> {
    label_with_root(index, digest_constant(&index.root), public, context)
}

pub(crate) fn label_with_root(index: &Index, root: [S; 2], public: &[S], context: [S; 2]) -> Vec<(S, usize)> {
    let mut out = Vec::new();
    let prefix = if index.index_log_inv_rate == 1 {
        b"format-native-arithmetic-v1"
    } else {
        b"format-native-arithmetic-v2"
    };
    for chunk in prefix.chunks(24) {
        let mut bytes = [0; 24];
        bytes[..chunk.len()].copy_from_slice(chunk);
        let limb = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        out.push((S::c(F192::new(limb(0), limb(8), limb(16))), chunk.len()));
    }
    if index.index_log_inv_rate != 1 {
        out.push((S::u(index.index_log_inv_rate as u64), 8));
    }
    out.extend(root.map(|s| (s, 16)));
    out.extend(context.map(|s| (s, 16)));
    out.extend([index.log_rows, index.public_log, public.len()].map(|n| (S::u(n as u64), 8)));
    out.extend(public.iter().map(|&s| (s, 24)));
    out
}
fn product(t: &mut Transcript<'_>, mu: usize) -> ([S; 3], Vec<S>, [S; 3]) {
    let roots = [t.next(), t.next(), t.next()];
    let mut values = roots;
    let mut point = Vec::new();
    let mut layer = mu;
    while layer > 0 {
        let lambda = t.sample();
        let rounds = mu - layer;
        let mut claim = eval_poly(&values, lambda);
        if layer % 2 == 1 {
            let tails: [[S; 2]; 3] = std::array::from_fn(|_| [t.next(), t.next()]);
            claim.assert_eq(eval_poly(&tails.map(|[a, b]| a * b), lambda));
            let x = t.sample();
            values = std::array::from_fn(|i| interpolate(tails[i][0], tails[i][1], x));
            point = vec![x];
            layer -= 1;
            continue;
        }
        let mut next_point = Vec::new();
        for &r in point.iter().take(rounds) {
            let coefficients = t.round(5, claim, r);
            let x = t.sample();
            claim = eval_poly(&coefficients, x);
            next_point.push(x);
        }
        let tails: [[S; 4]; 3] = std::array::from_fn(|_| [t.next(), t.next(), t.next(), t.next()]);
        claim.assert_eq(eval_poly(
            &tails.map(|a| a.into_iter().fold(S::u(1), |x, y| x * y)),
            lambda,
        ));
        let low = t.sample();
        let high = t.sample();
        values = std::array::from_fn(|i| {
            interpolate(
                interpolate(tails[i][0], tails[i][1], low),
                interpolate(tails[i][2], tails[i][3], low),
                high,
            )
        });
        point = vec![low, high];
        point.extend(next_point);
        layer -= 2;
    }
    (roots, point, values)
}
/// Append arithmetic proof verification to an active trace/transcript.
/// Caller must seed `t` with `label` and call `t.finish()` after this function.
pub(crate) fn verify(index: &Index, public: &[S], t: &mut Transcript<'_>) {
    let root = t.root();
    let (claims, index_claims) = reduce(index, public, t);
    trace::mark("native-witness-opening");
    opening(t, root, index.log_rows + 4, &claims);
    trace::mark("native-index-opening");
    opening_rate(
        t,
        digest_constant(&index.root),
        index.log_rows + 2,
        index.index_log_inv_rate,
        &index_claims,
    );
}

/// Native zerocheck/copy/public reduction. The caller owns commitment and
/// opening composition, allowing arithmetic and hash arguments to share a stack.
pub(crate) fn reduce(index: &Index, public: &[S], t: &mut Transcript<'_>) -> (Vec<Claim>, Vec<Claim>) {
    reduce_shape(index.verifier_shape(), public, t)
}

pub(crate) fn reduce_shape(index: ArithmeticShape, public: &[S], t: &mut Transcript<'_>) -> (Vec<Claim>, Vec<Claim>) {
    assert_eq!(public.len(), index.public_len);
    assert!(public.len() >= 2);
    public[0].assert_eq(S::u(0));
    public[1].assert_eq(S::u(1));
    let l = index.log_rows;
    let n = 1 << l;
    let mut claims = Vec::new();
    let mut index_claims = Vec::new();
    trace::mark("native-zerocheck");
    let r: Vec<_> = (0..l).map(|_| t.sample()).collect();
    let mut point = Vec::new();
    let mut target = S::u(0);
    for r in r {
        (S::u(1) + r).is_nonzero();
        let q = t.round(3, target, r);
        let x = t.sample();
        target = eval_poly(&q, x);
        point.push(x);
    }
    let gate: [S; 4] = std::array::from_fn(|col| read_field(t, l, col, &point, &mut claims));
    (gate[0] * gate[1] + gate[2] + gate[3]).assert_eq(target);
    let alpha = t.sample();
    let beta = t.sample();
    trace::mark("native-copy-product");
    let (roots, point, products) = product(t, l + 2);
    roots[0].assert_eq(roots[1]);
    roots[2].assert_eq(S::u(1));
    let (rho, role) = point.split_at(l);
    let values: [S; 4] = std::array::from_fn(|col| read_field(t, l, col, rho, &mut claims));
    let sigmas: [S; 4] = std::array::from_fn(|col| {
        let value = t.next();
        index_claims.push(Claim {
            offset: col * n,
            point: rho.to_vec(),
            value,
        });
        value
    });
    let id = rho.iter().enumerate().fold(S::u(0), |v, (i, &x)| v + x * S::u(1 << i));
    let mut a = S::u(0);
    let mut b = S::u(0);
    for (col, e) in kernel(role).into_iter().enumerate() {
        a = a + e * (alpha + id + S::u((col * n) as u64) + beta * values[col]);
        b = b + e * (alpha + sigmas[col] + beta * values[col]);
    }
    products[0].assert_eq(a);
    products[1].assert_eq(b);
    products[2].assert_eq(S::u(1));
    trace::mark("native-public");
    let point: Vec<_> = (0..index.public_log).map(|_| t.sample()).collect();
    let value = read_field(t, l, 3, &point, &mut claims);
    let expected = kernel(&point).iter().zip(public).fold(S::u(0), |v, (&e, &x)| v + e * x);
    value.assert_eq(expected);
    (claims, index_claims)
}
/// Record a proof with public values and caller context as circuit inputs.
/// The trace output commits to the full label, including the fixed index root.
/// Malformed serialization/paths panic during witness construction; inconsistent
/// arithmetic is represented by unsatisfied symbolic equations.
pub fn record(index: &Index, public: &[F192], context: &Hash, proof: &Proof) -> Trace {
    trace::start();
    let public: Vec<_> = public.iter().copied().map(S::input).collect();
    let context = fiat_shamir::merkle::hash_to_scalars(context).map(S::input);
    for s in context {
        s.slice(128, 64).assert_eq(S::u(0));
    }
    let label = label(index, &public, context);
    let output = hash(&label);
    let mut t = Transcript::from_state(proof, output);
    verify(index, &public, &mut t);
    t.finish();
    let mut result = trace::take();
    result.public = output.to_vec();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_arithmetic::{self, Circuit};
    use fiat_shamir::transcript::ProverState;
    use leanvm_core::gkr::{self, RootShape};

    fn literal(bytes: &[u8]) -> Vec<(S, usize)> {
        bytes.iter().map(|&b| (S::u(b as u64), 1)).collect()
    }
    #[test]
    fn product_recorder_matches_concrete_even_odd_and_zero_depths() {
        parallel::init();
        for mu in 0..=8 {
            let leaves = std::array::from_fn(|lane| {
                (0..1 << mu)
                    .map(|i| F192::new((i + 3 + lane * 19) as u64, 7, 11))
                    .collect()
            });
            let mut ps = ProverState::from_label(b"symbolic-gkr-test");
            let expected = gkr::prove_product_triple(leaves, &mut ps, RootShape::Distinct);
            let proof = ps.into_proof();
            trace::start();
            let label = literal(b"symbolic-gkr-test");
            let mut t = Transcript::from_state(&proof, hash(&label));
            let (roots, point, values) = product(&mut t, mu);
            t.finish();
            assert_eq!(roots.map(S::value), expected.roots);
            assert_eq!(point.into_iter().map(S::value).collect::<Vec<_>>(), expected.point);
            assert_eq!(values.map(S::value), expected.values);
            assert!(trace::take().satisfied());
        }
    }
    #[test]
    fn alternate_index_rate_records_and_binds_production_profile() {
        parallel::init();
        let circuit = Circuit {
            variables: 5,
            rows: vec![[2, 3, 0, 4]],
            public: vec![0, 1, 4],
        };
        let mut index = Index::new_with_rate(circuit.clone(), 2);
        let default = Index::new(circuit);
        assert_eq!(default.index_log_inv_rate, 1);
        assert_eq!(index.shape(), default.shape());
        assert_ne!(index.root, default.root);
        let x = F192::new(17, 3, 91);
        let y = F192::new(41, 52, 2);
        let values = vec![F192::ZERO, F192::ONE, x, y, x * y];
        let public = index.public_values(&values);
        let context = [37; 32];
        let proof = native_arithmetic::prove(&index, &values, &context);
        assert!(native_arithmetic::verify(&index, &public, &context, &proof));
        assert!(record(&index, &public, &context, &proof).satisfied());
        index.index_log_inv_rate = 1;
        assert!(!native_arithmetic::verify(&index, &public, &context, &proof));
        assert!(!std::panic::catch_unwind(|| record(&index, &public, &context, &proof)).is_ok_and(|t| t.satisfied()));
    }

    #[test]
    fn complete_recorder_enforces_same_public_context_index_and_proof() {
        parallel::init();
        let index = Index::new(Circuit {
            variables: 5,
            rows: vec![[2, 3, 0, 4]],
            public: vec![0, 1, 4],
        });
        let x = F192::new(17, 3, 91);
        let y = F192::new(41, 52, 2);
        let values = vec![F192::ZERO, F192::ONE, x, y, x * y];
        let public = index.public_values(&values);
        let context = [37; 32];
        let proof = native_arithmetic::prove(&index, &values, &context);
        assert!(native_arithmetic::verify(&index, &public, &context, &proof));
        let good = record(&index, &public, &context, &proof);
        assert!(good.satisfied());
        assert_eq!(good.public.len(), 2);
        let rejects = |public: &[F192], context: &Hash, proof: &Proof| {
            !std::panic::catch_unwind(|| record(&index, public, context, proof)).is_ok_and(|t| t.satisfied())
        };
        let mut wrong = public.clone();
        wrong[2] += F192::ONE;
        assert!(rejects(&wrong, &context, &proof));
        assert!(rejects(&public, &[38; 32], &proof));
        let mut bad = proof.clone();
        *bad.stream.last_mut().unwrap() += F192::ONE;
        assert!(rejects(&public, &context, &bad));
        let mut bad = proof.clone();
        bad.stream.push(F192::ZERO);
        assert!(rejects(&public, &context, &bad));
        let mut bad = proof.clone();
        bad.stream.pop();
        assert!(rejects(&public, &context, &bad));
        let mut bad = proof.clone();
        bad.merkle[0].sibling_hashes[0][0] ^= 1;
        assert!(rejects(&public, &context, &bad));
        let other = Index::new(Circuit {
            variables: 5,
            rows: vec![[2, 3, 1, 4]],
            public: vec![0, 1, 4],
        });
        assert!(!std::panic::catch_unwind(|| record(&other, &public, &context, &proof)).is_ok_and(|t| t.satisfied()));
    }
}
