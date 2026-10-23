//! Deferred sparse-matrix claims, using the leanVM tree's two-phase reduction.
use super::spartan::Setup;
use crate::{
    flock_trace,
    native_verifier::Claim,
    trace::{self, S, Trace, digest_constant, hash},
    verifier::{Transcript, eq, kernel, powers, verify_basis_opening_lanes_rate},
};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use flock::hash::{K_LOG, R1CS_DIGEST};
use flock::membership::Scalar;
use pcs::{pack::LOG_PACKING, whir::INITIAL_FOLDING_FACTOR};
use primitives::field::F192;

const SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
pub(crate) fn literal(bytes: &[u8]) -> Vec<(S, usize)> {
    bytes
        .chunks(24)
        .map(|c| {
            let mut b = [0; 24];
            b[..c.len()].copy_from_slice(c);
            let limb = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
            (S::c(F192::new(limb(0), limb(8), limb(16))), c.len())
        })
        .collect()
}
fn poly(q: &[S], x: S) -> S {
    q.iter().rev().fold(S::u(0), |v, &c| c + x * v)
}
pub(crate) fn plain_round(t: &mut Transcript<'_>, claim: S) -> [S; 3] {
    let c0 = t.next();
    let c2 = t.next();
    [c0, claim + c2, c2]
}
fn selector(offset: usize, low: usize, at: &[S]) -> S {
    at[low..].iter().enumerate().fold(S::u(1), |s, (i, &x)| {
        s * if (offset >> low) >> i & 1 == 1 { x } else { S::u(1) + x }
    })
}
#[derive(Clone)]
pub(crate) struct WireClaim {
    pub app_key: [S; 2],
    pub row_point: Vec<S>,
    pub col_point: Vec<S>,
    pub matrix_values: [S; 3],
}
impl WireClaim {
    pub(crate) fn flatten(&self) -> Vec<S> {
        self.app_key
            .into_iter()
            .chain(self.row_point.iter().copied())
            .chain(self.col_point.iter().copied())
            .chain(self.matrix_values)
            .collect()
    }
}
/// Replay all child checks without evaluating a matrix or reading its entries.
pub(crate) fn verify_in_rows(
    setup: &Setup,
    app_key: &Hash,
    public: &[F192],
    context: &Hash,
    proof: &Proof,
) -> (WireClaim, [S; 2]) {
    let identity = hash_to_scalars(app_key).map(S::input);
    for (got, want) in identity.into_iter().zip(digest_constant(&setup.key)) {
        got.assert_eq(want);
    }
    let public: Vec<_> = public.iter().copied().map(S::input).collect();
    verify_shape_in_rows(setup, identity, &public, context, proof)
}

/// Matrix identity is supplied by the parent and carried to a trusted root
/// registry. The proof layout remains fixed; no child proof check is skipped.
pub(crate) fn verify_shape_in_rows(
    setup: &Setup,
    identity: [S; 2],
    public: &[S],
    context: &Hash,
    proof: &Proof,
) -> (WireClaim, [S; 2]) {
    public[0].assert_eq(S::u(1));
    let mut label = literal(b"standard-spartan-deferred-native-hash-v2");
    label.extend(identity.map(|s| (s, 16)));
    label.extend(digest_constant(context).map(|s| (s, 16)));
    label.extend(digest_constant(&R1CS_DIGEST).map(|s| (s, 16)));
    label.extend(public.iter().map(|&s| (s, 24)));
    let mut binding = literal(b"r1cs-deferred-child-statement-v1");
    binding.extend(identity.map(|s| (s, 16)));
    binding.push((S::u(public.len() as u64), 8));
    binding.extend(public.iter().map(|&s| (s, 24)));
    let statement_digest = hash(&binding);
    let seed = hash(&label);
    let mut t = Transcript::from_state(proof, seed);
    let root = t.root();
    trace::mark("sparse-outer-sumcheck");
    let tau: Vec<_> = (0..setup.row_log).map(|_| t.sample()).collect();
    let mut row_point = Vec::new();
    let mut running = S::u(0);
    for r in tau {
        (S::u(1) + r).is_nonzero();
        let q = t.round(3, running, r);
        let x = t.sample();
        running = poly(&q, x);
        row_point.push(x);
    }
    let av = t.next();
    let bv = t.next();
    let cv = t.next();
    running.assert_eq(av * bv + cv);
    let alpha = t.sample();
    let alpha2 = alpha * alpha;
    running = av + alpha * bv + alpha2 * cv;
    trace::mark("sparse-inner-sumcheck");
    let mut col_point = Vec::new();
    for _ in 0..setup.z_log {
        let q = plain_round(&mut t, running);
        let x = t.sample();
        running = poly(&q, x);
        col_point.push(x);
    }
    let mut claims = Vec::new();
    let n = 1usize << setup.z_log;
    let mut zv = S::u(0);
    for (limb, basis) in [F192::ONE, F192::new(0, 1, 0), F192::new(0, 0, 1)]
        .into_iter()
        .enumerate()
    {
        let v = t.next();
        zv = zv + S::c(basis) * v;
        claims.push(Claim {
            offset: limb * n,
            point: col_point.clone(),
            value: v,
        });
    }
    let matrix_values = std::array::from_fn(|_| t.next());
    running.assert_eq((matrix_values[0] + alpha * matrix_values[1] + alpha2 * matrix_values[2]) * zv);
    let point: Vec<_> = (0..setup.r1cs.public_log).map(|_| t.sample()).collect();
    let weights = kernel(&point);
    for limb in 0..3 {
        let value = public
            .iter()
            .zip(&weights)
            .fold(S::u(0), |s, (&v, &w)| s + w * v.slice(limb * 64, 64));
        claims.push(Claim {
            offset: limb * n,
            point: point.clone(),
            value,
        });
    }
    trace::mark("sparse-flock-reduction");
    let flock = flock_trace::reduce(K_LOG + setup.r1cs.block_log, &mut t);
    let point: Vec<_> = (0..setup.r1cs.block_log).map(|_| t.sample()).collect();
    let values: [S; 18] = std::array::from_fn(|_| t.next());
    let blocks = 1usize << setup.r1cs.block_log;
    let stride = K_LOG - LOG_PACKING;
    for (slot, &value) in values.iter().enumerate() {
        for limb in 0..3 {
            claims.push(Claim {
                offset: limb * n + setup.r1cs.port_start + slot * blocks,
                point: point.clone(),
                value: if limb == 0 { value } else { S::u(0) },
            });
        }
        let mut strided: Vec<_> = (0..stride).map(|i| S::u(((SLOTS[slot] >> i) & 1) as u64)).collect();
        strided.extend_from_slice(&point);
        claims.push(Claim {
            offset: setup.q_offset,
            point: strided,
            value,
        });
    }
    trace::mark("sparse-joint-opening");
    let map: [S; 6] = std::array::from_fn(|_| t.sample());
    let lambda = t.sample();
    let weights = powers(lambda, 1 + claims.len());
    let target = claims
        .iter()
        .zip(&weights[1..])
        .fold(flock_trace::ring_target(&flock.s_hat_v, &map), |v, (c, &w)| {
            v + w * c.value
        });
    let qlog = stride + setup.r1cs.block_log;
    let lanes = setup.committed_words >> (setup.stack_log - INITIAL_FOLDING_FACTOR);
    verify_basis_opening_lanes_rate(&mut t, setup.stack_log, 2, lanes, root, target, |at| {
        let ring =
            selector(setup.q_offset, qlog, at) * flock_trace::ring_weight(&flock.suffix_point, &at[..qlog], &map);
        claims.iter().zip(&weights[1..]).fold(ring, |s, (c, &w)| {
            s + w * eq(&c.point, &at[..c.point.len()]) * selector(c.offset, c.point.len(), at)
        })
    });
    t.finish();
    (
        WireClaim {
            app_key: identity,
            row_point,
            col_point,
            matrix_values,
        },
        statement_digest,
    )
}

pub fn record_child(setup: &Setup, app_key: &Hash, public: &[F192], context: &Hash, proof: &Proof) -> Trace {
    trace::start();
    let (claim, _) = verify_in_rows(setup, app_key, public, context, proof);
    let mut program = trace::take();
    program.public = claim.flatten();
    program
}

#[cfg(test)]
mod tests {
    use super::super::{self as row_format, R1cs, generator::Generator};
    use super::*;
    #[test]
    fn source_generator_matches_sparse_matrices_without_holding_csr() {
        parallel::init();
        for case in ["shielded", "merge"] {
            let source = row_format::source(case);
            let setup = Setup::new(
                R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8),
                false,
            );
            let generator = Generator::new(&source, 8, setup.key);
            assert_eq!(generator.rows(), setup.r1cs.rows());
            assert_eq!(generator.row_log, setup.row_log);
            assert_eq!(generator.col_log, setup.z_log);
            let r: Vec<_> = (0..setup.row_log).map(|i| F192::new((i + 3) as u64, 19, 31)).collect();
            let c: Vec<_> = (0..setup.z_log).map(|i| F192::new((i + 7) as u64, 29, 41)).collect();
            assert_eq!(generator.evaluate(&r, &c), setup.matrix_evals(&r, &c), "{case}");
            let cw = primitives::multilinear::eq_table(&c);
            let rw = primitives::multilinear::eq_table(&r);
            let theta = F192::new(11, 17, 23);
            let products = setup
                .r1cs
                .matrices
                .each_ref()
                .map(|m| m.product(&cw, 1 << setup.row_log));
            let expected: Vec<_> = (0..1 << setup.row_log)
                .map(|i| products[0][i] + theta * products[1][i] + theta * theta * products[2][i])
                .collect();
            assert_eq!(generator.row_product(&cw, theta), expected, "{case} forward");
            let expected = setup
                .r1cs
                .matrices
                .each_ref()
                .map(|m| m.fold_rows(&rw, 1 << setup.z_log));
            assert_eq!(generator.column_products(&rw), expected, "{case} transpose");
        }
    }
    #[test]
    fn merkle_application_matches_blake2s_and_rejects_wrong_statement_and_proof() {
        parallel::init();
        let seed = 1usize;
        let source = row_format::merkle_source(seed);
        let fresh = row_format::merkle_source(seed + 1);
        assert_eq!(source.program_digest(), fresh.program_digest());
        let leaf: Vec<_> = (0..4)
            .flat_map(|i| ((seed as u64) * 0x10001 + i + 17).to_le_bytes())
            .collect();
        let mut node = primitives::protocol_hash::hash(&leaf);
        for level in 0..16 {
            let sibling: Vec<_> = (0..4)
                .flat_map(|i| ((seed as u64 + 3) * 0x1000001 + (level * 4 + i) as u64).to_le_bytes())
                .collect();
            let mut input = Vec::new();
            if (seed + level) & 1 == 1 {
                input.extend(node);
                input.extend(&sibling);
            } else {
                input.extend(&sibling);
                input.extend(node);
            }
            node = primitives::protocol_hash::hash(&input);
        }
        let setup = Setup::new(
            R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8),
            false,
        );
        let public = setup.public(&source.values);
        let digest: Vec<_> = public[1..].iter().flat_map(|w| w.c0.to_le_bytes()).collect();
        assert_eq!(digest, node);
        let ctx = [91; 32];
        let proof = setup.prove(&source.values, &source.compressions, &ctx);
        assert!(setup.verify_deferred(&public, &ctx, &proof, true).is_some());
        let mut wrong = public.clone();
        wrong[1] += F192::ONE;
        assert!(setup.verify_deferred(&wrong, &ctx, &proof, true).is_none());
        let mut wrong = proof.clone();
        *wrong.stream.last_mut().unwrap() += F192::ONE;
        assert!(setup.verify_deferred(&public, &ctx, &wrong, true).is_none());
    }
    #[test]
    fn deferred_child_replay_agrees_and_binds_identity_and_values() {
        parallel::init();
        let source = row_format::source("shielded");
        for ccs in [false, true] {
            let setup = Setup::new(
                R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8),
                ccs,
            );
            let public = setup.public(&source.values);
            let context = [17; 32];
            let proof = setup.prove(&source.values, &source.compressions, &context);
            let native = setup.verify_deferred(&public, &context, &proof, false).unwrap();
            let claim = setup.claim(&native);
            let program = record_child(&setup, &setup.key, &public, &context, &proof);
            assert!(program.satisfied());
            assert_eq!(
                program
                    .public
                    .iter()
                    .map(|s| program.nodes[s.0].value)
                    .collect::<Vec<_>>(),
                hash_to_scalars(&claim.app_key)
                    .into_iter()
                    .chain(claim.row_point.clone())
                    .chain(claim.col_point.clone())
                    .chain(claim.matrix_values)
                    .collect::<Vec<_>>()
            );
            let generator = Generator::new(&source, 8, setup.key);
            assert!(generator.settle(&claim));
            let mut bad = claim.clone();
            bad.matrix_values[1] += F192::ONE;
            assert!(!generator.settle(&bad));
            let mut other = setup.key;
            other[0] ^= 1;
            let mut bad = claim.clone();
            bad.app_key = other;
            assert!(!generator.settle(&bad));
            assert!(!record_child(&setup, &other, &public, &context, &proof).satisfied());
            let mut bad = proof.clone();
            *bad.stream.last_mut().unwrap() += F192::ONE;
            assert!(setup.verify_deferred(&public, &context, &bad, false).is_none());
        }
    }
}

/// The comparison path that settles a child's matrix claims inside the trace.
pub(crate) fn settle_in_rows(setup: &Setup, claim: &WireClaim) {
    let rows = kernel(&claim.row_point);
    let cols = kernel(&claim.col_point);
    for (j, m) in setup.r1cs.matrices.iter().enumerate() {
        let mut total = S::u(0);
        for r in 0..m.rows() {
            if m.row(r).is_empty() {
                continue;
            }
            let value = m.row(r).iter().fold(S::u(0), |v, &(col, c)| v + S::c(c) * cols[col]);
            total = total + rows[r] * value;
        }
        total.assert_eq(claim.matrix_values[j]);
    }
}
