//! Two-phase matrix reduction adapted from leanVM rec/tree/reduce/matrix.rs.
//! Row and column points use zero-padded short weights and repeated short polynomials.
use super::{
    deferred::{WireClaim, literal, plain_round},
    spartan::{DeferredClaim, Setup},
};
use crate::{
    trace::{self, S, Trace, digest_constant, hash},
    verifier::{Transcript, eq, powers},
};
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Transmitter},
};
use primitives::{
    field::F192,
    multilinear::{eq_table, poly_eval},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Reduction {
    pub proof: Proof,
    pub carried: Vec<DeferredClaim>,
}
fn scalar_bytes(out: &mut Vec<u8>, v: F192) {
    for limb in [v.c0, v.c1, v.c2] {
        out.extend(limb.to_le_bytes());
    }
}
fn label(claims: &[DeferredClaim], digest: &Hash) -> Vec<u8> {
    let mut out = b"r1cs-deferred-matrix-fold-v1".to_vec();
    out.extend(digest);
    out.extend((claims.len() as u64).to_le_bytes());
    for c in claims {
        out.extend(c.app_key);
        out.extend((c.row_point.len() as u64).to_le_bytes());
        out.extend((c.col_point.len() as u64).to_le_bytes());
        for &v in c.row_point.iter().chain(&c.col_point).chain(&c.matrix_values) {
            scalar_bytes(&mut out, v);
        }
    }
    out
}
fn label_rows(claims: &[WireClaim], digest: [S; 2]) -> Vec<(S, usize)> {
    let mut out = literal(b"r1cs-deferred-matrix-fold-v1");
    out.extend(digest.map(|v| (v, 16)));
    out.push((S::u(claims.len() as u64), 8));
    for c in claims {
        out.extend(c.app_key.map(|v| (v, 16)));
        out.push((S::u(c.row_point.len() as u64), 8));
        out.push((S::u(c.col_point.len() as u64), 8));
        out.extend(
            c.row_point
                .iter()
                .chain(&c.col_point)
                .chain(&c.matrix_values)
                .map(|&v| (v, 24)),
        );
    }
    out
}
fn app_indices(setups: &[&Setup], claims: &[DeferredClaim]) -> Vec<usize> {
    claims
        .iter()
        .map(|c| {
            setups
                .iter()
                .position(|s| s.key == c.app_key)
                .expect("known fixed application")
        })
        .collect()
}
fn sumcheck(pairs: &mut [(Vec<F192>, Vec<F192>)], mut claim: F192, ps: &mut ProverState) -> (Vec<F192>, F192) {
    let mut point = Vec::new();
    while pairs[0].0.len() > 1 {
        let half = pairs[0].0.len() / 2;
        let [c0, c2] = parallel::map_reduce(
            half,
            || [F192::ZERO; 2],
            |i| {
                pairs.iter().fold([F192::ZERO; 2], |s, (a, b)| {
                    [
                        s[0] + a[2 * i] * b[2 * i],
                        s[1] + (a[2 * i] + a[2 * i + 1]) * (b[2 * i] + b[2 * i + 1]),
                    ]
                })
            },
            |a, b| [a[0] + b[0], a[1] + b[1]],
        );
        let q = [c0, claim + c2, c2];
        ps.add_round_poly(&q, false);
        let r = ps.sample();
        claim = poly_eval(&q, r);
        point.push(r);
        for (a, b) in pairs.iter_mut() {
            *a = parallel::map_collect(half, |i| a[2 * i] + r * (a[2 * i] + a[2 * i + 1]));
            *b = parallel::map_collect(half, |i| b[2 * i] + r * (b[2 * i] + b[2 * i + 1]));
        }
    }
    assert_eq!(claim, pairs.iter().fold(F192::ZERO, |s, (a, b)| s + a[0] * b[0]));
    (point, claim)
}

#[tracing::instrument(skip_all, name = "Deferred matrix fold prove")]
pub fn prove(setups: &[&Setup], claims: &[DeferredClaim], digest: &Hash) -> Reduction {
    assert!(!claims.is_empty());
    let indices = app_indices(setups, claims);
    let rlog = setups.iter().map(|s| s.row_log).max().unwrap();
    let clog = setups.iter().map(|s| s.z_log).max().unwrap();
    let mut ps = ProverState::from_label(&label(claims, digest));
    let theta = ps.sample();
    let theta2 = theta * theta;
    let theta3 = theta2 * theta;
    let mut power = F192::ONE;
    let mut target = F192::ZERO;
    let mut pairs = Vec::new();
    for (c, &f) in claims.iter().zip(&indices) {
        let setup = setups[f];
        let mut u: Vec<_> = eq_table(&c.row_point).into_iter().map(|v| v * power).collect();
        u.resize(1usize << rlog, F192::ZERO);
        let cw = eq_table(&c.col_point);
        let product = setup
            .r1cs
            .matrices
            .each_ref()
            .map(|m| m.product(&cw, 1usize << setup.row_log));
        let short: Vec<_> = (0..1usize << setup.row_log)
            .map(|r| product[0][r] + theta * product[1][r] + theta2 * product[2][r])
            .collect();
        let g = parallel::map_collect(1usize << rlog, |r| short[r % short.len()]);
        target += power * (c.matrix_values[0] + theta * c.matrix_values[1] + theta2 * c.matrix_values[2]);
        pairs.push((u, g));
        power *= theta3;
    }
    let (rp, row_target) = sumcheck(&mut pairs, target, &mut ps);
    let mut columns = Vec::new();
    for (f, setup) in setups.iter().enumerate() {
        let rw = eq_table(&rp[..setup.row_log]);
        for (j, m) in setup.r1cs.matrices.iter().enumerate() {
            let short = m.fold_rows(&rw, 1usize << setup.z_log);
            let poly = parallel::map_collect(1usize << clog, |i| short[i % short.len()]);
            let mut weights = vec![F192::ZERO; 1usize << clog];
            let coefficient = [F192::ONE, theta, theta2][j];
            for (i, c) in claims.iter().enumerate().filter(|(i, _)| indices[*i] == f) {
                let scale = pairs[i].0[0] * coefficient;
                let w = eq_table(&c.col_point);
                parallel::chunks_mut(&mut weights[..w.len()], 4096, |chunk, out| {
                    for (k, v) in out.iter_mut().enumerate() {
                        *v += scale * w[chunk * 4096 + k];
                    }
                });
            }
            columns.push((poly, weights));
        }
    }
    let (cp, _) = sumcheck(&mut columns, row_target, &mut ps);
    let carried = setups
        .iter()
        .enumerate()
        .map(|(f, setup)| {
            let matrix_values = std::array::from_fn(|j| columns[3 * f + j].0[0]);
            ps.add_scalars(&matrix_values);
            DeferredClaim {
                app_key: setup.key,
                row_point: rp[..setup.row_log].to_vec(),
                col_point: cp[..setup.z_log].to_vec(),
                matrix_values,
            }
        })
        .collect();
    Reduction {
        proof: ps.into_proof(),
        carried,
    }
}
fn lift(point: &[S], k: usize) -> S {
    point[k..].iter().fold(S::u(1), |s, &v| s * (S::u(1) + v))
}
pub(crate) fn verify_rows(
    setups: &[&Setup],
    input_apps: &[usize],
    inputs: &[WireClaim],
    digest: [S; 2],
    proof: &Proof,
) -> Vec<WireClaim> {
    let rlog = setups.iter().map(|s| s.row_log).max().unwrap();
    let clog = setups.iter().map(|s| s.z_log).max().unwrap();
    let seed = hash(&label_rows(inputs, digest));
    let mut t = Transcript::from_state(proof, seed);
    let theta = t.sample();
    let theta2 = theta * theta;
    let theta3 = theta2 * theta;
    let pw = powers(theta3, inputs.len());
    let mut running = inputs.iter().zip(&pw).fold(S::u(0), |s, (c, &p)| {
        s + p * (c.matrix_values[0] + theta * c.matrix_values[1] + theta2 * c.matrix_values[2])
    });
    let mut phase = |n| {
        (0..n)
            .map(|_| {
                let q = plain_round(&mut t, running);
                let x = t.sample();
                running = q.iter().rev().fold(S::u(0), |s, &v| v + x * s);
                x
            })
            .collect::<Vec<_>>()
    };
    trace::mark("matrix-fold-row-sumcheck");
    let rp = phase(rlog);
    trace::mark("matrix-fold-column-sumcheck");
    let cp = phase(clog);
    let output: Vec<_> = setups
        .iter()
        .map(|s| WireClaim {
            app_key: digest_constant(&s.key),
            row_point: rp[..s.row_log].to_vec(),
            col_point: cp[..s.z_log].to_vec(),
            matrix_values: std::array::from_fn(|_| t.next()),
        })
        .collect();
    let mut total = S::u(0);
    for ((c, &power), &index) in inputs.iter().zip(&pw).zip(input_apps) {
        for (got, want) in c.app_key.into_iter().zip(digest_constant(&setups[index].key)) {
            got.assert_eq(want);
        }
        let setup = setups[index];
        let weight = power
            * eq(&c.row_point, &rp[..setup.row_log])
            * lift(&rp, setup.row_log)
            * eq(&c.col_point, &cp[..setup.z_log])
            * lift(&cp, setup.z_log);
        let values = output[index].matrix_values;
        total = total + weight * (values[0] + theta * values[1] + theta2 * values[2]);
    }
    total.assert_eq(running);
    t.finish();
    output
}

pub fn record(setups: &[&Setup], inputs: &[DeferredClaim], digest: &Hash, reduction: &Reduction) -> Trace {
    let input_apps = app_indices(setups, inputs);
    trace::start();
    let inputs: Vec<_> = inputs
        .iter()
        .map(|c| WireClaim {
            app_key: digest_constant(&c.app_key),
            row_point: c.row_point.iter().copied().map(S::input).collect(),
            col_point: c.col_point.iter().copied().map(S::input).collect(),
            matrix_values: c.matrix_values.map(S::input),
        })
        .collect();
    let output = verify_rows(setups, &input_apps, &inputs, digest_constant(digest), &reduction.proof);
    for (wire, claim) in output.iter().zip(&reduction.carried) {
        for (&got, want) in wire.flatten().iter().zip(hash_to_fields(claim)) {
            got.assert_eq(S::input(want));
        }
    }
    let mut program = trace::take();
    program.public = output.iter().flat_map(WireClaim::flatten).collect();
    program
}
fn hash_to_fields(c: &DeferredClaim) -> Vec<F192> {
    fiat_shamir::merkle::hash_to_scalars(&c.app_key)
        .into_iter()
        .chain(c.row_point.iter().copied())
        .chain(c.col_point.iter().copied())
        .chain(c.matrix_values)
        .collect()
}
