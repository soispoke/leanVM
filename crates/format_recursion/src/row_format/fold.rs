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
    field::{F192, F192Unreduced, mul_unreduced4, mul4},
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
pub(crate) fn label(claims: &[DeferredClaim], digest: &Hash) -> Vec<u8> {
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
pub(crate) fn label_rows(claims: &[WireClaim], digest: [S; 2]) -> Vec<(S, usize)> {
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
/// Build the scaled equality weights directly, avoiding a second full-table
/// pass and allocation. The shared field kernel supports a non-unit seed.
pub(crate) fn weighted_eq(point: &[F192], scale: F192) -> Vec<F192> {
    let n = 1usize << point.len();
    let mut out = Vec::<F192>::with_capacity(n);
    primitives::multilinear::fill_eq_table_uninit(point, scale, &mut out.spare_capacity_mut()[..n]);
    // SAFETY: fill_eq_table_uninit writes all n entries, as its API requires.
    unsafe {
        out.set_len(n);
    }
    out
}

pub(crate) fn sumcheck(
    pairs: &mut [(Vec<F192>, Vec<F192>)],
    rounds: usize,
    zero_first: bool,
    mut claim: F192,
    ps: &mut ProverState,
) -> (Vec<F192>, F192) {
    let mut point = Vec::new();
    for _ in 0..rounds {
        let [c0, c2] = pairs.iter().fold([F192::ZERO; 2], |total, (a, b)| {
            let part = if a.len() == 1 {
                [a[0] * b[0], F192::ZERO]
            } else {
                parallel::map_reduce(
                    (a.len() / 2).div_ceil(4),
                    || [F192Unreduced::ZERO; 2],
                    |block| {
                        let at = |v: &[F192], lane: usize, high: bool| {
                            v.get(8 * block + 2 * lane + usize::from(high))
                                .copied()
                                .unwrap_or(F192::ZERO)
                        };
                        let al: [F192; 4] = std::array::from_fn(|k| at(a, k, false));
                        let bl: [F192; 4] = std::array::from_fn(|k| at(b, k, false));
                        let ad: [F192; 4] = std::array::from_fn(|k| al[k] + at(a, k, true));
                        let bd: [F192; 4] = std::array::from_fn(|k| bl[k] + at(b, k, true));
                        [
                            mul_unreduced4(al, bl)
                                .into_iter()
                                .fold(F192Unreduced::ZERO, |x, y| x ^ y),
                            mul_unreduced4(ad, bd)
                                .into_iter()
                                .fold(F192Unreduced::ZERO, |x, y| x ^ y),
                        ]
                    },
                    |x, y| [x[0] ^ y[0], x[1] ^ y[1]],
                )
                .map(F192Unreduced::reduce)
            };
            [total[0] + part[0], total[1] + part[1]]
        });
        let q = [c0, claim + c2, c2];
        ps.add_round_poly(&q, false);
        let r = ps.sample();
        claim = poly_eval(&q, r);
        point.push(r);
        for (a, b) in pairs.iter_mut() {
            if a.len() == 1 {
                // The short polynomial repeats in unused coordinates, while
                // its matching weight is zero outside its native domain.
                if zero_first {
                    a[0] *= F192::ONE + r;
                } else {
                    b[0] *= F192::ONE + r;
                }
            } else {
                let half = a.len() / 2;
                let mut na = vec![F192::ZERO; half];
                let mut nb = vec![F192::ZERO; half];
                parallel::chunks_mut2(&mut na, &mut nb, 4096, |chunk, oa, ob| {
                    for (block, (aa, bb)) in oa.chunks_mut(4).zip(ob.chunks_mut(4)).enumerate() {
                        let start = chunk * 4096 + block * 4;
                        let al: [F192; 4] =
                            std::array::from_fn(|k| a.get(2 * (start + k)).copied().unwrap_or(F192::ZERO));
                        let bl: [F192; 4] =
                            std::array::from_fn(|k| b.get(2 * (start + k)).copied().unwrap_or(F192::ZERO));
                        let ad =
                            std::array::from_fn(|k| al[k] + a.get(2 * (start + k) + 1).copied().unwrap_or(F192::ZERO));
                        let bd =
                            std::array::from_fn(|k| bl[k] + b.get(2 * (start + k) + 1).copied().unwrap_or(F192::ZERO));
                        let ap = mul4([r; 4], ad);
                        let bp = mul4([r; 4], bd);
                        for k in 0..aa.len() {
                            aa[k] = al[k] + ap[k];
                            bb[k] = bl[k] + bp[k];
                        }
                    }
                });
                *a = na;
                *b = nb;
            }
        }
    }
    assert_eq!(claim, pairs.iter().fold(F192::ZERO, |s, (a, b)| s + a[0] * b[0]));
    (point, claim)
}

#[tracing::instrument(skip_all, name = "Deferred matrix fold prove")]
pub fn prove(setups: &[&Setup], claims: &[DeferredClaim], digest: &Hash) -> Reduction {
    prove_inner(setups, None, claims, digest)
}

pub fn prove_generated(
    setups: &[&Setup],
    generators: &[&super::generator::Generator],
    claims: &[DeferredClaim],
    digest: &Hash,
) -> Reduction {
    assert_eq!(setups.len(), generators.len());
    for (s, g) in setups.iter().zip(generators) {
        assert_eq!((s.key, s.row_log, s.z_log), (g.app_key, g.row_log, g.col_log));
    }
    prove_inner(setups, Some(generators), claims, digest)
}
fn prove_inner(
    setups: &[&Setup],
    generators: Option<&[&super::generator::Generator]>,
    claims: &[DeferredClaim],
    digest: &Hash,
) -> Reduction {
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
        let u = weighted_eq(&c.row_point, power);
        let cw = eq_table(&c.col_point);
        let g = if let Some(gs) = generators {
            gs[f].row_product(&cw, theta)
        } else {
            let product = setup
                .r1cs
                .matrices
                .each_ref()
                .map(|m| m.product(&cw, 1 << setup.row_log));
            parallel::map_collect(1 << setup.row_log, |r| {
                product[0][r] + theta * product[1][r] + theta2 * product[2][r]
            })
        };
        target += power * (c.matrix_values[0] + theta * c.matrix_values[1] + theta2 * c.matrix_values[2]);
        pairs.push((u, g));
        power *= theta3;
    }
    let (rp, row_target) = sumcheck(&mut pairs, rlog, true, target, &mut ps);
    let mut columns = Vec::new();
    for (f, setup) in setups.iter().enumerate() {
        let rw = eq_table(&rp[..setup.row_log]);
        let products = if let Some(gs) = generators {
            gs[f].column_products(&rw)
        } else {
            setup
                .r1cs
                .matrices
                .each_ref()
                .map(|m| m.fold_rows(&rw, 1 << setup.z_log))
        };
        let products: Vec<_> = if generators.is_some() {
            vec![parallel::map_collect(1 << setup.z_log, |i| {
                products[0][i] + theta * products[1][i] + theta2 * products[2][i]
            })]
        } else {
            products.into_iter().collect()
        };
        for (j, poly) in products.into_iter().enumerate() {
            let mut weights = vec![F192::ZERO; 1usize << setup.z_log];
            let coefficient = if generators.is_some() {
                F192::ONE
            } else {
                [F192::ONE, theta, theta2][j]
            };
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
    let (cp, _) = sumcheck(&mut columns, clog, false, row_target, &mut ps);
    let carried = setups
        .iter()
        .enumerate()
        .map(|(f, setup)| {
            let matrix_values = if let Some(gs) = generators {
                gs[f].evaluate(&rp[..setup.row_log], &cp[..setup.z_log])
            } else {
                std::array::from_fn(|j| columns[3 * f + j].0[0])
            };
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

/// Native verifier for the same two-phase matrix fold used by the recursion
/// circuit. It authenticates every key/dimension and consumes the entire proof.
/// Final root reduction can thereby settle multiple points of one identity once.
pub fn verify_native(
    setups: &[&Setup],
    inputs: &[DeferredClaim],
    digest: &Hash,
    reduction: &Reduction,
) -> Option<Vec<DeferredClaim>> {
    use fiat_shamir::transcript::{Receiver, VerifierState};
    use primitives::multilinear::eq_eval;
    if setups.is_empty() || inputs.is_empty() || reduction.carried.len() != setups.len() {
        return None;
    }
    for (i, s) in setups.iter().enumerate() {
        if setups[..i].iter().any(|other| other.key == s.key) {
            return None;
        }
    }
    let indices: Vec<_> = inputs
        .iter()
        .map(|c| setups.iter().position(|s| s.key == c.app_key))
        .collect::<Option<_>>()?;
    for (c, &i) in inputs.iter().zip(&indices) {
        if c.row_point.len() != setups[i].row_log || c.col_point.len() != setups[i].z_log {
            return None;
        }
    }
    let mut vs = VerifierState::from_label(&label(inputs, digest), &reduction.proof);
    let theta = vs.sample();
    let theta2 = theta * theta;
    let theta3 = theta2 * theta;
    let mut power = F192::ONE;
    let mut running = F192::ZERO;
    for c in inputs {
        running += power * (c.matrix_values[0] + theta * c.matrix_values[1] + theta2 * c.matrix_values[2]);
        power *= theta3;
    }
    let rlog = setups.iter().map(|s| s.row_log).max()?;
    let clog = setups.iter().map(|s| s.z_log).max()?;
    let mut phase = |n| -> Option<Vec<F192>> {
        let mut point = Vec::new();
        for _ in 0..n {
            let q = vs.next_round_poly(3, running, None).ok()?;
            let r = vs.sample();
            running = poly_eval(&q, r);
            point.push(r);
        }
        Some(point)
    };
    let rp = phase(rlog)?;
    let cp = phase(clog)?;
    let mut output = Vec::new();
    for s in setups {
        output.push(DeferredClaim {
            app_key: s.key,
            row_point: rp[..s.row_log].to_vec(),
            col_point: cp[..s.z_log].to_vec(),
            matrix_values: [vs.next_scalar().ok()?, vs.next_scalar().ok()?, vs.next_scalar().ok()?],
        });
    }
    let lift = |point: &[F192], k: usize| point[k..].iter().fold(F192::ONE, |a, &x| a * (F192::ONE + x));
    let mut total = F192::ZERO;
    power = F192::ONE;
    for (c, &i) in inputs.iter().zip(&indices) {
        let s = setups[i];
        let values = output[i].matrix_values;
        total += power
            * eq_eval(&c.row_point, &rp[..s.row_log])
            * lift(&rp, s.row_log)
            * eq_eval(&c.col_point, &cp[..s.z_log])
            * lift(&cp, s.z_log)
            * (values[0] + theta * values[1] + theta2 * values[2]);
        power *= theta3;
    }
    if total != running || output != reduction.carried {
        return None;
    }
    vs.finish().ok()?;
    Some(output)
}

#[cfg(test)]
mod native_tests {
    use super::super::{R1cs, Source, generator::Generator};
    use super::*;
    #[test]
    fn native_matrix_fold_matches_symbolic_and_rejects_mutations() {
        parallel::init();
        let mut b = crate::native_hash::Builder::default();
        let a = b.input(7);
        let z = b.gate(a, a, b.one());
        for w in b.hash_words(&[a, z]) {
            b.expose(w);
        }
        let (circuit, connectors) = b.export_protocol_circuit();
        let fixed_len = circuit.public.len() - 4;
        let source = Source {
            circuit,
            connectors,
            fixed_len,
            values: b.values.clone(),
            compressions: b.protocol_blocks(),
            rebuild: Box::new(|| unreachable!()),
        };
        let setup = Setup::new(
            R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8),
            false,
        );
        let generator = Generator::new(&source, 8, setup.key);
        let claims: Vec<_> = (0..2)
            .map(|i| {
                let rp: Vec<_> = (0..setup.row_log)
                    .map(|j| F192::new((i * 113 + j + 2) as u64, 3, 5))
                    .collect();
                let cp: Vec<_> = (0..setup.z_log)
                    .map(|j| F192::new((i * 37 + j + 9) as u64, 7, 11))
                    .collect();
                let values = generator.evaluate(&rp, &cp);
                DeferredClaim {
                    app_key: setup.key,
                    row_point: rp,
                    col_point: cp,
                    matrix_values: values,
                }
            })
            .collect();
        let digest = [71; 32];
        let reduction = prove_generated(&[&setup], &[&generator], &claims, &digest);
        let verified = verify_native(&[&setup], &claims, &digest, &reduction).unwrap();
        assert!(generator.settle(&verified[0]));
        assert!(record(&[&setup], &claims, &digest, &reduction).satisfied());
        let mut false_input = claims.clone();
        false_input[0].matrix_values[0] += F192::ONE;
        assert!(verify_native(&[&setup], &false_input, &digest, &reduction).is_none());
        let mut omitted = claims.clone();
        omitted.remove(0);
        assert!(verify_native(&[&setup], &omitted, &digest, &reduction).is_none());
        let mut wrong_key = claims.clone();
        wrong_key[0].app_key[0] ^= 1;
        assert!(verify_native(&[&setup], &wrong_key, &digest, &reduction).is_none());
        let mut wrong_shape = claims.clone();
        wrong_shape[0].row_point.pop();
        assert!(verify_native(&[&setup], &wrong_shape, &digest, &reduction).is_none());
        let mut forged = reduction.clone();
        forged.carried[0].matrix_values[0] += F192::ONE;
        assert!(verify_native(&[&setup], &claims, &digest, &forged).is_none());
        let mut forged = reduction.clone();
        forged.proof.stream.push(F192::ONE);
        assert!(verify_native(&[&setup], &claims, &digest, &forged).is_none());
        let mut forged = reduction.clone();
        forged.proof.stream.pop();
        assert!(verify_native(&[&setup], &claims, &digest, &forged).is_none());
        assert!(verify_native(&[&setup], &claims, &[72; 32], &reduction).is_none());
    }
}
