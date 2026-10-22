use super::*;

/// A separable weight whose block table is zero outside a subinterval.
pub(crate) struct PartialLaneWeight {
    pub lanes: Vec<F192>,
    pub offset: usize,
    pub block: Vec<F192>,
}

/// One dyadically aligned dense support, plus separable point weights.
pub(crate) struct HybridWeight {
    pub offset: usize,
    pub dense: Vec<F192>,
    pub points: Vec<PartialLaneWeight>,
}

// Fold only the requested group of original lanes. This is needed when a
// shrinking dense support first meets a partner outside its original support.
fn partner(f: &[F64], block: usize, lane: usize, rs: &[F192]) -> Vec<F192> {
    let first = lane << rs.len();
    let end = (first + (1 << rs.len())).min(f.len() / block);
    let eq = build_eq_table_ext(rs);
    let mut out = vec![F192::ZERO; block];
    parallel::chunks_mut(&mut out, INITIAL_BASIS_CHUNK, |chunk, dst| {
        let x = chunk * INITIAL_BASIS_CHUNK;
        let mut acc = [F192Unreduced::ZERO; INITIAL_BASIS_CHUNK];
        for l in first..end {
            let row = &f[l * block + x..l * block + x + dst.len()];
            for (a, &v) in acc.iter_mut().zip(row) {
                *a ^= eq[l - first].mul_base_unreduced(v);
            }
        }
        for (dst, acc) in dst.iter_mut().zip(acc) {
            *dst = acc.reduce();
        }
    });
    out
}

fn dot<T: RoundWitness>(f: &[T], b: &[F192]) -> F192 {
    let per = f.len().div_ceil(ROUND_CHUNK);
    let task = |chunk: usize| {
        let first = chunk * ROUND_CHUNK;
        let end = (first + ROUND_CHUNK).min(f.len());
        let mut acc = T::ZERO_ACC;
        for (&f, &b) in f[first..end].iter().zip(&b[first..end]) {
            acc ^= f.mul_basis_unreduced(b);
        }
        (acc, T::ZERO_ACC)
    };
    T::reduce(accumulate_msg(per, f.len(), T::ZERO_ACC, task).0)
}

pub(super) fn rounds<'a>(
    f: &'a [F64],
    weight: HybridWeight,
    target: F192,
    block: usize,
    initial_k: usize,
    ps: &mut impl Transmitter,
) -> (SumcheckProver<'a>, Vec<F192>) {
    let n_lanes = f.len() / block;
    let width = 1usize << initial_k;
    let HybridWeight { offset, dense, points } = weight;
    assert!(offset.is_multiple_of(block));
    assert!(dense.len().is_multiple_of(block));
    assert!(dense.len().is_power_of_two());
    assert!(offset.is_multiple_of(dense.len()));
    assert!(offset + dense.len() <= f.len());
    for w in &points {
        assert_eq!(w.lanes.len(), n_lanes);
        assert!(w.offset + w.block.len() <= block);
    }
    let mut lanes: Vec<Vec<F192>> = points
        .iter()
        .map(|w| {
            let mut lanes = w.lanes.clone();
            lanes.resize(width, F192::ZERO);
            lanes
        })
        .collect();
    let mut sums: Vec<Vec<F192>> = points
        .iter()
        .map(|w| {
            let per = w.block.len().div_ceil(ROUND_CHUNK);
            let partial = parallel::map_collect(n_lanes * per, |task| {
                let (lane, chunk) = (task / per, task % per);
                let x = chunk * ROUND_CHUNK;
                let len = ROUND_CHUNK.min(w.block.len() - x);
                let row = &f[lane * block + w.offset + x..lane * block + w.offset + x + len];
                let mut acc = F192Unreduced::ZERO;
                for (&v, &b) in row.iter().zip(&w.block[x..x + len]) {
                    acc ^= b.mul_base_unreduced(v);
                }
                acc
            });
            let mut sums = vec![F192::ZERO; width];
            for (lane, dst) in sums.iter_mut().enumerate().take(n_lanes) {
                let mut acc = F192Unreduced::ZERO;
                for &p in &partial[lane * per..(lane + 1) * per] {
                    acc ^= p;
                }
                *dst = acc.reduce();
            }
            sums
        })
        .collect();
    let point_message = |lanes: &[Vec<F192>], sums: &[Vec<F192>]| {
        let mut msg = SumcheckMessage {
            u_0: F192::ZERO,
            u_2: F192::ZERO,
        };
        for (c, s) in lanes.iter().zip(sums) {
            for i in 0..c.len() / 2 {
                msg.u_0 += c[2 * i] * s[2 * i];
                msg.u_2 += (c[2 * i] + c[2 * i + 1]) * (s[2 * i] + s[2 * i + 1]);
            }
        }
        msg
    };
    let mut dense = dense;
    let mut dense_lane = offset / block;
    let mut sparse_f = Witness::Base(&f[offset..offset + dense.len()]);
    let mut scale = F192::ONE;
    let mut claim = target;
    let mut rs = Vec::with_capacity(initial_k);
    let mut cached = None;
    for _ in 0..initial_k {
        let other = (dense.len() == block).then(|| partner(f, block, dense_lane ^ 1, &rs));
        let mut msg = if let Some(other) = &other {
            let own = match &sparse_f {
                Witness::Base(f) => dot(f, &dense),
                Witness::Ext(f) => dot(f, &dense),
            };
            SumcheckMessage {
                u_0: if dense_lane & 1 == 0 { scale * own } else { F192::ZERO },
                u_2: scale * (own + dot(other, &dense)),
            }
        } else {
            cached.take().unwrap_or_else(|| match &sparse_f {
                Witness::Base(f) => round_msg_blocks(f, &dense, block),
                Witness::Ext(f) => round_msg_blocks(f, &dense, block),
            })
        };
        let pm = point_message(&lanes, &sums);
        msg.u_0 += pm.u_0;
        msg.u_2 += pm.u_2;
        send_msg(ps, msg, claim);
        let r = ps.sample();
        claim = RoundQuad::from_msg(msg, claim).eval(r);
        for v in lanes.iter_mut().chain(&mut sums) {
            *v = (0..v.len() / 2)
                .map(|i| F192::fold_pair(v[2 * i], v[2 * i + 1], r))
                .collect();
        }
        if let Some(mut other) = other {
            let own_factor = if dense_lane & 1 == 0 { F192::ONE + r } else { r };
            let other_factor = F192::ONE + own_factor;
            scale *= own_factor;
            parallel::chunks_mut(&mut other, INITIAL_BASIS_CHUNK, |chunk, dst| {
                let x = chunk * INITIAL_BASIS_CHUNK;
                let end = x + dst.len();
                match &sparse_f {
                    Witness::Base(f) => {
                        for (o, &v) in dst.iter_mut().zip(&f[x..end]) {
                            *o = other_factor * *o + own_factor.mul_base(v);
                        }
                    }
                    Witness::Ext(f) => {
                        for (o, &v) in dst.iter_mut().zip(&f[x..end]) {
                            *o = other_factor * *o + own_factor * v;
                        }
                    }
                }
            });
            sparse_f = Witness::Ext(other);
        } else {
            let (nf, nb, next) = match &sparse_f {
                Witness::Base(f) => fold_and_msg_blocks(f, &dense, r, block, false),
                Witness::Ext(f) => fold_and_msg_blocks(f, &dense, r, block, false),
            };
            sparse_f = Witness::Ext(nf);
            dense = nb;
            cached = Some(next);
        }
        dense_lane /= 2;
        rs.push(r);
    }
    assert_eq!(dense_lane, 0);
    assert_eq!(dense.len(), block);
    let nf = match sparse_f {
        Witness::Ext(f) => f,
        Witness::Base(_) => unreachable!(),
    };
    let mut nb = dense;
    parallel::chunks_mut(&mut nb, INITIAL_BASIS_CHUNK, |chunk, out| {
        let x = chunk * INITIAL_BASIS_CHUNK;
        for v in out.iter_mut() {
            *v *= scale;
        }
        for (w, lane) in points.iter().zip(&lanes) {
            let lo = x.max(w.offset);
            let hi = (x + out.len()).min(w.offset + w.block.len());
            for i in lo..hi {
                out[i - x] += lane[0] * w.block[i - w.offset];
            }
        }
    });
    let msg = round_msg_lsb(&nf, &nb);
    send_msg(ps, msg, claim);
    (SumcheckProver::folded(nf, nb, claim, msg, initial_k), rs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::test_rng::Rng;

    #[test]
    fn hybrid_proof_matches_dense_with_overlap_and_missing_lanes() {
        for rate in [1, 4] {
            for (log_n, n_lanes, first, count) in [
                (13usize, 1usize, 0usize, 1usize),
                (13, 5, 4, 1),
                (13, 64, 0, 64),
                (18, 35, 16, 16),
                (18, 48, 32, 16),
            ] {
                let mut config = crate::whir_config::test_config_for(log_n);
                config.log_inv_rates.fill(rate);
                let block = 1 << (log_n - config.initial_k);
                let mut rng = Rng::new(0x4B21D + n_lanes as u64);
                let mut witness: Vec<_> = (0..n_lanes * block).map(|_| F64(rng.next_u64())).collect();
                witness.split_at_mut(n_lanes * block / 2).1.fill(F64::ZERO);
                let mut dense = rng.ext_vec(count * block);
                dense.split_at_mut(count * block / 2).1.fill(F192::ZERO);
                let points = (0..3)
                    .map(|i| PartialLaneWeight {
                        lanes: rng.ext_vec(n_lanes),
                        offset: if i == 0 { 0 } else { block / 4 },
                        block: rng.ext_vec(if i == 0 { block } else { block / 4 }),
                    })
                    .collect::<Vec<_>>();
                let mut expected = vec![F192::ZERO; witness.len()];
                expected[first * block..(first + count) * block].copy_from_slice(&dense);
                for w in &points {
                    for (lane, &c) in w.lanes.iter().enumerate() {
                        for (x, &b) in w.block.iter().enumerate() {
                            expected[lane * block + w.offset + x] += c * b;
                        }
                    }
                }
                let target = inner_product_base_ext(&witness, &expected);
                let (_, pd) = commit(&witness, log_n, config.initial_k, rate);
                let prove = |weight| {
                    let mut ps = fiat_shamir::transcript::ProverState::from_label(b"hybrid-dense-test");
                    recursive_prover_with_prepared_basis(
                        &config,
                        log_n,
                        &witness,
                        weight,
                        target,
                        &pd.codeword,
                        &pd.merkle_tree,
                        &mut ps,
                    );
                    ps.into_proof()
                };
                let reference = prove(InitialWeight::Dense(expected, None));
                let actual = prove(InitialWeight::Hybrid(HybridWeight {
                    offset: first * block,
                    dense,
                    points,
                }));
                assert_eq!(
                    actual, reference,
                    "rate={rate}, log_n={log_n}, lanes={n_lanes}, first={first}, count={count}"
                );
            }
        }
    }
}
