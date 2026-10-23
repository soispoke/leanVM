//! Direct gather openings for word-table query coordinates.
//!
//! The fixed query schedule names existing committed witness cells (three F64
//! limbs per F192 value), or public constants. It creates no query copy rows.
//! A degree-two sumcheck reduces all query evaluations to one stack PCS claim.
//! This module is a reduction: its returned stack claim MUST be opened.
use crate::lookup_reduction::Evaluation;
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, ProverState, Receiver, Transmitter, VerifierState},
};
use primitives::{
    field::{F64, F192},
    multilinear::{eq_table, interp},
};

#[derive(Clone, Copy, Debug)]
pub enum Source {
    Constant(F192),
    Cells([usize; 3]),
}
pub struct Schedule {
    pub stack_log: usize,
    /// Coordinate columns; includes the fixed padding queries.
    pub columns: [Vec<Source>; 6],
}
fn basis(limb: usize) -> F192 {
    match limb {
        0 => F192::ONE,
        1 => F192::new(0, 1, 0),
        2 => F192::new(0, 0, 1),
        _ => unreachable!(),
    }
}
impl Schedule {
    fn valid(&self, claims: &[Evaluation]) -> bool {
        if self.stack_log == 0 || self.stack_log > 29 || claims.len() != 6 {
            return false;
        }
        self.columns.iter().zip(claims).all(|(column, claim)| {
            claim.point.len() <= 22
                && column.len() == 1 << claim.point.len()
                && column.iter().all(|source| match source {
                    Source::Constant(_) => true,
                    Source::Cells(cells) => cells.iter().all(|&cell| cell < 1 << self.stack_log),
                })
        })
    }
    fn digest(&self) -> Hash {
        let mut bytes = b"word-direct-query-schedule-v1".to_vec();
        bytes.extend((self.stack_log as u64).to_le_bytes());
        for column in &self.columns {
            bytes.extend((column.len() as u64).to_le_bytes());
            for source in column {
                match source {
                    Source::Constant(v) => {
                        bytes.push(0);
                        for limb in [v.c0, v.c1, v.c2] {
                            bytes.extend(limb.to_le_bytes());
                        }
                    }
                    Source::Cells(cells) => {
                        bytes.push(1);
                        for &cell in cells {
                            bytes.extend((cell as u64).to_le_bytes());
                        }
                    }
                }
            }
        }
        primitives::hash::hash(&bytes)
    }
    /// Materialize uncommitted advice only; opening claims bind it later.
    pub fn query_columns(&self, stack: &[F64]) -> Option<[Vec<F192>; 6]> {
        if stack.len() > 1 << self.stack_log {
            return None;
        }
        let mut result: [Vec<F192>; 6] = std::array::from_fn(|_| Vec::new());
        for (column, out) in self.columns.iter().zip(&mut result) {
            for source in column {
                out.push(match source {
                    Source::Constant(v) => *v,
                    Source::Cells(cells) => F192::new(
                        stack.get(cells[0]).copied().unwrap_or(F64::ZERO).0,
                        stack.get(cells[1]).copied().unwrap_or(F64::ZERO).0,
                        stack.get(cells[2]).copied().unwrap_or(F64::ZERO).0,
                    ),
                });
            }
        }
        Some(result)
    }
    fn visit(&self, claims: &[Evaluation], alpha: &[F192], mut visit: impl FnMut(usize, F192)) -> F192 {
        let mut constant = F192::ZERO;
        for ((column, claim), &a) in self.columns.iter().zip(claims).zip(alpha) {
            for (source, weight) in column.iter().zip(eq_table(&claim.point)) {
                let w = weight * a;
                match source {
                    Source::Constant(v) => constant += *v * w,
                    Source::Cells(cells) => {
                        for (limb, &cell) in cells.iter().enumerate() {
                            visit(cell, w * basis(limb));
                        }
                    }
                }
            }
        }
        constant
    }
}
/// Return a stack MLE evaluation to be opened against the pre-existing root.
/// Intentionally permits false query claims for end-to-end rejection tests.
pub fn prove(schedule: &Schedule, stack: &[F64], claims: &[Evaluation], ps: &mut ProverState) -> Option<Evaluation> {
    if !schedule.valid(claims) || stack.len() > 1 << schedule.stack_log {
        return None;
    }
    ps.add_root(&schedule.digest());
    let alpha = ps.sample_vec(6);
    let mut weights = vec![F192::ZERO; 1 << schedule.stack_log];
    let _constant = schedule.visit(claims, &alpha, |cell, w| weights[cell] += w);
    let mut values: Vec<_> = stack.iter().map(|&v| F192::from(v)).collect();
    values.resize(1 << schedule.stack_log, F192::ZERO);
    let mut point = Vec::with_capacity(schedule.stack_log);
    while values.len() > 1 {
        let mut q0 = F192::ZERO;
        let mut q2 = F192::ZERO;
        for (v, w) in values.as_chunks::<2>().0.iter().zip(weights.as_chunks::<2>().0.iter()) {
            q0 += v[0] * w[0];
            q2 += (v[0] + v[1]) * (w[0] + w[1]);
        }
        ps.add_scalar(q0);
        ps.add_scalar(q2);
        let r = ps.sample();
        for i in 0..values.len() / 2 {
            values[i] = interp(values[2 * i], values[2 * i + 1], r);
            weights[i] = interp(weights[2 * i], weights[2 * i + 1], r);
        }
        values.truncate(values.len() / 2);
        weights.truncate(weights.len() / 2);
        point.push(r);
    }
    ps.add_scalar(values[0]);
    Some(Evaluation {
        point,
        value: values[0],
    })
}
/// Return an unbound stack evaluation. Verification is complete only after PCS.
pub fn verify(schedule: &Schedule, claims: &[Evaluation], vs: &mut VerifierState<'_>) -> Option<Evaluation> {
    if !schedule.valid(claims) || vs.next_root().ok()? != schedule.digest() {
        return None;
    }
    let alpha = vs.sample_vec(6);
    let mut sum = claims.iter().zip(&alpha).fold(F192::ZERO, |s, (c, &a)| s + c.value * a);
    // Constants are independent of the stack and must be removed from its claim.
    sum += schedule.visit(claims, &alpha, |_, _| {});
    let mut point = Vec::with_capacity(schedule.stack_log);
    for _ in 0..schedule.stack_log {
        let q0 = vs.next_scalar().ok()?;
        let q2 = vs.next_scalar().ok()?;
        let r = vs.sample();
        sum = q0 + (sum + q2) * r + q2 * r.square();
        point.push(r);
    }
    let value = vs.next_scalar().ok()?;
    // Split equality weights avoid a stack-sized verifier allocation.
    let split = point.len() / 2;
    let lo = eq_table(&point[..split]);
    let hi = eq_table(&point[split..]);
    let mask = lo.len() - 1;
    let mut weight = F192::ZERO;
    schedule.visit(claims, &alpha, |cell, w| {
        weight += w * lo[cell & mask] * hi[cell >> split]
    });
    (sum == value * weight).then_some(Evaluation { point, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_gather_binds_coordinates_limbs_and_schedule() {
        let stack: Vec<_> = (0..32).map(F64).collect();
        let schedule = Schedule {
            stack_log: 5,
            columns: std::array::from_fn(|c| {
                vec![
                    Source::Cells([c, c + 7, c + 14]),
                    Source::Constant(F192::new(c as u64, 0, 0)),
                ]
            }),
        };
        let columns = schedule.query_columns(&stack).unwrap();
        let point = vec![F192::new(123, 456, 789)];
        let w = eq_table(&point);
        let claims: Vec<_> = columns
            .iter()
            .map(|col| Evaluation {
                point: point.clone(),
                value: col[0] * w[0] + col[1] * w[1],
            })
            .collect();
        let mut ps = ProverState::from_label(b"direct-gather-test");
        let opened = prove(&schedule, &stack, &claims, &mut ps).unwrap();
        let proof = ps.into_proof();
        let mut vs = VerifierState::from_label(b"direct-gather-test", &proof);
        assert_eq!(verify(&schedule, &claims, &mut vs), Some(opened.clone()));
        assert!(vs.finish().is_ok());
        let expected = stack
            .iter()
            .zip(eq_table(&opened.point))
            .fold(F192::ZERO, |s, (&v, w)| s + F192::from(v) * w);
        assert_eq!(expected, opened.value);
        // Forge the claim, then produce a sumcheck without a prover precheck.
        let mut bad = claims.clone();
        bad[3].value += F192::ONE;
        let mut ps = ProverState::from_label(b"direct-gather-test");
        prove(&schedule, &stack, &bad, &mut ps).unwrap();
        let proof = ps.into_proof();
        let mut vs = VerifierState::from_label(b"direct-gather-test", &proof);
        assert!(verify(&schedule, &bad, &mut vs).is_none());
    }
}
