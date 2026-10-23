//! Measurement prototype: Spartan's two sumchecks with directly evaluated sparse matrices.
//! The unchanged native hash relation shares one WHIR witness commitment.

use super::{Matrix, R1cs};
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::{
    hash::{
        Blake2sSetup, Compression, K_LOG, R1CS_DIGEST, generate_witness_with_ab_packed_and_lincheck, ring_switch_open,
        ring_switch_verify,
    },
    zerocheck,
};
use pcs::{
    pack::LOG_PACKING,
    stack_open::{StackClaim, open_batch_mixed_whir_stacked, verify_opening_batch_mixed_whir_stacked},
    whir::{self, INITIAL_FOLDING_FACTOR},
};
use primitives::{
    field::{F64, F192},
    multilinear::{eq_table, poly_eval},
};

const SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
const RATE: usize = 2;

fn scaled(c: F192, x: F192) -> F192 {
    if c == F192::ONE { x } else { c * x }
}
fn dot(a: &[F192], b: &[F192]) -> F192 {
    parallel::map_reduce(a.len(), || F192::ZERO, |i| a[i] * b[i], |x, y| x + y)
}

impl Matrix {
    pub(crate) fn fold_rows(&self, weights: &[F192], n: usize) -> Vec<F192> {
        // Sparse rows are independent.  Accumulate per worker, then reduce the
        // dense column vectors once; this removes the serial CSR traversal from
        // the mixed prover while preserving deterministic field arithmetic.
        let chunk = self.rows().div_ceil(12).max(1);
        let partials = parallel::map_collect(self.rows().div_ceil(chunk), |part| {
            let start = part * chunk;
            let end = (start + chunk).min(self.rows());
            let mut local = vec![F192::ZERO; n];
            for (r, &w) in weights.iter().enumerate().take(end).skip(start) {
                for &(col, c) in self.row(r) {
                    local[col] += scaled(c, w);
                }
            }
            local
        });
        parallel::map_collect(n, |col| partials.iter().fold(F192::ZERO, |sum, local| sum + local[col]))
    }
}

pub struct Setup {
    pub r1cs: R1cs,
    pub key: Hash,
    pub ccs: bool,
    pub z_log: usize,
    pub row_log: usize,
    pub q_offset: usize,
    pub stack_log: usize,
    pub committed_words: usize,
}

pub struct Verified {
    pub row_point: Vec<F192>,
    pub col_point: Vec<F192>,
    pub matrix_values: [F192; 3],
}

/// A matrix evaluation left by a child verifier for a later merge or root.
/// The key is the fixed circuit identity, not a prover supplied label.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeferredClaim {
    pub app_key: Hash,
    pub row_point: Vec<F192>,
    pub col_point: Vec<F192>,
    pub matrix_values: [F192; 3],
}

impl Setup {
    /// Standard CCS configured with M=[A,B,C], S=[{0,1},{2}], c=[1,1].
    /// Minus and plus coincide in the binary field.
    pub fn ccs_configuration(&self) -> serde_json::Value {
        serde_json::json!({"matrices":["A","B","C"],"sets":[[0,1],[2]],"coefficients":[1,1],"degree":2,"t":3,"q":2})
    }
    pub fn new(r1cs: R1cs, ccs: bool) -> Self {
        let z_log = r1cs.origins.len().next_power_of_two().trailing_zeros() as usize;
        let row_log = r1cs.rows().next_power_of_two().trailing_zeros() as usize;
        let q_words = 1usize << (K_LOG - LOG_PACKING + r1cs.block_log);
        let q_offset = (3usize << z_log).next_multiple_of(q_words);
        let committed_words = q_offset + q_words;
        let stack_log = committed_words.next_power_of_two().trailing_zeros() as usize;
        let mut h = primitives::hash::Hasher::new();
        h.update(b"standard-row-format-direct-matrices-v1");
        h.update(&[u8::from(ccs)]);
        for x in [
            r1cs.rows(),
            r1cs.origins.len(),
            r1cs.public_len,
            r1cs.port_start,
            r1cs.block_log,
            r1cs.actual_blocks,
            z_log,
            row_log,
            q_offset,
            stack_log,
            RATE,
        ] {
            h.update(&(x as u64).to_le_bytes());
        }
        for m in &r1cs.matrices {
            for &o in &m.offsets {
                h.update(&(o as u64).to_le_bytes());
            }
            for &(col, c) in &m.entries {
                h.update(&(col as u64).to_le_bytes());
                for limb in [c.c0, c.c1, c.c2] {
                    h.update(&limb.to_le_bytes());
                }
            }
        }
        Self {
            r1cs,
            key: h.finalize(),
            ccs,
            z_log,
            row_log,
            q_offset,
            stack_log,
            committed_words,
        }
    }
    fn label(&self, public: &[F192], context: &Hash) -> Vec<u8> {
        let mut out = b"standard-spartan-deferred-native-hash-v2".to_vec();
        out.extend(self.key);
        out.extend(context);
        out.extend(R1CS_DIGEST);
        for x in public {
            for limb in [x.c0, x.c1, x.c2] {
                out.extend(limb.to_le_bytes());
            }
        }
        out
    }
    pub fn public(&self, source: &[F192]) -> Vec<F192> {
        self.r1cs.witness(source)[..self.r1cs.public_len].to_vec()
    }
    fn send_field(
        &self,
        stack: &[F64],
        offset: usize,
        point: &[F192],
        ps: &mut ProverState,
        claims: &mut Vec<StackClaim>,
    ) -> F192 {
        let weights = eq_table(point);
        let mut limbs = [F192::ZERO; 3];
        let n = 1usize << self.z_log;
        for limb in 0..3 {
            let at = limb * n + offset;
            let value = whir::inner_product_base_ext(&stack[at..at + weights.len()], &weights);
            ps.add_scalar(value);
            limbs[limb] = value;
            claims.push(StackClaim::Point {
                offset: at,
                low_point: point.to_vec(),
                value,
            });
        }
        limbs[0] + F192::new(0, 1, 0) * limbs[1] + F192::new(0, 0, 1) * limbs[2]
    }
    fn read_field(
        &self,
        offset: usize,
        point: &[F192],
        vs: &mut VerifierState,
        claims: &mut Vec<StackClaim>,
    ) -> Option<F192> {
        let mut limbs = [F192::ZERO; 3];
        for limb in 0..3 {
            let value = vs.next_scalar().ok()?;
            limbs[limb] = value;
            claims.push(StackClaim::Point {
                offset: limb * (1usize << self.z_log) + offset,
                low_point: point.to_vec(),
                value,
            });
        }
        Some(limbs[0] + F192::new(0, 1, 0) * limbs[1] + F192::new(0, 0, 1) * limbs[2])
    }
    fn public_claims(&self, public: &[F192], point: &[F192], claims: &mut Vec<StackClaim>) {
        let weights = eq_table(point);
        let n = 1usize << self.z_log;
        for limb in 0..3 {
            let value = public
                .iter()
                .zip(&weights)
                .fold(F192::ZERO, |s, (&v, &w)| s + w.mul_base(F64([v.c0, v.c1, v.c2][limb])));
            claims.push(StackClaim::Point {
                offset: limb * n,
                low_point: point.to_vec(),
                value,
            });
        }
    }
    fn port_claims(&self, point: &[F192], values: &[F192; 18], claims: &mut Vec<StackClaim>) {
        let n = 1usize << self.z_log;
        let blocks = 1usize << self.r1cs.block_log;
        for (slot, &value) in values.iter().enumerate() {
            for limb in 0..3 {
                claims.push(StackClaim::Point {
                    offset: limb * n + self.r1cs.port_start + slot * blocks,
                    low_point: point.to_vec(),
                    value: if limb == 0 { value } else { F192::ZERO },
                });
            }
            claims.push(StackClaim::Strided {
                offset: self.q_offset,
                slot: SLOTS[slot],
                stride_log: K_LOG - LOG_PACKING,
                point: point.to_vec(),
                value,
            });
        }
    }
    #[tracing::instrument(skip_all, name = "Sparse matrix direct evaluation")]
    pub fn matrix_evals(&self, row_point: &[F192], col_point: &[F192]) -> [F192; 3] {
        let rows = eq_table(row_point);
        let cols = eq_table(col_point);
        parallel::map_reduce(
            self.r1cs.rows(),
            || [F192::ZERO; 3],
            |r| {
                self.r1cs.matrices.each_ref().map(|m| {
                    let v = m.row(r).iter().fold(F192::ZERO, |s, &(c, k)| s + scaled(k, cols[c]));
                    if m.row(r).is_empty() { F192::ZERO } else { rows[r] * v }
                })
            },
            |a, b| std::array::from_fn(|i| a[i] + b[i]),
        )
    }

    pub fn claim(&self, verified: &Verified) -> DeferredClaim {
        DeferredClaim {
            app_key: self.key,
            row_point: verified.row_point.clone(),
            col_point: verified.col_point.clone(),
            matrix_values: verified.matrix_values,
        }
    }

    /// Settle one deferred claim by walking this fixed circuit once per matrix.
    pub fn settle(&self, claim: &DeferredClaim) -> bool {
        claim.app_key == self.key
            && claim.row_point.len() == self.row_log
            && claim.col_point.len() == self.z_log
            && self.matrix_evals(&claim.row_point, &claim.col_point) == claim.matrix_values
    }
    /// Count this generic direct evaluator in the existing four-cell row format.
    /// Constants and first accumulator terms alias instead of allocating add rows.
    pub fn matrix_gate_census(&self) -> serde_json::Value {
        let mut scalar_rows = 0usize;
        let mut nonempty = 0usize;
        let mut nonunit = 0usize;
        for m in &self.r1cs.matrices {
            for r in 0..m.rows() {
                let row = m.row(r);
                if row.is_empty() {
                    continue;
                }
                nonempty += 1;
                scalar_rows += row.len() - 1 + usize::from(row[0].1 != F192::ONE) + 1;
                nonunit += row.iter().filter(|&&(_, c)| c != F192::ONE).count();
            }
        }
        let eq_rows =
            (2 * ((1usize << self.row_log) - 2) + self.row_log) + (2 * ((1usize << self.z_log) - 2) + self.z_log);
        serde_json::json!({"matrix_evaluation_native_rows":scalar_rows+eq_rows,"eq_basis_native_rows":eq_rows,"sparse_accumulation_native_rows":scalar_rows,"nonempty_matrix_rows":nonempty,"nonunit_coefficients":nonunit,"matrix_evaluation_compressions":0,"kind":"algorithmic row count for generic direct evaluation, excludes transcript and WHIR"})
    }
    /// Record the generic sparse evaluator and lower it with the existing native compiler.
    pub fn recorded_matrix_census(&self, verified: &Verified) -> serde_json::Value {
        use crate::trace::{self, S};
        fn table(point: &[S]) -> Vec<S> {
            let mut out = vec![S::u(1)];
            for &r in point {
                let complement = S::u(1) + r;
                let mut next = Vec::with_capacity(2 * out.len());
                next.extend(out.iter().map(|&v| v * complement));
                next.extend(out.iter().map(|&v| v * r));
                out = next;
            }
            out
        }
        trace::start();
        let rp: Vec<_> = verified.row_point.iter().copied().map(S::input).collect();
        let cp: Vec<_> = verified.col_point.iter().copied().map(S::input).collect();
        let rows = table(&rp);
        let cols = table(&cp);
        let mut result = [S::u(0); 3];
        for (j, m) in self.r1cs.matrices.iter().enumerate() {
            for r in 0..m.rows() {
                if m.row(r).is_empty() {
                    continue;
                }
                let value = m.row(r).iter().fold(S::u(0), |s, &(c, k)| s + S::c(k) * cols[c]);
                result[j] = result[j] + rows[r] * value;
            }
        }
        let mut program = trace::take();
        program.public = result.to_vec();
        let expected = self.matrix_evals(&verified.row_point, &verified.col_point);
        assert_eq!(result.map(|s| program.nodes[s.0].value), expected);
        let lower = crate::private_trace::lower(&program, &program).unwrap();
        serde_json::json!({"recorded_native_rows":lower.circuit.rows.len(),"recorded_compressions":lower.compressions.len(),"recorded_scalar_nodes":program.nodes.len(),"recorded_variables":lower.circuit.variables,"algorithmic":self.matrix_gate_census()})
    }
    #[tracing::instrument(skip_all, name = "Spartan direct prove")]
    pub fn prove(&self, source: &[F192], blocks: &[Compression], context: &Hash) -> Proof {
        assert_eq!(blocks.len(), self.r1cs.actual_blocks);
        let mut z = self.r1cs.witness(source);
        let public = z[..self.r1cs.public_len].to_vec();
        z.resize(1usize << self.z_log, F192::ZERO);
        let (q, ha, hb, lincheck) = tracing::info_span!("Hash witness")
            .in_scope(|| generate_witness_with_ab_packed_and_lincheck(blocks, self.r1cs.block_log));
        let mut stack = vec![F64::ZERO; self.committed_words];
        let n = z.len();
        parallel::chunks_mut(&mut stack[..3 * n], n.min(4096), |chunk, out| {
            let start = chunk * n.min(4096);
            let limb = start / n;
            let at = start % n;
            let len = out.len();
            for (dest, v) in out.iter_mut().zip(&z[at..at + len]) {
                *dest = F64([v.c0, v.c1, v.c2][limb]);
            }
        });
        for (dest, &v) in stack[self.q_offset..].iter_mut().zip(&q) {
            *dest = F64(v);
        }
        let (commitment, data) = tracing::info_span!("Joint commitment")
            .in_scope(|| whir::commit(&stack, self.stack_log, INITIAL_FOLDING_FACTOR, RATE));
        let mut ps = ProverState::from_label(&self.label(&public, context));
        ps.add_root(&commitment.root);
        let mut claims = Vec::new();
        let tau = ps.sample_vec(self.row_log);
        let [a, b, c] = tracing::info_span!("Sparse matrix products").in_scope(|| {
            self.r1cs
                .matrices
                .each_ref()
                .map(|m| m.product(&z, 1usize << self.row_log))
        });
        let c_saved = c.clone();
        let (row_point, av, bv, terminal) = tracing::info_span!("Outer R1CS sumcheck").in_scope(|| {
            zerocheck::prove_tables(a, b, c, &tau, F192::ZERO, &mut |_| (F192::ZERO, F192::ZERO), &mut ps)
        });
        let row_weights = eq_table(&row_point);
        let cv = dot(&row_weights, &c_saved);
        drop(c_saved);
        assert_eq!(terminal, av * bv + cv);
        ps.add_scalars(&[av, bv, cv]);
        let alpha = ps.sample();
        let alpha2 = alpha * alpha;
        let mut g = vec![F192::ZERO; n];
        tracing::info_span!("Sparse matrix row folding").in_scope(|| {
            for (m, weight) in self.r1cs.matrices.iter().zip([F192::ONE, alpha, alpha2]) {
                let fold = m.fold_rows(&row_weights, n);
                parallel::chunks_mut(&mut g, 4096, |c, out| {
                    for (j, v) in out.iter_mut().enumerate() {
                        *v += scaled(weight, fold[c * 4096 + j]);
                    }
                });
            }
        });
        drop(row_weights);
        let claim = av + alpha * bv + alpha2 * cv;
        let (col_point, _, z_value) =
            tracing::info_span!("Inner matrix sumcheck").in_scope(|| product_sumcheck(g, z, claim, &mut ps));
        let opened = self.send_field(&stack, 0, &col_point, &mut ps, &mut claims);
        assert_eq!(opened, z_value);
        let matrix_values = self.matrix_evals(&row_point, &col_point);
        ps.add_scalars(&matrix_values);
        let public_point = ps.sample_vec(self.r1cs.public_log);
        self.public_claims(&public, &public_point, &mut claims);
        let reduced = tracing::info_span!("Hash reduction").in_scope(|| {
            Blake2sSetup::new(self.r1cs.actual_blocks.max(128))
                .prove_reduction_precomputed(&q, &ha, &hb, &lincheck, &mut ps)
        });
        drop((q, ha, hb, lincheck));
        let point = ps.sample_vec(self.r1cs.block_log);
        let weights = eq_table(&point);
        let mut ports = [F192::ZERO; 18];
        for (slot, v) in ports.iter_mut().enumerate() {
            let at = self.r1cs.port_start + slot * (1usize << self.r1cs.block_log);
            *v = whir::inner_product_base_ext(&stack[at..at + weights.len()], &weights);
            ps.add_scalar(*v);
        }
        self.port_claims(&point, &ports, &mut claims);
        let ring = ring_switch_open(1usize << self.r1cs.block_log, self.q_offset, &reduced);
        let config = whir::config_for_rate(self.stack_log, RATE).unwrap();
        tracing::info_span!("Joint WHIR opening").in_scope(|| {
            open_batch_mixed_whir_stacked(&mut ps, self.stack_log, &stack, &data, &config, &claims, &ring)
        });
        ps.into_proof()
    }
    #[tracing::instrument(skip_all, name = "Spartan direct verify")]
    pub fn verify(&self, public: &[F192], context: &Hash, proof: &Proof) -> Option<Verified> {
        self.verify_deferred(public, context, proof, true)
    }

    /// Verify all child transcript, sumcheck, native-hash, and opening checks.
    /// When `settle_matrix` is false, leave the three matrix values as a carried claim.
    pub fn verify_deferred(
        &self,
        public: &[F192],
        context: &Hash,
        proof: &Proof,
        settle_matrix: bool,
    ) -> Option<Verified> {
        if public.len() != self.r1cs.public_len || public[0] != F192::ONE {
            return None;
        }
        let mut vs = VerifierState::from_label(&self.label(public, context), proof);
        let root = vs.next_root().ok()?;
        let tau = vs.sample_vec(self.row_log);
        let (row_point, terminal) = zerocheck::verify_tables(&tau, F192::ZERO, &mut vs).ok()?;
        let av = vs.next_scalar().ok()?;
        let bv = vs.next_scalar().ok()?;
        let cv = vs.next_scalar().ok()?;
        if terminal != av * bv + cv {
            return None;
        }
        let alpha = vs.sample();
        let alpha2 = alpha * alpha;
        let mut running = av + alpha * bv + alpha2 * cv;
        let mut col_point = Vec::new();
        for _ in 0..self.z_log {
            let poly = vs.next_round_poly(3, running, None).ok()?;
            let r = vs.sample();
            running = poly_eval(&poly, r);
            col_point.push(r);
        }
        let mut claims = Vec::new();
        let zv = self.read_field(0, &col_point, &mut vs, &mut claims)?;
        let ma = vs.next_scalar().ok()?;
        let mb = vs.next_scalar().ok()?;
        let mc = vs.next_scalar().ok()?;
        let matrix_values = [ma, mb, mc];
        if settle_matrix && self.matrix_evals(&row_point, &col_point) != matrix_values {
            return None;
        }
        if running != (ma + alpha * mb + alpha2 * mc) * zv {
            return None;
        }
        let public_point = vs.sample_vec(self.r1cs.public_log);
        self.public_claims(public, &public_point, &mut claims);
        let reduced = Blake2sSetup::new(self.r1cs.actual_blocks.max(128))
            .verify_reduction(&mut vs)
            .ok()?;
        let point = vs.sample_vec(self.r1cs.block_log);
        let mut ports = [F192::ZERO; 18];
        for v in &mut ports {
            *v = vs.next_scalar().ok()?;
        }
        self.port_claims(&point, &ports, &mut claims);
        let ring = ring_switch_verify(1usize << self.r1cs.block_log, self.q_offset, &reduced.claim);
        let config = whir::config_for_rate(self.stack_log, RATE).ok()?;
        let lanes = self.committed_words / (1usize << (self.stack_log - INITIAL_FOLDING_FACTOR));
        verify_opening_batch_mixed_whir_stacked(&mut vs, &config, self.stack_log, lanes, &root, &claims, &ring).ok()?;
        vs.finish().ok()?;
        Some(Verified {
            row_point,
            col_point,
            matrix_values,
        })
    }
}

fn product_sumcheck(
    mut a: Vec<F192>,
    mut b: Vec<F192>,
    mut running: F192,
    ps: &mut ProverState,
) -> (Vec<F192>, F192, F192) {
    let mut point = Vec::new();
    while a.len() > 1 {
        let half = a.len() / 2;
        let [c0, c2] = parallel::map_reduce(
            half,
            || [F192::ZERO; 2],
            |i| {
                [
                    a[2 * i] * b[2 * i],
                    (a[2 * i] + a[2 * i + 1]) * (b[2 * i] + b[2 * i + 1]),
                ]
            },
            |a, b| [a[0] + b[0], a[1] + b[1]],
        );
        let poly = [c0, running + c2, c2];
        ps.add_round_poly(&poly, false);
        let r = ps.sample();
        running = poly_eval(&poly, r);
        point.push(r);
        a = parallel::map_collect(half, |i| a[2 * i] + r * (a[2 * i] + a[2 * i + 1]));
        b = parallel::map_collect(half, |i| b[2 * i] + r * (b[2 * i] + b[2 * i + 1]));
    }
    assert_eq!(running, a[0] * b[0]);
    (point, a[0], b[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_spartan_and_r1cs_ccs_bind_products_hash_ports_and_public_output() {
        parallel::init();
        let mut b = crate::native_hash::Builder::default();
        let a = b.input(3);
        let c = b.input(5);
        let p = b.gate(a, c, b.zero());
        let hash = b.hash_words(&[p, a, c]);
        for w in hash {
            b.expose(w);
        }
        let (circuit, ports) = b.export_circuit();
        let fixed_len = circuit.public.len() - 4;
        for ccs in [false, true] {
            let r = R1cs::lower_bounded(&circuit, &ports, &b.values, fixed_len, 16);
            assert!(r.satisfied(&r.witness(&b.values)));
            let setup = Setup::new(r, ccs);
            let public = setup.public(&b.values);
            let context = [42; 32];
            let proof = setup.prove(&b.values, &b.compressions, &context);
            assert!(setup.verify(&public, &context, &proof).is_some());
            let mut wrong = public.clone();
            wrong[1] += F192::ONE;
            assert!(setup.verify(&wrong, &context, &proof).is_none());
            let mut bad = proof.clone();
            bad.stream[5] += F192::ONE;
            assert!(setup.verify(&public, &context, &bad).is_none());
            let mut foreign = b.values.clone();
            foreign[2] += F192::ONE;
            let z = setup.r1cs.witness(&foreign);
            assert!(!setup.r1cs.satisfied(&z));
        }
    }
}
