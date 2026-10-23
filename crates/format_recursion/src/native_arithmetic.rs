//! Experimental native-field multiply-add circuit argument.
//! Uses the existing table zerocheck, permutation GKR and WHIR opening code.
//! This composition has tests, not a Lean soundness or implementation proof.

use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::zerocheck;
use leanvm_core::gkr::{self, RootShape};
use pcs::whir::{self, ProverData};
use primitives::{
    field::{F64, F192, F192Unreduced},
    multilinear::{eq_eval, eq_table},
};

/// Resource cap, with four cell-address columns still fitting in u32.
pub const MAX_LOG_ROWS: usize = 26;

/// A row enforces z = x*y + u. Variables zero and one are pinned public anchors.
#[derive(Clone)]
pub struct Circuit {
    pub variables: usize,
    pub rows: Vec<[usize; 4]>,
    pub public: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArithmeticShape {
    pub log_rows: usize,
    pub public_log: usize,
    pub public_len: usize,
    pub index_log_inv_rate: usize,
}

pub struct Index {
    pub root: Hash,
    pub log_rows: usize,
    pub public_log: usize,
    pub index_log_inv_rate: usize,
    circuit: Circuit,
    rows: Vec<[usize; 4]>,
    sigma: Vec<u32>,
    stack: Vec<F64>,
    data: ProverData,
}

impl Index {
    pub fn new(circuit: Circuit) -> Self {
        Self::new_with_rate(circuit, 1)
    }
    /// Select a validated production WHIR profile for the fixed circuit index.
    /// Standalone witness openings retain their rate-1/2 profile.
    pub fn new_with_rate(circuit: Circuit, index_log_inv_rate: usize) -> Self {
        whir::validate_log_inv_rate(index_log_inv_rate).expect("supported index WHIR rate");
        assert_eq!(&circuit.public[..2], &[0, 1]);
        assert!(circuit.variables >= 2);
        assert!(
            circuit
                .public
                .iter()
                .chain(circuit.rows.iter().flatten())
                .all(|&v| v < circuit.variables)
        );
        let public_log = circuit.public.len().next_power_of_two().trailing_zeros() as usize;
        let public_rows = 1 << public_log;
        let count = public_rows + circuit.rows.len();
        let log_rows = (count.next_power_of_two().trailing_zeros() as usize).max(13);
        assert!(log_rows <= MAX_LOG_ROWS, "bounded experimental index");
        let n = 1 << log_rows;
        let mut rows: Vec<_> = circuit.public.iter().map(|&v| [v, 1, 0, v]).collect();
        rows.resize(public_rows, [0, 1, 0, 0]);
        rows.extend_from_slice(&circuit.rows);
        rows.resize(n, [0, 0, 0, 0]);
        let mut first = vec![None; circuit.variables];
        let mut last = vec![0usize; circuit.variables];
        let mut sigma = vec![0u32; 4 * n];
        for role in 0..4 {
            for (r, row) in rows.iter().enumerate() {
                let at = r + role * n;
                let v = row[role];
                if let Some(start) = first[v] {
                    sigma[last[v]] = at as u32;
                    sigma[at] = start as u32;
                } else {
                    first[v] = Some(at);
                    sigma[at] = at as u32;
                }
                last[v] = at;
            }
        }
        let stack: Vec<_> = sigma.iter().map(|&v| F64(v as u64)).collect();
        let (commitment, data) = whir::commit(&stack, log_rows + 2, whir::INITIAL_FOLDING_FACTOR, index_log_inv_rate);
        Self {
            root: commitment.root,
            log_rows,
            public_log,
            index_log_inv_rate,
            circuit,
            rows,
            sigma,
            stack,
            data,
        }
    }
    pub fn verifier_shape(&self) -> ArithmeticShape {
        ArithmeticShape {
            log_rows: self.log_rows,
            public_log: self.public_log,
            public_len: self.circuit.public.len(),
            index_log_inv_rate: self.index_log_inv_rate,
        }
    }
    /// First committed cell for each requested variable in the compact layout.
    pub fn compact_variable_cells(&self, variables: &[usize]) -> Option<Vec<[usize; 3]>> {
        let n = 1usize << self.log_rows;
        let mut first = vec![None; self.circuit.variables];
        for role in 0..4 {
            for (row, entries) in self.rows.iter().enumerate() {
                first[entries[role]].get_or_insert([
                    3 * role * n + row,
                    (3 * role + 1) * n + row,
                    (3 * role + 2) * n + row,
                ]);
            }
        }
        variables.iter().map(|&v| first.get(v).copied().flatten()).collect()
    }
    pub fn public_values(&self, values: &[F192]) -> Vec<F192> {
        self.circuit.public.iter().map(|&v| values[v]).collect()
    }
    pub fn shape(&self) -> (usize, usize, usize) {
        (
            self.circuit.variables,
            self.circuit.rows.len(),
            self.circuit.public.len(),
        )
    }
    /// Nonzeros if these padded native rows are written literally as x*y=(z+u).
    /// The zero anchor contributes no coefficient and repeated C entries cancel.
    pub fn r1cs_shadow_nonzeros(&self) -> [usize; 3] {
        let mut counts = [0; 3];
        for &[x, y, u, z] in &self.rows {
            counts[0] += usize::from(x != 0);
            counts[1] += usize::from(y != 0);
            if u != z {
                counts[2] += usize::from(u != 0) + usize::from(z != 0);
            }
        }
        counts
    }
    fn columns(&self, values: &[F192]) -> [Vec<F192>; 4] {
        assert_eq!(values.len(), self.circuit.variables);
        std::array::from_fn(|role| parallel::map_collect(self.rows.len(), |row| values[self.rows[row][role]]))
    }
}

#[derive(Clone)]
pub(crate) struct Claim {
    pub offset: usize,
    pub point: Vec<F192>,
    pub value: F192,
}
fn claim_eval(claim: &Claim, at: &[F192]) -> F192 {
    let mut v = eq_eval(&claim.point, &at[..claim.point.len()]);
    let selector = claim.offset >> claim.point.len();
    for (i, &x) in at[claim.point.len()..].iter().enumerate() {
        v *= if (selector >> i) & 1 == 1 { x } else { F192::ONE + x };
    }
    v
}
fn label(index: &Index, public: &[F192], context: &Hash) -> Vec<u8> {
    let mut out = if index.index_log_inv_rate == 1 {
        b"format-native-arithmetic-v1".to_vec()
    } else {
        let mut out = b"format-native-arithmetic-v2".to_vec();
        out.extend_from_slice(&(index.index_log_inv_rate as u64).to_le_bytes());
        out
    };
    out.extend_from_slice(&index.root);
    out.extend_from_slice(context);
    for n in [index.log_rows, index.public_log, public.len()] {
        out.extend_from_slice(&(n as u64).to_le_bytes());
    }
    for x in public {
        for limb in [x.c0, x.c1, x.c2] {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
    out
}
fn stack_columns(cols: &[Vec<F192>; 4], column_stride: usize, capacity: usize) -> Vec<F64> {
    assert!(column_stride == 3 || column_stride == 4);
    let n = cols[0].len();
    let words = 4 * column_stride * n;
    assert!(capacity >= words);
    let mut stack = if capacity == words {
        vec![F64::ZERO; words]
    } else {
        let mut stack = Vec::with_capacity(capacity);
        stack.resize(words, F64::ZERO);
        stack
    };
    // Native columns have power-of-two length. Smaller tasks stay within one
    // limb column and expose more parallelism than its twelve populated limbs.
    let chunk_len = n.min(4096);
    parallel::chunks_mut(&mut stack, chunk_len, |chunk, dst| {
        let at = chunk * chunk_len;
        let slot = at / n;
        let first = at % n;
        let limb = slot % column_stride;
        if limb < 3 {
            let len = dst.len();
            for (dest, value) in dst.iter_mut().zip(&cols[slot / column_stride][first..first + len]) {
                *dest = F64(match limb {
                    0 => value.c0,
                    1 => value.c1,
                    _ => value.c2,
                });
            }
        }
    });
    stack
}
/// Evaluate several base-field columns against one shared extension basis.
/// Reduction is linear over XOR, so each window accumulates unreduced products
/// and reduces once after the parallel reduction. Basis windows stay in cache.
fn evaluate_base_columns<const C: usize>(columns: [&[F64]; C], weights: &[F192]) -> [F192; C] {
    assert!(columns.iter().all(|column| column.len() == weights.len()));
    const WINDOW: usize = 256;
    let xor = |mut left: [F192Unreduced; C], right: [F192Unreduced; C]| {
        for i in 0..C {
            left[i] ^= right[i];
        }
        left
    };
    let window = |first: usize, end: usize| {
        let mut sums = [F192Unreduced::ZERO; C];
        for column in 0..C {
            for (i, &weight) in weights.iter().enumerate().take(end).skip(first) {
                let word = columns[column][i];
                if word != F64::ZERO {
                    sums[column] ^= weight.mul_base_unreduced(word);
                }
            }
        }
        sums
    };
    let sums = if weights.len() < 4096 {
        window(0, weights.len())
    } else {
        parallel::map_reduce(
            weights.len().div_ceil(WINDOW),
            || [F192Unreduced::ZERO; C],
            |i| window(i * WINDOW, ((i + 1) * WINDOW).min(weights.len())),
            xor,
        )
    };
    sums.map(F192Unreduced::reduce)
}

/// The two copy-product leaves differ only in the public cell address. Share
/// their witness multiplication and avoid multiplying the fixed zero/one cells.
fn copy_leaves(cols: &[Vec<F192>; 4], sigma: &[u32], alpha: F192, beta: F192) -> (Vec<F192>, Vec<F192>) {
    let n = cols[0].len();
    assert!(cols.iter().all(|column| column.len() == n));
    assert_eq!(sigma.len(), 4 * n);
    // SAFETY: chunks_mut2 covers every position of both vectors, and each
    // loop iteration writes both outputs before either vector is read.
    let (mut ids, mut permuted) = unsafe {
        (
            primitives::uninit_vec::<F192>(4 * n),
            primitives::uninit_vec::<F192>(4 * n),
        )
    };
    parallel::chunks_mut2(&mut ids, &mut permuted, 256, |chunk, ids, permuted| {
        let start = chunk * 256;
        for (i, (id, permuted)) in ids.iter_mut().zip(permuted).enumerate() {
            let at = start + i;
            let value = cols[at / n][at % n];
            let scaled = if value == F192::ZERO {
                F192::ZERO
            } else if value == F192::ONE {
                beta
            } else {
                beta * value
            };
            let common = alpha + scaled;
            *id = common + F192::new(at as u64, 0, 0);
            *permuted = common + F192::new(sigma[at] as u64, 0, 0);
        }
    });
    (ids, permuted)
}

fn send_field(
    stack: &[F64],
    l: usize,
    col: usize,
    column_stride: usize,
    point: &[F192],
    weights: &[F192],
    ps: &mut ProverState,
    claims: &mut Vec<Claim>,
) -> F192 {
    let n = 1 << l;
    let mut value = F192::ZERO;
    let mut basis = F192::ONE;
    let columns = std::array::from_fn(|limb| {
        let offset = (col * column_stride + limb) * n;
        &stack[offset..offset + weights.len()]
    });
    let evaluations: [F192; 3] = evaluate_base_columns(columns, weights);
    for (limb, v) in evaluations.into_iter().enumerate() {
        let offset = (col * 4 + limb) * n;
        ps.add_scalar(v);
        claims.push(Claim {
            offset,
            point: point.to_vec(),
            value: v,
        });
        value += basis * v;
        basis *= F192::Y;
    }
    value
}
fn read_field(
    l: usize,
    col: usize,
    point: &[F192],
    vs: &mut VerifierState<'_>,
    claims: &mut Vec<Claim>,
) -> Option<F192> {
    let mut value = F192::ZERO;
    let mut basis = F192::ONE;
    for limb in 0..3 {
        let v = vs.next_scalar().ok()?;
        claims.push(Claim {
            offset: (col * 4 + limb) * (1 << l),
            point: point.to_vec(),
            value: v,
        });
        value += basis * v;
        basis *= F192::Y;
    }
    Some(value)
}
/// Claims are accumulated in their original order. Only disjoint rows within
/// one claim run in parallel, preserving exact overlap and transcript behavior.
fn accumulate_weights(weights: &mut [F192], offset: usize, equality: &[F192], power: F192) {
    let destination = &mut weights[offset..offset + equality.len()];
    if equality.len() < 4096 {
        for (out, &eq) in destination.iter_mut().zip(equality) {
            *out += power * eq;
        }
    } else {
        parallel::chunks_mut(destination, 256, |chunk, out| {
            let first = chunk * 256;
            for (out, &eq) in out.iter_mut().zip(&equality[first..]) {
                *out += power * eq;
            }
        });
    }
}

fn open(stack: &[F64], data: &ProverData, l: usize, log_inv_rate: usize, claims: &[Claim], ps: &mut ProverState) {
    let weights_span = tracing::info_span!("Native opening weights").entered();
    let lambda = ps.sample();
    let mut power = F192::ONE;
    let mut target = F192::ZERO;
    let mut weights = vec![F192::ZERO; stack.len()];
    let mut previous_point: Option<&[F192]> = None;
    let mut eq = Vec::new();
    for claim in claims {
        target += power * claim.value;
        if previous_point != Some(claim.point.as_slice()) {
            eq = eq_table(&claim.point);
            previous_point = Some(&claim.point);
        }
        accumulate_weights(&mut weights, claim.offset, &eq, power);
        power *= lambda;
    }
    drop(weights_span);
    let config = whir::config_for_rate(l, log_inv_rate).unwrap();
    whir::recursive_prover_with_basis(
        &config,
        l,
        stack,
        weights,
        target,
        &data.codeword,
        &data.merkle_tree,
        ps,
    );
}
fn verify_open(root: &Hash, l: usize, log_inv_rate: usize, claims: &[Claim], vs: &mut VerifierState<'_>) -> bool {
    let lambda = vs.sample();
    let mut power = F192::ONE;
    let mut target = F192::ZERO;
    let mut powers = Vec::new();
    for claim in claims {
        target += power * claim.value;
        powers.push(power);
        power *= lambda;
    }
    let Ok(config) = whir::config_for_rate(l, log_inv_rate) else {
        return false;
    };
    whir::recursive_verifier_with_basis_succinct(
        &config,
        l,
        1 << whir::INITIAL_FOLDING_FACTOR,
        target,
        root,
        |x| {
            claims
                .iter()
                .zip(&powers)
                .fold(F192::ZERO, |acc, (claim, &power)| acc + power * claim_eval(claim, x))
        },
        vs,
    )
    .is_ok()
}

/// Prove the fixed multiply-add circuit. Public values, index and caller context
/// enter the transcript before the witness commitment and all random checks.
pub(crate) struct Prepared {
    pub stack: Vec<F64>,
    cols: [Vec<F192>; 4],
}
pub(crate) fn prepare(index: &Index, values: &[F192]) -> Prepared {
    let cols = index.columns(values);
    let stack = stack_columns(&cols, 4, 16 << index.log_rows);
    Prepared { stack, cols }
}
/// Build the twelve populated limbs directly for the private joint stack.
/// The caller may take this stack, append its other committed tables and pass
/// the resulting stack to `prove_reduction_compact` without copying the limbs.
#[allow(dead_code)] // Also consumed by the separately integrated private bridge.
pub(crate) fn prepare_compact(index: &Index, values: &[F192]) -> Prepared {
    prepare_compact_with_capacity(index, values, 12 << index.log_rows)
}
/// Reserve the final joint length up front so that growing the taken stack
/// does not reallocate or move its populated native limbs.
#[allow(dead_code)] // Also consumed by the separately integrated private bridge.
pub(crate) fn prepare_compact_with_capacity(index: &Index, values: &[F192], capacity: usize) -> Prepared {
    let cols = index.columns(values);
    let stack = stack_columns(&cols, 3, capacity);
    Prepared { stack, cols }
}
pub(crate) fn prove_reduction(index: &Index, witness: &Prepared, ps: &mut ProverState) -> (Vec<Claim>, Vec<Claim>) {
    prove_reduction_with_stack(index, witness, &witness.stack, 4, ps)
}
/// Read twelve contiguous limbs from the joint commitment, while emitting the
/// original sixteen-slot claim coordinates for the bridge's existing mapping.
/// All populated limbs are read; no suffix or populated column is omitted.
#[allow(dead_code)] // Also consumed by the separately integrated private bridge.
pub(crate) fn prove_reduction_compact(
    index: &Index,
    witness: &Prepared,
    stack: &[F64],
    ps: &mut ProverState,
) -> (Vec<Claim>, Vec<Claim>) {
    prove_reduction_with_stack(index, witness, stack, 3, ps)
}
fn prove_reduction_with_stack(
    index: &Index,
    witness: &Prepared,
    stack: &[F64],
    column_stride: usize,
    ps: &mut ProverState,
) -> (Vec<Claim>, Vec<Claim>) {
    let l = index.log_rows;
    let n = 1 << l;
    let cols = &witness.cols;
    assert!(stack.len() >= 4 * column_stride * n);
    let mut claims = Vec::new();
    let mut index_claims = Vec::new();
    let zerocheck_span = tracing::info_span!("Native zerocheck").entered();
    let r = ps.sample_vec(l);
    let c = parallel::map_collect(n, |i| cols[2][i] + cols[3][i]);
    let (point, _, _, _) = zerocheck::prove_tables(
        cols[0].clone(),
        cols[1].clone(),
        c,
        &r,
        F192::ZERO,
        &mut |_| (F192::ZERO, F192::ZERO),
        ps,
    );
    drop(zerocheck_span);
    let gate_span = tracing::info_span!("Native gate evaluations").entered();
    let weights = eq_table(&point);
    for col in 0..4 {
        send_field(stack, l, col, column_stride, &point, &weights, ps, &mut claims);
    }
    drop(weights);
    drop(gate_span);
    let leaves_span = tracing::info_span!("Native copy leaves").entered();
    let alpha = ps.sample();
    let beta = ps.sample();
    let (ids, sigma) = copy_leaves(cols, &index.sigma, alpha, beta);
    drop(leaves_span);
    let product_span = tracing::info_span!("Native copy product").entered();
    let product = gkr::prove_product_triple([ids, sigma, vec![F192::ONE]], ps, RootShape::Distinct);
    drop(product_span);
    let copy_span = tracing::info_span!("Native copy evaluations").entered();
    let rho = &product.point[..l];
    let weights = eq_table(rho);
    for col in 0..4 {
        send_field(stack, l, col, column_stride, rho, &weights, ps, &mut claims);
    }
    let index_columns = std::array::from_fn(|col| &index.stack[col * n..(col + 1) * n]);
    let index_values: [F192; 4] = evaluate_base_columns(index_columns, &weights);
    for (col, value) in index_values.into_iter().enumerate() {
        ps.add_scalar(value);
        index_claims.push(Claim {
            offset: col * n,
            point: rho.to_vec(),
            value,
        });
    }
    drop(weights);
    drop(copy_span);
    let public_span = tracing::info_span!("Native public evaluation").entered();
    let point = ps.sample_vec(index.public_log);
    let weights = eq_table(&point);
    send_field(stack, l, 3, column_stride, &point, &weights, ps, &mut claims);
    drop(public_span);
    (claims, index_claims)
}
pub(crate) fn prove_index_open(index: &Index, claims: &[Claim], ps: &mut ProverState) {
    let log_n = index.log_rows + 2;
    let config = whir::config_for_rate(log_n, index.index_log_inv_rate).unwrap();
    let n = 1usize << index.log_rows;
    let canonical = (2..=log_n).contains(&config.initial_k)
        && claims.len() == 4
        && claims.iter().enumerate().all(|(column, claim)| {
            claim.offset == column * n && claim.point.len() == index.log_rows && claim.point == claims[0].point
        });
    if !canonical {
        open(&index.stack, &index.data, log_n, index.index_log_inv_rate, claims, ps);
        return;
    }
    let weights_span = tracing::info_span!("Native opening weights").entered();
    let lambda = ps.sample();
    let log_block = log_n - config.initial_k;
    let (low, high) = claims[0].point.split_at(log_block);
    let selectors = eq_table(high);
    let mut lanes = vec![F192::ZERO; 1usize << config.initial_k];
    let mut power = F192::ONE;
    let mut target = F192::ZERO;
    for (column, claim) in claims.iter().enumerate() {
        target += power * claim.value;
        for (lane, &selector) in selectors.iter().enumerate() {
            lanes[column * selectors.len() + lane] = power * selector;
        }
        power *= lambda;
    }
    let weights = [whir::LaneWeight {
        lanes,
        block: eq_table(low),
    }];
    drop(weights_span);
    whir::recursive_prover_with_lane_weights(
        &config,
        log_n,
        &index.stack,
        &weights,
        target,
        &index.data.codeword,
        &index.data.merkle_tree,
        ps,
    );
}
pub(crate) fn verify_index_open(index: &Index, claims: &[Claim], vs: &mut VerifierState<'_>) -> bool {
    verify_open(&index.root, index.log_rows + 2, index.index_log_inv_rate, claims, vs)
}
pub fn prove(index: &Index, values: &[F192], context: &Hash) -> Proof {
    let l = index.log_rows;
    let public = index.public_values(values);
    let mut ps = ProverState::from_label(&label(index, &public, context));
    let witness = prepare(index, values);
    let (commitment, data) = whir::commit(&witness.stack, l + 4, whir::INITIAL_FOLDING_FACTOR, 1);
    ps.add_root(&commitment.root);
    let (claims, index_claims) = prove_reduction(index, &witness, &mut ps);
    open(&witness.stack, &data, l + 4, 1, &claims, &mut ps);
    prove_index_open(index, &index_claims, &mut ps);
    ps.into_proof()
}

/// Verify against a trusted index. This verifier does not read witness values
/// or walk the arithmetic circuit or its permutation.
pub(crate) fn verify_reduction(
    index: &Index,
    public: &[F192],
    vs: &mut VerifierState<'_>,
) -> Option<(Vec<Claim>, Vec<Claim>)> {
    if public.len() != index.circuit.public.len() || public[..2] != [F192::ZERO, F192::ONE] {
        return None;
    }
    let l = index.log_rows;
    let n = 1 << l;
    let mut claims = Vec::new();
    let mut index_claims = Vec::new();
    let r = vs.sample_vec(l);
    if r.contains(&F192::ONE) {
        return None;
    }
    let (point, target) = zerocheck::verify_tables(&r, F192::ZERO, vs).ok()?;
    let gate: Option<Vec<_>> = (0..4).map(|col| read_field(l, col, &point, vs, &mut claims)).collect();
    let gate = gate?;
    if gate[0] * gate[1] + gate[2] + gate[3] != target {
        return None;
    }
    let alpha = vs.sample();
    let beta = vs.sample();
    let product = gkr::verify_product_triple(l + 2, vs, RootShape::Distinct).ok()?;
    if product.roots[0] != product.roots[1] || product.roots[2] != F192::ONE {
        return None;
    }
    let (rho, role_point) = product.point.split_at(l);
    let values: Option<Vec<_>> = (0..4).map(|col| read_field(l, col, rho, vs, &mut claims)).collect();
    let values = values?;
    let mut sigmas = Vec::new();
    for col in 0..4 {
        let value = vs.next_scalar().ok()?;
        sigmas.push(value);
        index_claims.push(Claim {
            offset: col * n,
            point: rho.to_vec(),
            value,
        });
    }
    let id = rho
        .iter()
        .enumerate()
        .fold(F192::ZERO, |acc, (i, &x)| acc + x * F192::new(1 << i, 0, 0));
    let mut a = F192::ZERO;
    let mut b = F192::ZERO;
    for (col, e) in eq_table(role_point).into_iter().enumerate() {
        a += e * (alpha + id + F192::new((col * n) as u64, 0, 0) + beta * values[col]);
        b += e * (alpha + sigmas[col] + beta * values[col]);
    }
    if product.values != [a, b, F192::ONE] {
        return None;
    }
    let point = vs.sample_vec(index.public_log);
    let value = read_field(l, 3, &point, vs, &mut claims)?;
    let expected = eq_table(&point)
        .iter()
        .zip(public)
        .fold(F192::ZERO, |acc, (&e, &v)| acc + e * v);
    if value != expected {
        return None;
    }
    Some((claims, index_claims))
}
pub fn verify(index: &Index, public: &[F192], context: &Hash, proof: &Proof) -> bool {
    let mut vs = VerifierState::from_label(&label(index, public, context), proof);
    let Some(root) = vs.next_root().ok() else {
        return false;
    };
    let Some((claims, index_claims)) = verify_reduction(index, public, &mut vs) else {
        return false;
    };
    verify_open(&root, index.log_rows + 4, 1, &claims, &mut vs)
        && verify_index_open(index, &index_claims, &mut vs)
        && vs.finish().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    #[test]
    fn deferred_native_evaluations_match_reference_for_dense_sparse_and_boundary_lengths() {
        parallel::init();
        let mut rng = StdRng::seed_from_u64(0xB4515);
        for n in [0usize, 1, 255, 256, 257, 4095, 4096, 4097, 8192] {
            let weights: Vec<_> = (0..n)
                .map(|_| F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64()))
                .collect();
            let columns: [Vec<_>; 4] = std::array::from_fn(|column| {
                (0..n)
                    .map(|i| {
                        if column == 0 || (column == 1 && i % 3 != 0) {
                            F64::ZERO
                        } else {
                            F64(rng.next_u64())
                        }
                    })
                    .collect()
            });
            let got = evaluate_base_columns(columns.each_ref().map(Vec::as_slice), &weights);
            for i in 0..4 {
                assert_eq!(
                    got[i],
                    whir::inner_product_base_ext(&columns[i], &weights),
                    "n={n} column={i}"
                );
            }
        }
    }

    #[test]
    fn shared_copy_fingerprints_match_reference_including_zero_one_and_extension_cells() {
        parallel::init();
        let mut rng = StdRng::seed_from_u64(0xC0B1);
        for n in [1usize, 255, 256, 257, 8192] {
            let cols: [Vec<_>; 4] = std::array::from_fn(|_| {
                (0..n)
                    .map(|i| match i % 4 {
                        0 => F192::ZERO,
                        1 => F192::ONE,
                        _ => F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64()),
                    })
                    .collect()
            });
            let sigma: Vec<_> = (0..4 * n).map(|i| ((i + 11) % (4 * n)) as u32).collect();
            let alpha = F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64());
            let beta = F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64());
            let (ids, permuted) = copy_leaves(&cols, &sigma, alpha, beta);
            for i in 0..4 * n {
                let common = alpha + beta * cols[i / n][i % n];
                assert_eq!(ids[i], common + F192::new(i as u64, 0, 0));
                assert_eq!(permuted[i], common + F192::new(sigma[i] as u64, 0, 0));
            }
        }
    }

    #[test]
    fn parallel_opening_weights_preserve_overlapping_claim_accumulation() {
        parallel::init();
        let mut rng = StdRng::seed_from_u64(0xB45152);
        let mut got = vec![F192::ONE; 32768];
        let mut expected = got.clone();
        for (offset, length) in [
            (0usize, 8192usize),
            (4096, 4096),
            (257, 257),
            (4097, 4097),
            (8192, 8192),
            (0, 32768),
        ] {
            let equality: Vec<_> = (0..length)
                .map(|_| F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64()))
                .collect();
            let power = F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64());
            accumulate_weights(&mut got, offset, &equality, power);
            for (out, &eq) in expected[offset..].iter_mut().zip(&equality) {
                *out += power * eq;
            }
            assert_eq!(got, expected, "offset={offset} length={length}");
        }
    }

    #[test]
    fn factored_index_opening_matches_the_complete_dense_proof() {
        parallel::init();
        let mut rng = StdRng::seed_from_u64(0xFA_C701);
        for rate in [1, 4] {
            let index = Index::new_with_rate(
                Circuit {
                    variables: 6,
                    rows: vec![[2, 3, 0, 4], [4, 1, 2, 5]],
                    public: vec![0, 1, 5],
                },
                rate,
            );
            let point: Vec<_> = (0..index.log_rows)
                .map(|_| F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64()))
                .collect();
            let n = 1usize << index.log_rows;
            let equality = eq_table(&point);
            let claims: Vec<_> = (0..4)
                .map(|column| Claim {
                    offset: column * n,
                    point: point.clone(),
                    value: whir::inner_product_base_ext(&index.stack[column * n..(column + 1) * n], &equality),
                })
                .collect();
            for canonical in [true, false] {
                // Reordering preserves a valid batched claim while exercising the dense fallback.
                let mut claims = claims.clone();
                if !canonical {
                    claims.swap(0, 1);
                }
                let label = b"factored-index-opening-reference";
                let mut dense = ProverState::from_label(label);
                open(&index.stack, &index.data, index.log_rows + 2, rate, &claims, &mut dense);
                let expected = dense.into_proof();
                let mut actual = ProverState::from_label(label);
                prove_index_open(&index, &claims, &mut actual);
                let actual = actual.into_proof();
                assert_eq!(actual, expected, "rate={rate} canonical={canonical}");
                let mut verifier = VerifierState::from_label(label, &actual);
                assert!(verify_index_open(&index, &claims, &mut verifier));
                assert!(verifier.finish().is_ok());
            }
        }
    }

    #[test]
    fn compact_preparation_and_reduction_preserve_every_limb_claim_and_transcript() {
        parallel::init();
        let index = Index::new(Circuit {
            variables: 6,
            rows: vec![[2, 3, 0, 4], [4, 1, 2, 5]],
            public: vec![0, 1, 5],
        });
        let x = F192::new(17, 3, 91);
        let y = F192::new(41, 52, 2);
        let values = [F192::ZERO, F192::ONE, x, y, x * y, x * y + x];
        let padded = prepare(&index, &values);
        let minimal_compact = prepare_compact(&index, &values);
        let n = 1 << index.log_rows;
        let mut compact = prepare_compact_with_capacity(&index, &values, 16 * n);
        assert_eq!(padded.stack.len(), 16 * n);
        assert_eq!(compact.stack.len(), 12 * n);
        assert_eq!(minimal_compact.stack, compact.stack);
        for column in 0..4 {
            for limb in 0..3 {
                assert_eq!(
                    padded.stack[(4 * column + limb) * n..(4 * column + limb + 1) * n],
                    compact.stack[(3 * column + limb) * n..(3 * column + limb + 1) * n],
                );
            }
            assert!(
                padded.stack[(4 * column + 3) * n..(4 * column + 4) * n]
                    .iter()
                    .all(|&word| word == F64::ZERO)
            );
        }
        let mut joint_stack = std::mem::take(&mut compact.stack);
        let initial_pointer = joint_stack.as_ptr();
        joint_stack.resize(16 * n, F64(0x12345678));
        assert_eq!(initial_pointer, joint_stack.as_ptr());
        let label = b"compact-native-equivalence-control";
        let mut padded_ps = ProverState::from_label(label);
        let mut compact_ps = ProverState::from_label(label);
        let padded_claims = prove_reduction(&index, &padded, &mut padded_ps);
        let compact_claims = prove_reduction_compact(&index, &compact, &joint_stack, &mut compact_ps);
        let claim_tuples = |claims: Vec<Claim>| {
            claims
                .into_iter()
                .map(|claim| (claim.offset, claim.point, claim.value))
                .collect::<Vec<_>>()
        };
        assert_eq!(claim_tuples(padded_claims.0), claim_tuples(compact_claims.0));
        assert_eq!(claim_tuples(padded_claims.1), claim_tuples(compact_claims.1));
        let reference = padded_ps.into_proof();
        assert_eq!(reference, compact_ps.into_proof());
        let public = index.public_values(&values);
        let mut vs = VerifierState::from_label(label, &reference);
        assert!(verify_reduction(&index, &public, &mut vs).is_some());
        assert!(vs.finish().is_ok());

        // The last row is circuit padding, but it is still authenticated. Each
        // one of the twelve populated limb columns must affect the reduction.
        for slot in 0..12 {
            let at = (slot + 1) * n - 1;
            joint_stack[at] += F64::ONE;
            let mut ps = ProverState::from_label(label);
            prove_reduction_compact(&index, &compact, &joint_stack, &mut ps);
            let altered = ps.into_proof();
            assert_ne!(reference, altered, "slot={slot}");
            let mut vs = VerifierState::from_label(label, &altered);
            assert!(verify_reduction(&index, &public, &mut vs).is_none(), "slot={slot}");
            joint_stack[at] += F64::ONE;
        }
    }

    #[test]
    fn native_circuit_proves_and_rejects_gate_public_and_transcript_changes() {
        parallel::init();
        let circuit = Circuit {
            variables: 6,
            rows: vec![[2, 3, 0, 4], [4, 1, 2, 5]],
            public: vec![0, 1, 5],
        };
        let index = Index::new(circuit);
        let x = F192::new(17, 3, 91);
        let y = F192::new(41, 52, 2);
        let values = vec![F192::ZERO, F192::ONE, x, y, x * y, x * y + x];
        let public = index.public_values(&values);
        let context = [17; 32];
        let proof = prove(&index, &values, &context);
        assert!(verify(&index, &public, &context, &proof));
        let mut bad_public = public.clone();
        bad_public[2] += F192::ONE;
        assert!(!verify(&index, &bad_public, &context, &proof));
        assert!(!verify(&index, &public, &[18; 32], &proof));
        for at in [0, 2, proof.stream.len() - 1] {
            let mut bad = proof.clone();
            bad.stream[at] += F192::ONE;
            assert!(!verify(&index, &public, &context, &bad));
        }
        let mut bad = proof.clone();
        bad.stream.push(F192::ZERO);
        assert!(!verify(&index, &public, &context, &bad));
        let mut bad = proof.clone();
        bad.stream.pop();
        assert!(!verify(&index, &public, &context, &bad));
        let wrong_index = Index::new(Circuit {
            variables: 6,
            rows: vec![[2, 3, 0, 4], [4, 1, 3, 5]],
            public: vec![0, 1, 5],
        });
        assert!(!verify(&wrong_index, &public, &context, &proof));
        let mut wrong_anchors = public.clone();
        wrong_anchors[0] = F192::ONE;
        assert!(!verify(&index, &wrong_anchors, &context, &proof));
        let mut bad_values = values.clone();
        bad_values[4] += F192::ONE;
        let bad = prove(&index, &bad_values, &context);
        assert!(!verify(&index, &public, &context, &bad));
    }
}
