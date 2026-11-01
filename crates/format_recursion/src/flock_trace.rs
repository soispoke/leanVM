//! Symbolic Flock reduction for a recursively proved native-field verifier.
//! This records the complete reduction; a PCS opening must still bind its output.
//! The copied matrix walk mirrors `flock::{gf2,hash}` at commit 1b1b2cff.
//! No Lean proof is claimed for this backend.

use crate::trace::S;
use flock::hash::{
    BLAKE2S_IV, COUNTER_HI_BASE, COUNTER_LO_BASE, CV_BASE, FINAL_BASE, G_LANES, G_STRIDE, GS_BASE, K, K_LOG, K_SKIP,
    LAST_NODE_BASE, MSG_BASE, N_G_PER_ROUND, N_ROUNDS, OUT_BASE, SIGMA, Z_CONST_POS,
};
use primitives::field::{F192, PHI_8_TABLE_192};

const WORD_BITS: usize = 32;
const CARRY_BITS_PER_ADD: usize = 31;
const RIPPLE_BITS_PER_ADD3: usize = 30;
const G_ADD3_A1: usize = 0;
const G_ADD_C1: usize = 61;
const G_ADD3_A2: usize = 92;
const G_ADD_C2: usize = 153;

fn h_bit(w: usize, b: usize) -> usize {
    CV_BASE + WORD_BITS * w + b
}
fn m_bit(w: usize, b: usize) -> usize {
    MSG_BASE + WORD_BITS * w + b
}
fn out_bit(w: usize, b: usize) -> usize {
    OUT_BASE + WORD_BITS * w + b
}
fn g_slot(g: usize, off: usize) -> usize {
    GS_BASE + G_STRIDE * g + off
}

/// A channel must record absorption and sampling, as well as returning values.
/// Native replay of challenges alone is insufficient for a recursion circuit.
pub trait Channel {
    fn scalar(&mut self) -> S;
    fn challenge(&mut self) -> S;
}

impl Channel for crate::verifier::Transcript<'_> {
    fn scalar(&mut self) -> S {
        self.next()
    }
    fn challenge(&mut self) -> S {
        self.sample()
    }
}

pub struct SliceClaim {
    pub suffix_point: Vec<S>,
    pub s_hat_v: Vec<S>,
}

fn eq(a: &[S], b: &[S]) -> S {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).fold(S::u(1), |p, (&a, &b)| p * (S::u(1) + a + b))
}
fn kernel(point: &[S]) -> Vec<S> {
    let mut out = vec![S::u(1)];
    for &x in point {
        for i in 0..out.len() {
            let hi = out[i] * x;
            out.push(hi);
            out[i] = out[i] + hi;
        }
    }
    out
}
fn poly(q: [S; 3], x: S) -> S {
    q[0] + x * (q[1] + x * q[2])
}
fn round(c: &mut impl Channel, target: S, eq: Option<S>) -> [S; 3] {
    let a = c.scalar();
    let b = c.scalar();
    match eq {
        Some(r) => [target + r * (a + b), a, b],
        None => [a, target + b, b],
    }
}

/// Polynomial form, with constant denominators: valid even at an interpolation node.
fn lagrange_weights(n: usize, z: S) -> Vec<S> {
    let nodes = &PHI_8_TABLE_192[..n];
    let mut prefix = S::c(primitives::multilinear::window_denominator(n));
    let mut weights = Vec::with_capacity(n);
    for &node in nodes {
        weights.push(prefix);
        prefix = prefix * (z + S::c(node));
    }
    let mut suffix = S::u(1);
    for (w, &node) in weights.iter_mut().zip(nodes).rev() {
        *w = *w * suffix;
        suffix = suffix * (z + S::c(node));
    }
    weights
}

/// Zerocheck and lincheck. Both the matrix walk and terminal equality become constraints.
pub fn reduce(m: usize, c: &mut impl Channel) -> SliceClaim {
    reduce_with(m, K_LOG, Z_CONST_POS, bilinear_walk, c)
}

pub fn reduce_keccak(m: usize, c: &mut impl Channel) -> SliceClaim {
    reduce_with(m, flock::keccak::K_LOG, 0, keccak_bilinear, c)
}

fn reduce_with(
    m: usize,
    k_log: usize,
    constant_slot: usize,
    walk: fn(S, &[S], &[S]) -> S,
    c: &mut impl Channel,
) -> SliceClaim {
    assert!(m >= k_log);
    let mut r_rest: Vec<S> = flock::zerocheck::univariate_skip_optimized::small_challenges()
        .into_iter()
        .chain(flock::zerocheck::univariate_skip_optimized::medium_challenges())
        .map(S::c)
        .collect();
    r_rest.extend((0..m - K_SKIP - 7).map(|_| c.challenge()));
    let msg: Vec<S> = (0..64).map(|_| c.scalar()).collect();
    let z = c.challenge();
    let w = lagrange_weights(128, z);
    let mut running = msg.iter().zip(&w[64..]).fold(S::u(0), |s, (&v, &w)| s + v * w);
    let mut point = Vec::new();
    for r in r_rest {
        let q = round(c, running, Some(r));
        let x = c.challenge();
        point.push(x);
        running = poly(q, x);
    }
    let a = c.scalar();
    let b = c.scalar();
    let v_c = running + a * b;
    let alpha = c.challenge();
    let alpha_sq = alpha * alpha;
    let beta = alpha_sq * alpha;
    running = a + alpha * b + alpha_sq * v_c + beta;
    let mut r_inner = Vec::new();
    for _ in 0..k_log - K_SKIP {
        let q = round(c, running, None);
        let x = c.challenge();
        r_inner.push(x);
        running = poly(q, x);
    }
    let slices: Vec<S> = (0..64).map(|_| c.scalar()).collect();
    r_inner.reverse();
    let lambda = lagrange_weights(64, z);
    let eq_inner = kernel(&point[..k_log - K_SKIP])
        .into_iter()
        .flat_map(|e| lambda.iter().map(move |&l| e * l))
        .collect::<Vec<_>>();
    let columns = kernel(&r_inner)
        .into_iter()
        .flat_map(|e| slices.iter().map(move |&s| e * s))
        .collect::<Vec<_>>();
    let c_slice = lambda.iter().zip(&slices).fold(S::u(0), |s, (&a, &b)| s + a * b);
    let final_sum = walk(alpha, &eq_inner, &columns)
        + beta * columns[constant_slot]
        + alpha_sq * eq(&point[..k_log - K_SKIP], &r_inner) * c_slice;
    running.assert_eq(final_sum);
    r_inner.extend_from_slice(&point[k_log - K_SKIP..]);
    SliceClaim {
        suffix_point: r_inner,
        s_hat_v: slices,
    }
}

fn composed(mut x: S, challenges: &[S; 6]) -> S {
    for (&c, shift) in challenges.iter().zip([32, 16, 8, 4, 2, 1]) {
        let mut f = x;
        for _ in 0..shift {
            f = f * f;
        }
        x = x + c * f;
    }
    x
}
/// Ring-switch target in its row form, avoiding disclosed bit projections.
pub fn ring_target(slices: &[S], challenges: &[S; 6]) -> S {
    assert_eq!(slices.len(), 64);
    slices.iter().enumerate().fold(S::u(0), |s, (i, &v)| {
        s + S::c(F192::new(1u64 << i, 0, 0)) * composed(v, challenges)
    })
}
/// Succinct ring-switch weight from the same six composed-map challenges.
pub fn ring_weight(suffix: &[S], query: &[S], challenges: &[S; 6]) -> S {
    assert_eq!(suffix.len(), query.len());
    let mut coeff = [None; 64];
    coeff[0] = Some(S::u(1));
    for (&c, shift) in challenges.iter().zip([32, 16, 8, 4, 2, 1]) {
        for k in 0..64 - shift {
            if let (Some(mut x), None) = (coeff[k], coeff[k + shift]) {
                for _ in 0..shift {
                    x = x * x;
                }
                coeff[k + shift] = Some(c * x);
            }
        }
    }
    let mut conjugate = suffix.to_vec();
    let mut sum = S::u(0);
    for (k, c) in coeff.into_iter().enumerate() {
        if k > 0 {
            for x in &mut conjugate {
                *x = *x * *x;
            }
        }
        sum = sum + c.unwrap() * eq(&conjugate, query);
    }
    sum
}

type WireWord = [S; WORD_BITS];

#[inline]
fn wire_from_slot_base(w: &[S], base: usize) -> WireWord {
    std::array::from_fn(|i| w[base + i])
}

/// Constant word: a set bit is the constant-wire lin_func, a clear bit empty.
#[inline]
fn wire_from_const(w: &[S], val: u32, const_pos: usize) -> WireWord {
    std::array::from_fn(|i| if (val >> i) & 1 == 1 { w[const_pos] } else { S::u(0) })
}

#[inline]
fn wire_xor(x: &WireWord, y: &WireWord) -> WireWord {
    std::array::from_fn(|i| x[i] + y[i])
}

#[inline]
fn wire_rotr(x: &WireWord, n: usize) -> WireWord {
    std::array::from_fn(|i| x[(i + n) % WORD_BITS])
}

/// The matrix-vector products `(A_0 w, B_0 w)`. Rows with no wire keep their zeros.
struct RowValues {
    a: Vec<S>,
    b: Vec<S>,
    wc: S,
}

impl RowValues {
    fn new(k: usize, wc: S) -> Self {
        Self {
            a: vec![S::u(0); k],
            b: vec![S::u(0); k],
            wc,
        }
    }

    #[inline]
    fn product(&mut self, k: usize, a: S, b: S) {
        self.a[k] = a;
        self.b[k] = b;
    }

    #[inline]
    fn bconst(&mut self, k: usize, a: S) {
        self.a[k] = a;
        self.b[k] = self.wc;
    }
}

/// Walk one 32-bit ADD: report the 31
/// carry rows to `sink` and return the sum-bit wires.
///
///   carry row cb+i:  A = X[i] ⊕ cin[i],  B = Y[i] ⊕ cin[i]
///   sum[i]         = X[i] ⊕ Y[i] ⊕ cin[i]
///
/// with `cin[i] = ⊕_{j<i} carry_aux[cb+j]`, a running prefix of `w` reads.
fn walk_add(sink: &mut RowValues, w: &[S], x: &WireWord, y: &WireWord, carry_base: usize) -> WireWord {
    let mut out = [S::u(0); WORD_BITS];
    let mut cin = S::u(0);
    for i in 0..WORD_BITS {
        let a_side = x[i] + cin;
        let b_side = y[i] + cin;
        out[i] = a_side + y[i];
        if i < CARRY_BITS_PER_ADD {
            sink.product(carry_base + i, a_side, b_side);
            cin = cin + w[carry_base + i];
        }
    }
    out
}

/// Walk one fused three-operand ADD:
/// report the 31 majority rows and the 30 ripple rows to `sink` and
/// return the sum-bit wires.
fn walk_add3_fused(sink: &mut RowValues, w: &[S], x: &WireWord, y: &WireWord, z: &WireWord, base: usize) -> WireWord {
    let rip_base = base + CARRY_BITS_PER_ADD;
    let mut maj = [S::u(0); CARRY_BITS_PER_ADD];
    for i in 0..CARRY_BITS_PER_ADD {
        sink.product(base + i, x[i] + z[i], y[i] + z[i]);
        maj[i] = w[base + i] + z[i];
    }

    let mut out = [S::u(0); WORD_BITS];
    let mut cin = S::u(0);
    for i in 0..WORD_BITS {
        let q_i = if i == 0 { S::u(0) } else { maj[i - 1] };
        let a_side = x[i] + y[i] + z[i] + cin;
        out[i] = a_side + q_i;
        if (1..=RIPPLE_BITS_PER_ADD3).contains(&i) {
            sink.product(rip_base + i - 1, a_side, q_i + cin);
            cin = cin + w[rip_base + i - 1];
        }
    }
    out
}

fn forward_walk(sink: &mut RowValues, w: &[S]) {
    sink.bconst(Z_CONST_POS, w[Z_CONST_POS]);
    // Free-input rows: A = [slot], B = [Z_CONST].
    for (base, len) in [
        (CV_BASE, 8 * WORD_BITS),
        (MSG_BASE, 16 * WORD_BITS),
        (COUNTER_LO_BASE, 4 * WORD_BITS),
    ] {
        for s in base..base + len {
            sink.bconst(s, w[s]);
        }
    }

    let mut state: [WireWord; 16] = std::array::from_fn(|_| [S::u(0); WORD_BITS]);
    for wd in 0..8 {
        state[wd] = wire_from_slot_base(w, h_bit(wd, 0));
    }
    for i in 0..4 {
        state[8 + i] = wire_from_const(w, BLAKE2S_IV[i], Z_CONST_POS);
    }
    for (i, base) in [COUNTER_LO_BASE, COUNTER_HI_BASE, FINAL_BASE, LAST_NODE_BASE]
        .into_iter()
        .enumerate()
    {
        state[12 + i] = wire_xor(
            &wire_from_const(w, BLAKE2S_IV[4 + i], Z_CONST_POS),
            &wire_from_slot_base(w, base),
        );
    }

    for r in 0..N_ROUNDS {
        for g_in_round in 0..N_G_PER_ROUND {
            let g = r * N_G_PER_ROUND + g_in_round;
            let [la, lb, lc, ld] = G_LANES[g_in_round];
            let (a, b, c, d) = (state[la], state[lb], state[lc], state[ld]);
            let mx = wire_from_slot_base(w, m_bit(SIGMA[r][2 * g_in_round], 0));
            let my = wire_from_slot_base(w, m_bit(SIGMA[r][2 * g_in_round + 1], 0));

            let a_1 = walk_add3_fused(sink, w, &a, &b, &mx, g_slot(g, G_ADD3_A1));
            let d_1 = wire_rotr(&wire_xor(&d, &a_1), 16);
            let c_1 = walk_add(sink, w, &c, &d_1, g_slot(g, G_ADD_C1));
            let b_1 = wire_rotr(&wire_xor(&b, &c_1), 12);
            let a_2 = walk_add3_fused(sink, w, &a_1, &b_1, &my, g_slot(g, G_ADD3_A2));
            let d_2 = wire_rotr(&wire_xor(&d_1, &a_2), 8);
            let c_2 = walk_add(sink, w, &c_1, &d_2, g_slot(g, G_ADD_C2));
            let b_2 = wire_rotr(&wire_xor(&b_1, &c_2), 7);

            state[la] = a_2;
            state[lb] = b_2;
            state[lc] = c_2;
            state[ld] = d_2;
        }
    }

    // Finalization: out[w] = h[w] ^ v[w] ^ v[w+8], the only lin-id rows.
    for wd in 0..8 {
        let out = wire_xor(
            &wire_xor(&state[wd], &state[wd + 8]),
            &wire_from_slot_base(w, h_bit(wd, 0)),
        );
        for i in 0..WORD_BITS {
            sink.bconst(out_bit(wd, i), out[i]);
        }
    }
}

fn bilinear_walk_pair(u: &[S], w: &[S]) -> (S, S) {
    assert_eq!(u.len(), K);
    assert_eq!(w.len(), K);
    let (a, b) = row_values_walk(w);
    let mut va = S::u(0);
    let mut vb = S::u(0);
    for ((&ui, &ai), &bi) in u.iter().zip(&a).zip(&b) {
        va = va + ui * ai;
        vb = vb + ui * bi;
    }
    (va, vb)
}

/// The matrix-vector products `(A_0 w, B_0 w)`, i.e. every row's inner product
/// with `w`, by one forward walk. This takes O(circuit) additions instead of one
/// pass over the nonzeros, and neither matrix is materialized.
fn row_values_walk(w: &[S]) -> (Vec<S>, Vec<S>) {
    assert_eq!(w.len(), K);
    let mut sink = RowValues::new(K, w[Z_CONST_POS]);
    forward_walk(&mut sink, w);
    (sink.a, sink.b)
}

/// `(uᵀ A_0 w) + α·(uᵀ B_0 w)`, the α-batched form lincheck's verifier
/// consumes.
fn bilinear_walk(alpha: S, u: &[S], w: &[S]) -> S {
    let (va, vb) = bilinear_walk_pair(u, w);
    va + alpha * vb
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace;
    use fiat_shamir::transcript::{Challenger, ProverState, Receiver, VerifierState};
    use flock::hash::{Blake2sSetup, generate_witness_with_ab_packed_and_lincheck, padding_block};

    fn field(i: usize) -> F192 {
        F192::new((i as u64 + 17) * 371, (i as u64 + 27) * 113, (i as u64 + 31) * 971)
    }
    #[test]
    fn symbolic_matrix_walk_matches_reference() {
        let u: Vec<_> = (0..K).map(field).collect();
        let w: Vec<_> = (K..2 * K).map(field).collect();
        let alpha = field(2 * K);
        let expected = flock::hash::bilinear_walk(alpha, &u, &w);
        trace::start();
        let us: Vec<_> = u.into_iter().map(S::input).collect();
        let ws: Vec<_> = w.into_iter().map(S::input).collect();
        let out = bilinear_walk(S::input(alpha), &us, &ws);
        assert_eq!(out.value(), expected);
        out.assert_eq(S::c(expected));
        assert!(trace::take().satisfied());
    }
    #[test]
    fn polynomial_lagrange_and_ring_views_match_at_random_and_domain_points() {
        for z in [field(7), PHI_8_TABLE_192[0], PHI_8_TABLE_192[17], PHI_8_TABLE_192[63]] {
            trace::start();
            let w = lagrange_weights(64, S::input(z));
            let expected = primitives::multilinear::lagrange_weights_naive(6, z);
            for (s, v) in w.into_iter().zip(expected) {
                assert_eq!(s.value(), v);
            }
            trace::take();
        }
        let slices: Vec<_> = (0..64).map(field).collect();
        let challenges = std::array::from_fn(|i| field(i + 64));
        let point: Vec<_> = (70..85).map(field).collect();
        let query: Vec<_> = (85..100).map(field).collect();
        let expected = pcs::ring_switch::batched_claim(&slices, &challenges);
        let weights = pcs::ring_switch::build_coordinate_weights(&challenges);
        assert_eq!(expected, pcs::ring_switch::verify_finish(&slices, &weights));
        let expected_weight = pcs::ring_switch::eval_rs_eq(&point, &query, &weights);
        trace::start();
        let ss: Vec<_> = slices.into_iter().map(S::input).collect();
        let cs = challenges.map(S::input);
        let ps: Vec<_> = point.into_iter().map(S::input).collect();
        let qs: Vec<_> = query.into_iter().map(S::input).collect();
        assert_eq!(ring_target(&ss, &cs).value(), expected);
        assert_eq!(ring_weight(&ps, &qs, &cs).value(), expected_weight);
        trace::take();
    }
    // Differential function test: this channel provides native transcript values.
    // A recursion caller must use a symbolic hashing channel, not this test adapter.
    struct NativeChannel<'a>(VerifierState<'a>);
    impl Channel for NativeChannel<'_> {
        fn scalar(&mut self) -> S {
            S::input(self.0.next_scalar().unwrap())
        }
        fn challenge(&mut self) -> S {
            S::input(self.0.sample())
        }
    }
    #[test]
    fn reduction_matches_reference_and_rejects_changed_terminal_slice() {
        parallel::init();
        let blocks = vec![padding_block(); 8];
        let setup = Blake2sSetup::new(blocks.len());
        let (z, a, b, lin) = generate_witness_with_ab_packed_and_lincheck(&blocks, setup.n_blocks_log());
        let label = b"symbolic-flock-reduction-test";
        let mut ps = ProverState::from_label(label);
        let honest = setup.prove_reduction_precomputed(&z, &a, &b, &lin, &mut ps);
        let proof = ps.into_proof();
        let mut native = VerifierState::from_label(label, &proof);
        let expected = setup.verify_reduction(&mut native).unwrap().claim;
        assert_eq!(honest, expected);
        assert!(native.finish().is_ok());
        trace::start();
        let mut c = NativeChannel(VerifierState::from_label(label, &proof));
        let actual = reduce(setup.m(), &mut c);
        assert!(c.0.finish().is_ok());
        assert_eq!(
            actual.suffix_point.iter().map(|s| s.value()).collect::<Vec<_>>(),
            expected.suffix_point
        );
        assert_eq!(
            actual.s_hat_v.iter().map(|s| s.value()).collect::<Vec<_>>(),
            expected.s_hat_v
        );
        assert!(trace::take().satisfied());
        let mut bad = proof;
        *bad.stream.last_mut().unwrap() += F192::ONE;
        trace::start();
        reduce(setup.m(), &mut NativeChannel(VerifierState::from_label(label, &bad)));
        assert!(!trace::take().satisfied());
    }

    #[test]
    fn reduction_records_its_transcript_hashes_and_has_fixed_program() {
        parallel::init();
        let label = b"symbolic-flock-bound-transcript";
        let run = |word: u32| {
            let mut blocks = vec![padding_block(); 8];
            blocks[0].1[0] = word;
            let setup = Blake2sSetup::new(blocks.len());
            let (z, a, b, lin) = generate_witness_with_ab_packed_and_lincheck(&blocks, setup.n_blocks_log());
            let mut ps = ProverState::from_label(label);
            let expected = setup.prove_reduction_precomputed(&z, &a, &b, &lin, &mut ps);
            let proof = ps.into_proof();
            trace::start();
            let state = trace::digest_constant(&primitives::protocol_hash::hash(label));
            let mut channel = crate::verifier::Transcript::from_state(&proof, state);
            let actual = reduce(setup.m(), &mut channel);
            channel.finish();
            assert_eq!(
                actual.s_hat_v.iter().map(|s| s.value()).collect::<Vec<_>>(),
                expected.s_hat_v
            );
            let t = trace::take();
            assert!(t.satisfied());
            assert!(t.hash_compressions() > 0);
            t
        };
        let first = run(17);
        let second = run(19);
        assert!(first.same_program(&second), "proof contents must remain circuit inputs");
    }
}

fn keccak_bilinear(alpha: S, u: &[S], w: &[S]) -> S {
    use flock::keccak::{INPUT, OUTPUT, RC, STATE};
    const ROT: [[usize; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];
    let at = |x: usize, y: usize, z: usize| 64 * (x + 5 * y) + z;
    assert_eq!(u.len(), 1 << flock::keccak::K_LOG);
    assert_eq!(w.len(), u.len());
    let one = w[0];
    let mut va = u[0] * one;
    let mut vb = u[0] * one;
    let mut state = w[INPUT..INPUT + STATE].to_vec();
    for j in 0..STATE {
        va = va + u[INPUT + j] * state[j];
        vb = vb + u[INPUT + j] * one;
    }
    for (r, rc) in RC.into_iter().enumerate() {
        let columns: Vec<_> = (0..320)
            .map(|j| {
                let (x, z) = (j / 64, j % 64);
                (1..5).fold(state[at(x, 0, z)], |v, y| v + state[at(x, y, z)])
            })
            .collect();
        let mut linear = vec![S::u(0); STATE];
        for x in 0..5 {
            for z in 0..64 {
                let d = columns[((x + 4) % 5) * 64 + z] + columns[((x + 1) % 5) * 64 + (z + 63) % 64];
                for y in 0..5 {
                    linear[at(y, (2 * x + 3 * y) % 5, (z + ROT[x][y]) % 64)] = state[at(x, y, z)] + d;
                }
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let j = at(x, y, z);
                    let slot = INPUT + STATE + r * STATE + j;
                    va = va + u[slot] * (one + linear[at((x + 1) % 5, y, z)]);
                    vb = vb + u[slot] * linear[at((x + 2) % 5, y, z)];
                    state[j] = linear[j] + w[slot];
                    if x == 0 && y == 0 && (rc >> z) & 1 == 1 {
                        state[j] = state[j] + one;
                    }
                }
            }
        }
    }
    for j in 0..STATE {
        va = va + u[OUTPUT + j] * state[j];
        vb = vb + u[OUTPUT + j] * one;
    }
    va + alpha * vb
}

#[cfg(test)]
mod keccak_matrix_tests {
    use super::*;
    #[test]
    fn symbolic_keccak_matrix_matches_native_forward() {
        let field = |i: usize| F192::new(i as u64 * 371 + 17, i as u64 * 113 + 27, i as u64 * 971 + 31);
        let n = 1 << flock::keccak::K_LOG;
        let u: Vec<_> = (0..n).map(field).collect();
        let w: Vec<_> = (n..2 * n).map(field).collect();
        let alpha = field(2 * n);
        let (a, b) = flock::keccak::forward(&w);
        let expected = (0..n).fold(F192::ZERO, |v, i| v + u[i] * (a[i] + alpha * b[i]));
        crate::trace::start();
        let us: Vec<_> = u.into_iter().map(S::input).collect();
        let ws: Vec<_> = w.into_iter().map(S::input).collect();
        assert_eq!(keccak_bilinear(S::input(alpha), &us, &ws).value(), expected);
    }
}
