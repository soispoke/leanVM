//! Keccak-f[1600] as one flock R1CS block: the circuit a native Keccak instruction
//! would prove, as [`crate::hash`] is for `BLAKE2s`.
//!
//! flock proves `(A z)_i · (B z)_i = z_i` for every slot `i` of a `2^K_LOG` block, with
//! linear forms free over GF(2). Keccak's only nonlinear step is chi's
//! `b[x] ⊕ ¬b[x+1]·b[x+2]`, so a block needs one product slot per state bit per
//! round and nothing else:
//!
//! ```text
//!   slot 0                    the constant one        A = B = z_0
//!   64 .. 1664                the input state         A = z_i,   B = z_0
//!   1664 + 1600 r + j         round r's chi product   A = 1 ⊕ b[x+1], B = b[x+2]
//!   40,064 .. 41,664         the output state        A = s_24[j], B = z_0
//!   the rest                  zero                    A = B = 0
//! ```
//!
//! where `b = rho∘pi∘theta(s_r)` and `s_{r+1}[j] = b[j] ⊕ p_{r,j} ⊕ iota_r[j]` are linear
//! forms, never wires: like `BLAKE2s`'s lanes they cascade through every round, so the
//! matrices are dense and are never built. [`forward`] evaluates `A w` and `B w` for any
//! column weights by running the round structure over the field, and [`KeccakCircuit`]'s
//! fold runs its transpose backwards. Each product slot depends only on earlier slots, so a
//! satisfying witness is unique given the input: the block computes exactly the
//! permutation of its input into its pinned output.
pub mod reduction;

use crate::lincheck::LincheckCircuit;
use primitives::field::F192;

pub const K_LOG: usize = 16;
pub const STATE: usize = 1600;
const ROUNDS: usize = 24;
const PIN: usize = 0;
/// Whole-word I/O offsets let the native bridge open each lane directly.
pub const INPUT: usize = 64;
const PRODUCTS: usize = INPUT + STATE;
pub const OUTPUT: usize = PRODUCTS + ROUNDS * STATE;
/// Slots a block uses; the other `2^K_LOG − USED` are zero.
pub const USED: usize = OUTPUT + STATE;
const _: () = assert!(USED <= 1 << K_LOG);

pub const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
/// `ROT[x][y]`, the rho offset of lane `(x, y)`.
const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
const fn at(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}
/// Where theta's output bit `(x, y, z)` lands after rho and pi.
const fn pi_rho(x: usize, y: usize, z: usize) -> usize {
    at(y, (2 * x + 3 * y) % 5, (z + ROT[x][y]) % 64)
}
fn product_slot(round: usize, j: usize) -> usize {
    PRODUCTS + STATE * round + j
}

/// `rho∘pi∘theta`, the round's linear layer.
fn linear(a: &[F192]) -> Vec<F192> {
    let mut c = [[F192::ZERO; 64]; 5];
    for (x, column) in c.iter_mut().enumerate() {
        for (z, bit) in column.iter_mut().enumerate() {
            *bit = (0..5).fold(F192::ZERO, |acc, y| acc + a[at(x, y, z)]);
        }
    }
    let mut b = vec![F192::ZERO; STATE];
    for x in 0..5 {
        for z in 0..64 {
            let d = c[(x + 4) % 5][z] + c[(x + 1) % 5][(z + 63) % 64];
            for y in 0..5 {
                b[pi_rho(x, y, z)] = a[at(x, y, z)] + d;
            }
        }
    }
    b
}

/// The transpose of [`linear`]: the adjoint of `a` given the adjoint of `b`.
fn linear_transpose(adj_b: &[F192]) -> Vec<F192> {
    let mut adj_a = vec![F192::ZERO; STATE];
    let mut adj_c = [[F192::ZERO; 64]; 5];
    for x in 0..5 {
        for z in 0..64 {
            let mut adj_d = F192::ZERO;
            for y in 0..5 {
                let g = adj_b[pi_rho(x, y, z)];
                adj_a[at(x, y, z)] += g;
                adj_d += g;
            }
            adj_c[(x + 4) % 5][z] += adj_d;
            adj_c[(x + 1) % 5][(z + 63) % 64] += adj_d;
        }
    }
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..64 {
                adj_a[at(x, y, z)] += adj_c[x][z];
            }
        }
    }
    adj_a
}

/// The round structure over the field. `product(slot, a, b)` supplies each product
/// slot's value given its two row forms; the return is the output state.
fn rounds(input: &[F192], one: F192, mut product: impl FnMut(usize, F192, F192) -> F192) -> Vec<F192> {
    (0..ROUNDS).fold(input.to_vec(), |s, r| {
        let b = linear(&s);
        let mut next = vec![F192::ZERO; STATE];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let j = at(x, y, z);
                    let p = product(
                        product_slot(r, j),
                        one + b[at((x + 1) % 5, y, z)],
                        b[at((x + 2) % 5, y, z)],
                    );
                    let iota = if j < 64 && RC[r] >> j & 1 == 1 { one } else { F192::ZERO };
                    next[j] = b[j] + p + iota;
                }
            }
        }
        next
    })
}

/// The block's witness for one permutation input (bits LSB first, lane by lane).
pub fn witness(input: &[bool; STATE]) -> Vec<bool> {
    let mut z = vec![F192::ZERO; 1 << K_LOG];
    z[PIN] = F192::ONE;
    let state: Vec<F192> = input.iter().map(|&b| F192::new(u64::from(b), 0, 0)).collect();
    z[INPUT..PRODUCTS].copy_from_slice(&state);
    let out = rounds(&state, F192::ONE, |slot, a, b| {
        z[slot] = a * b;
        z[slot]
    });
    z[OUTPUT..USED].copy_from_slice(&out);
    z.iter().map(|v| *v == F192::ONE).collect()
}

/// `(A w, B w)` for column weights `w`, one entry per slot.
pub fn forward(w: &[F192]) -> (Vec<F192>, Vec<F192>) {
    let k = 1 << K_LOG;
    assert_eq!(w.len(), k);
    let (mut a, mut b) = (vec![F192::ZERO; k], vec![F192::ZERO; k]);
    (a[PIN], b[PIN]) = (w[PIN], w[PIN]);
    for i in INPUT..PRODUCTS {
        (a[i], b[i]) = (w[i], w[PIN]);
    }
    let out = rounds(&w[INPUT..PRODUCTS], w[PIN], |slot, row_a, row_b| {
        (a[slot], b[slot]) = (row_a, row_b);
        w[slot]
    });
    for (j, s) in out.into_iter().enumerate() {
        (a[OUTPUT + j], b[OUTPUT + j]) = (s, w[PIN]);
    }
    (a, b)
}

/// The block's matrices, reached only through [`forward`] and its transpose.
pub struct KeccakCircuit;

impl LincheckCircuit for KeccakCircuit {
    fn n_cols(&self) -> usize {
        1 << K_LOG
    }

    fn const_pin_col(&self) -> usize {
        PIN
    }

    /// `eᵀA + α·eᵀB`, by running [`forward`]'s dependencies backwards.
    fn fold_alpha_batched(&self, alpha: F192, e: &[F192]) -> Vec<F192> {
        let mut comb = vec![F192::ZERO; 1 << K_LOG];
        comb[PIN] += e[PIN] * (F192::ONE + alpha);
        for i in INPUT..PRODUCTS {
            comb[i] += e[i];
            comb[PIN] += alpha * e[i];
        }
        let mut adj_s: Vec<F192> = e[OUTPUT..USED].to_vec();
        comb[PIN] += alpha * e[OUTPUT..USED].iter().fold(F192::ZERO, |acc, &v| acc + v);
        for r in (0..ROUNDS).rev() {
            // s_{r+1}[j] = b[j] + p_{r,j} + iota_r[j]·1; A = 1 + b[x+1]; B = b[x+2].
            let mut adj_b = adj_s.clone();
            for x in 0..5 {
                for y in 0..5 {
                    for z in 0..64 {
                        let j = at(x, y, z);
                        let slot = product_slot(r, j);
                        comb[slot] += adj_s[j];
                        if j < 64 && RC[r] >> j & 1 == 1 {
                            comb[PIN] += adj_s[j];
                        }
                        comb[PIN] += e[slot];
                        adj_b[at((x + 1) % 5, y, z)] += e[slot];
                        adj_b[at((x + 2) % 5, y, z)] += alpha * e[slot];
                    }
                }
            }
            adj_s = linear_transpose(&adj_b);
        }
        for (i, g) in adj_s.into_iter().enumerate() {
            comb[INPUT + i] += g;
        }
        comb
    }

    fn bilinear_form(&self, alpha: F192, u: &[F192], w: &[F192]) -> Option<F192> {
        let (a, b) = forward(w);
        Some(
            u.iter()
                .zip(a.iter().zip(&b))
                .fold(F192::ZERO, |acc, (&e, (&x, &y))| acc + e * (x + alpha * y)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lincheck::{self, QuirkyPoint, build_quirky_eq_table, pack_z_lincheck};
    use primitives::multilinear::eq_table;
    use primitives::test_rng::Rng;

    /// FIPS 202 on 64-bit lanes, written independently of the circuit.
    fn reference_round(a: &mut [u64; 25], rc: u64) {
        let c: [u64; 5] = std::array::from_fn(|x| (0..5).fold(0, |p, y| p ^ a[x + 5 * y]));
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x][y] as u32);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        let mut padded = bytes.to_vec();
        padded.push(1);
        padded.resize(padded.len().div_ceil(136) * 136, 0);
        *padded.last_mut().unwrap() |= 0x80;
        let mut a = [0u64; 25];
        for block in padded.chunks(136) {
            for (lane, word) in a.iter_mut().zip(block.chunks(8)) {
                *lane ^= u64::from_le_bytes(word.try_into().unwrap());
            }
            RC.iter().for_each(|&rc| reference_round(&mut a, rc));
        }
        std::array::from_fn(|i| (a[i / 8] >> (8 * (i % 8))) as u8)
    }
    fn lanes(bits: &[bool]) -> [u64; 25] {
        std::array::from_fn(|l| (0..64).fold(0, |w, z| w | (u64::from(bits[64 * l + z]) << z)))
    }

    #[test]
    fn reference_matches_known_answers() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    /// The witness satisfies every slot, its output is the permutation, and a flipped
    /// product or output bit breaks some slot.
    #[test]
    fn witness_satisfies_exactly_the_permutation() {
        let mut rng = Rng::new(0x6b65);
        for _ in 0..3 {
            let input: [bool; STATE] = std::array::from_fn(|_| rng.next_u64() & 1 == 1);
            let z = witness(&input);
            let mut expected = lanes(&input);
            RC.iter().for_each(|&rc| reference_round(&mut expected, rc));
            assert_eq!(lanes(&z[OUTPUT..USED]), expected);
            let satisfied = |z: &[bool]| {
                let w: Vec<F192> = z.iter().map(|&b| F192::new(u64::from(b), 0, 0)).collect();
                let (a, b) = forward(&w);
                (0..1 << K_LOG).all(|i| a[i] * b[i] == w[i])
            };
            assert!(satisfied(&z));
            for slot in [product_slot(0, 7), product_slot(23, 1599), OUTPUT + 3, USED] {
                let mut bad = z.clone();
                bad[slot] ^= true;
                assert!(!satisfied(&bad), "slot {slot} flipped and still satisfied");
            }
        }
    }

    /// The fold is the transpose of the forward walk: `⟨eᵀA + α eᵀB, w⟩ = eᵀ(A w) + α eᵀ(B w)`
    /// for random `e`, `w`, `α`. A wrong transpose fails this with probability `1 − 1/|F|`.
    #[test]
    fn fold_is_the_transpose_of_the_walk() {
        let mut rng = Rng::new(0x7472);
        let k = 1 << K_LOG;
        for _ in 0..2 {
            let (e, w, alpha) = (rng.ext_vec(k), rng.ext_vec(k), rng.ext());
            let fold = KeccakCircuit.fold_alpha_batched(alpha, &e);
            let lhs = fold.iter().zip(&w).fold(F192::ZERO, |acc, (&c, &x)| acc + c * x);
            assert_eq!(Some(lhs), KeccakCircuit.bilinear_form(alpha, &e, &w));
        }
    }

    /// One round of the block equals the FIPS 202 round on every input, by the argument
    /// in `examples/comparison_support/keccak.rs`: both are of degree at most two over
    /// GF(2), so agreement on all inputs of weight at most two is equality. The block's
    /// own [`linear`] runs 192 inputs at once in a field element's limbs (addition is XOR);
    /// chi's product is that limb-wise AND.
    #[test]
    fn block_round_is_exactly_the_reference_round() {
        let rc = RC[5];
        let mut points: Vec<Vec<usize>> = vec![vec![]];
        points.extend((0..STATE).map(|i| vec![i]));
        points.extend((0..STATE).flat_map(|i| (i + 1..STATE).map(move |j| vec![i, j])));
        let limb = |v: F192, k: usize| [v.c0, v.c1, v.c2][k / 64] >> (k % 64) & 1 == 1;
        let and = |a: F192, b: F192| F192::new(a.c0 & b.c0, a.c1 & b.c1, a.c2 & b.c2);
        let ones = F192::new(!0, !0, !0);
        for chunk in points.chunks(192) {
            let mut state = vec![F192::ZERO; STATE];
            for (k, point) in chunk.iter().enumerate() {
                for &i in point {
                    let mut l = [state[i].c0, state[i].c1, state[i].c2];
                    l[k / 64] |= 1 << (k % 64);
                    state[i] = F192::new(l[0], l[1], l[2]);
                }
            }
            let b = linear(&state);
            let block: Vec<F192> = (0..STATE)
                .map(|j| {
                    let (x, y, z) = (j / 64 % 5, j / 320, j % 64);
                    let p = and(ones + b[at((x + 1) % 5, y, z)], b[at((x + 2) % 5, y, z)]);
                    b[j] + p + if j < 64 && rc >> j & 1 == 1 { ones } else { F192::ZERO }
                })
                .collect();
            for (k, point) in chunk.iter().enumerate() {
                let mut bits = [false; STATE];
                point.iter().for_each(|&i| bits[i] = true);
                let mut expected = lanes(&bits);
                reference_round(&mut expected, rc);
                let got: Vec<bool> = block.iter().map(|&v| limb(v, k)).collect();
                assert_eq!(lanes(&got), expected, "input {point:?}");
            }
        }
    }

    /// The circuit-agnostic lincheck proves and verifies a batch of permutations
    /// against these walks: the reduction a native instruction would run.
    #[test]
    fn lincheck_roundtrip_over_permutations() {
        let mut rng = Rng::new(0x6c69);
        let (k_skip, n_log) = (6, 3);
        let m = K_LOG + n_log;
        let z: Vec<bool> = (0..1 << n_log)
            .flat_map(|_| witness(&std::array::from_fn(|_| rng.next_u64() & 1 == 1)))
            .collect();
        let to_field = |v: &[bool]| v.iter().map(|&b| F192::new(u64::from(b), 0, 0)).collect::<Vec<_>>();
        let (a, b): (Vec<bool>, Vec<bool>) = z
            .chunks(1 << K_LOG)
            .flat_map(|block| {
                let (a, b) = forward(&to_field(block));
                a.into_iter()
                    .zip(b)
                    .map(|(x, y)| (x == F192::ONE, y == F192::ONE))
                    .collect::<Vec<_>>()
            })
            .unzip();
        let point = QuirkyPoint {
            z_skip: rng.ext(),
            x_inner_rest: rng.ext_vec(K_LOG - k_skip),
            x_outer: rng.ext_vec(n_log),
        };
        let inner = build_quirky_eq_table(point.z_skip, &point.x_inner_rest, k_skip);
        let outer = eq_table(&point.x_outer);
        let eval = |f: &[bool]| {
            f.iter()
                .enumerate()
                .filter(|(_, b)| **b)
                .fold(F192::ZERO, |acc, (i, _)| {
                    acc + inner[i % (1 << K_LOG)] * outer[i >> K_LOG]
                })
        };
        let (v_a, v_b, v_c) = (eval(&a), eval(&b), eval(&z));
        let packed = pack_z_lincheck(&z, m, K_LOG);
        let mut ps = fiat_shamir::transcript::ProverState::from_label(b"flock-keccak-test");
        let proved = lincheck::prove_padded_capture_s_hat_v(
            &packed,
            m,
            K_LOG,
            k_skip,
            1 << K_LOG,
            &KeccakCircuit,
            &point,
            &mut ps,
        );
        let proof = ps.into_proof();
        let mut vs = fiat_shamir::transcript::VerifierState::from_label(b"flock-keccak-test", &proof);
        let verified = lincheck::verify(m, K_LOG, k_skip, &KeccakCircuit, &point, v_a, v_b, v_c, &mut vs)
            .expect("honest permutations verify");
        assert_eq!(proved, verified);
        // A claim on a different witness value does not.
        let mut vs = fiat_shamir::transcript::VerifierState::from_label(b"flock-keccak-test", &proof);
        assert!(
            lincheck::verify(
                m,
                K_LOG,
                k_skip,
                &KeccakCircuit,
                &point,
                v_a,
                v_b,
                v_c + F192::ONE,
                &mut vs
            )
            .is_err()
        );
    }
}
