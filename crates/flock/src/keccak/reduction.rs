//! Batched Keccak permutation reduction, sharing the BLAKE2s zerocheck,
//! lincheck and PCS ring-switch protocols. The embedding bridge must bind the
//! circuit identity, shape, I/O wiring and witness commitment before challenges.
use super::{INPUT, K_LOG, KeccakCircuit, OUTPUT, RC, ROT, USED};
use crate::{hash::SliceClaim, lincheck, verifier::VerifyError, witness::packed_bytes, zerocheck};
use fiat_shamir::transcript::{ProverState, VerifierState};
use pcs::{
    pack::LOG_PACKING,
    stack_open::{RingSwitchClaim, RingSwitchOpen, RingSwitchVerify, RingSwitchVerifyClaim},
};

pub type Permutation = [u64; 25];

/// Independent word-oriented witness generation. Linear layers use XOR and
/// rotations; each chi product occupies exactly one bit per state bit.
fn block(input: &Permutation) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let words = 1 << (K_LOG - LOG_PACKING);
    let (mut z, mut a, mut b) = (vec![0; words], vec![0; words], vec![0; words]);
    z[0] = 1;
    a[0] = 1;
    b[0] = 1;
    let first = INPUT / 64;
    z[first..first + 25].copy_from_slice(input);
    a[first..first + 25].copy_from_slice(input);
    b[first..first + 25].fill(u64::MAX);
    let mut state = *input;
    for (r, &rc) in RC.iter().enumerate() {
        let c: [u64; 5] = std::array::from_fn(|x| (0..5).fold(0, |v, y| v ^ state[x + 5 * y]));
        let mut linear = [0; 25];
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                linear[y + 5 * ((2 * x + 3 * y) % 5)] = (state[x + 5 * y] ^ d).rotate_left(ROT[x][y] as u32);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                let j = x + 5 * y;
                let slot = (INPUT + 1600) / 64 + 25 * r + j;
                a[slot] = !linear[(x + 1) % 5 + 5 * y];
                b[slot] = linear[(x + 2) % 5 + 5 * y];
                z[slot] = a[slot] & b[slot];
                state[j] = linear[j] ^ z[slot];
            }
        }
        state[0] ^= rc;
    }
    let last = OUTPUT / 64;
    z[last..last + 25].copy_from_slice(&state);
    a[last..last + 25].copy_from_slice(&state);
    b[last..last + 25].fill(u64::MAX);
    (z, a, b)
}

pub fn permute(input: &Permutation) -> Permutation {
    let (z, _, _) = block(input);
    z[OUTPUT / 64..OUTPUT / 64 + 25].try_into().unwrap()
}

/// Packed Boolean witnesses, including honest zero-input padding permutations.
pub fn generate(inputs: &[Permutation], block_log: usize) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u8>) {
    assert!(inputs.len() <= 1usize << block_log);
    let blocks = parallel::map_collect(1 << block_log, |i| block(inputs.get(i).unwrap_or(&[0; 25])));
    let mut z = Vec::new();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (zi, ai, bi) in blocks {
        z.extend(zi);
        a.extend(ai);
        b.extend(bi);
    }
    let stripes = lincheck::pack_z_lincheck_from_packed(&z, K_LOG + block_log, K_LOG);
    (z, a, b, stripes)
}

fn point(zc: &zerocheck::ZerocheckClaim) -> lincheck::QuirkyPoint {
    let inner = K_LOG - zerocheck::K_SKIP;
    lincheck::QuirkyPoint {
        z_skip: zc.z,
        x_inner_rest: zc.mlv_challenges[..inner].to_vec(),
        x_outer: zc.mlv_challenges[inner..].to_vec(),
    }
}
fn claim(lc: &lincheck::LincheckClaim, outer: &[primitives::field::F192]) -> SliceClaim {
    let mut suffix_point = lc.r_inner_rest.clone();
    suffix_point.extend_from_slice(outer);
    SliceClaim {
        suffix_point,
        s_hat_v: lc.s_hat_v.clone(),
    }
}

pub struct KeccakSetup {
    pub block_log: usize,
}
impl KeccakSetup {
    pub fn prove(&self, z: &[u64], a: &[u64], b: &[u64], stripes: &[u8], ps: &mut ProverState) -> SliceClaim {
        let m = K_LOG + self.block_log;
        let padding = zerocheck::PaddingSpec {
            k_log: K_LOG,
            useful_bits_per_block: USED,
        };
        let zc = zerocheck::prove_packed_padded(packed_bytes(a), packed_bytes(b), packed_bytes(z), m, &padding, ps);
        let at = point(&zc);
        let lc =
            lincheck::prove_padded_capture_s_hat_v(stripes, m, K_LOG, zerocheck::K_SKIP, USED, &KeccakCircuit, &at, ps);
        claim(&lc, &at.x_outer)
    }
    pub fn verify(&self, vs: &mut VerifierState<'_>) -> Result<SliceClaim, VerifyError> {
        let m = K_LOG + self.block_log;
        let zc = zerocheck::verify(m, vs).map_err(VerifyError::Zerocheck)?;
        let at = point(&zc);
        let lc = lincheck::verify(
            m,
            K_LOG,
            zerocheck::K_SKIP,
            &KeccakCircuit,
            &at,
            zc.a_eval,
            zc.b_eval,
            zc.c_eval,
            vs,
        )
        .map_err(VerifyError::Lincheck)?;
        Ok(claim(&lc, &at.x_outer))
    }
}

pub fn ring_open(offset: usize, reduced: &SliceClaim) -> RingSwitchOpen {
    RingSwitchOpen {
        offset,
        qflock_vars: reduced.suffix_point.len(),
        claims: vec![RingSwitchClaim {
            suffix_point: reduced.suffix_point.clone(),
            s_hat_v: Some(reduced.s_hat_v.clone()),
        }],
    }
}
pub fn ring_verify(offset: usize, reduced: &SliceClaim) -> RingSwitchVerify<'_> {
    RingSwitchVerify {
        offset,
        qflock_vars: reduced.suffix_point.len(),
        claims: vec![RingSwitchVerifyClaim {
            suffix_point: &reduced.suffix_point,
            s_hat_v: reduced.s_hat_v.as_slice().try_into().unwrap(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::field::F192;
    #[test]
    fn packed_witness_matches_bit_circuit_and_full_reduction() {
        parallel::init();
        let inputs: Vec<Permutation> = (0..8)
            .map(|i| std::array::from_fn(|j| (i * 25 + j) as u64 * 1234567))
            .collect();
        let (z, a, b, stripes) = generate(&inputs, 3);
        for (i, input) in inputs.iter().enumerate() {
            let bits = std::array::from_fn(|j| input[j / 64] >> (j % 64) & 1 != 0);
            let reference = super::super::witness(&bits);
            let packed = &z[i * 1024..(i + 1) * 1024];
            assert!((0..1 << K_LOG).all(|j| reference[j] == (packed[j / 64] >> (j % 64) & 1 != 0)));
            let w: Vec<_> = reference
                .iter()
                .map(|&v| if v { F192::ONE } else { F192::ZERO })
                .collect();
            let (ra, rb) = super::super::forward(&w);
            for j in 0..1 << K_LOG {
                assert_eq!(ra[j] == F192::ONE, a[i * 1024 + j / 64] >> (j % 64) & 1 != 0);
                assert_eq!(rb[j] == F192::ONE, b[i * 1024 + j / 64] >> (j % 64) & 1 != 0);
            }
        }
        let setup = KeccakSetup { block_log: 3 };
        let mut ps = ProverState::from_label(b"keccak-full-reduction-test");
        let expected = setup.prove(&z, &a, &b, &stripes, &mut ps);
        let proof = ps.into_proof();
        let mut vs = VerifierState::from_label(b"keccak-full-reduction-test", &proof);
        let got = setup.verify(&mut vs).unwrap();
        assert_eq!(expected.suffix_point, got.suffix_point);
        assert_eq!(expected.s_hat_v, got.s_hat_v);
        assert!(vs.finish().is_ok());
    }
}
