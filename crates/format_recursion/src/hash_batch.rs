//! Experimental Flock adapter with explicit public compression I/O binding.
//! The caller must bind these requests to its own computation separately.

use fiat_shamir::{
    digest_words,
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::hash::{
    Blake2sSetup, Compression, K_LOG, R1CS_DIGEST, blake2s_compress, generate_witness_with_ab_packed_and_lincheck,
    padding_block, param_iv, ring_switch_open, ring_switch_verify,
};
use pcs::{
    pack::LOG_PACKING,
    stack_open::{StackClaim, open_batch_mixed_whir_stacked, verify_opening_batch_mixed_whir_stacked},
    whir::{INITIAL_FOLDING_FACTOR, LOG_INV_RATE_0, commit, config_for_rate},
};
use primitives::{
    field::{F64, F192},
    hash::hash,
    multilinear::eq_table,
};

const LABEL: &[u8] = b"format-recursion-public-hash-batch-v1";
const MAX_COMPRESSIONS: usize = 1 << 16;
// The pinned WHIR configuration needs at least fifteen committed variables.
const MIN_COMPRESSIONS: usize = 128;
// Packed F64 words: CV, output, message, counter, flags. All public I/O is covered.
const IO_SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];

#[derive(Clone, Debug)]
pub struct Request {
    pub message: Vec<u8>,
    pub digest: Hash,
}

#[derive(Clone, Debug)]
pub struct BatchProof {
    /// Outputs of non-final compressions, in request and block order.
    /// The verifier uses these as advice and authenticates them through Flock.
    pub intermediates: Vec<[u32; 8]>,
    pub proof: Proof,
}

#[derive(Clone)]
struct Row {
    block: Compression,
    output: [u32; 8],
}

fn words(bytes: &[u8; 32]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn compression_count(requests: &[Request]) -> Option<usize> {
    if requests.is_empty() || requests.len() > MAX_COMPRESSIONS {
        return None;
    }
    requests.iter().try_fold(0usize, |sum, r| {
        sum.checked_add(r.message.len().div_ceil(64).max(1))
            .filter(|&n| n <= MAX_COMPRESSIONS)
    })
}

fn rows(requests: &[Request], intermediates: &[[u32; 8]]) -> Option<Vec<Row>> {
    let count = compression_count(requests)?;
    if intermediates.len() != count - requests.len() {
        return None;
    }
    let mut advice = intermediates.iter();
    let mut result = Vec::with_capacity(count);
    for request in requests {
        let mut cv = param_iv();
        let n = request.message.len().div_ceil(64).max(1);
        for i in 0..n {
            let start = (64 * i).min(request.message.len());
            let end = (64 * (i + 1)).min(request.message.len());
            let mut bytes = [0u8; 64];
            bytes[..end - start].copy_from_slice(&request.message[start..end]);
            let message = std::array::from_fn(|j| u32::from_le_bytes(bytes[4 * j..4 * j + 4].try_into().unwrap()));
            let last = i + 1 == n;
            let block = (cv, message, end as u64, if last { u32::MAX } else { 0 }, 0);
            let output = if last { words(&request.digest) } else { *advice.next()? };
            result.push(Row { block, output });
            cv = output;
        }
    }
    Some(result)
}

fn padding_row() -> Row {
    let block = padding_block();
    Row {
        output: blake2s_compress(&block.0, &block.1, block.2, block.3, block.4),
        block,
    }
}

fn io(row: &Row) -> [u64; 18] {
    let (h, m, t, f0, f1) = &row.block;
    let pack = |a: u32, b: u32| u64::from(a) | (u64::from(b) << 32);
    std::array::from_fn(|i| match i {
        0..4 => pack(h[2 * i], h[2 * i + 1]),
        4..8 => pack(row.output[2 * (i - 4)], row.output[2 * (i - 4) + 1]),
        8..16 => pack(m[2 * (i - 8)], m[2 * (i - 8) + 1]),
        16 => *t,
        17 => pack(*f0, *f1),
        _ => unreachable!(),
    })
}

fn seed(context: &Hash, rows: &[Row]) -> [F64; 4] {
    let mut bytes = Vec::with_capacity(72 + rows.len() * 144);
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(&R1CS_DIGEST);
    bytes.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        for word in io(row) {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    digest_words(&hash(&bytes))
}

fn binding_claims(rows: &[Row], point: Vec<F192>) -> Vec<StackClaim> {
    let weights = eq_table(&point);
    let padding = io(&padding_row());
    let mut values = [F192::ZERO; 18];
    for (i, &weight) in weights.iter().enumerate() {
        let row = rows.get(i).map_or(padding, io);
        for j in 0..18 {
            values[j] += weight.mul_base(F64(row[j]));
        }
    }
    IO_SLOTS
        .iter()
        .zip(values)
        .map(|(&slot, value)| StackClaim::Strided {
            offset: 0,
            slot,
            stride_log: K_LOG - LOG_PACKING,
            point: point.clone(),
            value,
        })
        .collect()
}

/// Prove the requested digests, including arbitrary message lengths and chaining.
/// This does not prove the caller's arithmetic or hide the requests.
pub fn prove(context: &Hash, requests: &[Request]) -> Option<BatchProof> {
    compression_count(requests)?;
    let mut intermediates = Vec::new();
    for request in requests {
        let n = request.message.len().div_ceil(64).max(1);
        let mut cv = param_iv();
        for i in 0..n.saturating_sub(1) {
            let chunk = &request.message[64 * i..64 * (i + 1)];
            let m = std::array::from_fn(|j| u32::from_le_bytes(chunk[4 * j..4 * j + 4].try_into().unwrap()));
            cv = blake2s_compress(&cv, &m, (64 * (i + 1)) as u64, 0, 0);
            intermediates.push(cv);
        }
    }
    let rows = rows(requests, &intermediates)?;
    let setup = Blake2sSetup::new(rows.len().max(MIN_COMPRESSIONS));
    let mu = setup.m() - LOG_PACKING;
    let blocks: Vec<_> = rows.iter().map(|r| r.block).collect();
    let (z, a, b, lincheck) = generate_witness_with_ab_packed_and_lincheck(&blocks, setup.n_blocks_log());
    let table: Vec<_> = z.iter().copied().map(F64).collect();
    let config = config_for_rate(mu, LOG_INV_RATE_0).ok()?;
    let (commitment, data) = commit(&table, mu, INITIAL_FOLDING_FACTOR, LOG_INV_RATE_0);
    let mut ps = ProverState::new(digest_words(&hash(LABEL)), seed(context, &rows));
    ps.add_root(&commitment.root);
    // Both the public I/O table and the witness commitment precede the random point.
    let point = ps.sample_vec(setup.n_blocks_log());
    let bindings = binding_claims(&rows, point);
    let reduced = setup.prove_reduction_precomputed(&z, &a, &b, &lincheck, &mut ps);
    drop((z, a, b, lincheck));
    let ring = ring_switch_open(1 << setup.n_blocks_log(), 0, &reduced);
    open_batch_mixed_whir_stacked(&mut ps, mu, &table, &data, &config, &bindings, &ring);
    Some(BatchProof {
        intermediates,
        proof: ps.into_proof(),
    })
}

/// Bind every compression's CV, message, counter, flags and output to one Flock witness.
pub fn verify(context: &Hash, requests: &[Request], certificate: &BatchProof) -> bool {
    let Some(rows) = rows(requests, &certificate.intermediates) else {
        return false;
    };
    let setup = Blake2sSetup::new(rows.len().max(MIN_COMPRESSIONS));
    let mu = setup.m() - LOG_PACKING;
    let Ok(config) = config_for_rate(mu, LOG_INV_RATE_0) else {
        return false;
    };
    let mut vs = VerifierState::new(digest_words(&hash(LABEL)), &certificate.proof, seed(context, &rows));
    let Ok(root) = vs.next_root() else {
        return false;
    };
    let point = vs.sample_vec(setup.n_blocks_log());
    let bindings = binding_claims(&rows, point);
    let Ok(reduced) = setup.verify_reduction(&mut vs) else {
        return false;
    };
    let ring = ring_switch_verify(1 << setup.n_blocks_log(), 0, &reduced.claim);
    verify_opening_batch_mixed_whir_stacked(
        &mut vs,
        &config,
        mu,
        1 << INITIAL_FOLDING_FACTOR,
        &root,
        &bindings,
        &ring,
    )
    .is_ok()
        && vs.finish().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_io_matches_packed_flock_layout() {
        parallel::init();
        let block = (
            std::array::from_fn(|i| i as u32 + 13),
            std::array::from_fn(|i| i as u32 + 31),
            0x123456789abc,
            0xfedcba98,
            0xabcdef01,
        );
        let row = Row {
            output: blake2s_compress(&block.0, &block.1, block.2, block.3, block.4),
            block,
        };
        let (z, _, _, _) = generate_witness_with_ab_packed_and_lincheck(&[block], 3);
        for (slot, value) in IO_SLOTS.iter().zip(io(&row)) {
            assert_eq!(z[*slot], value);
        }
    }

    #[test]
    fn honest_and_adversarial_public_batch() {
        parallel::init();
        let requests: Vec<_> = [0usize, 1, 63, 64, 65, 128, 129]
            .into_iter()
            .map(|len| {
                let message: Vec<_> = (0..len).map(|i| i.wrapping_mul(37) as u8).collect();
                Request {
                    digest: hash(&message),
                    message,
                }
            })
            .collect();
        let context = [5; 32];
        let proof = prove(&context, &requests).unwrap();
        assert!(verify(&context, &requests, &proof));
        assert!(!verify(&[6; 32], &requests, &proof));
        for i in 0..requests.len() {
            let mut bad = requests.clone();
            bad[i].digest[0] ^= 1;
            assert!(!verify(&context, &bad, &proof));
            if !bad[i].message.is_empty() {
                bad = requests.clone();
                bad[i].message[0] ^= 1;
                assert!(!verify(&context, &bad, &proof));
            }
        }
        let mut bad = requests.clone();
        bad.swap(1, 2);
        assert!(!verify(&context, &bad, &proof));
        bad = requests.clone();
        bad.pop();
        assert!(!verify(&context, &bad, &proof));
        bad = requests.clone();
        bad[3].message.push(0);
        assert!(!verify(&context, &bad, &proof));
        let mut bad = proof.clone();
        bad.intermediates[0][0] ^= 1;
        assert!(!verify(&context, &requests, &bad));
        bad = proof.clone();
        bad.intermediates.push([0; 8]);
        assert!(!verify(&context, &requests, &bad));
        bad = proof.clone();
        bad.proof.stream.push(F192::ONE);
        assert!(!verify(&context, &requests, &bad));
        bad = proof.clone();
        bad.proof.stream.clear();
        assert!(!verify(&context, &requests, &bad));
        assert!(!verify(&context, &[], &proof));
    }

    #[test]
    fn binding_point_detects_every_io_column_including_padding() {
        parallel::init();
        let row = padding_row();
        let setup = Blake2sSetup::new(1);
        let (z, _, _, _) = generate_witness_with_ab_packed_and_lincheck(&[row.block], setup.n_blocks_log());
        // Boolean points select each real or padded block exactly, without probabilistic testing.
        for block in 0..8 {
            let point = (0..3).map(|i| F192::from(F64(((block >> i) & 1) as u64))).collect();
            let claims = binding_claims(std::slice::from_ref(&row), point);
            for (claim, &slot) in claims.iter().zip(&IO_SLOTS) {
                assert_eq!(claim.value(), F192::from(F64(z[block * 256 + slot])));
            }
        }
    }

    #[test]
    fn an_unbound_proof_of_unrelated_hashes_is_rejected() {
        parallel::init();
        let message = b"the caller requested this message".to_vec();
        let requests = vec![Request {
            digest: hash(&message),
            message,
        }];
        let public_rows = rows(&requests, &[]).unwrap();
        let context = [7; 32];
        let setup = Blake2sSetup::new(MIN_COMPRESSIONS);
        let mu = setup.m() - LOG_PACKING;
        // This malicious prover hashes a different message but seeds its transcript
        // with exactly the statement the protected verifier expects.
        let (z, a, b, lincheck) =
            generate_witness_with_ab_packed_and_lincheck(&[padding_block()], setup.n_blocks_log());
        let table: Vec<_> = z.iter().copied().map(F64).collect();
        let config = config_for_rate(mu, LOG_INV_RATE_0).unwrap();
        let (commitment, data) = commit(&table, mu, INITIAL_FOLDING_FACTOR, LOG_INV_RATE_0);
        let mut ps = ProverState::new(digest_words(&hash(LABEL)), seed(&context, &public_rows));
        ps.add_root(&commitment.root);
        ps.sample_vec(setup.n_blocks_log());
        let reduced = setup.prove_reduction_precomputed(&z, &a, &b, &lincheck, &mut ps);
        let ring = ring_switch_open(MIN_COMPRESSIONS, 0, &reduced);
        open_batch_mixed_whir_stacked(&mut ps, mu, &table, &data, &config, &[], &ring);
        let proof = ps.into_proof();
        // Establish that the unbound Flock proof itself is valid, so this tests
        // the binding requirement rather than an arbitrary broken proof.
        let mut vs = VerifierState::new(digest_words(&hash(LABEL)), &proof, seed(&context, &public_rows));
        let root = vs.next_root().unwrap();
        vs.sample_vec(setup.n_blocks_log());
        let reduced = setup.verify_reduction(&mut vs).unwrap();
        let ring = ring_switch_verify(MIN_COMPRESSIONS, 0, &reduced.claim);
        assert!(
            verify_opening_batch_mixed_whir_stacked(
                &mut vs,
                &config,
                mu,
                1 << INITIAL_FOLDING_FACTOR,
                &root,
                &[],
                &ring
            )
            .is_ok()
        );
        assert!(vs.finish().is_ok());
        assert!(!verify(
            &context,
            &requests,
            &BatchProof {
                intermediates: Vec::new(),
                proof
            }
        ));
    }
}
