//! Experimental private binding of native arithmetic to batched BLAKE2s.
//! The fixed circuit supplies every compression I/O word as a native variable.
//! No request table or intermediate chaining values enter the serialized proof.
//! This composition is tested engineering, not a formal security certificate.

use crate::native_arithmetic::{self, ArithmeticShape, Circuit, Index};
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::hash::{
    Blake2sSetup, Compression, K_LOG, R1CS_DIGEST, blake2s_compress, generate_witness_with_ab_packed_and_lincheck,
    padding_block, ring_switch_open, ring_switch_verify,
};
use pcs::{
    pack::LOG_PACKING,
    stack_open::{StackClaim, open_batch_mixed_whir_stacked, verify_opening_batch_mixed_whir_stacked},
    whir::{self, INITIAL_FOLDING_FACTOR},
};
use primitives::{
    field::{F64, F192},
    multilinear::eq_table,
};

const SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
/// Candidate production WHIR profile for the joint private witness only.
/// The fixed circuit index uses a separate validated production profile.
pub(crate) const JOINT_LOG_INV_RATE: usize = 2;
const INDEX_LOG_INV_RATE: usize = 4;
const MIN_BLOCKS: usize = 128;
pub(crate) const MAX_BLOCKS: usize = 1 << 17;

/// Four native columns have three F64 limbs each. Unlike the standalone
/// arithmetic stack, this joint commitment does not retain each fourth slot.
fn joint_layout(log_rows: usize, q_log: usize) -> Option<(usize, usize)> {
    let native_words = 12usize.checked_mul(1usize.checked_shl(log_rows.try_into().ok()?)?)?;
    let q_words = 1usize.checked_shl(q_log.try_into().ok()?)?;
    let q_offset = native_words.checked_next_multiple_of(q_words)?;
    let stack_log = q_offset
        .checked_add(q_words)?
        .checked_next_power_of_two()?
        .trailing_zeros() as usize;
    Some((q_offset, stack_log))
}

#[cfg(all(test, not(feature = "keccak-protocol")))]
fn copy_compact_native(destination: &mut [F64], source: &[F64], log_rows: usize) {
    let n = 1usize << log_rows;
    assert_eq!(source.len(), 16 * n);
    assert!(destination.len() >= 12 * n);
    for col in 0..4 {
        for limb in 0..3 {
            let from = (4 * col + limb) * n;
            let to = (3 * col + limb) * n;
            destination[to..to + n].copy_from_slice(&source[from..from + n]);
        }
    }
}

/// The order is `CV[4]`, `output[4]`, `message[8]`, counter, flags.
pub fn io_words(block: &Compression, output: &[u32; 8]) -> [u64; 18] {
    let (h, m, t, f0, f1) = block;
    let pack = |a: u32, b: u32| u64::from(a) | (u64::from(b) << 32);
    std::array::from_fn(|i| match i {
        0..4 => pack(h[2 * i], h[2 * i + 1]),
        4..8 => pack(output[2 * (i - 4)], output[2 * (i - 4) + 1]),
        8..16 => pack(m[2 * (i - 8)], m[2 * (i - 8) + 1]),
        16 => *t,
        17 => pack(*f0, *f1),
        _ => unreachable!(),
    })
}

/// Fixed verifier metadata, without a commitment or prover allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateShape {
    pub index: ArithmeticShape,
    pub n_blocks: usize,
    pub block_log: usize,
    pub connector_start: usize,
    pub q_offset: usize,
    pub stack_log: usize,
}

impl PrivateShape {
    pub fn for_circuit(rows: usize, public_len: usize, n_blocks: usize) -> Option<Self> {
        let shape = Self::plan(rows, public_len, n_blocks)?;
        (shape.index.log_rows <= native_arithmetic::MAX_LOG_ROWS).then_some(shape)
    }

    /// Metadata-only final layout, including connectors and alignment. Planning
    /// may exceed the backend row cap; it does not authorize a proving key.
    pub fn plan(rows: usize, public_len: usize, n_blocks: usize) -> Option<Self> {
        if n_blocks == 0 || n_blocks > MAX_BLOCKS || public_len < 2 {
            return None;
        }
        let full_public = public_len.checked_add(18)?;
        let public_rows = full_public.checked_next_power_of_two()?;
        let blocks = n_blocks.max(MIN_BLOCKS).checked_next_power_of_two()?;
        let block_log = blocks.trailing_zeros() as usize;
        let connector_start = public_rows.checked_add(rows)?.checked_next_multiple_of(blocks)?;
        let count = connector_start.checked_add(6 * blocks)?;
        let log_rows = (count.checked_next_power_of_two()?.trailing_zeros() as usize).max(13);
        let q_log = K_LOG - LOG_PACKING + block_log;
        let (q_offset, stack_log) = joint_layout(log_rows, q_log)?;
        Some(Self {
            index: ArithmeticShape {
                log_rows,
                public_log: public_rows.trailing_zeros() as usize,
                public_len: full_public,
                index_log_inv_rate: INDEX_LOG_INV_RATE,
            },
            n_blocks,
            block_log,
            connector_start,
            q_offset,
            stack_log,
        })
    }

    pub fn committed_lanes(&self) -> usize {
        let q_log = K_LOG - LOG_PACKING + self.block_log;
        let lane_words = 1usize << (self.stack_log - INITIAL_FOLDING_FACTOR);
        (self.q_offset + (1usize << q_log)).div_ceil(lane_words)
    }

    pub(crate) fn compact_native_offset(&self, offset: usize, low_log: usize) -> usize {
        let n = 1usize << self.index.log_rows;
        assert!(low_log <= self.index.log_rows, "native claim exceeds its column");
        let slot = offset / n;
        let within = offset % n;
        assert!(slot < 16 && slot % 4 < 3, "claim addresses an unused native limb slot");
        let width = 1usize << low_log;
        assert!(
            offset.is_multiple_of(width) && within + width <= n,
            "unaligned native claim"
        );
        (3 * (slot / 4) + slot % 4) * n + within
    }

    pub(crate) fn connector_offset(&self, slot: usize, limb: usize) -> usize {
        assert!(slot < 18 && limb < 3, "invalid connector coordinate");
        let n = 1usize << self.index.log_rows;
        (3 * (slot / 6) + limb) * n + self.connector_start + ((slot % 6) << self.block_log)
    }
}

/// Trusted preprocessing for a fixed native circuit and compression schedule.
/// The caller's circuit must constrain serialization, chaining and statement
/// meaning; this bridge proves equality of its named words to valid compressions.
pub struct PrivateBridge {
    pub index: Index,
    pub n_blocks: usize,
    pub block_log: usize,
    pub connector_start: usize,
    pub q_offset: usize,
    pub stack_log: usize,
    variables: usize,
    public_len: usize,
    io_variables: Vec<[usize; 18]>,
    padding: [u64; 18],
}

impl PrivateBridge {
    /// Only whole initial WHIR lanes containing circuit/hash data are stored.
    /// The omitted suffix is zero and is authenticated by WHIR's existing
    /// leading-zero leaf convention. Shape is fixed by trusted preprocessing.
    pub fn verifier_shape(&self) -> PrivateShape {
        PrivateShape {
            index: self.index.verifier_shape(),
            n_blocks: self.n_blocks,
            block_log: self.block_log,
            connector_start: self.connector_start,
            q_offset: self.q_offset,
            stack_log: self.stack_log,
        }
    }

    pub fn committed_lanes(&self) -> usize {
        self.verifier_shape().committed_lanes()
    }

    /// A second native hash-row kind under the same arithmetic/index proof and
    /// joint WHIR commitment. Existing BLAKE2s-only keys are unchanged.
    pub fn new_mixed(
        circuit: Circuit,
        blake_io: Vec<[usize; 18]>,
        keccak_io: Vec<[usize; 50]>,
    ) -> Option<crate::keccak_bridge::KeccakBridge> {
        crate::keccak_bridge::KeccakBridge::new_mixed(circuit, keccak_io, blake_io)
    }

    pub fn new(circuit: Circuit, io_variables: Vec<[usize; 18]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, false)
    }

    pub(crate) fn new_padded(circuit: Circuit, io_variables: Vec<[usize; 18]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, true)
    }

    fn new_inner(mut circuit: Circuit, io_variables: Vec<[usize; 18]>, padded: bool) -> Option<Self> {
        if cfg!(feature = "keccak-protocol")
            || io_variables.is_empty()
            || io_variables.len() > MAX_BLOCKS
            || circuit.public.len() < 2
            || circuit.public[..2] != [0, 1]
            || circuit.variables < 2
            || circuit
                .public
                .iter()
                .chain(circuit.rows.iter().flatten())
                .chain(io_variables.iter().flatten())
                .any(|&v| v >= circuit.variables)
        {
            return None;
        }
        let variables = circuit.variables;
        let public_len = circuit.public.len();
        let actual_blocks = io_variables.len();
        let count = actual_blocks.max(MIN_BLOCKS).next_power_of_two();
        let n_blocks = if padded { count } else { actual_blocks };
        let block_log = count.trailing_zeros() as usize;
        let padding_block = padding_block();
        let padding = io_words(
            &padding_block,
            &blake2s_compress(
                &padding_block.0,
                &padding_block.1,
                padding_block.2,
                padding_block.3,
                padding_block.4,
            ),
        );
        let padding_variables: [usize; 18] = std::array::from_fn(|i| variables + i);
        circuit.variables += 18;
        circuit.public.extend(padding_variables);
        let public_rows = circuit.public.len().next_power_of_two();
        let alignment = count;
        let connector_start = (public_rows + circuit.rows.len()).next_multiple_of(alignment);
        circuit.rows.resize(connector_start - public_rows, [0, 0, 0, 0]);
        let helper_start = circuit.variables;
        circuit.variables = circuit.variables.checked_add(6 * count)?;
        for group in 0..6 {
            for block in 0..count {
                let inputs: [usize; 3] = std::array::from_fn(|col| {
                    let slot = 6 * col + group;
                    io_variables.get(block).map_or(padding_variables[slot], |row| row[slot])
                });
                circuit
                    .rows
                    .push([inputs[0], inputs[1], inputs[2], helper_start + group * count + block]);
            }
        }
        let required_rows = public_rows.checked_add(circuit.rows.len())?;
        if required_rows.next_power_of_two().trailing_zeros() as usize > native_arithmetic::MAX_LOG_ROWS {
            return None;
        }
        let index = Index::new_with_rate(circuit, INDEX_LOG_INV_RATE);
        let q_log = K_LOG - LOG_PACKING + block_log;
        let (q_offset, stack_log) = joint_layout(index.log_rows, q_log)?;
        Some(Self {
            index,
            n_blocks,
            block_log,
            connector_start,
            q_offset,
            stack_log,
            variables,
            public_len,
            io_variables,
            padding,
        })
    }
    /// Translate only native witness claims; permutation-index claims use a
    /// different four-column layout and must never pass through this mapping.
    pub(crate) fn compact_native_offset(&self, offset: usize, low_log: usize) -> usize {
        self.verifier_shape().compact_native_offset(offset, low_log)
    }

    pub(crate) fn connector_offset(&self, slot: usize, limb: usize) -> usize {
        self.verifier_shape().connector_offset(slot, limb)
    }

    pub(crate) fn public(&self, public: &[F192]) -> Option<Vec<F192>> {
        if public.len() != self.public_len || public[..2] != [F192::ZERO, F192::ONE] {
            return None;
        }
        let mut full = public.to_vec();
        full.extend(self.padding.map(|x| F192::new(x, 0, 0)));
        Some(full)
    }
    pub(crate) fn label(&self, public: &[F192], context: &Hash) -> Vec<u8> {
        let mut out = b"format-private-bridge-v5".to_vec();
        out.extend_from_slice(&self.index.root);
        out.extend_from_slice(context);
        out.extend_from_slice(&R1CS_DIGEST);
        for x in [
            self.index.log_rows,
            self.index.public_log,
            self.n_blocks,
            self.block_log,
            self.connector_start,
            self.q_offset,
            self.stack_log,
            JOINT_LOG_INV_RATE,
            self.index.index_log_inv_rate,
            public.len(),
        ] {
            out.extend_from_slice(&(x as u64).to_le_bytes());
        }
        for x in public {
            for limb in [x.c0, x.c1, x.c2] {
                out.extend_from_slice(&limb.to_le_bytes());
            }
        }
        out
    }
    pub(crate) fn claims(&self, point: &[F192], values: &[F192; 18]) -> Vec<StackClaim> {
        let mut claims = Vec::new();
        for (slot, &value) in values.iter().enumerate() {
            for limb in 0..3 {
                claims.push(StackClaim::Point {
                    offset: self.connector_offset(slot, limb),
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
        claims
    }
    pub fn prove(&self, values: &[F192], blocks: &[Compression], context: &Hash) -> Option<Proof> {
        if values.len() != self.variables || blocks.len() != self.io_variables.len() {
            return None;
        }
        for (block, variables) in blocks.iter().zip(&self.io_variables) {
            let output = blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
            for (variable, word) in variables.iter().zip(io_words(block, &output)) {
                if values[*variable] != F192::new(word, 0, 0) {
                    return None;
                }
            }
        }
        self.prove_unchecked(values, blocks, context)
    }
    // Deliberately separate from the precheck so tests can prove malformed
    // witness bindings and exercise rejection by the argument verifier itself.
    fn extend_values(&self, values: &[F192]) -> Vec<F192> {
        let mut values = values.to_vec();
        values.extend(self.padding.map(|x| F192::new(x, 0, 0)));
        for group in 0..6 {
            for block in 0..1usize << self.block_log {
                let inputs: [F192; 3] = std::array::from_fn(|col| {
                    let slot = 6 * col + group;
                    let variable = self
                        .io_variables
                        .get(block)
                        .map_or(self.variables + slot, |row| row[slot]);
                    values[variable]
                });
                values.push(inputs[0] * inputs[1] + inputs[2]);
            }
        }
        values
    }
    fn prove_unchecked(&self, values: &[F192], blocks: &[Compression], context: &Hash) -> Option<Proof> {
        let values = self.extend_values(values);
        let public = self.index.public_values(&values);
        let lane_words = 1usize << (self.stack_log - INITIAL_FOLDING_FACTOR);
        let joint_words = self.committed_lanes() * lane_words;
        let mut witness = tracing::info_span!("Arithmetic witness")
            .in_scope(|| native_arithmetic::prepare_compact_with_capacity(&self.index, &values, joint_words));
        drop(values);
        let (z, a, b, lincheck) = tracing::info_span!("Hash witness")
            .in_scope(|| generate_witness_with_ab_packed_and_lincheck(blocks, self.block_log));
        let mut stack = std::mem::take(&mut witness.stack);
        stack.resize(joint_words, F64::ZERO);
        for (dest, &word) in stack[self.q_offset..].iter_mut().zip(&z) {
            *dest = F64(word);
        }
        let (commitment, data) = tracing::info_span!("Joint commitment")
            .in_scope(|| whir::commit(&stack, self.stack_log, INITIAL_FOLDING_FACTOR, JOINT_LOG_INV_RATE));
        let mut ps = ProverState::from_label(&self.label(&public, context));
        ps.add_root(&commitment.root);
        let (native_claims, index_claims) = tracing::info_span!("Arithmetic reduction")
            .in_scope(|| native_arithmetic::prove_reduction_compact(&self.index, &witness, &stack, &mut ps));
        drop(witness);
        let reduced = tracing::info_span!("Hash reduction").in_scope(|| {
            Blake2sSetup::new(self.n_blocks.max(MIN_BLOCKS)).prove_reduction_precomputed(&z, &a, &b, &lincheck, &mut ps)
        });
        drop((z, a, b, lincheck));
        let point = ps.sample_vec(self.block_log);
        let weights = eq_table(&point);
        let mut bridge_values = [F192::ZERO; 18];
        for (slot, value) in bridge_values.iter_mut().enumerate() {
            let offset = self.connector_offset(slot, 0);
            *value = whir::inner_product_base_ext(&stack[offset..offset + weights.len()], &weights);
            ps.add_scalar(*value);
        }
        let mut claims: Vec<_> = native_claims
            .into_iter()
            .map(|c| StackClaim::Point {
                offset: self.compact_native_offset(c.offset, c.point.len()),
                low_point: c.point,
                value: c.value,
            })
            .collect();
        claims.extend(self.claims(&point, &bridge_values));
        let ring = ring_switch_open(1 << self.block_log, self.q_offset, &reduced);
        let config = whir::config_for_rate(self.stack_log, JOINT_LOG_INV_RATE).ok()?;
        tracing::info_span!("Joint opening").in_scope(|| {
            open_batch_mixed_whir_stacked(&mut ps, self.stack_log, &stack, &data, &config, &claims, &ring);
        });
        tracing::info_span!("Index opening")
            .in_scope(|| native_arithmetic::prove_index_open(&self.index, &index_claims, &mut ps));
        Some(ps.into_proof())
    }
    pub fn verify(&self, public: &[F192], context: &Hash, proof: &Proof) -> bool {
        let Some(public) = self.public(public) else {
            return false;
        };
        let mut vs = VerifierState::from_label(&self.label(&public, context), proof);
        let Ok(root) = vs.next_root() else {
            return false;
        };
        let Some((native_claims, index_claims)) = native_arithmetic::verify_reduction(&self.index, &public, &mut vs)
        else {
            return false;
        };
        let Ok(reduced) = Blake2sSetup::new(self.n_blocks.max(MIN_BLOCKS)).verify_reduction(&mut vs) else {
            return false;
        };
        let point = vs.sample_vec(self.block_log);
        let mut bridge_values = [F192::ZERO; 18];
        for value in &mut bridge_values {
            let Ok(x) = vs.next_scalar() else {
                return false;
            };
            *value = x;
        }
        let mut claims: Vec<_> = native_claims
            .into_iter()
            .map(|c| StackClaim::Point {
                offset: self.compact_native_offset(c.offset, c.point.len()),
                low_point: c.point,
                value: c.value,
            })
            .collect();
        claims.extend(self.claims(&point, &bridge_values));
        let ring = ring_switch_verify(1 << self.block_log, self.q_offset, &reduced.claim);
        let Ok(config) = whir::config_for_rate(self.stack_log, JOINT_LOG_INV_RATE) else {
            return false;
        };
        verify_opening_batch_mixed_whir_stacked(
            &mut vs,
            &config,
            self.stack_log,
            self.committed_lanes(),
            &root,
            &claims,
            &ring,
        )
        .is_ok()
            && native_arithmetic::verify_index_open(&self.index, &index_claims, &mut vs)
            && vs.finish().is_ok()
    }
}

#[cfg(all(test, not(feature = "keccak-protocol")))]
mod tests {
    use super::*;
    use flock::hash::param_iv;

    #[test]
    fn joint_rate_profile_uses_validated_production_parameters() {
        for log_n in [18usize, 22, 26, 29] {
            let baseline = whir::config_for_rate(log_n, 1).unwrap();
            let candidate = whir::config_for_rate(log_n, JOINT_LOG_INV_RATE).unwrap();
            let index = whir::config_for_rate(log_n, INDEX_LOG_INV_RATE).unwrap();
            assert_eq!(INDEX_LOG_INV_RATE, 4);
            assert_eq!(index.log_inv_rates[0], INDEX_LOG_INV_RATE);
            assert!(index.queries[0] < candidate.queries[0]);
            assert_eq!(candidate.initial_k, INITIAL_FOLDING_FACTOR);
            assert_eq!(candidate.log_inv_rates[0], JOINT_LOG_INV_RATE);
            assert_eq!(candidate.grinding_bits, baseline.grinding_bits);
            assert!(candidate.queries[0] < baseline.queries[0]);
            eprintln!(
                "joint log_n={log_n} rate1_queries={:?} rate2_queries={:?}",
                baseline.queries, candidate.queries
            );
        }
    }

    fn fixture(count: usize, seed: u32) -> (Circuit, Vec<[usize; 18]>, Vec<F192>, Vec<Compression>) {
        let mut values = vec![F192::ZERO, F192::ONE];
        let mut circuit = Circuit {
            variables: 2,
            rows: Vec::new(),
            public: vec![0, 1],
        };
        let mut io = Vec::<[usize; 18]>::new();
        let mut blocks = Vec::new();
        let mut cv = param_iv();
        for i in 0..count {
            let message = std::array::from_fn(|j| seed.wrapping_add((i * 97 + j) as u32));
            let block = (
                cv,
                message,
                ((i + 1) * 64) as u64,
                if i + 1 == count { u32::MAX } else { 0 },
                0,
            );
            let output = blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
            let words = io_words(&block, &output);
            let mut variables = [0usize; 18];
            for slot in 0..18 {
                if i > 0 && slot < 4 {
                    variables[slot] = io[i - 1][4 + slot];
                } else {
                    variables[slot] = values.len();
                    values.push(F192::new(words[slot], 0, 0));
                }
                if (i == 0 && slot < 4) || slot >= 16 || (i + 1 == count && (4..8).contains(&slot)) {
                    circuit.public.push(variables[slot]);
                }
            }
            cv = output;
            blocks.push(block);
            io.push(variables);
        }
        circuit.variables = values.len();
        (circuit, io, values, blocks)
    }

    #[test]
    fn private_chain_proves_without_disclosed_requests_and_rejects_mutations() {
        parallel::init();
        for count in [1, 2] {
            let (circuit, io, values, blocks) = fixture(count, 17);
            let public: Vec<_> = circuit.public.iter().map(|&i| values[i]).collect();
            let bridge = PrivateBridge::new(circuit, io).unwrap();
            let context = [41; 32];
            let proof = bridge.prove(&values, &blocks, &context).unwrap();
            assert!(bridge.verify(&public, &context, &proof));
            let encoded = bincode::serialize(&proof).unwrap();
            assert!(encoded.len() <= 1 << 20, "proof exceeds one MiB: {}", encoded.len());
            eprintln!("private_chain blocks={count} proof_bytes={}", encoded.len());
            assert!(!bridge.verify(&public, &[42; 32], &proof));
            for i in [0, public.len() - 1] {
                let mut bad = public.clone();
                bad[i] += F192::ONE;
                assert!(!bridge.verify(&bad, &context, &proof));
            }
            for i in [0, proof.stream.len() / 2, proof.stream.len() - 1] {
                let mut bad = proof.clone();
                bad.stream[i] += F192::ONE;
                assert!(!bridge.verify(&public, &context, &bad));
            }
            let mut bad = proof.clone();
            bad.stream.push(F192::ZERO);
            assert!(!bridge.verify(&public, &context, &bad));
            let mut bad = proof.clone();
            bad.stream.pop();
            assert!(!bridge.verify(&public, &context, &bad));
            let mut bad = proof.clone();
            bad.merkle.clear();
            assert!(!bridge.verify(&public, &context, &bad));
            for block in 0..count {
                for slot in 0..18 {
                    let mut bad_values = values.clone();
                    bad_values[bridge.io_variables[block][slot]] += F192::ONE;
                    assert!(bridge.prove(&bad_values, &blocks, &context).is_none());
                }
            }
            let mut high = values.clone();
            high[bridge.io_variables[0][8]].c1 = 1;
            assert!(bridge.prove(&high, &blocks, &context).is_none());
            let mut changed_blocks = blocks.clone();
            changed_blocks[0].3 ^= 1;
            assert!(bridge.prove(&values, &changed_blocks, &context).is_none());
            let mut changed_blocks = blocks.clone();
            changed_blocks[0].2 ^= 1;
            assert!(bridge.prove(&values, &changed_blocks, &context).is_none());
        }
    }

    #[test]
    fn verifier_rejects_invalid_private_bindings_without_prover_prechecks() {
        parallel::init();
        let (mut circuit, io, values, blocks) = fixture(2, 29);
        // Keep all compression I/O private so rejection cannot come merely
        // from comparing a mutated connector against a public input.
        circuit.public.truncate(2);
        let public: Vec<_> = circuit.public.iter().map(|&i| values[i]).collect();
        let bridge = PrivateBridge::new(circuit, io).unwrap();
        let context = [63; 32];
        // Each witness has valid arithmetic connector rows but disagrees with
        // a genuine Flock compression. Exercise every named slot and each
        // native limb without relying on the prover's connector precheck.
        for slot in 0..18 {
            for limb in 0..3 {
                let mut bad = values.clone();
                let at = bridge.io_variables[0][slot];
                let delta = match limb {
                    0 => F192::ONE,
                    1 => F192::new(0, 1, 0),
                    2 => F192::new(0, 0, 1),
                    _ => unreachable!(),
                };
                bad[at] += delta;
                let proof = bridge.prove_unchecked(&bad, &blocks, &context).unwrap();
                assert!(
                    !bridge.verify(&public, &context, &proof),
                    "accepted invalid private connector slot={slot} limb={limb}"
                );
            }
        }
        // A correct compression witness cannot rescue a false arithmetic gate.
        let (mut circuit, io, values, blocks) = fixture(1, 31);
        circuit.rows.push([io[0][8], io[0][8], 0, io[0][4]]);
        let public: Vec<_> = circuit.public.iter().map(|&i| values[i]).collect();
        let bridge = PrivateBridge::new(circuit, io).unwrap();
        let proof = bridge.prove(&values, &blocks, &context).unwrap();
        assert!(!bridge.verify(&public, &context, &proof));
    }

    #[test]
    fn connector_triples_keep_original_words_and_constrain_their_helpers() {
        parallel::init();
        let (circuit, io, values, _) = fixture(3, 37);
        let bridge = PrivateBridge::new(circuit, io.clone()).unwrap();
        let full = bridge.extend_values(&values);
        let prepared = native_arithmetic::prepare(&bridge.index, &full);
        let n = 1usize << bridge.index.log_rows;
        let count = 1usize << bridge.block_log;
        let read = |col: usize, row: usize| {
            F192::new(
                prepared.stack[(4 * col) * n + row].0,
                prepared.stack[(4 * col + 1) * n + row].0,
                prepared.stack[(4 * col + 2) * n + row].0,
            )
        };
        for group in 0..6 {
            for block in 0..count {
                let row = bridge.connector_start + group * count + block;
                for col in 0..3 {
                    let slot = 6 * col + group;
                    let expected = io
                        .get(block)
                        .map_or(F192::new(bridge.padding[slot], 0, 0), |v| values[v[slot]]);
                    assert_eq!(read(col, row), expected);
                }
                assert_eq!(read(3, row), read(0, row) * read(1, row) + read(2, row));
            }
        }
        let public = bridge.index.public_values(&full);
        let mut bad = full;
        bad[values.len() + 18] += F192::ONE;
        let context = [93; 32];
        let proof = native_arithmetic::prove(&bridge.index, &bad, &context);
        assert!(!native_arithmetic::verify(&bridge.index, &public, &context, &proof));
    }

    #[test]
    fn compact_native_views_and_claims_preserve_every_used_limb() {
        let (circuit, io, _, _) = fixture(1, 7);
        let bridge = PrivateBridge::new(circuit, io).unwrap();
        let l = bridge.index.log_rows;
        let n = 1usize << l;
        let source: Vec<_> = (0..16 * n).map(|i| F64(i as u64 + 1)).collect();
        let mut compact = vec![F64::ZERO; 12 * n + 16];
        copy_compact_native(&mut compact, &source, l);
        for col in 0..4 {
            for limb in 0..3 {
                let from = (4 * col + limb) * n;
                let to = (3 * col + limb) * n;
                assert_eq!(bridge.compact_native_offset(from, l), to);
                assert_eq!(bridge.compact_native_offset(from + n - 1, 0), to + n - 1);
                assert_eq!(bridge.compact_native_offset(from + n / 2, l - 1), to + n / 2);
                assert_eq!(&compact[to..to + n], &source[from..from + n]);
            }
        }
        assert!(compact[12 * n..].iter().all(|&x| x == F64::ZERO));
        let mut positions = std::collections::BTreeSet::new();
        for slot in 0..18 {
            assert!(positions.insert((slot / 6, slot % 6)));
            for limb in 0..3 {
                let offset = (4 * (slot / 6) + limb) * n + bridge.connector_start + ((slot % 6) << bridge.block_log);
                let compact_offset = bridge.connector_offset(slot, limb);
                assert_eq!(bridge.compact_native_offset(offset, bridge.block_log), compact_offset);
                assert_eq!(
                    &compact[compact_offset..compact_offset + (1 << bridge.block_log)],
                    &source[offset..offset + (1 << bridge.block_log)],
                );
            }
        }
        assert_eq!(positions.len(), 18);
        for (offset, low_log) in [
            (3 * n, 0),
            (7 * n, 0),
            (11 * n, 0),
            (15 * n, 0),
            (16 * n, 0),
            (0, l + 1),
            (1, l),
        ] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    bridge.compact_native_offset(offset, low_log)
                }))
                .is_err(),
                "accepted invalid native view offset={offset} low_log={low_log}"
            );
        }
    }

    #[test]
    fn compact_joint_layout_keeps_flock_aligned_and_disjoint() {
        for l in 13..=24 {
            let n = 1usize << l;
            for q_log in 0..=24 {
                let q_words = 1usize << q_log;
                let (offset, log) = joint_layout(l, q_log).unwrap();
                assert!(offset >= 12 * n);
                assert!(offset.is_multiple_of(q_words));
                assert!(offset - 12 * n < q_words);
                assert!(offset + q_words <= 1usize << log);
                assert!(offset + q_words > 1usize << (log - 1));
            }
            assert_eq!(joint_layout(l, l + 2).unwrap(), (12 * n, l + 4));
            assert_eq!(joint_layout(l, l + 3).unwrap(), (16 * n, l + 5));
        }
    }

    #[test]
    fn bridge_shape_is_bounded_and_all_named_words_are_valid_variables() {
        let (circuit, io, _, _) = fixture(1, 7);
        assert!(PrivateBridge::new(circuit.clone(), Vec::new()).is_none());
        let mut bad = io.clone();
        bad[0][17] = circuit.variables;
        assert!(PrivateBridge::new(circuit.clone(), bad).is_none());
        let mut bad = circuit;
        bad.public.clear();
        assert!(PrivateBridge::new(bad, io).is_none());
    }
}

pub mod lookup;
