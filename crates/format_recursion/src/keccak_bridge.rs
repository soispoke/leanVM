//! Experimental private binding of native arithmetic to batched Keccak-f[1600].
//! The fixed circuit supplies every permutation I/O word as a native variable.
//! No request table or intermediate chaining values enter the serialized proof.
//! This composition is tested engineering, not a formal security certificate.

use crate::native_arithmetic::{self, ArithmeticShape, Circuit, Index};
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::keccak::{
    INPUT, K_LOG, OUTPUT,
    reduction::{KeccakSetup, Permutation, generate, permute, ring_open, ring_verify},
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

const SLOTS: [usize; 50] = slots();
const fn slots() -> [usize; 50] {
    let mut out = [0; 50];
    let mut i = 0;
    while i < 25 {
        out[i] = INPUT / 64 + i;
        out[25 + i] = OUTPUT / 64 + i;
        i += 1;
    }
    out
}
/// Candidate production WHIR profile for the joint private witness only.
/// The fixed circuit index uses a separate validated production profile.
pub(crate) const JOINT_LOG_INV_RATE: usize = 2;
const INDEX_LOG_INV_RATE: usize = 4;
const MIN_BLOCKS: usize = 8;
pub(crate) const MAX_BLOCKS: usize = 1 << 15;

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

/// Input lanes followed by output lanes, in Keccak little-endian lane order.
pub fn io_words(block: &Permutation, output: &Permutation) -> [u64; 50] {
    std::array::from_fn(|i| if i < 25 { block[i] } else { output[i - 25] })
}

/// Fixed verifier metadata, without a commitment or prover allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeccakShape {
    pub index: ArithmeticShape,
    pub n_blocks: usize,
    pub block_log: usize,
    pub connector_start: usize,
    pub q_offset: usize,
    pub stack_log: usize,
}

impl KeccakShape {
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
        let full_public = public_len.checked_add(50)?;
        let public_rows = full_public.checked_next_power_of_two()?;
        let blocks = n_blocks.max(MIN_BLOCKS).checked_next_power_of_two()?;
        let block_log = blocks.trailing_zeros() as usize;
        let connector_start = public_rows.checked_add(rows)?.checked_next_multiple_of(blocks)?;
        let count = connector_start.checked_add(17 * blocks)?;
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
        assert!(slot < 50 && limb < 3, "invalid connector coordinate");
        let n = 1usize << self.index.log_rows;
        (3 * (slot / 17) + limb) * n + self.connector_start + ((slot % 17) << self.block_log)
    }
}

/// Trusted preprocessing for a fixed native circuit and permutation schedule.
/// The caller's circuit must constrain serialization, chaining and statement
/// meaning; this bridge proves equality of its named words to valid permutations.
pub struct KeccakBridge {
    pub index: Index,
    pub n_blocks: usize,
    pub block_log: usize,
    pub connector_start: usize,
    pub q_offset: usize,
    pub stack_log: usize,
    variables: usize,
    public_len: usize,
    io_variables: Vec<[usize; 50]>,
    padding: [u64; 50],
}

impl KeccakBridge {
    /// Only whole initial WHIR lanes containing circuit/hash data are stored.
    /// The omitted suffix is zero and is authenticated by WHIR's existing
    /// leading-zero leaf convention. Shape is fixed by trusted preprocessing.
    pub fn verifier_shape(&self) -> KeccakShape {
        KeccakShape {
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

    pub fn new(circuit: Circuit, io_variables: Vec<[usize; 50]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, false)
    }

    pub fn new_padded(circuit: Circuit, io_variables: Vec<[usize; 50]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, true)
    }

    fn new_inner(mut circuit: Circuit, io_variables: Vec<[usize; 50]>, padded: bool) -> Option<Self> {
        if io_variables.is_empty()
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
        let padding = io_words(&[0; 25], &permute(&[0; 25]));
        let padding_variables: [usize; 50] = std::array::from_fn(|i| variables + i);
        circuit.variables += 50;
        circuit.public.extend(padding_variables);
        let public_rows = circuit.public.len().next_power_of_two();
        let alignment = count;
        let connector_start = (public_rows + circuit.rows.len()).next_multiple_of(alignment);
        circuit.rows.resize(connector_start - public_rows, [0, 0, 0, 0]);
        let helper_start = circuit.variables;
        circuit.variables = circuit.variables.checked_add(17 * count)?;
        for group in 0..17 {
            for block in 0..count {
                let inputs: [usize; 3] = std::array::from_fn(|col| {
                    let slot = 17 * col + group;
                    if slot < 50 {
                        io_variables.get(block).map_or(padding_variables[slot], |row| row[slot])
                    } else {
                        0
                    }
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
        let mut out = b"format-private-keccak-bridge-v1".to_vec();
        out.extend_from_slice(&self.index.root);
        out.extend_from_slice(context);
        out.extend_from_slice(b"keccak-f1600-chi-24-k16-io64-v1");
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
    pub(crate) fn claims(&self, point: &[F192], values: &[F192; 50]) -> Vec<StackClaim> {
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
    pub fn prove(&self, values: &[F192], blocks: &[Permutation], context: &Hash) -> Option<Proof> {
        if values.len() != self.variables || blocks.len() != self.io_variables.len() {
            return None;
        }
        for (block, variables) in blocks.iter().zip(&self.io_variables) {
            let output = permute(block);
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
        for group in 0..17 {
            for block in 0..1usize << self.block_log {
                let inputs: [F192; 3] = std::array::from_fn(|col| {
                    let slot = 17 * col + group;
                    if slot < 50 {
                        let variable = self
                            .io_variables
                            .get(block)
                            .map_or(self.variables + slot, |row| row[slot]);
                        values[variable]
                    } else {
                        F192::ZERO
                    }
                });
                values.push(inputs[0] * inputs[1] + inputs[2]);
            }
        }
        values
    }
    fn prove_unchecked(&self, values: &[F192], blocks: &[Permutation], context: &Hash) -> Option<Proof> {
        let values = self.extend_values(values);
        let public = self.index.public_values(&values);
        let lane_words = 1usize << (self.stack_log - INITIAL_FOLDING_FACTOR);
        let joint_words = self.committed_lanes() * lane_words;
        let mut witness = tracing::info_span!("Arithmetic witness")
            .in_scope(|| native_arithmetic::prepare_compact_with_capacity(&self.index, &values, joint_words));
        drop(values);
        let (z, a, b, lincheck) = tracing::info_span!("Hash witness").in_scope(|| generate(blocks, self.block_log));
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
            KeccakSetup {
                block_log: self.block_log,
            }
            .prove(&z, &a, &b, &lincheck, &mut ps)
        });
        drop((z, a, b, lincheck));
        let point = ps.sample_vec(self.block_log);
        let weights = eq_table(&point);
        let mut bridge_values = [F192::ZERO; 50];
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
        let ring = ring_open(self.q_offset, &reduced);
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
        let Ok(reduced) = (KeccakSetup {
            block_log: self.block_log,
        })
        .verify(&mut vs) else {
            return false;
        };
        let point = vs.sample_vec(self.block_log);
        let mut bridge_values = [F192::ZERO; 50];
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
        let ring = ring_verify(self.q_offset, &reduced);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (KeccakBridge, Vec<F192>, Vec<Permutation>) {
        let first: Permutation = std::array::from_fn(|i| i as u64 * 12345);
        let middle = permute(&first);
        let last = permute(&middle);
        let mut values = vec![F192::ZERO, F192::ONE];
        values.extend(first.into_iter().chain(middle).chain(last).map(|v| F192::new(v, 0, 0)));
        let circuit = Circuit {
            variables: values.len(),
            rows: Vec::new(),
            // Fixed initial state and expected final output; middle is private.
            public: (0..27).chain(52..77).collect(),
        };
        let connectors = vec![std::array::from_fn(|i| 2 + i), std::array::from_fn(|i| 27 + i)];
        (
            KeccakBridge::new(circuit, connectors).unwrap(),
            values,
            vec![first, middle],
        )
    }
    #[test]
    fn permutation_bridge_rejects_malformed_proofs_without_prover_prechecks() {
        parallel::init();
        let (setup, values, blocks) = fixture();
        let public: Vec<_> = setup.index.public_values(&setup.extend_values(&values))[..setup.public_len].to_vec();
        let context = [37; 32];
        let proof = setup.prove(&values, &blocks, &context).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        let mut wrong_digest = public.clone();
        *wrong_digest.last_mut().unwrap() += F192::ONE;
        assert!(!setup.verify(&wrong_digest, &context, &proof));
        let mut wrong_output = values.clone();
        wrong_output[27] += F192::ONE;
        let forged = setup.prove_unchecked(&wrong_output, &blocks, &context).unwrap();
        assert!(
            !setup.verify(&public, &context, &forged),
            "wrong intermediate permutation output"
        );
        let mut wrong_wiring = blocks.clone();
        wrong_wiring.swap(0, 1);
        let forged = setup.prove_unchecked(&values, &wrong_wiring, &context).unwrap();
        assert!(
            !setup.verify(&public, &context, &forged),
            "swapped rows with unchanged circuit wiring"
        );
        let mut tampered = proof.clone();
        tampered.stream[0] += F192::ONE;
        assert!(!setup.verify(&public, &context, &tampered));
    }
}
