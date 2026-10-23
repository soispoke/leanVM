//! Experimental private binding of native arithmetic to batched Keccak-f[1600].
//! The fixed circuit supplies every permutation I/O word as a native variable.
//! No request table or intermediate chaining values enter the serialized proof.
//! This composition is tested engineering, not a formal security certificate.

use crate::native_arithmetic::{self, ArithmeticShape, Circuit, Index};
use fiat_shamir::{
    merkle::Hash,
    transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState},
};
use flock::hash::{self as blake, Compression, SliceClaim};
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
    pub q_log: usize,
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
            q_log,
            q_offset,
            stack_log,
        })
    }

    pub fn committed_lanes(&self) -> usize {
        let q_log = self.q_log;
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
    pub q_log: usize,
    pub q_offset: usize,
    pub stack_log: usize,
    variables: usize,
    public_len: usize,
    io_variables: Vec<[usize; 50]>,
    padding: [u64; 50],
    blake: Option<BlakeRows>,
    word_queries: Option<crate::word_query_binding::Schedule>,
}

#[derive(Clone, Copy)]
pub enum WordCoordinate {
    Constant(F192),
    Variable(usize),
}

struct BlakeRows {
    io: Vec<[usize; 18]>,
    padding: [u64; 18],
    block_log: usize,
    connector_start: usize,
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
            q_log: self.q_log,
            q_offset: self.q_offset,
            stack_log: self.stack_log,
        }
    }

    pub fn committed_lanes(&self) -> usize {
        self.verifier_shape().committed_lanes()
    }

    pub fn new(circuit: Circuit, io_variables: Vec<[usize; 50]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, Vec::new(), false)
    }

    pub fn new_padded(circuit: Circuit, io_variables: Vec<[usize; 50]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, Vec::new(), true)
    }

    /// Both hash families share one arithmetic reduction and one joint WHIR opening.
    pub fn new_mixed(circuit: Circuit, io_variables: Vec<[usize; 50]>, blake_io: Vec<[usize; 18]>) -> Option<Self> {
        Self::new_inner(circuit, io_variables, blake_io, false)
    }

    fn new_inner(
        mut circuit: Circuit,
        io_variables: Vec<[usize; 50]>,
        blake_io: Vec<[usize; 18]>,
        padded: bool,
    ) -> Option<Self> {
        if io_variables.is_empty()
            || io_variables.len() > MAX_BLOCKS
            || blake_io.len() > crate::private_bridge::MAX_BLOCKS
            || circuit.public.len() < 2
            || circuit.public[..2] != [0, 1]
            || circuit.variables < 2
            || circuit
                .public
                .iter()
                .chain(circuit.rows.iter().flatten())
                .chain(io_variables.iter().flatten())
                .chain(blake_io.iter().flatten())
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
        let blake_padding = if blake_io.is_empty() {
            None
        } else {
            let block = blake::padding_block();
            let output = blake::blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
            let words = crate::private_bridge::io_words(&block, &output);
            let start = circuit.variables;
            circuit.public.extend(start..start + 18);
            circuit.variables += 18;
            Some(words)
        };
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
        let blake = if let Some(padding) = blake_padding {
            let bcount = blake_io.len().max(128).next_power_of_two();
            let block_log = bcount.trailing_zeros() as usize;
            let connector_start = (public_rows + circuit.rows.len()).next_multiple_of(bcount);
            circuit.rows.resize(connector_start - public_rows, [0; 4]);
            let helper = circuit.variables;
            circuit.variables += 6 * bcount;
            for group in 0..6 {
                for block in 0..bcount {
                    let input: [usize; 3] = std::array::from_fn(|col| {
                        let slot = 6 * col + group;
                        blake_io.get(block).map_or(variables + 50 + slot, |row| row[slot])
                    });
                    circuit
                        .rows
                        .push([input[0], input[1], input[2], helper + group * bcount + block]);
                }
            }
            Some(BlakeRows {
                io: blake_io,
                padding,
                block_log,
                connector_start,
            })
        } else {
            None
        };
        let required_rows = public_rows.checked_add(circuit.rows.len())?;
        if required_rows.next_power_of_two().trailing_zeros() as usize > native_arithmetic::MAX_LOG_ROWS {
            return None;
        }
        let index = Index::new_with_rate(circuit, INDEX_LOG_INV_RATE);
        let q_log = K_LOG - LOG_PACKING + block_log;
        let q_log = blake
            .as_ref()
            .map_or(q_log, |b| q_log.max(blake::K_LOG - LOG_PACKING + b.block_log) + 1);
        let (q_offset, stack_log) = joint_layout(index.log_rows, q_log)?;
        Some(Self {
            index,
            n_blocks,
            block_log,
            connector_start,
            q_log,
            q_offset,
            stack_log,
            variables,
            public_len,
            io_variables,
            padding,
            blake,
            word_queries: None,
        })
    }
    /// Freeze a padded query schedule over existing arithmetic variables.
    /// Missing variables are rejected rather than silently added as advice.
    pub fn with_word_queries(mut self, queries: &[[WordCoordinate; 6]]) -> Option<Self> {
        use crate::word_query_binding::{Schedule, Source};
        if queries.len() < 2 || !queries.len().is_power_of_two() || queries.len() > 1 << 22 {
            return None;
        }
        let variables: Vec<_> = queries
            .iter()
            .flatten()
            .filter_map(|c| match c {
                WordCoordinate::Variable(v) => Some(*v),
                WordCoordinate::Constant(_) => None,
            })
            .collect();
        let cells = self.index.compact_variable_cells(&variables)?;
        let mut cells = cells.into_iter();
        let mut columns: [Vec<Source>; 6] = std::array::from_fn(|_| Vec::with_capacity(queries.len()));
        for query in queries {
            for (column, coordinate) in columns.iter_mut().zip(query) {
                column.push(match coordinate {
                    WordCoordinate::Constant(v) => Source::Constant(*v),
                    WordCoordinate::Variable(_) => Source::Cells(cells.next()?),
                });
            }
        }
        self.word_queries = Some(Schedule {
            stack_log: self.stack_log,
            columns,
        });
        Some(self)
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
        if let Some(b) = &self.blake {
            full.extend(b.padding.map(|v| F192::new(v, 0, 0)));
        }
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
        out.extend_from_slice(&self.q_log.to_le_bytes());
        if let Some(b) = &self.blake {
            out.extend_from_slice(&blake::R1CS_DIGEST);
            for v in [b.io.len(), b.block_log, b.connector_start] {
                out.extend_from_slice(&(v as u64).to_le_bytes());
            }
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
    fn lift(&self, mut claim: SliceClaim, offset: usize) -> SliceClaim {
        let start = claim.suffix_point.len();
        assert!(offset.is_multiple_of(1usize << start));
        claim
            .suffix_point
            .extend((start..self.q_log).map(|i| if offset >> i & 1 == 0 { F192::ZERO } else { F192::ONE }));
        claim
    }
    fn blake_connector_offset(&self, slot: usize, limb: usize) -> usize {
        let b = self.blake.as_ref().unwrap();
        (3 * (slot / 6) + limb) * (1usize << self.index.log_rows) + b.connector_start + ((slot % 6) << b.block_log)
    }
    fn blake_claims(&self, point: &[F192], values: &[F192; 18]) -> Vec<StackClaim> {
        const SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        let mut claims = Vec::new();
        for (slot, &value) in values.iter().enumerate() {
            for limb in 0..3 {
                claims.push(StackClaim::Point {
                    offset: self.blake_connector_offset(slot, limb),
                    low_point: point.to_vec(),
                    value: if limb == 0 { value } else { F192::ZERO },
                });
            }
            claims.push(StackClaim::Strided {
                offset: self.q_offset + (1usize << (self.q_log - 1)),
                slot: SLOTS[slot],
                stride_log: blake::K_LOG - LOG_PACKING,
                point: point.to_vec(),
                value,
            });
        }
        claims
    }
    pub fn prove(&self, values: &[F192], blocks: &[Permutation], context: &Hash) -> Option<Proof> {
        self.prove_mixed(values, blocks, &[], context)
    }
    pub fn prove_mixed(
        &self,
        values: &[F192],
        blocks: &[Permutation],
        blake_blocks: &[Compression],
        context: &Hash,
    ) -> Option<Proof> {
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
        if blake_blocks.len() != self.blake.as_ref().map_or(0, |b| b.io.len()) {
            return None;
        }
        if let Some(b) = &self.blake {
            for (block, vars) in blake_blocks.iter().zip(&b.io) {
                let output = blake::blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
                for (&var, word) in vars.iter().zip(crate::private_bridge::io_words(block, &output)) {
                    if values[var] != F192::new(word, 0, 0) {
                        return None;
                    }
                }
            }
        }
        self.prove_mixed_unchecked(values, blocks, blake_blocks, context)
    }
    // Deliberately separate from the precheck so tests can prove malformed
    // witness bindings and exercise rejection by the argument verifier itself.
    fn extend_values(&self, values: &[F192]) -> Vec<F192> {
        let mut values = values.to_vec();
        values.extend(self.padding.map(|x| F192::new(x, 0, 0)));
        if let Some(b) = &self.blake {
            values.extend(b.padding.map(|v| F192::new(v, 0, 0)));
        }
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
        if let Some(b) = &self.blake {
            for group in 0..6 {
                for block in 0..1usize << b.block_log {
                    let input: [F192; 3] = std::array::from_fn(|col| {
                        let slot = 6 * col + group;
                        values[b.io.get(block).map_or(self.variables + 50 + slot, |row| row[slot])]
                    });
                    values.push(input[0] * input[1] + input[2]);
                }
            }
        }
        values
    }
    #[cfg(test)]
    fn prove_unchecked(&self, values: &[F192], blocks: &[Permutation], context: &Hash) -> Option<Proof> {
        self.prove_mixed_unchecked(values, blocks, &[], context)
    }
    /// Experimental adversarial-test entry point. Deliberately bypasses host
    /// hash prechecks; callers must submit the result to the ordinary verifier.
    #[doc(hidden)]
    pub fn prove_mixed_without_prechecks_for_tests(
        &self,
        values: &[F192],
        blocks: &[Permutation],
        blake_blocks: &[Compression],
        context: &Hash,
    ) -> Option<Proof> {
        self.prove_mixed_unchecked(values, blocks, blake_blocks, context)
    }
    fn prove_mixed_unchecked(
        &self,
        values: &[F192],
        blocks: &[Permutation],
        blake_blocks: &[Compression],
        context: &Hash,
    ) -> Option<Proof> {
        self.prove_mixed_with_word_advice(values, blocks, blake_blocks, context, None)
    }
    fn prove_mixed_with_word_advice(
        &self,
        values: &[F192],
        blocks: &[Permutation],
        blake_blocks: &[Compression],
        context: &Hash,
        word_advice: Option<(&[Vec<F192>; 6], &[(usize, u64)])>,
    ) -> Option<Proof> {
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
        let blake_witness = self.blake.as_ref().map(|b| {
            let w = blake::generate_witness_with_ab_packed_and_lincheck(blake_blocks, b.block_log);
            let offset = self.q_offset + (1usize << (self.q_log - 1));
            for (dest, &word) in stack[offset..].iter_mut().zip(&w.0) {
                *dest = F64(word);
            }
            w
        });
        let (commitment, data) = tracing::info_span!("Joint commitment")
            .in_scope(|| whir::commit(&stack, self.stack_log, INITIAL_FOLDING_FACTOR, JOINT_LOG_INV_RATE));
        let mut ps = ProverState::from_label(&self.label(&public, context));
        ps.add_root(&commitment.root);
        let word_claim = if let Some(schedule) = &self.word_queries {
            let honest_queries = schedule.query_columns(&stack)?;
            let queries = word_advice.map_or(&honest_queries, |a| a.0);
            let mut counts = crate::word_tables::Multiplicities::default();
            for row in 0..if word_advice.is_none() { queries[0].len() } else { 0 } {
                let mut tuple = [0; 6];
                for (coordinate, column) in tuple.iter_mut().zip(queries) {
                    let v = column[row];
                    if v != F192::new(v.c0, 0, 0) {
                        return None;
                    }
                    *coordinate = v.c0;
                }
                let table = crate::word_tables::TABLES.into_iter().find(|&t| t as u64 == tuple[0])?;
                counts.add(table, &tuple)?;
            }
            let honest_counts: Vec<_> = counts.entries().collect();
            let counts = word_advice.map_or(honest_counts.as_slice(), |a| a.1);
            let evaluations = crate::word_lookup_reduction::prove(
                queries[0].len().trailing_zeros() as usize,
                queries,
                counts,
                &mut ps,
            )?;
            let gathered = crate::word_query_binding::prove(schedule, &stack, &evaluations, &mut ps)?;
            let low_log = self.stack_log - INITIAL_FOLDING_FACTOR;
            let weights = eq_table(&gathered.point[..low_log]);
            let mut openings = Vec::with_capacity(self.committed_lanes());
            for (lane, slice) in stack.chunks_exact(1 << low_log).enumerate() {
                let value = whir::inner_product_base_ext(slice, &weights);
                ps.add_scalar(value);
                openings.push(StackClaim::Point {
                    offset: lane << low_log,
                    low_point: gathered.point[..low_log].to_vec(),
                    value,
                });
            }
            Some(openings)
        } else {
            None
        };
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
        let blake_reduced = self.blake.as_ref().zip(blake_witness).map(|(b, (z, a, bb, stripes))| {
            blake::Blake2sSetup::new(b.io.len().max(128)).prove_reduction_precomputed(&z, &a, &bb, &stripes, &mut ps)
        });
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
        if let Some(openings) = word_claim {
            claims.extend(openings);
        }
        claims.extend(self.claims(&point, &bridge_values));
        if let Some(b) = &self.blake {
            let point = ps.sample_vec(b.block_log);
            let weights = eq_table(&point);
            let values: [F192; 18] = std::array::from_fn(|slot| {
                let offset = self.blake_connector_offset(slot, 0);
                let v = whir::inner_product_base_ext(&stack[offset..offset + weights.len()], &weights);
                ps.add_scalar(v);
                v
            });
            claims.extend(self.blake_claims(&point, &values));
        }
        let reduced = self.lift(reduced, 0);
        let blake_reduced = blake_reduced.map(|c| self.lift(c, 1usize << (self.q_log - 1)));
        let mut ring = ring_open(self.q_offset, &reduced);
        if let Some(c) = &blake_reduced {
            ring.claims.extend(ring_open(self.q_offset, c).claims);
        }
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
        let word_claim = if let Some(schedule) = &self.word_queries {
            let Some(evaluations) =
                crate::word_lookup_reduction::verify(schedule.columns[0].len().trailing_zeros() as usize, &mut vs)
            else {
                return false;
            };
            let Some(claim) = crate::word_query_binding::verify(schedule, &evaluations, &mut vs) else {
                return false;
            };
            let low_log = self.stack_log - INITIAL_FOLDING_FACTOR;
            let high_weights = eq_table(&claim.point[low_log..]);
            let mut sum = F192::ZERO;
            let mut openings = Vec::with_capacity(self.committed_lanes());
            for (lane, &weight) in high_weights.iter().take(self.committed_lanes()).enumerate() {
                let Ok(value) = vs.next_scalar() else {
                    return false;
                };
                sum += weight * value;
                openings.push(StackClaim::Point {
                    offset: lane << low_log,
                    low_point: claim.point[..low_log].to_vec(),
                    value,
                });
            }
            if sum != claim.value {
                return false;
            }
            Some(openings)
        } else {
            None
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
        let blake_reduced = if let Some(b) = &self.blake {
            let Ok(c) = blake::Blake2sSetup::new(b.io.len().max(128)).verify_reduction(&mut vs) else {
                return false;
            };
            Some(c.claim)
        } else {
            None
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
        if let Some(openings) = word_claim {
            claims.extend(openings);
        }
        claims.extend(self.claims(&point, &bridge_values));
        if let Some(b) = &self.blake {
            let point = vs.sample_vec(b.block_log);
            let mut values = [F192::ZERO; 18];
            for v in &mut values {
                let Ok(x) = vs.next_scalar() else {
                    return false;
                };
                *v = x;
            }
            claims.extend(self.blake_claims(&point, &values));
        }
        let reduced = self.lift(reduced, 0);
        let blake_reduced = blake_reduced.map(|c| self.lift(c, 1usize << (self.q_log - 1)));
        let mut ring = ring_verify(self.q_offset, &reduced);
        if let Some(c) = &blake_reduced {
            ring.claims.extend(ring_verify(self.q_offset, c).claims);
        }
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
    #[test]
    #[ignore = "full Falcon adversarial proofs"]
    fn falcon_word_verifier_rejections_without_prechecks() {
        parallel::init();
        let app = std::env::var("L3C_REJECTION_APP").unwrap_or_else(|_| "falcon".to_owned());
        let c = match app.as_str() {
            "falcon" => {
                let (original, _, _) = circuit_suite::build::<circuit_suite::falcon::Falcon512>();
                let identity = crate::application_lowering::identity(&original);
                crate::falcon_word::application(&circuit_suite::falcon::fixtures()[0], identity).0
            }
            "sha256" => {
                use circuit_suite::Workload;
                let (original, _, _) = circuit_suite::build::<circuit_suite::sha256::Sha256OneKiB>();
                let identity = crate::application_lowering::identity(&original);
                let instance = circuit_suite::sha256::Sha256OneKiB::instance(0);
                let message: Vec<u8> = instance
                    .inputs
                    .chunks_exact(8)
                    .map(|bits| bits.iter().enumerate().fold(0, |n, (i, &b)| n | (u8::from(b) << i)))
                    .collect();
                crate::sha256_word::application(&message, identity)
            }
            "shielded" => crate::shielded_word::application(&circuit_suite::shielded_blake2s::leanvm_input(0)),
            _ => panic!("unknown rejection application"),
        };
        let setup = c.setup().unwrap();
        let public = c.b.public_values();
        let context = primitives::hash::hash(b"falcon-word-adversarial");
        let witness = native_arithmetic::prepare_compact(&setup.index, &setup.extend_values(&c.b.values));
        let mut columns = setup
            .word_queries
            .as_ref()
            .unwrap()
            .query_columns(&witness.stack)
            .unwrap();
        drop(witness);
        let mut multiplicities = crate::word_tables::Multiplicities::default();
        for row in 0..columns[0].len() {
            let tuple = std::array::from_fn(|i| columns[i][row].c0);
            let table = crate::word_tables::TABLES
                .into_iter()
                .find(|&t| t as u64 == tuple[0])
                .unwrap();
            multiplicities.add(table, &tuple).unwrap();
        }
        let counts: Vec<_> = multiplicities.entries().collect();
        let add = columns[0].iter().position(|&v| v == F192::new(2, 0, 0)).unwrap();
        let mul = columns[0].iter().position(|&v| v == F192::new(3, 0, 0));
        for (name, row, coordinate, value) in [
            ("wrong carry", add, 3, F192::new(2, 0, 0)),
            ("wrong sum", add, 4, columns[4][add] + F192::ONE),
            (
                "wrong product",
                mul.unwrap_or(add),
                3,
                columns[3][mul.unwrap_or(add)] + F192::ONE,
            ),
            ("wrong tag", add, 0, F192::new(9, 0, 0)),
            ("out of range", add, 1, F192::new(256, 0, 0)),
        ] {
            let old_tuple: [F192; 6] = std::array::from_fn(|i| columns[i][row]);
            let mut injected_counts = None;
            if name == "wrong product" && mul.is_none() {
                let old: [u64; 6] = std::array::from_fn(|i| old_tuple[i].c0);
                let table = crate::word_tables::TABLES
                    .into_iter()
                    .find(|&t| t as u64 == old[0])
                    .unwrap();
                let old_index = table.offset() + table.index(&old).unwrap();
                let target = crate::word_tables::Table::Mul8.offset() + 255 + 256 * 255;
                let mut altered: std::collections::BTreeMap<usize, u64> = counts.iter().copied().collect();
                *altered.get_mut(&old_index).unwrap() -= 1;
                if altered[&old_index] == 0 {
                    altered.remove(&old_index);
                }
                *altered.entry(target).or_default() += 1;
                injected_counts = Some(altered.into_iter().collect::<Vec<_>>());
                let wrong = [3, 255, 255, 0, 254, 0];
                for i in 0..6 {
                    columns[i][row] = F192::new(wrong[i], 0, 0);
                }
            } else {
                columns[coordinate][row] = value;
            }
            let selected_counts = injected_counts.as_deref().unwrap_or(&counts);
            let proof = setup
                .prove_mixed_with_word_advice(
                    &c.b.values,
                    &c.b.permutations,
                    &c.b.compressions,
                    &context,
                    Some((&columns, selected_counts)),
                )
                .unwrap();
            assert!(!setup.verify(&public, &context, &proof), "{name}");
            for i in 0..6 {
                columns[i][row] = old_tuple[i];
            }
            println!("rejected: {name}");
        }
        let mut bad_counts = counts.clone();
        let from = bad_counts.iter().position(|(_, count)| *count > 1).unwrap();
        let to = if from == 0 { 1 } else { 0 };
        bad_counts[from].1 -= 1;
        bad_counts[to].1 += 1;
        let proof = setup
            .prove_mixed_with_word_advice(
                &c.b.values,
                &c.b.permutations,
                &c.b.compressions,
                &context,
                Some((&columns, &bad_counts)),
            )
            .unwrap();
        assert!(!setup.verify(&public, &context, &proof));
        println!("rejected: altered multiplicity");
        drop(columns);
        let mut wrong_output = c.b.values.clone();
        wrong_output[setup.io_variables[0][25]] += F192::ONE;
        let proof = setup
            .prove_mixed_unchecked(&wrong_output, &c.b.permutations, &c.b.compressions, &context)
            .unwrap();
        assert!(!setup.verify(&public, &context, &proof));
        println!("rejected: wrong Keccak output");
    }

    #[test]
    fn shared_word_queries_open_against_joint_keccak_commitment() {
        use crate::{
            native_hash::Builder,
            word_tables::{Multiplicities, Table},
        };
        use WordCoordinate::{Constant as C, Variable as V};
        let mut b = Builder::default();
        for value in [250, 10, 1, 5, 1] {
            let v = b.input(value);
            b.expose(v);
        }
        b.keccak_f([crate::native_hash::Word::ZERO; 25]);
        let query = [C(F192::new(2, 0, 0)), V(2), V(3), V(4), V(5), V(6)];
        let setup = b.setup_mixed().unwrap().with_word_queries(&[query; 2]).unwrap();
        let context = primitives::hash::hash(b"joint-word-binding");
        let public = b.public_values();
        let proof = setup.prove_mixed(&b.values, &b.permutations, &[], &context).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        let original = [2, 250, 10, 1, 5, 1];
        let columns: [Vec<F192>; 6] = std::array::from_fn(|i| vec![F192::new(original[i], 0, 0); 2]);
        let count = |tuple: &[u64; 6]| {
            let mut counts = Multiplicities::default();
            counts.add(Table::Add8, tuple).unwrap();
            counts.add(Table::Add8, tuple).unwrap();
            counts.entries().collect::<Vec<_>>()
        };
        let counts = count(&original);
        for (coordinate, value) in [(3, 2), (4, 6), (5, 0), (0, 9), (1, 256)] {
            let mut wrong = columns.clone();
            wrong[coordinate][0] = F192::new(value, 0, 0);
            let proof = setup
                .prove_mixed_with_word_advice(&b.values, &b.permutations, &[], &context, Some((&wrong, &counts)))
                .unwrap();
            assert!(!setup.verify(&public, &context, &proof), "coordinate {coordinate}");
        }
        let other = [2, 249, 10, 1, 4, 1];
        let wrong: [Vec<F192>; 6] = std::array::from_fn(|i| vec![F192::new(other[i], 0, 0); 2]);
        let other_counts = count(&other);
        for (columns, counts) in [(&wrong, &other_counts), (&columns, &other_counts)] {
            let proof = setup
                .prove_mixed_with_word_advice(&b.values, &b.permutations, &[], &context, Some((columns, counts)))
                .unwrap();
            assert!(
                !setup.verify(&public, &context, &proof),
                "binding or multiplicity forgery"
            );
        }
    }

    #[test]
    fn mixed_hash_kinds_share_opening_and_reject_bad_rows() {
        use crate::native_hash::Builder;
        parallel::init();
        let mut b = Builder::default();
        let input = std::array::from_fn(|i| b.constant((i + 1) as u64));
        let permuted = b.keccak_f(input);
        let digest = b.hash_words(&permuted[..4]);
        for word in digest {
            b.expose(word);
        }
        let public = b.public_values();
        let setup = b.setup_mixed().unwrap();
        let context = [91; 32];
        let proof = setup
            .prove_mixed(&b.values, &b.permutations, &b.compressions, &context)
            .unwrap();
        assert!(setup.verify(&public, &context, &proof), "honest mixed hash proof");
        let mut bad_keccak = b.permutations.clone();
        bad_keccak[0][0] ^= 1;
        let forged = setup
            .prove_mixed_unchecked(&b.values, &bad_keccak, &b.compressions, &context)
            .unwrap();
        assert!(!setup.verify(&public, &context, &forged), "Keccak input wiring changed");
        let mut bad_blake = b.compressions.clone();
        bad_blake[0].1[0] ^= 1;
        let forged = setup
            .prove_mixed_unchecked(&b.values, &b.permutations, &bad_blake, &context)
            .unwrap();
        assert!(!setup.verify(&public, &context, &forged), "BLAKE input wiring changed");
        let mut bad_public = public.clone();
        *bad_public.last_mut().unwrap() += F192::ONE;
        assert!(!setup.verify(&bad_public, &context, &proof));
        let mut bad_proof = proof;
        bad_proof.stream[0] += F192::ONE;
        assert!(!setup.verify(&public, &context, &bad_proof));
    }
}
