//! Joint native arithmetic/hash/lookup prototype. One witness root binds query
//! copy rows and multiplicity bits before every bus challenge.
use super::*;
use crate::{
    lookup_reduction,
    shielded_lookup::{self, QueryLayout},
    shielded_lookup_prototype::{self, Prepared},
};

pub struct LookupBridge {
    base: PrivateBridge,
    queries: QueryLayout,
    shape: lookup_reduction::Shape,
    tables: [Vec<F64>; 6],
    table_digest: Hash,
    fixed_public: Vec<F192>,
}
impl LookupBridge {
    pub fn new(payload: &[u8]) -> Option<Self> {
        let start=std::time::Instant::now();
        let prepared = shielded_lookup_prototype::prepare(payload);
        phase("witness",start);
        if !prepared.census.arithmetic_valid || !prepared.census.lookup_valid {
            return None;
        }
        let base = prepared.builder.setup()?;
        let mut fixed_public = prepared.builder.public_values();
        fixed_public.truncate(fixed_public.len().checked_sub(4)?);
        let tables = shielded_lookup::fixed_columns();
        let mut bytes = b"lookup-fixed-tables-v1".to_vec();
        for column in &tables {
            for word in column {
                bytes.extend_from_slice(&word.0.to_le_bytes());
            }
        }
        let table_digest = primitives::hash::hash(&bytes);
        let shape = lookup_reduction::Shape {
            table_log: 18,
            query_log: prepared.layout.log_queries,
            count_bits: 13,
        };
        shape.valid().then_some(Self {
            base,
            queries: prepared.layout,
            shape,
            tables,
            table_digest,
            fixed_public,
        })
    }
    fn layout(&self) -> (usize, usize, usize) {
        let origin = 1usize << self.shape.leaf_log();
        let end = origin + self.base.q_offset + (1usize << (K_LOG - LOG_PACKING + self.base.block_log));
        let log = end.next_power_of_two().trailing_zeros() as usize;
        let lane = 1usize << (log - INITIAL_FOLDING_FACTOR);
        (origin, log, end.div_ceil(lane))
    }
    pub fn committed_words(&self) -> usize {
        let (_, log, lanes) = self.layout();
        lanes * (1usize << (log - INITIAL_FOLDING_FACTOR))
    }
    pub fn arithmetic_rows_padded(&self) -> usize {
        1usize << self.base.index.log_rows
    }
    fn label(&self, public: &[F192], context: &Hash) -> Vec<u8> {
        let mut label = self.base.label(public, context);
        label.extend_from_slice(b"joint-lookup-v1");
        label.extend_from_slice(&self.table_digest);
        let (origin, log, lanes) = self.layout();
        for value in [
            self.queries.start,
            self.queries.log_queries,
            self.queries.actual_queries,
            self.shape.table_log,
            self.shape.count_bits,
            origin,
            log,
            lanes,
        ] {
            label.extend_from_slice(&(value as u64).to_le_bytes());
        }
        label
    }
    fn public(&self, digest: &Hash) -> Vec<F192> {
        let mut public = self.fixed_public.clone();
        public.extend(
            digest
                .chunks(8)
                .map(|b| F192::new(u64::from_le_bytes(b.try_into().unwrap()), 0, 0)),
        );
        public
    }
    pub fn prove(&self, payload: &[u8], context: &Hash) -> Option<Proof> {
        let prepared = shielded_lookup_prototype::prepare(payload);
        if !prepared.census.arithmetic_valid || !prepared.census.lookup_valid {
            return None;
        }
        self.prove_prepared(prepared, context, None)
    }
    fn prove_prepared(&self, prepared: Prepared, context: &Hash, override_counts: Option<&[u64]>) -> Option<Proof> {
        if prepared.layout != self.queries {
            return None;
        }
        let public = prepared.builder.public_values();
        if public.len() != self.fixed_public.len() + 4 || public[..self.fixed_public.len()] != self.fixed_public {
            return None;
        }
        let full = self.base.public(&public)?;
        let start=std::time::Instant::now();
        let bits = lookup_reduction::bit_witness(&self.shape, override_counts.unwrap_or(&prepared.multiplicities))?;
        let extended = self.base.extend_values(&prepared.builder.values);
        let mut witness = native_arithmetic::prepare_compact_with_capacity(
            &self.base.index,
            &extended,
            self.base.committed_lanes() * (1usize << (self.base.stack_log - INITIAL_FOLDING_FACTOR)),
        );
        let (z, a, b, lincheck) =
            generate_witness_with_ab_packed_and_lincheck(&prepared.builder.compressions, self.base.block_log);
        phase("hash_witness",start);
        let start=std::time::Instant::now();
        let (origin, stack_log, lanes) = self.layout();
        let mut stack = vec![F64::ZERO; self.committed_words()];
        stack[..bits.len()].copy_from_slice(&bits);
        let native = std::mem::take(&mut witness.stack);
        stack[origin..origin + native.len()].copy_from_slice(&native);
        drop(native);
        for (dest, &word) in stack[origin + self.base.q_offset..].iter_mut().zip(&z) {
            *dest = F64(word);
        }
        phase("stack_assembly",start);
        let start=std::time::Instant::now();
        let (commitment, data) = whir::commit(&stack, stack_log, INITIAL_FOLDING_FACTOR, JOINT_LOG_INV_RATE);
        phase("joint_commitment",start);
        let start=std::time::Instant::now();
        let mut ps = ProverState::from_label(&self.label(&full, context));
        ps.add_root(&commitment.root);
        let (native_claims, index_claims) =
            native_arithmetic::prove_reduction_compact(&self.base.index, &witness, &stack[origin..], &mut ps);
        drop(witness);
        phase("arithmetic_reduction",start);
        let start=std::time::Instant::now();
        let reduced = Blake2sSetup::new(self.base.n_blocks.max(MIN_BLOCKS))
            .prove_reduction_precomputed(&z, &a, &b, &lincheck, &mut ps);
        drop((z, a, b, lincheck));
        phase("hash_reduction",start);
        let start=std::time::Instant::now();
        let point = ps.sample_vec(self.base.block_log);
        let weights = eq_table(&point);
        let mut bridge_values = [F192::ZERO; 18];
        for (slot, value) in bridge_values.iter_mut().enumerate() {
            let offset = origin + self.base.connector_offset(slot, 0);
            *value = whir::inner_product_base_ext(&stack[offset..offset + weights.len()], &weights);
            ps.add_scalar(*value);
        }
        let mut claims: Vec<_> = native_claims
            .into_iter()
            .map(|c| StackClaim::Point {
                offset: origin + self.base.compact_native_offset(c.offset, c.point.len()),
                low_point: c.point,
                value: c.value,
            })
            .collect();
        claims.extend(
            self.base
                .claims(&point, &bridge_values)
                .into_iter()
                .map(|c| shift(c, origin)),
        );
        let query_columns: Vec<_> = prepared.queries.into_iter().collect();
        phase("bridge_and_query_preparation",start);
        let start=std::time::Instant::now();
        let lookup = lookup_reduction::prove(&self.shape, &self.tables, &query_columns, &bits, &mut ps)?;
        phase("lookup_bus",start);
        let start=std::time::Instant::now();
        self.prove_query_claims(origin, &stack, &lookup.queries, &mut ps, &mut claims)?;
        claims.extend(lookup.multiplicities.into_iter().map(|c| StackClaim::Point {
            offset: 0,
            low_point: c.point,
            value: c.value,
        }));
        let mut ring = ring_switch_open(1 << self.base.block_log, origin + self.base.q_offset, &reduced);
        ring.offset = origin + self.base.q_offset;
        let config = whir::config_for_rate(stack_log, JOINT_LOG_INV_RATE).ok()?;
        phase("query_opening_preparation",start);
        let start=std::time::Instant::now();
        open_batch_mixed_whir_stacked(&mut ps, stack_log, &stack, &data, &config, &claims, &ring);
        phase("joint_opening",start);
        let start=std::time::Instant::now();
        native_arithmetic::prove_index_open(&self.base.index, &index_claims, &mut ps);
        phase("index_opening",start);
        debug_assert_eq!(
            lanes,
            self.committed_words() / (1usize << (stack_log - INITIAL_FOLDING_FACTOR))
        );
        Some(ps.into_proof())
    }
    fn prove_query_claims(
        &self,
        origin: usize,
        stack: &[F64],
        queries: &[lookup_reduction::Evaluation],
        ps: &mut ProverState,
        claims: &mut Vec<StackClaim>,
    ) -> Option<()> {
        if queries.len() != 6 {
            return None;
        }
        for (coordinate, query) in queries.iter().enumerate() {
            let weights = eq_table(&query.point);
            let mut reconstructed = F192::ZERO;
            for limb in 0..3 {
                let offset = origin
                    + self
                        .queries
                        .coordinate_offset(self.base.index.log_rows, coordinate, limb)?;
                let value = whir::inner_product_base_ext(&stack[offset..offset + weights.len()], &weights);
                ps.add_scalar(value);
                reconstructed += value * basis(limb);
                claims.push(StackClaim::Point {
                    offset,
                    low_point: query.point.clone(),
                    value,
                });
            }
            if reconstructed != query.value {
                return None;
            }
        }
        Some(())
    }
    pub fn verify(&self, digest: &Hash, context: &Hash, proof: &Proof) -> bool {
        self.verify_inner(digest, context, proof).unwrap_or(false)
    }
    fn verify_inner(&self, digest: &Hash, context: &Hash, proof: &Proof) -> Option<bool> {
        let public = self.base.public(&self.public(digest))?;
        let mut vs = VerifierState::from_label(&self.label(&public, context), proof);
        let root = vs.next_root().ok()?;
        let (origin, stack_log, lanes) = self.layout();
        let (native_claims, index_claims) = native_arithmetic::verify_reduction(&self.base.index, &public, &mut vs)?;
        let reduced = Blake2sSetup::new(self.base.n_blocks.max(MIN_BLOCKS))
            .verify_reduction(&mut vs)
            .ok()?;
        let point = vs.sample_vec(self.base.block_log);
        let mut bridge_values = [F192::ZERO; 18];
        for value in &mut bridge_values {
            *value = vs.next_scalar().ok()?;
        }
        let mut claims: Vec<_> = native_claims
            .into_iter()
            .map(|c| StackClaim::Point {
                offset: origin + self.base.compact_native_offset(c.offset, c.point.len()),
                low_point: c.point,
                value: c.value,
            })
            .collect();
        claims.extend(
            self.base
                .claims(&point, &bridge_values)
                .into_iter()
                .map(|c| shift(c, origin)),
        );
        let lookup = lookup_reduction::verify(&self.shape, &self.tables, &mut vs)?;
        for (coordinate, query) in lookup.queries.into_iter().enumerate() {
            let mut reconstructed = F192::ZERO;
            for limb in 0..3 {
                let value = vs.next_scalar().ok()?;
                let offset = origin
                    + self
                        .queries
                        .coordinate_offset(self.base.index.log_rows, coordinate, limb)?;
                reconstructed += value * basis(limb);
                claims.push(StackClaim::Point {
                    offset,
                    low_point: query.point.clone(),
                    value,
                });
            }
            if reconstructed != query.value {
                return None;
            }
        }
        claims.extend(lookup.multiplicities.into_iter().map(|c| StackClaim::Point {
            offset: 0,
            low_point: c.point,
            value: c.value,
        }));
        let ring = ring_switch_verify(1 << self.base.block_log, origin + self.base.q_offset, &reduced.claim);
        let config = whir::config_for_rate(stack_log, JOINT_LOG_INV_RATE).ok()?;
        Some(
            verify_opening_batch_mixed_whir_stacked(&mut vs, &config, stack_log, lanes, &root, &claims, &ring).is_ok()
                && native_arithmetic::verify_index_open(&self.base.index, &index_claims, &mut vs)
                && vs.finish().is_ok(),
        )
    }
}
fn basis(limb: usize) -> F192 {
    match limb {
        0 => F192::ONE,
        1 => F192::new(0, 1, 0),
        2 => F192::new(0, 0, 1),
        _ => unreachable!(),
    }
}
fn shift(claim: StackClaim, origin: usize) -> StackClaim {
    match claim {
        StackClaim::Point {
            offset,
            low_point,
            value,
        } => StackClaim::Point {
            offset: offset + origin,
            low_point,
            value,
        },
        StackClaim::Strided {
            offset,
            slot,
            stride_log,
            point,
            value,
        } => StackClaim::Strided {
            offset: offset + origin,
            slot,
            stride_log,
            point,
            value,
        },
    }
}

fn phase(name:&str,start:std::time::Instant) {if std::env::var_os("LOOKUP_PROFILE").is_some() {eprintln!("{}",serde_json::json!({"phase":name,"elapsed_s":start.elapsed().as_secs_f64()}));}}
