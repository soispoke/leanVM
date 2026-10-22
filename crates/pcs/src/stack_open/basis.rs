use std::mem::MaybeUninit;

use primitives::field::{F64, F192};
use primitives::multilinear::fill_eq_table_uninit;

use super::{RingSwitchOpen, StackClaim};
use crate::ring_switch::{DeferredRingSwitchOutput, combine_deferred_chunk};
use crate::whir::{
    HybridWeight, INITIAL_BASIS_CHUNK, PartialLaneWeight, SumcheckMessage, build_eq_table_ext, build_initial_basis,
};

pub(super) fn hybrid(
    stack: &[F64],
    lane_block: usize,
    claims: &[StackClaim],
    lambdas: &[F192],
    ring: &RingSwitchOpen,
    rs_outputs: &[DeferredRingSwitchOutput],
) -> Option<HybridWeight> {
    let ring_end = ring.offset + (1 << ring.qflock_vars);
    if claims.iter().any(|c| {
        matches!(c, StackClaim::Strided { .. })
            && (super::claim_range(c).0 < ring.offset || super::claim_range(c).1 > ring_end)
    }) {
        return None;
    }
    assert_eq!(claims.len(), lambdas.len());
    let block_log = lane_block.ilog2() as usize;
    let n_lanes = stack.len() / lane_block;
    let mut groups: Vec<(Vec<F192>, usize, Vec<F192>)> = Vec::new();
    let mut dense_claims = Vec::new();
    let mut dense_lambdas = Vec::new();
    let dense_start = ring.offset / lane_block * lane_block;
    let dense_end = ring_end.next_multiple_of(lane_block);
    for (claim, &lambda) in claims.iter().zip(lambdas) {
        match claim {
            StackClaim::Point { offset, low_point, .. } => {
                assert!(offset.is_multiple_of(1 << low_point.len()));
                let (low, high) = low_point.split_at(low_point.len().min(block_log));
                let within = offset % lane_block;
                let index = groups.iter().position(|(p, o, _)| p == low && *o == within);
                let index = index.unwrap_or_else(|| {
                    groups.push((low.to_vec(), within, vec![F192::ZERO; n_lanes]));
                    groups.len() - 1
                });
                let lanes = &mut groups[index].2;
                let first = offset / lane_block;
                for (i, value) in build_eq_table_ext(high).into_iter().enumerate() {
                    lanes[first + i] += lambda * value;
                }
            }
            StackClaim::Strided {
                offset,
                slot,
                stride_log,
                point,
                value,
            } => {
                dense_claims.push(StackClaim::Strided {
                    offset: offset - dense_start,
                    slot: *slot,
                    stride_log: *stride_log,
                    point: point.clone(),
                    value: *value,
                });
                dense_lambdas.push(lambda);
            }
        }
    }
    let local_ring = RingSwitchOpen {
        offset: ring.offset - dense_start,
        qflock_vars: ring.qflock_vars,
        claims: Vec::new(),
    };
    let (dense, _) = build(
        &stack[dense_start..dense_end],
        lane_block,
        &dense_claims,
        &dense_lambdas,
        &local_ring,
        rs_outputs,
    );
    let points = groups
        .into_iter()
        .map(|(point, offset, lanes)| {
            let block = primitives::multilinear::eq_table(&point);
            PartialLaneWeight { lanes, offset, block }
        })
        .collect();
    Some(HybridWeight {
        offset: dense_start,
        dense,
        points,
    })
}

struct PointWeight<'a> {
    offset: usize,
    end: usize,
    slot: usize,
    stride: usize,
    low: &'a [F192],
    high: Vec<F192>,
}

impl<'a> PointWeight<'a> {
    fn new(claim: &'a StackClaim, lambda: F192, chunk_log: usize) -> Self {
        let (offset, slot, stride_log, point) = match claim {
            StackClaim::Point { offset, low_point, .. } => (*offset, 0, 0, low_point.as_slice()),
            StackClaim::Strided {
                offset,
                slot,
                stride_log,
                point,
                ..
            } => (*offset, *slot, *stride_log, point.as_slice()),
        };
        let len = 1usize << (stride_log + point.len());
        let stride = 1usize << stride_log;
        assert!(offset.is_multiple_of(len), "claim must be aligned to its support");
        assert!(slot < stride, "claim slot must fit the stride");
        let low_vars = point.len().min(chunk_log.saturating_sub(stride_log));
        let (low, high_point) = point.split_at(low_vars);
        let mut high = Box::new_uninit_slice(1 << high_point.len()).into_vec();
        fill_eq_table_uninit(high_point, lambda, &mut high);
        // SAFETY: the seeded equality build initializes the whole table.
        let high = unsafe { high.into_boxed_slice().assume_init() }.into_vec();
        Self {
            offset,
            end: offset + len,
            slot,
            stride,
            low,
            high,
        }
    }

    fn add(&self, start: usize, dst: &mut [F192], scratch: &mut [MaybeUninit<F192>]) {
        let base = self.offset + self.slot;
        let lo = start.max(base);
        let hi = (start + dst.len()).min(self.end);
        if lo >= hi {
            return;
        }
        let first = (lo - base).div_ceil(self.stride);
        let end = (hi - base).div_ceil(self.stride);
        if first == end {
            return;
        }
        let len = 1usize << self.low.len();
        assert!(first.is_multiple_of(len) && end - first == len);
        fill_eq_table_uninit(self.low, self.high[first / len], &mut scratch[..len]);
        // SAFETY: the build above initializes this prefix before the scatter reads it.
        let eq = unsafe { std::slice::from_raw_parts(scratch.as_ptr().cast::<F192>(), len) };
        let dst_offset = base + first * self.stride - start;
        for (i, &value) in eq.iter().enumerate() {
            dst[dst_offset + i * self.stride] += value;
        }
    }
}

pub(super) fn build(
    stack: &[F64],
    lane_block: usize,
    claims: &[StackClaim],
    lambdas: &[F192],
    ring: &RingSwitchOpen,
    rs_outputs: &[DeferredRingSwitchOutput],
) -> (Vec<F192>, SumcheckMessage) {
    assert_eq!(claims.len(), lambdas.len());
    let chunk_log = lane_block.min(INITIAL_BASIS_CHUNK).ilog2() as usize;
    let weights: Vec<_> = claims
        .iter()
        .zip(lambdas)
        .map(|(claim, &lambda)| PointWeight::new(claim, lambda, chunk_log))
        .collect();
    let mut by_lane = vec![Vec::new(); stack.len() / lane_block];
    for (index, weight) in weights.iter().enumerate() {
        for lane in &mut by_lane[weight.offset / lane_block..weight.end.div_ceil(lane_block)] {
            lane.push(index);
        }
    }
    let ring_end = ring.offset + (1 << ring.qflock_vars);
    build_initial_basis(stack, lane_block, |start, dst| {
        dst.fill(F192::ZERO);
        let lo = start.max(ring.offset);
        let hi = (start + dst.len()).min(ring_end);
        if lo < hi {
            combine_deferred_chunk(rs_outputs, lo - ring.offset, &mut dst[lo - start..hi - start]);
        }
        let mut scratch = [MaybeUninit::uninit(); INITIAL_BASIS_CHUNK];
        for &index in &by_lane[start / lane_block] {
            weights[index].add(start, dst, &mut scratch);
        }
    })
}
