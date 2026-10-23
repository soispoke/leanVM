//! Symbolic verifier of the private arithmetic/BLAKE2s bridge.
//! Hash I/O stays in the committed witness and is linked at a shared random
//! point; the recorder checks both arguments and their joint PCS opening.
use crate::{
    flock_trace,
    native_verifier::{self, Claim},
    private_bridge::{JOINT_LOG_INV_RATE, PrivateBridge, PrivateShape},
    trace::{self, S, Trace, digest_constant, hash},
    verifier::{Transcript, eq, powers, verify_basis_opening_lanes_rate},
};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use flock::hash::{K_LOG, R1CS_DIGEST};
use pcs::pack::LOG_PACKING;
use primitives::field::F192;

const SLOTS: [usize; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
fn literal(bytes: &[u8]) -> Vec<(S, usize)> {
    bytes
        .chunks(24)
        .map(|c| {
            let mut b = [0; 24];
            b[..c.len()].copy_from_slice(c);
            let limb = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
            (S::c(F192::new(limb(0), limb(8), limb(16))), c.len())
        })
        .collect()
}
fn selector(offset: usize, low_log: usize, at: &[S]) -> S {
    let index = offset >> low_log;
    at[low_log..].iter().enumerate().fold(S::u(1), |e, (i, &x)| {
        e * if index >> i & 1 == 1 { x } else { S::u(1) + x }
    })
}
fn claim_eval(claim: &Claim, at: &[S]) -> S {
    eq(&claim.point, &at[..claim.point.len()]) * selector(claim.offset, claim.point.len(), at)
}
/// Complete private bridge label, with the child verification key supplied as
/// symbolic digest words. Circuit dimensions remain fixed by trusted metadata.
pub(crate) fn label(bridge: &PrivateBridge, index_root: [S; 2], context: [S; 2], public: &[S]) -> Vec<(S, usize)> {
    label_shape(bridge.verifier_shape(), index_root, context, public)
}

pub(crate) fn label_shape(bridge: PrivateShape, index_root: [S; 2], context: [S; 2], public: &[S]) -> Vec<(S, usize)> {
    let mut label = literal(b"format-private-bridge-v5");
    label.extend(index_root.map(|x| (x, 16)));
    label.extend(context.map(|x| (x, 16)));
    label.extend(digest_constant(&R1CS_DIGEST).map(|x| (x, 16)));
    label.extend(
        [
            bridge.index.log_rows,
            bridge.index.public_log,
            bridge.n_blocks,
            bridge.block_log,
            bridge.connector_start,
            bridge.q_offset,
            bridge.stack_log,
            JOINT_LOG_INV_RATE,
            bridge.index.index_log_inv_rate,
            public.len(),
        ]
        .map(|n| (S::u(n as u64), 8)),
    );
    label.extend(public.iter().map(|&x| (x, 24)));
    label
}
/// Append complete verification equations to an active trace. `public` includes
/// the bridge's pinned padding words. The caller seeds and finishes `t`.
pub(crate) fn verify(bridge: &PrivateBridge, index_root: [S; 2], public: &[S], t: &mut Transcript<'_>) {
    verify_shape(bridge.verifier_shape(), index_root, public, t);
}

pub(crate) fn verify_shape(bridge: PrivateShape, index_root: [S; 2], public: &[S], t: &mut Transcript<'_>) {
    trace::mark("private-arithmetic-reduction");
    let root = t.root();
    let (mut claims, index_claims) = native_verifier::reduce_shape(bridge.index, public, t);
    for claim in &mut claims {
        claim.offset = bridge.compact_native_offset(claim.offset, claim.point.len());
    }
    trace::mark("private-flock-reduction");
    let flock = flock_trace::reduce(K_LOG + bridge.block_log, t);
    let point: Vec<_> = (0..bridge.block_log).map(|_| t.sample()).collect();
    let values: [S; 18] = std::array::from_fn(|_| t.next());
    let stride = K_LOG - LOG_PACKING;
    for (slot, &value) in values.iter().enumerate() {
        for limb in 0..3 {
            claims.push(Claim {
                offset: bridge.connector_offset(slot, limb),
                point: point.clone(),
                value: if limb == 0 { value } else { S::u(0) },
            });
        }
        let mut strided_point: Vec<_> = (0..stride).map(|i| S::u(((SLOTS[slot] >> i) & 1) as u64)).collect();
        strided_point.extend_from_slice(&point);
        claims.push(Claim {
            offset: bridge.q_offset,
            point: strided_point,
            value,
        });
    }
    trace::mark("private-joint-opening");
    let map: [S; 6] = std::array::from_fn(|_| t.sample());
    let lambda = t.sample();
    let weights = powers(lambda, 1 + claims.len());
    let target = claims
        .iter()
        .zip(&weights[1..])
        .fold(flock_trace::ring_target(&flock.s_hat_v, &map), |v, (claim, &weight)| {
            v + weight * claim.value
        });
    let qlog = stride + bridge.block_log;
    assert_eq!(flock.suffix_point.len(), qlog);
    verify_basis_opening_lanes_rate(
        t,
        bridge.stack_log,
        JOINT_LOG_INV_RATE,
        bridge.committed_lanes(),
        root,
        target,
        |at| {
            let ring =
                selector(bridge.q_offset, qlog, at) * flock_trace::ring_weight(&flock.suffix_point, &at[..qlog], &map);
            claims
                .iter()
                .zip(&weights[1..])
                .fold(ring, |sum, (claim, &weight)| sum + weight * claim_eval(claim, at))
        },
    );
    trace::mark("private-index-opening");
    native_verifier::opening_rate(
        t,
        index_root,
        bridge.index.log_rows + 2,
        bridge.index.index_log_inv_rate,
        &index_claims,
    );
}
fn record_impl(
    bridge: &PrivateBridge,
    public: &[F192],
    context: &Hash,
    index_root: &Hash,
    proof: &Proof,
    dynamic: bool,
) -> Trace {
    let full = bridge.public(public).expect("valid bridge public anchors and length");
    trace::start();
    let values: Vec<_> = full
        .iter()
        .enumerate()
        .map(|(i, &x)| if i < public.len() { S::input(x) } else { S::c(x) })
        .collect();
    let context = hash_to_scalars(context).map(S::input);
    let index_root = hash_to_scalars(index_root).map(|x| if dynamic { S::input(x) } else { S::c(x) });
    for x in context.into_iter().chain(index_root) {
        x.assert_eq(x.slice(0, 128));
    }
    let output = hash(&label(bridge, index_root, context, &values));
    let mut t = Transcript::from_state(proof, output);
    verify(bridge, index_root, &values, &mut t);
    t.finish();
    let mut trace = trace::take();
    trace.public = output.to_vec();
    trace
}
/// First-level two-proof aggregation under a fixed bridge key and context.
/// Constants/public anchors are fixed by setup; each child's last four public
/// values are its 64-bit application digest words. Both full verifiers run.
pub fn record_application_pair(
    bridge: &PrivateBridge,
    public: [&[F192]; 2],
    context: &Hash,
    proofs: [&Proof; 2],
) -> Option<Trace> {
    if public[0].len() < 6 || public[0].len() != public[1].len() {
        return None;
    }
    let fixed = public[0].len() - 4;
    if public[0][..fixed] != public[1][..fixed] {
        return None;
    }
    trace::start();
    let root = digest_constant(&bridge.index.root);
    let ctx = digest_constant(context);
    let mut outputs = Vec::new();
    for child in 0..2 {
        let full = bridge.public(public[child])?;
        let values: Vec<_> = full
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                if (fixed..public[child].len()).contains(&i) {
                    let x = S::input(v);
                    x.assert_eq(x.slice(0, 64));
                    outputs.push((x, 8));
                    x
                } else {
                    S::c(v)
                }
            })
            .collect();
        let seed = hash(&label(bridge, root, ctx, &values));
        let mut t = Transcript::from_state(proofs[child], seed);
        verify(bridge, root, &values, &mut t);
        t.finish();
    }
    let mut parts = vec![(S::u(0x4e), 1)];
    parts.extend(outputs);
    let out = hash(&parts);
    let mut result = trace::take();
    result.public = out.to_vec();
    Some(result)
}

/// Record against a fixed trusted child index, binding full public data/context.
pub fn record(bridge: &PrivateBridge, public: &[F192], context: &Hash, proof: &Proof) -> Trace {
    record_impl(bridge, public, context, &bridge.index.root, proof, false)
}
/// Record a verifier with the child index root as an input. The returned public
/// claim commits to that root; callers must bind it to their permitted child key.
/// This API alone does not authorize arbitrary child circuits for recursion.
pub fn record_with_index_root(
    bridge: &PrivateBridge,
    public: &[F192],
    context: &Hash,
    index_root: &Hash,
    proof: &Proof,
) -> Trace {
    record_impl(bridge, public, context, index_root, proof, true)
}

#[cfg(all(test, not(feature = "keccak-protocol")))]
mod tests {
    use super::*;
    use crate::{native_arithmetic::Circuit, private_bridge::io_words};
    use flock::hash::{blake2s_compress, param_iv};

    #[test]
    fn private_argument_records_complete_verifier_and_binds_key_public_context() {
        parallel::init();
        let block = (param_iv(), std::array::from_fn(|i| 37 + i as u32), 64, u32::MAX, 0);
        let output = blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
        let mut values = vec![F192::ZERO, F192::ONE];
        values.extend(io_words(&block, &output).map(|x| F192::new(x, 0, 0)));
        let bridge = PrivateBridge::new(
            Circuit {
                variables: values.len(),
                rows: vec![],
                public: (0..values.len()).collect(),
            },
            vec![std::array::from_fn(|i| i + 2)],
        )
        .unwrap();
        let context = [71; 32];
        let proof = bridge.prove(&values, &[block], &context).unwrap();
        assert!(bridge.verify(&values, &context, &proof));
        let good = record(&bridge, &values, &context, &proof);
        assert!(good.satisfied());
        let expected = hash_to_scalars(&primitives::protocol_hash::hash(
            &bridge.label(&bridge.public(&values).unwrap(), &context),
        ));
        assert_eq!(
            good.public.iter().map(|s| good.nodes[s.0].value).collect::<Vec<_>>(),
            expected
        );
        assert!(good.hash_compressions() > 0);
        let dynamic = record_with_index_root(&bridge, &values, &context, &bridge.index.root, &proof);
        assert!(dynamic.satisfied());
        let second_proof = bridge.prove(&values, &[block], &[72; 32]).unwrap();
        let second = record_with_index_root(&bridge, &values, &[72; 32], &bridge.index.root, &second_proof);
        assert!(second.satisfied());
        assert!(
            dynamic.same_program(&second),
            "child proof contents must not change the verifier program"
        );
        eprintln!(
            "private verifier nodes={} hashes={} public={}",
            dynamic.nodes.len(),
            dynamic.hash_compressions(),
            dynamic.public.len()
        );
        assert_eq!(
            dynamic
                .public
                .iter()
                .map(|s| dynamic.nodes[s.0].value)
                .collect::<Vec<_>>(),
            expected
        );
        let accepts = |public: &[F192], context: &Hash, root: &Hash, proof: &Proof| {
            std::panic::catch_unwind(|| record_with_index_root(&bridge, public, context, root, proof))
                .is_ok_and(|t| t.satisfied())
        };
        let mut wrong = values.clone();
        wrong[7] += F192::ONE;
        assert!(!accepts(&wrong, &context, &bridge.index.root, &proof));
        assert!(!accepts(&values, &[72; 32], &bridge.index.root, &proof));
        let mut root = bridge.index.root;
        root[0] ^= 1;
        assert!(!accepts(&values, &context, &root, &proof));
        let mut bad = proof.clone();
        *bad.stream.last_mut().unwrap() += F192::ONE;
        assert!(!accepts(&values, &context, &bridge.index.root, &bad));
        let mut bad = proof.clone();
        bad.stream.push(F192::ZERO);
        assert!(!accepts(&values, &context, &bridge.index.root, &bad));
        let mut bad = proof.clone();
        bad.merkle[0].sibling_hashes[0][0] ^= 1;
        assert!(!accepts(&values, &context, &bridge.index.root, &bad));
    }
}
