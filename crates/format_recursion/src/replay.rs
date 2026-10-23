//! Transparent arithmetic replay around the experimental hash coprocessor.
//! Values are disclosed and all non-hash operations run natively. This is not
//! a succinct recursive proof or a replacement for proving the main circuit.

use crate::{
    hash_batch::{self, BatchProof, Request},
    trace::{Op, S, Trace},
};
use fiat_shamir::merkle::{Hash, scalars_to_hash};
use primitives::field::F192;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub values: Vec<F192>,
    pub hashes: BatchProof,
}

fn scalar_bytes(x: F192) -> [u8; 24] {
    let mut out = [0u8; 24];
    for (part, word) in out.as_chunks_mut::<8>().0.iter_mut().zip([x.c0, x.c1, x.c2]) {
        part.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn slice(value: F192, offset: usize, len: usize) -> Option<F192> {
    if offset.checked_add(len)? > 192 {
        return None;
    }
    let bytes = scalar_bytes(value);
    let mut out = [0u64; 3];
    for i in 0..len {
        out[i / 64] |= u64::from((bytes[(offset + i) / 8] >> ((offset + i) % 8)) & 1) << (i % 64);
    }
    Some(F192::new(out[0], out[1], out[2]))
}

/// Replay against a trusted fixed program, never against a prover-supplied trace.
/// Hash outputs become public requests and must subsequently pass `hash_batch::verify`.
pub fn requests(program: &Trace, values: &[F192], expected_public: &[F192]) -> Option<Vec<Request>> {
    if values.len() != program.nodes.len() || expected_public.len() != program.public.len() {
        return None;
    }
    let mut requests = Vec::new();
    for (i, node) in program.nodes.iter().enumerate() {
        let get = |s: S| (s.0 < i).then(|| values[s.0]);
        let expected = match &node.op {
            Op::Constant => node.value,
            Op::Input => continue,
            Op::Add(a, b) => get(*a)? + get(*b)?,
            Op::Mul(a, b) => get(*a)? * get(*b)?,
            Op::Frobenius(a) => get(*a)?.frobenius(),
            Op::Slice(a, start, len) => slice(get(*a)?, *start, *len)?,
            Op::Pack(parts) => {
                let mut output = [0u64; 3];
                let mut offset = 0usize;
                for (s, len) in parts {
                    if offset.checked_add(*len)? > 192 {
                        return None;
                    }
                    let bytes = scalar_bytes(get(*s)?);
                    for bit in 0..*len {
                        output[(offset + bit) / 64] |=
                            u64::from((bytes[bit / 8] >> (bit % 8)) & 1) << ((offset + bit) % 64);
                    }
                    offset += len;
                }
                F192::new(output[0], output[1], output[2])
            }
            Op::Select(bit, a, b) => match get(*bit)? {
                F192::ZERO => get(*a)?,
                F192::ONE => get(*b)?,
                _ => return None,
            },
            Op::Hash(parts) => {
                // The recorder emits exactly one adjacent high half per call.
                if program.nodes.get(i + 1)?.op != Op::HashHigh(S(i)) {
                    return None;
                }
                let digest = scalars_to_hash(&[values[i], *values.get(i + 1)?]).ok()?;
                let mut message = Vec::new();
                for &(s, len) in parts {
                    if len > 24 {
                        return None;
                    }
                    message.extend_from_slice(&scalar_bytes(get(s)?)[..len]);
                }
                requests.push(Request { message, digest });
                continue;
            }
            Op::HashHigh(a) => {
                if a.0.checked_add(1)? != i || !matches!(program.nodes.get(a.0)?.op, Op::Hash(_)) {
                    return None;
                }
                continue;
            }
        };
        if values[i] != expected {
            return None;
        }
    }
    for &(a, b) in &program.checks {
        if values.get(a.0)? != values.get(b.0)? {
            return None;
        }
    }
    for (s, expected) in program.public.iter().zip(expected_public) {
        if values.get(s.0)? != expected {
            return None;
        }
    }
    Some(requests)
}

/// Context pins the trusted program and public output, independent of witness values.
pub fn context(program: &Trace, expected_public: &[F192]) -> Hash {
    let mut bytes = b"format-recursion-transparent-replay-v1".to_vec();
    // This encoding is deliberately local to the experiment, not a registration format.
    for node in &program.nodes {
        let op = format!("{:?}", node.op);
        bytes.extend_from_slice(&(op.len() as u64).to_le_bytes());
        bytes.extend_from_slice(op.as_bytes());
        if matches!(node.op, Op::Constant) {
            bytes.extend_from_slice(&scalar_bytes(node.value));
        }
    }
    bytes.extend_from_slice(format!("{:?}{:?}", program.checks, program.public).as_bytes());
    bytes.extend_from_slice(&(expected_public.len() as u64).to_le_bytes());
    for &value in expected_public {
        bytes.extend_from_slice(&scalar_bytes(value));
    }
    primitives::protocol_hash::hash(&bytes)
}

pub fn prove(program: &Trace, values: Vec<F192>, expected_public: &[F192]) -> Option<Certificate> {
    let requests = requests(program, &values, expected_public)?;
    let hashes = hash_batch::prove(&context(program, expected_public), &requests)?;
    Some(Certificate { values, hashes })
}

pub fn verify(program: &Trace, expected_public: &[F192], proof: &Certificate) -> bool {
    let Some(requests) = requests(program, &proof.values, expected_public) else {
        return false;
    };
    hash_batch::verify(&context(program, expected_public), &requests, &proof.hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{self, hash};

    #[test]
    fn replay_checks_every_arithmetic_kind_and_public_output() {
        trace::start();
        let x = S::input(F192::new(19, 3, 17));
        let y = S::input(F192::new(7, 9, 13));
        let p = x * y;
        let _ = p + x;
        let _ = <S as flock::membership::Scalar>::frobenius(p);
        let bit = x.slice(0, 1);
        let _ = S::select(bit, x, y);
        let _ = S::pack(&[(x, 64), (y, 128)]);
        p.assert_eq(S::c(p.value()));
        let h = hash(&[(p, 24)]);
        let mut program = trace::take();
        program.public = h.to_vec();
        let values: Vec<_> = program.nodes.iter().map(|n| n.value).collect();
        let public: Vec<_> = program.public.iter().map(|s| values[s.0]).collect();
        assert_eq!(requests(&program, &values, &public).unwrap().len(), 1);
        for i in 0..values.len() {
            let mut bad = values.clone();
            bad[i].c0 ^= 1;
            assert!(requests(&program, &bad, &public).is_none(), "node {i}");
        }
        let mut bad = public.clone();
        bad[0].c0 ^= 1;
        assert!(requests(&program, &values, &bad).is_none());
        assert!(requests(&program, &values[..values.len() - 1], &public).is_none());
    }

    #[test]
    fn replay_cannot_stand_in_for_hash_verification() {
        trace::start();
        let input = S::input(F192::ONE);
        let h = hash(&[(input, 24)]);
        let mut program = trace::take();
        program.public = h.to_vec();
        let mut values: Vec<_> = program.nodes.iter().map(|n| n.value).collect();
        // Unchanged digest and changed hash message pass arithmetic replay.
        // Only the coupled Flock proof can reject this forged hash.
        values[input.0] = F192::ZERO;
        let public: Vec<_> = program.public.iter().map(|s| values[s.0]).collect();
        let requests = requests(&program, &values, &public).unwrap();
        assert_ne!(primitives::protocol_hash::hash(&requests[0].message), requests[0].digest);
    }
}
