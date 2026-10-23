//! Complete experimental child-verifier argument with public hash I/O.
//! Unlike transparent replay, field identities are proved, not re-executed by
//! the verifier. The public hash request table is still disclosed.

use crate::{
    hash_batch::{self, BatchProof, Request},
    native_arithmetic::{self, Circuit, Index},
    public_plan, replay,
    trace::{Op, Trace},
};
use fiat_shamir::{merkle::Hash, transcript::Proof};
use primitives::field::F192;

pub struct Setup {
    pub index: Index,
    public_nodes: Vec<usize>,
    frobenius: Vec<usize>,
    program: Trace,
    program_digest: Hash,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Certificate {
    pub requests: Vec<Request>,
    pub hashes: Vec<BatchProof>,
    pub arithmetic: Proof,
}
impl Setup {
    /// Trusted preprocessing. The public projection pattern and arithmetic
    /// circuit are fixed here, independent of subsequent child proof values.
    pub fn new(program: Trace, requests: &[Request]) -> Option<Self> {
        let known = public_plan::values(&program, requests)?;
        public_plan::check_projections(&program, &known)?;
        let public_nodes: Vec<_> = known
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.is_some().then_some(i))
            .collect();
        let mut variables = program.nodes.len() + 2;
        let mut rows = Vec::new();
        let mut frobenius = Vec::new();
        for (i, node) in program.nodes.iter().enumerate() {
            let z = i + 2;
            match node.op {
                Op::Add(a, b) => rows.push([a.0 + 2, 1, b.0 + 2, z]),
                Op::Mul(a, b) => rows.push([a.0 + 2, b.0 + 2, 0, z]),
                Op::Frobenius(a) => {
                    let mut previous = a.0 + 2;
                    for step in 0..64 {
                        let output = if step == 63 {
                            z
                        } else {
                            let v = variables;
                            variables += 1;
                            v
                        };
                        rows.push([previous, previous, 0, output]);
                        previous = output;
                    }
                    frobenius.push(a.0);
                }
                _ => (),
            }
        }
        for &(a, b) in &program.checks {
            rows.push([a.0 + 2, 1, 0, b.0 + 2]);
        }
        let public = std::iter::once(0)
            .chain(std::iter::once(1))
            .chain(public_nodes.iter().map(|i| i + 2))
            .collect();
        let index = Index::new(Circuit {
            variables,
            rows,
            public,
        });
        let program_digest = replay::context(&program, &[]);
        Some(Self {
            index,
            public_nodes,
            frobenius,
            program,
            program_digest,
        })
    }
    fn context(&self, expected_public: &[F192]) -> Hash {
        let mut bytes = b"format-native-recursion-v1".to_vec();
        bytes.extend_from_slice(&self.program_digest);
        bytes.extend_from_slice(&self.index.root);
        for x in expected_public {
            for limb in [x.c0, x.c1, x.c2] {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
        primitives::protocol_hash::hash(&bytes)
    }
    fn public_values(&self, requests: &[Request], expected_public: &[F192]) -> Option<Vec<F192>> {
        if expected_public.len() != self.program.public.len() {
            return None;
        }
        let known = public_plan::values(&self.program, requests)?;
        public_plan::check_projections(&self.program, &known)?;
        let nodes: Vec<_> = known
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.is_some().then_some(i))
            .collect();
        if nodes != self.public_nodes {
            return None;
        }
        for (s, expected) in self.program.public.iter().zip(expected_public) {
            if known[s.0]? != *expected {
                return None;
            }
        }
        let mut public = vec![F192::ZERO, F192::ONE];
        public.extend(self.public_nodes.iter().map(|&i| known[i].unwrap()));
        Some(public)
    }
    pub fn prove(&self, trace: &Trace, expected_public: &[F192]) -> Option<Certificate> {
        if !self.program.same_program(trace) {
            return None;
        }
        let mut values = vec![F192::ZERO, F192::ONE];
        values.extend(trace.nodes.iter().map(|n| n.value));
        let requests = replay::requests(&self.program, &values[2..], expected_public)?;
        let public = self.public_values(&requests, expected_public)?;
        for &source in &self.frobenius {
            let mut value = values[source + 2];
            for _ in 0..63 {
                value = value * value;
                values.push(value);
            }
        }
        if self.index.public_values(&values) != public {
            return None;
        }
        let context = self.context(expected_public);
        let hashes = chunks(&requests)?
            .into_iter()
            .map(|(start, end)| hash_batch::prove(&context, &requests[start..end]))
            .collect::<Option<Vec<_>>>()?;
        let arithmetic = native_arithmetic::prove(&self.index, &values, &context);
        Some(Certificate {
            requests,
            hashes,
            arithmetic,
        })
    }
    /// The arithmetic witness is absent from the certificate. Native work here
    /// derives public byte/bit projections and verifies the two proof arguments.
    pub fn verify(&self, expected_public: &[F192], proof: &Certificate) -> bool {
        let Some(public) = self.public_values(&proof.requests, expected_public) else {
            return false;
        };
        let context = self.context(expected_public);
        let Some(chunks) = chunks(&proof.requests) else {
            return false;
        };
        if chunks.len() != proof.hashes.len() {
            return false;
        }
        native_arithmetic::verify(&self.index, &public, &context, &proof.arithmetic)
            && chunks
                .iter()
                .zip(&proof.hashes)
                .all(|(&(start, end), hashes)| hash_batch::verify(&context, &proof.requests[start..end], hashes))
    }
}

fn chunks(requests: &[Request]) -> Option<Vec<(usize, usize)>> {
    if requests.is_empty() {
        return None;
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut count = 0;
    for (i, request) in requests.iter().enumerate() {
        let n = request.message.len().div_ceil(64).max(1);
        if n > hash_batch::MAX_COMPRESSIONS {
            return None;
        }
        if count + n > hash_batch::MAX_COMPRESSIONS {
            chunks.push((start, i));
            start = i;
            count = 0;
        }
        count += n;
    }
    chunks.push((start, requests.len()));
    Some(chunks)
}

// These fixtures exercise the legacy BLAKE2s application/bridge backend.
#[cfg(all(test, not(feature = "keccak-protocol")))]
mod tests {
    use super::*;
    use crate::trace::{self, S};
    #[test]
    fn complete_certificate_binds_public_requests_context_and_components() {
        parallel::init();
        trace::start();
        let x = S::input(F192::new(7, 11, 13));
        let y = S::input(F192::new(17, 19, 23));
        trace::hash(&[(x, 24)]);
        let output = trace::hash(&[(x * y, 24)]);
        let mut t = trace::take();
        t.public = output.to_vec();
        let witness: Vec<_> = t.nodes.iter().map(|n| n.value).collect();
        let public: Vec<_> = output.iter().map(|s| witness[s.0]).collect();
        let requests = replay::requests(&t, &witness, &public).unwrap();
        let setup = Setup::new(t, &requests).unwrap();
        let proof = setup.prove(&setup.program, &public).unwrap();
        assert!(setup.verify(&public, &proof));
        let mut wrong = public.clone();
        wrong[0] += F192::ONE;
        assert!(!setup.verify(&wrong, &proof));
        for which in 0..8 {
            let mut bad = proof.clone();
            match which {
                0 => bad.requests[0].message[0] ^= 1,
                1 => bad.requests[0].digest[0] ^= 1,
                2 => {
                    bad.requests.swap(0, 1);
                }
                3 => {
                    bad.requests.pop();
                }
                4 => {
                    bad.hashes.clear();
                }
                5 => {
                    bad.hashes.push(proof.hashes[0].clone());
                }
                6 => bad.arithmetic.stream[0] += F192::ONE,
                7 => bad.hashes[0].proof.stream[0] += F192::ONE,
                _ => unreachable!(),
            }
            assert!(!setup.verify(&public, &bad), "mutation {which}");
        }
        let mut changed = setup;
        changed.program_digest[0] ^= 1;
        assert!(!changed.verify(&public, &proof));
    }
    #[test]
    fn compression_chunks_have_fixed_order_and_boundaries() {
        let request = Request {
            message: vec![0],
            digest: [0; 32],
        };
        assert!(chunks(&[]).is_none());
        let requests = vec![request; hash_batch::MAX_COMPRESSIONS + 1];
        assert_eq!(
            chunks(&requests).unwrap(),
            [
                (0, hash_batch::MAX_COMPRESSIONS),
                (hash_batch::MAX_COMPRESSIONS, requests.len())
            ]
        );
        assert_eq!(
            chunks(&requests[..hash_batch::MAX_COMPRESSIONS]).unwrap(),
            [(0, hash_batch::MAX_COMPRESSIONS)]
        );
        assert!(
            chunks(&[Request {
                message: vec![0; 64 * hash_batch::MAX_COMPRESSIONS + 1],
                digest: [0; 32]
            }])
            .is_none()
        );
    }
}
