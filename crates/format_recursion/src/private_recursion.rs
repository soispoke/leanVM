//! Experimental private trace proof and repeated recursion helpers.
//! This is local implementation work, not a recursion.fast security certificate.

use crate::{
    private_bridge::PrivateBridge,
    private_trace, private_verifier,
    trace::{self, S, Trace, digest_constant, hash},
    verifier::Transcript,
};
use bincode::Options;
use fiat_shamir::{merkle::Hash, transcript::Proof};
use primitives::field::F192;

pub const PROOF_CAP: usize = 1 << 20;

pub struct Setup {
    pub bridge: PrivateBridge,
    program: private_trace::PreparedProgram,
    pub(crate) fixed_public: Vec<F192>,
    raw_fixed_len: usize,
    pub(crate) outputs: usize,
    pub(crate) context: Hash,
}

impl Setup {
    /// Preprocess a fixed program independently of subsequent witnesses.
    #[tracing::instrument(skip_all, name = "Private setup")]
    pub fn new(program: Trace) -> Option<Self> {
        Self::new_with_context(program, primitives::protocol_hash::hash(b"format-private-recursion-v1"))
    }

    pub(crate) fn new_with_context(program: Trace, context: Hash) -> Option<Self> {
        Self::new_inner(program, context, None)
    }

    pub(crate) fn new_closed(program: Trace, context: Hash, public_capacity: usize) -> Option<Self> {
        Self::new_inner(program, context, Some(public_capacity))
    }

    fn new_inner(program: Trace, context: Hash, public_capacity: Option<usize>) -> Option<Self> {
        let mut prepared = private_trace::PreparedProgram::new(program)?;
        // The constructor's canonical witness is owned by the prepared program.
        let mut lower = prepared.lower_setup()?;
        let raw_fixed_len = lower.fixed_public.len();
        let bridge = if let Some(capacity) = public_capacity {
            if capacity < raw_fixed_len {
                return None;
            }
            lower.circuit.public.splice(
                raw_fixed_len..raw_fixed_len,
                std::iter::repeat_n(0, capacity - raw_fixed_len),
            );
            lower.fixed_public.resize(capacity, F192::ZERO);
            PrivateBridge::new_padded(lower.circuit, lower.connectors)?
        } else {
            PrivateBridge::new(lower.circuit, lower.connectors)?
        };
        Some(Self {
            bridge,
            program: prepared,
            fixed_public: lower.fixed_public,
            raw_fixed_len,
            outputs: lower.original_public_len,
            context,
        })
    }

    fn public_values(&self, outputs: &[F192]) -> Option<Vec<F192>> {
        if outputs.len() != self.outputs {
            return None;
        }
        let mut values = self.fixed_public.clone();
        values.extend_from_slice(outputs);
        Some(values)
    }

    #[tracing::instrument(skip_all, name = "Private prove")]
    pub fn prove(&self, witness: &Trace, outputs: &[F192]) -> Option<Proof> {
        let mut lower = tracing::info_span!("Compile witness").in_scope(|| self.program.prepare_witness(witness))?;
        if self.fixed_public.len() != self.raw_fixed_len {
            lower.public.splice(
                self.raw_fixed_len..self.raw_fixed_len,
                std::iter::repeat_n(F192::ZERO, self.fixed_public.len() - self.raw_fixed_len),
            );
        }
        let public = self.public_values(outputs)?;
        if lower.public != public {
            return None;
        }
        let proof = self.bridge.prove(&lower.values, &lower.compressions, &self.context)?;
        encode(&proof)?;
        Some(proof)
    }

    pub fn verify(&self, outputs: &[F192], proof: &Proof) -> bool {
        let Some(public) = self.public_values(outputs) else {
            return false;
        };
        encode(proof).is_some() && self.bridge.verify(&public, &self.context, proof)
    }

    pub fn verify_bytes(&self, outputs: &[F192], bytes: &[u8]) -> bool {
        decode(bytes).is_some_and(|proof| self.verify(outputs, &proof))
    }

    /// Append verification to the active trace with the child key fixed by this
    /// trusted setup. No prover-selected circuit key is authorized here.
    fn append_verification(&self, outputs: &[S], proof: &Proof) -> Option<()> {
        if outputs.len() != self.outputs || encode(proof).is_none() {
            return None;
        }
        let zeros = vec![F192::ZERO; self.outputs];
        let full = self.bridge.public(&self.public_values(&zeros)?)?;
        let mut public: Vec<_> = full.iter().copied().map(S::c).collect();
        public[self.fixed_public.len()..self.fixed_public.len() + outputs.len()].copy_from_slice(outputs);
        let index_root = digest_constant(&self.bridge.index.root);
        let context = digest_constant(&self.context);
        let label = hash(&private_verifier::label(&self.bridge, index_root, context, &public));
        let mut transcript = Transcript::from_state(proof, label);
        private_verifier::verify(&self.bridge, index_root, &public, &mut transcript);
        transcript.finish();
        Some(())
    }
}

/// Fixed-integer bincode, with bounded input and rejection of trailing bytes.
pub fn decode(bytes: &[u8]) -> Option<Proof> {
    if bytes.len() > PROOF_CAP {
        return None;
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(PROOF_CAP as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .ok()
}

pub fn encode(proof: &Proof) -> Option<Vec<u8>> {
    if bincode::serialized_size(proof).ok()? > PROOF_CAP as u64 {
        return None;
    }
    bincode::serialize(proof).ok()
}

pub fn outputs(trace: &Trace) -> Vec<F192> {
    trace.public.iter().map(|s| trace.nodes[s.0].value).collect()
}

/// Exact tagged chain/leaf statement, with n fixed in the circuit.
pub fn leaf(start: &Hash, n: usize) -> Option<Trace> {
    if n > crate::recursion_fast::CHAIN_CAP as usize {
        return None;
    }
    trace::start();
    let mut digest = fiat_shamir::merkle::hash_to_scalars(start).map(S::input);
    for x in digest {
        x.assert_eq(x.slice(0, 128));
    }
    for _ in 0..n {
        digest = hash(&[(S::u(0x43), 1), (digest[0], 16), (digest[1], 16)]);
    }
    let result = hash(&[(S::u(0x4c), 1), (digest[0], 16), (digest[1], 16), (S::u(n as u64), 8)]);
    let mut trace = trace::take();
    trace.public = result.to_vec();
    Some(trace)
}

/// Ordered two-child node with full child verifier equations. Leaves and nodes
/// use the same native/Flock/WHIR backend. Each level currently has a separately
/// preprocessed circuit; this is not yet one closed fixed-shape verifier.
pub fn node(left: (&Setup, &Hash, &Proof), right: (&Setup, &Hash, &Proof)) -> Option<Trace> {
    trace::start();
    let mut digests = Vec::new();
    for (setup, digest, proof) in [left, right] {
        let words = fiat_shamir::merkle::hash_to_scalars(digest).map(S::input);
        for word in words {
            word.assert_eq(word.slice(0, 128));
        }
        setup.append_verification(&words, proof)?;
        digests.push(words);
    }
    let result = hash(&[
        (S::u(0x4e), 1),
        (digests[0][0], 16),
        (digests[0][1], 16),
        (digests[1][0], 16),
        (digests[1][1], 16),
    ]);
    let mut trace = trace::take();
    trace.public = result.to_vec();
    Some(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_leaf_proofs_bind_fresh_statements_and_strict_bytes() {
        parallel::init();
        let setup = Setup::new(leaf(&[3; 32], 2).unwrap()).unwrap();
        for start in [[7; 32], [11; 32]] {
            let witness = leaf(&start, 2).unwrap();
            let expected = crate::recursion_fast::expected_leaf(&start, 2).unwrap();
            let public = fiat_shamir::merkle::hash_to_scalars(&expected);
            assert_eq!(outputs(&witness), public);
            let proof = setup.prove(&witness, &public).unwrap();
            assert!(setup.verify(&public, &proof));
            let bytes = encode(&proof).unwrap();
            // The fresh witness schedule must preserve the original prover's
            // complete deterministic transcript, not just accepted outputs.
            let reference = setup.program.lower(&witness).unwrap();
            let reference_proof = setup
                .bridge
                .prove(&reference.values, &reference.compressions, &setup.context)
                .unwrap();
            assert_eq!(encode(&reference_proof).unwrap(), bytes);
            assert!(setup.verify_bytes(&public, &bytes));
            assert!(!setup.verify_bytes(&public, &bytes[..bytes.len() - 1]));
            let mut appended = bytes.clone();
            appended.push(0);
            assert!(!setup.verify_bytes(&public, &appended));
            let mut wrong = public;
            wrong[0] += F192::ONE;
            assert!(!setup.verify(&wrong, &proof));
            assert!(setup.prove(&witness, &wrong).is_none());
            let mut corrupt = proof.clone();
            corrupt.stream[0] += F192::ONE;
            assert!(!setup.verify(&public, &corrupt));
            assert!(setup.prove(&leaf(&start, 1).unwrap(), &public).is_none());
        }
        assert!(decode(&vec![0; PROOF_CAP + 1]).is_none());
    }
}
