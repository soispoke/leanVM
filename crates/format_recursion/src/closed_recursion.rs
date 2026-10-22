//! Experimental single-key recursion with an explicit bounded height.
//! This construction relies on the native bridge's unproved soundness assumptions.
use crate::{
    private_bridge::{PrivateShape, io_words},
    private_recursion::Setup,
    private_trace, private_verifier,
    trace::{self, S, Trace, digest_constant, hash},
    verifier::Transcript,
};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use flock::hash::{blake2s_compress, padding_block};
use primitives::field::F192;

const OUTPUTS: usize = 5;
const HEIGHT_BITS: usize = 32;
const PUBLIC_CAPACITY: usize = 1024 - OUTPUTS - 18;
const CERTIFICATE_CAP: u64 = crate::private_recursion::PROOF_CAP as u64 + 36;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Certificate {
    pub height: u32,
    pub statement: Hash,
    pub proof: Proof,
}

impl Certificate {
    pub fn encode(&self) -> Option<Vec<u8>> {
        use bincode::Options;
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(CERTIFICATE_CAP);
        options.serialize(self).ok()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        use bincode::Options;
        if bytes.len() as u64 > CERTIFICATE_CAP {
            return None;
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(CERTIFICATE_CAP)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .ok()
    }
}

pub struct ClosedSetup {
    backend: Setup,
    shape: PrivateShape,
    fixed_public: Vec<F192>,
    chain: usize,
}

fn context() -> Hash {
    primitives::hash::hash(b"format-closed-recursion-v1")
}

fn padding() -> [F192; 18] {
    let block = padding_block();
    let output = blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
    io_words(&block, &output).map(|word| F192::new(word, 0, 0))
}

fn range(word: S, bits: usize) {
    word.assert_eq(word.slice(0, bits));
}

fn successor(value: S) -> (S, S) {
    let mut carry = S::u(1);
    let bits: Vec<_> = (0..HEIGHT_BITS)
        .map(|i| {
            let bit = value.slice(i, 1);
            let sum = bit + carry;
            carry = carry * bit;
            (sum, 1)
        })
        .collect();
    (S::pack(&bits), carry)
}

fn maximum(left: S, right: S) -> S {
    let mut equal = S::u(1);
    let mut less = S::u(0);
    for i in (0..HEIGHT_BITS).rev() {
        let a = left.slice(i, 1);
        let b = right.slice(i, 1);
        less = less + equal * (S::u(1) + a) * b;
        equal = equal * (S::u(1) + a + b);
    }
    S::select(less, left, right)
}

fn record(
    shape: PrivateShape,
    fixed_public: &[F192],
    chain: usize,
    key: &Hash,
    start: &Hash,
    children: Option<[&Certificate; 2]>,
) -> Trace {
    trace::start();
    let enabled = S::input(F192::from(primitives::field::F64(u64::from(children.is_some()))));
    (enabled * (enabled + S::u(1))).assert_eq(S::u(0));
    let key = hash_to_scalars(key).map(S::input);
    for word in key {
        range(word, 128);
    }
    let height = S::input(F192::new(
        children.map_or(0, |c| u64::from(c[0].height.max(c[1].height)) + 1),
        0,
        0,
    ));
    let child_heights: [S; 2] =
        std::array::from_fn(|i| S::input(F192::new(children.map_or(0, |c| u64::from(c[i].height)), 0, 0)));
    range(height, HEIGHT_BITS);
    for child_height in child_heights {
        range(child_height, HEIGHT_BITS);
    }
    let (increment, overflow) = successor(maximum(child_heights[0], child_heights[1]));
    (enabled * (height + increment)).assert_eq(S::u(0));
    (enabled * overflow).assert_eq(S::u(0));
    ((S::u(1) + enabled) * height).assert_eq(S::u(0));
    let mut digest = hash_to_scalars(start).map(S::input);
    for word in digest {
        range(word, 128);
    }
    for _ in 0..chain {
        digest = hash(&[(S::u(0x43), 1), (digest[0], 16), (digest[1], 16)]);
    }
    let leaf = hash(&[
        (S::u(0x4c), 1),
        (digest[0], 16),
        (digest[1], 16),
        (S::u(chain as u64), 8),
    ]);
    let mut digests = Vec::new();
    for i in 0..2 {
        let child = children.map(|children| children[i]);
        let words = hash_to_scalars(&child.map_or([0; 32], |c| c.statement)).map(S::input);
        for word in words {
            range(word, 128);
        }
        let mut public: Vec<_> = fixed_public.iter().copied().map(S::c).collect();
        public.extend([key[0], key[1], child_heights[i], words[0], words[1]]);
        public.extend(padding().map(S::c));
        let before = trace::check_count();
        let seed = hash(&private_verifier::label_shape(
            shape,
            key,
            digest_constant(&context()),
            &public,
        ));
        let mut transcript = child.map_or_else(
            || Transcript::placeholder(seed),
            |c| Transcript::from_state(&c.proof, seed),
        );
        private_verifier::verify_shape(shape, key, &public, &mut transcript);
        transcript.finish();
        trace::gate_checks_since(before, enabled);
        digests.push(words);
    }
    let node = hash(&[
        (S::u(0x4e), 1),
        (digests[0][0], 16),
        (digests[0][1], 16),
        (digests[1][0], 16),
        (digests[1][1], 16),
    ]);
    let digest = std::array::from_fn::<_, 2, _>(|i| S::select(enabled, leaf[i], node[i]));
    let mut result = trace::take();
    result.public = vec![key[0], key[1], height, digest[0], digest[1]];
    result
}

/// Search metadata and public constants without creating PCS commitments.
pub fn shape_iterations(chain: usize, max_iterations: usize) -> Option<Vec<(PrivateShape, usize)>> {
    find_program(chain, max_iterations).map(|program| program.history)
}

struct FixedProgram {
    shape: PrivateShape,
    fixed_public: Vec<F192>,
    trace: Trace,
    history: Vec<(PrivateShape, usize)>,
}

fn find_program(chain: usize, max_iterations: usize) -> Option<FixedProgram> {
    if chain > crate::recursion_fast::CHAIN_CAP as usize {
        return None;
    }
    let mut fixed = vec![F192::ZERO, F192::ONE];
    fixed.resize(PUBLIC_CAPACITY, F192::ZERO);
    let mut shape = PrivateShape::for_circuit(0, fixed.len() + OUTPUTS, 128)?;
    let mut history = Vec::new();
    for _ in 0..max_iterations {
        let program = record(shape, &fixed, chain, &[0; 32], &[0; 32], None);
        let mut lower = private_trace::lower(&program, &program)?;
        if lower.fixed_public.len() > PUBLIC_CAPACITY {
            return None;
        }
        lower.fixed_public.resize(PUBLIC_CAPACITY, F192::ZERO);
        let blocks = lower.compressions.len().max(128).next_power_of_two();
        let next = PrivateShape::for_circuit(lower.circuit.rows.len(), PUBLIC_CAPACITY + OUTPUTS, blocks)?;
        history.push((next, lower.fixed_public.len()));
        eprintln!(
            "closure shape iteration {}: {:?}, fixed public slots {}",
            history.len(),
            next,
            lower.fixed_public.len()
        );
        if next == shape && lower.fixed_public == fixed {
            if !program.satisfied() {
                return None;
            }
            return Some(FixedProgram {
                shape,
                fixed_public: fixed,
                trace: program,
                history,
            });
        }
        shape = next;
        fixed = lower.fixed_public;
    }
    None
}

impl ClosedSetup {
    pub fn new(chain: usize) -> Option<Self> {
        let FixedProgram {
            shape,
            fixed_public,
            trace,
            ..
        } = find_program(chain, 24)?;
        let backend = Setup::new_closed(trace, context(), PUBLIC_CAPACITY)?;
        if backend.bridge.verifier_shape() != shape {
            return None;
        }
        Some(Self {
            backend,
            shape,
            fixed_public,
            chain,
        })
    }

    pub fn key(&self) -> Hash {
        self.backend.bridge.index.root
    }
    pub fn shape(&self) -> PrivateShape {
        self.shape
    }

    fn outputs(&self, height: u32, statement: &Hash) -> [F192; OUTPUTS] {
        let key = hash_to_scalars(&self.key());
        let words = hash_to_scalars(statement);
        [key[0], key[1], F192::new(u64::from(height), 0, 0), words[0], words[1]]
    }

    pub fn verify(&self, certificate: &Certificate) -> bool {
        self.backend.verify(
            &self.outputs(certificate.height, &certificate.statement),
            &certificate.proof,
        )
    }

    pub fn prove_leaf(&self, start: &Hash) -> Option<Certificate> {
        let _span = tracing::info_span!("closed_leaf").entered();
        let statement = crate::recursion_fast::expected_leaf(start, self.chain as u64).ok()?;
        let program = record(self.shape, &self.fixed_public, self.chain, &self.key(), start, None);
        let proof = self.backend.prove(&program, &self.outputs(0, &statement))?;
        Some(Certificate {
            height: 0,
            statement,
            proof,
        })
    }

    pub fn prove_node(&self, left: &Certificate, right: &Certificate) -> Option<Certificate> {
        let _span = tracing::info_span!("closed_node").entered();
        if !self.verify(left) || !self.verify(right) {
            return None;
        }
        let height = left.height.max(right.height).checked_add(1)?;
        let statement = crate::recursion_fast::node_statement(&left.statement, &right.statement);
        let program = record(
            self.shape,
            &self.fixed_public,
            self.chain,
            &self.key(),
            &[0; 32],
            Some([left, right]),
        );
        let proof = self.backend.prove(&program, &self.outputs(height, &statement))?;
        Some(Certificate {
            height,
            statement,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_successor_is_nonwrapping() {
        for value in [0, 1, 255, u32::MAX - 1, u32::MAX] {
            trace::start();
            let input = S::input(F192::new(u64::from(value), 0, 0));
            range(input, HEIGHT_BITS);
            let (next, overflow) = successor(input);
            assert_eq!(next.value(), F192::new(u64::from(value.wrapping_add(1)), 0, 0));
            assert_eq!(overflow.value(), F192::new(u64::from(value == u32::MAX), 0, 0));
            assert!(trace::take().satisfied());
        }
    }

    #[test]
    fn height_maximum_matches_integer_order_at_boundaries() {
        for left in [0, 1, 255, 256, u32::MAX - 1, u32::MAX] {
            for right in [0, 1, 255, 256, u32::MAX - 1, u32::MAX] {
                trace::start();
                let a = S::input(F192::new(u64::from(left), 0, 0));
                let b = S::input(F192::new(u64::from(right), 0, 0));
                range(a, HEIGHT_BITS);
                range(b, HEIGHT_BITS);
                assert_eq!(maximum(a, b).value(), F192::new(u64::from(left.max(right)), 0, 0));
                assert!(trace::take().satisfied());
            }
        }
    }

    #[test]
    fn common_key_verifies_leaf_and_repeated_composition_and_rejects_wrong_claims() {
        parallel::init();
        let setup = ClosedSetup::new(2).expect("shape and constants stabilize");
        let key = setup.key();
        let leaf = setup.prove_leaf(&[7; 32]).expect("common program proves its base case");
        assert!(setup.verify(&leaf));
        assert_eq!(leaf.height, 0);
        let second = setup.prove_leaf(&[11; 32]).unwrap();
        assert!(setup.verify(&second));
        let mut current = setup
            .prove_node(&leaf, &second)
            .expect("same program proves its own verifier");
        assert!(setup.verify(&current));
        for expected_height in 2..=4 {
            current = setup.prove_node(&current, &current).unwrap();
            assert_eq!(current.height, expected_height);
            assert!(setup.verify(&current));
            assert_eq!(setup.key(), key);
        }
        let mixed = setup.prove_node(&leaf, &current).expect("mixed-height composition");
        assert_eq!(mixed.height, 5);
        assert!(setup.verify(&mixed));
        let bytes = mixed.encode().unwrap();
        assert_eq!(Certificate::decode(&bytes), Some(mixed.clone()));
        assert!(Certificate::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Certificate::decode(&trailing).is_none());
        assert!(Certificate::decode(&vec![0; CERTIFICATE_CAP as usize + 1]).is_none());
        let mut wrong = current.clone();
        wrong.height -= 1;
        assert!(!setup.verify(&wrong));
        wrong = current.clone();
        wrong.statement[0] ^= 1;
        assert!(!setup.verify(&wrong));
        assert!(setup.prove_node(&wrong, &current).is_none());
        wrong = current.clone();
        wrong.proof.stream[0] += F192::ONE;
        assert!(!setup.verify(&wrong));
        assert!(setup.prove_node(&wrong, &current).is_none());
        wrong = current.clone();
        wrong.proof.merkle.pop();
        assert!(!setup.verify(&wrong));
        let program = record(setup.shape, &setup.fixed_public, setup.chain, &[19; 32], &[7; 32], None);
        let mut outputs = setup.outputs(0, &leaf.statement);
        outputs[..2].copy_from_slice(&hash_to_scalars(&[19; 32]));
        let foreign = setup
            .backend
            .prove(&program, &outputs)
            .expect("base relation allows a key claim, wrapper must pin it");
        assert!(setup.backend.verify(&outputs, &foreign));
        assert!(!setup.verify(&Certificate {
            height: 0,
            statement: leaf.statement,
            proof: foreign
        }));
    }
}
