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
    application: Option<Trace>,
}

/// Separate specialized base proof setup and recursively closed node setup.
/// Base certificates are height-zero proofs under the pinned base key; internal
/// nodes verify each child as either a base certificate (height 0) or a node
/// certificate (height > 0) under the pinned node key, without a separate
/// per-leaf conversion proof.
pub struct SplitClosedSetup {
    base: Setup,
    node: Setup,
    shape: PrivateShape,
    fixed_public: Vec<F192>,
}

fn context() -> Hash {
    primitives::protocol_hash::hash(b"format-closed-recursion-v1")
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
    record_program(shape, fixed_public, chain, None, key, start, children)
}

#[allow(clippy::too_many_arguments)]
fn record_program(
    shape: PrivateShape,
    fixed_public: &[F192],
    chain: usize,
    application: Option<&Trace>,
    key: &Hash,
    start: &Hash,
    children: Option<[&Certificate; 2]>,
) -> Trace {
    if let Some(program) = application {
        trace::resume(program.clone());
    } else {
        trace::start();
    }
    let enabled = S::input(F192::from(primitives::field::F64(u64::from(children.is_some()))));
    if application.is_some() {
        // Only the base relation's equations are conditional. The base program's
        // arithmetic and hashes are still constrained on both branches.
        trace::gate_checks_since(0, S::u(1) + enabled);
    }
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
    let leaf = if let Some(program) = application {
        let digest: [S; 2] = program.public.as_slice().try_into().expect("two base outputs");
        for word in digest {
            range(word, 128);
        }
        digest
    } else {
        let mut digest = hash_to_scalars(start).map(S::input);
        for word in digest {
            range(word, 128);
        }
        for _ in 0..chain {
            digest = hash(&[(S::u(0x43), 1), (digest[0], 16), (digest[1], 16)]);
        }
        hash(&[
            (S::u(0x4c), 1),
            (digest[0], 16),
            (digest[1], 16),
            (S::u(chain as u64), 8),
        ])
    };
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
    find_application_program(chain, None, max_iterations)
}

fn find_application_program(chain: usize, application: Option<&Trace>, max_iterations: usize) -> Option<FixedProgram> {
    if application.is_some_and(|program| program.public.len() != 2 || !program.satisfied()) {
        return None;
    }
    if chain > crate::recursion_fast::CHAIN_CAP as usize {
        return None;
    }
    let mut capacity = PUBLIC_CAPACITY;
    let mut fixed = vec![F192::ZERO, F192::ONE];
    fixed.resize(capacity, F192::ZERO);
    let mut shape = PrivateShape::for_circuit(0, fixed.len() + OUTPUTS, 128)?;
    let mut history = Vec::new();
    for _ in 0..max_iterations {
        let program = record_program(shape, &fixed, chain, application, &[0; 32], &[0; 32], None);
        let mut lower = private_trace::lower(&program, &program).or_else(|| {
            eprintln!(
                "closure program exceeds lowering limits: {:?}",
                private_trace::allocation_bound(&program)
            );
            None
        })?;
        if lower.fixed_public.len() > capacity {
            capacity = lower
                .fixed_public
                .len()
                .checked_add(OUTPUTS + 18)?
                .checked_next_power_of_two()?
                - OUTPUTS
                - 18;
        }
        lower.fixed_public.resize(capacity, F192::ZERO);
        let blocks = lower.compressions.len().max(128).next_power_of_two();
        let next = PrivateShape::for_circuit(lower.circuit.rows.len(), capacity + OUTPUTS, blocks)?;
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
        Self::new_inner(chain, None)
    }

    /// Close a fixed base relation with two canonical hash limbs as its public
    /// output. The exact base circuit, including application identity and child
    /// verification keys, is bound by the resulting common recursion key.
    pub fn from_program(program: Trace) -> Option<Self> {
        if program.public.len() != 2 {
            return None;
        }
        let words = std::array::from_fn(|i| program.nodes[program.public[i].0].value);
        fiat_shamir::merkle::scalars_to_hash(&words).ok()?;
        Self::new_inner(0, Some(program))
    }

    fn new_inner(chain: usize, application: Option<Trace>) -> Option<Self> {
        let FixedProgram {
            shape,
            fixed_public,
            trace,
            ..
        } = find_application_program(chain, application.as_ref(), 24)?;
        let backend = Setup::new_closed(trace, context(), fixed_public.len())?;
        if backend.bridge.verifier_shape() != shape {
            return None;
        }
        Some(Self {
            backend,
            shape,
            fixed_public,
            chain,
            application,
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
        if self.application.is_some() {
            return None;
        }
        let statement = crate::recursion_fast::expected_leaf(start, self.chain as u64).ok()?;
        let program = record(self.shape, &self.fixed_public, self.chain, &self.key(), start, None);
        let proof = self.backend.prove(&program, &self.outputs(0, &statement))?;
        Some(Certificate {
            height: 0,
            statement,
            proof,
        })
    }

    /// Adapt a fresh witness of the exact base program into the common proof
    /// format. This cost is separate from creating an existing application proof.
    pub fn prove_program(&self, witness: &Trace) -> Option<Certificate> {
        let _span = tracing::info_span!("closed_application").entered();
        let application = self.application.as_ref()?;
        if !application.same_program(witness) || !witness.satisfied() {
            return None;
        }
        let words = std::array::from_fn(|i| witness.nodes[witness.public[i].0].value);
        let statement = fiat_shamir::merkle::scalars_to_hash(&words).ok()?;
        let program = record_program(
            self.shape,
            &self.fixed_public,
            0,
            Some(witness),
            &self.key(),
            &[0; 32],
            None,
        );
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
        let program = record_program(
            self.shape,
            &self.fixed_public,
            self.chain,
            self.application.as_ref(),
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

fn non_zero_height(value: S) -> S {
    (0..HEIGHT_BITS).fold(S::u(0), |any, i| {
        let bit = value.slice(i, 1);
        any + bit + any * bit
    })
}

fn record_split_node(
    base: &Setup,
    shape: PrivateShape,
    fixed_public: &[F192],
    node_key: &Hash,
    children: Option<[&Certificate; 2]>,
) -> Trace {
    trace::start();
    let key = hash_to_scalars(node_key).map(S::input);
    for word in key {
        range(word, 128);
    }
    let height = S::input(F192::new(
        children.map_or(1, |c| u64::from(c[0].height.max(c[1].height)) + 1),
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
    height.assert_eq(increment);
    overflow.assert_eq(S::u(0));
    let base_shape = base.bridge.verifier_shape();
    let base_root = digest_constant(&base.bridge.index.root);
    let base_context = digest_constant(&base.context);
    let node_context = digest_constant(&context());
    let mut digests = Vec::new();
    for i in 0..2 {
        let child = children.map(|children| children[i]);
        let words = hash_to_scalars(&child.map_or([0; 32], |c| c.statement)).map(S::input);
        for word in words {
            range(word, 128);
        }
        let is_node = non_zero_height(child_heights[i]);
        let mut base_public: Vec<_> = base.fixed_public.iter().copied().map(S::c).collect();
        base_public.extend(words);
        base_public.extend(padding().map(S::c));
        let before = trace::check_count();
        let base_seed = hash(&private_verifier::label_shape(
            base_shape,
            base_root,
            base_context,
            &base_public,
        ));
        let mut base_transcript = match child {
            Some(c) if c.height == 0 => Transcript::from_state(&c.proof, base_seed),
            _ => Transcript::placeholder(base_seed),
        };
        private_verifier::verify_shape(base_shape, base_root, &base_public, &mut base_transcript);
        base_transcript.finish();
        trace::gate_checks_since(before, S::u(1) + is_node);
        let mut node_public: Vec<_> = fixed_public.iter().copied().map(S::c).collect();
        node_public.extend([key[0], key[1], child_heights[i], words[0], words[1]]);
        node_public.extend(padding().map(S::c));
        let before = trace::check_count();
        let node_seed = hash(&private_verifier::label_shape(shape, key, node_context, &node_public));
        let mut node_transcript = match child {
            Some(c) if c.height > 0 => Transcript::from_state(&c.proof, node_seed),
            _ => Transcript::placeholder(node_seed),
        };
        private_verifier::verify_shape(shape, key, &node_public, &mut node_transcript);
        node_transcript.finish();
        trace::gate_checks_since(before, is_node);
        digests.push(words);
    }
    let node = hash(&[
        (S::u(0x4e), 1),
        (digests[0][0], 16),
        (digests[0][1], 16),
        (digests[1][0], 16),
        (digests[1][1], 16),
    ]);
    let mut result = trace::take();
    result.public = vec![key[0], key[1], height, node[0], node[1]];
    result
}

fn find_split_program(base: &Setup, canonical: &Certificate, max_iterations: usize) -> Option<FixedProgram> {
    if base.outputs != 2 {
        return None;
    }
    let mut capacity = PUBLIC_CAPACITY;
    let mut fixed = vec![F192::ZERO, F192::ONE];
    fixed.resize(capacity, F192::ZERO);
    let mut shape = PrivateShape::for_circuit(0, fixed.len() + OUTPUTS, 128)?;
    let mut history = Vec::new();
    for _ in 0..max_iterations {
        let program = record_split_node(base, shape, &fixed, &[0; 32], Some([canonical, canonical]));
        let mut lower = private_trace::lower(&program, &program).or_else(|| {
            eprintln!(
                "split closure program exceeds lowering limits: {:?}",
                private_trace::allocation_bound(&program)
            );
            None
        })?;
        if lower.fixed_public.len() > capacity {
            capacity = lower
                .fixed_public
                .len()
                .checked_add(OUTPUTS + 18)?
                .checked_next_power_of_two()?
                - OUTPUTS
                - 18;
        }
        lower.fixed_public.resize(capacity, F192::ZERO);
        let blocks = lower.compressions.len().max(128).next_power_of_two();
        let next = PrivateShape::for_circuit(lower.circuit.rows.len(), capacity + OUTPUTS, blocks)?;
        history.push((next, lower.fixed_public.len()));
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

impl SplitClosedSetup {
    pub fn from_program(program: Trace) -> Option<Self> {
        if program.public.len() != 2 || !program.satisfied() {
            return None;
        }
        let words = std::array::from_fn(|i| program.nodes[program.public[i].0].value);
        let statement = fiat_shamir::merkle::scalars_to_hash(&words).ok()?;
        let base = Setup::new(program.clone())?;
        let canonical = Certificate {
            height: 0,
            statement,
            proof: base.prove(&program, &words)?,
        };
        if !base.verify(&words, &canonical.proof) {
            return None;
        }
        let FixedProgram {
            shape,
            fixed_public,
            trace,
            ..
        } = find_split_program(&base, &canonical, 24)?;
        let node = Setup::new_closed(trace, context(), fixed_public.len())?;
        if node.bridge.verifier_shape() != shape {
            return None;
        }
        Some(Self {
            base,
            node,
            shape,
            fixed_public,
        })
    }

    pub fn base_key(&self) -> Hash {
        self.base.bridge.index.root
    }

    pub fn node_key(&self) -> Hash {
        self.node.bridge.index.root
    }

    pub fn base_shape(&self) -> PrivateShape {
        self.base.bridge.verifier_shape()
    }

    pub fn node_shape(&self) -> PrivateShape {
        self.shape
    }

    fn node_outputs(&self, height: u32, statement: &Hash) -> [F192; OUTPUTS] {
        let key = hash_to_scalars(&self.node_key());
        let words = hash_to_scalars(statement);
        [key[0], key[1], F192::new(u64::from(height), 0, 0), words[0], words[1]]
    }

    pub fn verify(&self, certificate: &Certificate) -> bool {
        if certificate.height == 0 {
            self.base
                .verify(&hash_to_scalars(&certificate.statement), &certificate.proof)
        } else {
            self.node.verify(
                &self.node_outputs(certificate.height, &certificate.statement),
                &certificate.proof,
            )
        }
    }

    pub fn prove_base(&self, witness: &Trace) -> Option<Certificate> {
        let _span = tracing::info_span!("split_base").entered();
        if !witness.satisfied() || witness.public.len() != 2 {
            return None;
        }
        let words = std::array::from_fn(|i| witness.nodes[witness.public[i].0].value);
        let statement = fiat_shamir::merkle::scalars_to_hash(&words).ok()?;
        let proof = self.base.prove(witness, &words)?;
        Some(Certificate {
            height: 0,
            statement,
            proof,
        })
    }

    pub fn prove_node(&self, left: &Certificate, right: &Certificate) -> Option<Certificate> {
        let _span = tracing::info_span!("split_node").entered();
        if !tracing::info_span!("Admit children").in_scope(|| self.verify(left) && self.verify(right)) {
            return None;
        }
        let height = left.height.max(right.height).checked_add(1)?;
        let statement = crate::recursion_fast::node_statement(&left.statement, &right.statement);
        let program = tracing::info_span!("Record node witness").in_scope(|| {
            record_split_node(
                &self.base,
                self.shape,
                &self.fixed_public,
                &self.node_key(),
                Some([left, right]),
            )
        });
        let proof = self.node.prove(&program, &self.node_outputs(height, &statement))?;
        Some(Certificate {
            height,
            statement,
            proof,
        })
    }
}

/// Shape-only screen of a tree verifier with first/tree keys and kind bound as
/// public outputs. Placeholder proofs are deliberately not satisfying witnesses.
/// This is not a proving API or a closed tree setup.
pub fn tree_only_census() -> Option<(PrivateShape, usize, usize, usize)> {
    const OUT: usize = 8;
    let capacity = 1024 - OUT - 18;
    let mut fixed = vec![F192::ZERO, F192::ONE];
    fixed.resize(capacity, F192::ZERO);
    let mut shape = PrivateShape::for_circuit(0, capacity + OUT, 128)?;
    for _ in 0..24 {
        trace::start();
        let keys: [S; 4] = std::array::from_fn(|_| S::input(F192::ZERO));
        for k in keys {
            range(k, 128);
        }
        let height = S::input(F192::new(2, 0, 0));
        range(height, HEIGHT_BITS);
        let mut digests = Vec::new();
        for _ in 0..2 {
            let kind = S::input(F192::ZERO);
            (kind * (kind + S::u(1))).assert_eq(S::u(0));
            let child_height = S::input(F192::ONE);
            range(child_height, HEIGHT_BITS);
            let (next, overflow) = successor(child_height);
            height.assert_eq(next);
            overflow.assert_eq(S::u(0));
            let root = [S::select(kind, keys[0], keys[2]), S::select(kind, keys[1], keys[3])];
            let words = [S::input(F192::ZERO), S::input(F192::ZERO)];
            for w in words {
                range(w, 128);
            }
            let mut public: Vec<_> = fixed.iter().copied().map(S::c).collect();
            public.extend(keys);
            public.extend([kind, child_height, words[0], words[1]]);
            public.extend(padding().map(S::c));
            let seed = hash(&private_verifier::label_shape(
                shape,
                root,
                digest_constant(&context()),
                &public,
            ));
            let mut t = Transcript::placeholder(seed);
            private_verifier::verify_shape(shape, root, &public, &mut t);
            t.finish();
            digests.push(words);
        }
        let digest = hash(&[
            (S::u(0x4e), 1),
            (digests[0][0], 16),
            (digests[0][1], 16),
            (digests[1][0], 16),
            (digests[1][1], 16),
        ]);
        let kind = S::u(1);
        let mut program = trace::take();
        program.public = keys.into_iter().chain([kind, height, digest[0], digest[1]]).collect();
        let lower = private_trace::lower(&program, &program)?;
        if lower.fixed_public.len() > capacity {
            return None;
        }
        let mut next_fixed = lower.fixed_public.clone();
        next_fixed.resize(capacity, F192::ZERO);
        let next = PrivateShape::for_circuit(
            lower.circuit.rows.len(),
            capacity + OUT,
            lower.compressions.len().max(128).next_power_of_two(),
        )?;
        if next == shape && next_fixed == fixed {
            let products = program
                .nodes
                .iter()
                .filter(|n| matches!(n.op, crate::trace::Op::Mul(..)))
                .count();
            return Some((shape, lower.circuit.rows.len(), lower.compressions.len(), products));
        }
        shape = next;
        fixed = next_fixed;
    }
    None
}

/// Record two complete native-hash bridge verifiers with pinned key/context.
/// The public prefix is trusted setup data; each child's final four words
/// are bound to its 32-byte statement. This is a first-level recorder only.
pub fn record_native_first(
    bridge: &crate::private_bridge::PrivateBridge,
    prefix: &[F192],
    context: &Hash,
    children: [&Certificate; 2],
) -> Trace {
    trace::start();
    let root = digest_constant(&bridge.index.root);
    let ctx = digest_constant(context);
    let mut digests = Vec::new();
    for child in children {
        trace::mark("native-claim-binding");
        let digest = hash_to_scalars(&child.statement).map(S::input);
        for w in digest {
            range(w, 128);
        }
        let mut public: Vec<_> = prefix.iter().copied().map(S::c).collect();
        public.extend([
            digest[0].slice(0, 64),
            digest[0].slice(64, 64),
            digest[1].slice(0, 64),
            digest[1].slice(64, 64),
        ]);
        public.extend(padding().map(S::c));
        let seed = hash(&private_verifier::label(bridge, root, ctx, &public));
        let mut t = Transcript::from_state(&child.proof, seed);
        private_verifier::verify(bridge, root, &public, &mut t);
        t.finish();
        digests.push(digest);
    }
    trace::mark("native-output-binding");
    let digest = hash(&[
        (S::u(0x4e), 1),
        (digests[0][0], 16),
        (digests[0][1], 16),
        (digests[1][0], 16),
        (digests[1][1], 16),
    ]);
    let mut program = trace::take();
    program.public = digest.to_vec();
    program
}

/// Experimental first-level aggregation with a pinned base key only.
/// It accepts exactly two height-zero certificates and cannot verify tree proofs.
pub struct FirstMergeSetup {
    base: Setup,
    first: Setup,
    pub arithmetic_rows: usize,
    pub compressions: usize,
    pub products: usize,
}

fn record_first<const N: usize>(base: &Setup, children: [&Certificate; N]) -> Trace {
    trace::start();
    let root = digest_constant(&base.bridge.index.root);
    let ctx = digest_constant(&base.context);
    let mut words = Vec::new();
    for child in children {
        let digest = hash_to_scalars(&child.statement).map(S::input);
        for word in digest {
            range(word, 128);
        }
        let mut public: Vec<_> = base.fixed_public.iter().copied().map(S::c).collect();
        public.extend(digest);
        public.extend(padding().map(S::c));
        let seed = hash(&private_verifier::label(&base.bridge, root, ctx, &public));
        let mut t = Transcript::from_state(&child.proof, seed);
        private_verifier::verify(&base.bridge, root, &public, &mut t);
        t.finish();
        words.push(digest);
    }
    let output = if N == 1 {
        words[0]
    } else {
        hash(&[
            (S::u(0x4e), 1),
            (words[0][0], 16),
            (words[0][1], 16),
            (words[1][0], 16),
            (words[1][1], 16),
        ])
    };
    let mut result = trace::take();
    result.public = output.to_vec();
    result
}

impl FirstMergeSetup {
    pub fn new(program: Trace) -> Option<Self> {
        if program.public.len() != 2 || !program.satisfied() {
            return None;
        }
        let words = std::array::from_fn(|i| program.nodes[program.public[i].0].value);
        let base = Setup::new(program.clone())?;
        let canonical = Certificate {
            height: 0,
            statement: fiat_shamir::merkle::scalars_to_hash(&words).ok()?,
            proof: base.prove(&program, &words)?,
        };
        let trace = record_first(&base, [&canonical, &canonical]);
        let lower = private_trace::lower(&trace, &trace)?;
        let arithmetic_rows = lower.circuit.rows.len();
        let compressions = lower.compressions.len();
        let products = trace
            .nodes
            .iter()
            .filter(|n| matches!(n.op, crate::trace::Op::Mul(..)))
            .count();
        drop(lower);
        // Distinct domain plus the base root pinned as constants in the circuit.
        let first = Setup::new_with_context(trace, primitives::protocol_hash::hash(b"format-first-merge-v1"))?;
        Some(Self {
            base,
            first,
            arithmetic_rows,
            compressions,
            products,
        })
    }
    pub fn shape(&self) -> PrivateShape {
        self.first.bridge.verifier_shape()
    }
    pub fn verify(&self, certificate: &Certificate) -> bool {
        certificate.height == 1
            && self
                .first
                .verify(&hash_to_scalars(&certificate.statement), &certificate.proof)
    }
    pub fn prove(&self, left: &Certificate, right: &Certificate) -> Option<Certificate> {
        for child in [left, right] {
            if child.height != 0 || !self.base.verify(&hash_to_scalars(&child.statement), &child.proof) {
                return None;
            }
        }
        let trace = record_first(&self.base, [left, right]);
        let statement = crate::recursion_fast::node_statement(&left.statement, &right.statement);
        let proof = self.first.prove(&trace, &hash_to_scalars(&statement))?;
        Some(Certificate {
            height: 1,
            statement,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_relation(input: u64, square: u64, identity: u64) -> Trace {
        trace::start();
        let x = S::input(F192::new(input, 0, 0));
        let y = S::input(F192::new(square, 0, 0));
        (x * x).assert_eq(y);
        let digest = hash(&[(S::u(identity), 8), (x, 24), (y, 24)]);
        let mut program = trace::take();
        program.public = digest.to_vec();
        program
    }

    #[test]
    fn first_merge_rejects_malformed_child_without_host_admission() {
        parallel::init();
        let program = base_relation(2, 4, 17);
        let setup = FirstMergeSetup::new(program.clone()).unwrap();
        let words = std::array::from_fn(|i| program.nodes[program.public[i].0].value);
        let good = Certificate {
            height: 0,
            statement: fiat_shamir::merkle::scalars_to_hash(&words).unwrap(),
            proof: setup.base.prove(&program, &words).unwrap(),
        };
        let merged = setup.prove(&good, &good).unwrap();
        assert!(setup.verify(&merged));
        assert!(!setup.verify(&good));
        assert!(setup.prove(&merged, &good).is_none());
        let mut wrong = good.clone();
        wrong.statement[0] ^= 1;
        assert!(setup.prove(&wrong, &good).is_none());
        // Bypass host child admission and prove the recorded verifier equations.
        let trace = record_first(&setup.base, [&wrong, &good]);
        assert!(!trace.satisfied());
        let statement = crate::recursion_fast::node_statement(&wrong.statement, &good.statement);
        if let Some(proof) = setup.first.prove(&trace, &hash_to_scalars(&statement)) {
            assert!(!setup.verify(&Certificate {
                height: 1,
                statement,
                proof
            }));
        }
    }

    #[test]
    fn fixed_base_relation_closes_and_enforces_equations_without_host_admission() {
        parallel::init();
        assert!(ClosedSetup::from_program(Trace::default()).is_none());
        trace::start();
        let noncanonical = S::input(F192::new(0, 0, 1));
        let mut wide = trace::take();
        wide.public = vec![noncanonical, noncanonical];
        assert!(ClosedSetup::from_program(wide).is_none());
        let canonical = base_relation(1, 1, 17);
        let setup = ClosedSetup::from_program(canonical).unwrap();
        let key = setup.key();
        let a = setup.prove_program(&base_relation(2, 4, 17)).unwrap();
        let b = setup.prove_program(&base_relation(3, 5, 17)).unwrap();
        assert!(setup.verify(&a) && setup.verify(&b));
        assert!(setup.prove_leaf(&[0; 32]).is_none());
        assert!(setup.prove_program(&base_relation(2, 4, 18)).is_none());
        let invalid = base_relation(2, 5, 17);
        assert!(!invalid.satisfied());
        assert!(setup.prove_program(&invalid).is_none());
        // Bypass the public API's admission checks. The base equations must be
        // enforced by the proving circuit itself, rather than only by the host.
        let words = std::array::from_fn(|i| invalid.nodes[invalid.public[i].0].value);
        let statement = fiat_shamir::merkle::scalars_to_hash(&words).unwrap();
        let program = record_program(
            setup.shape,
            &setup.fixed_public,
            0,
            Some(&invalid),
            &key,
            &[0; 32],
            None,
        );
        assert!(!program.satisfied());
        let outputs = setup.outputs(0, &statement);
        if let Some(forged) = setup.backend.prove(&program, &outputs) {
            assert!(!setup.backend.verify(&outputs, &forged));
        }
        let mut current = setup.prove_node(&a, &b).unwrap();
        for height in 2..=3 {
            current = setup.prove_node(&current, &a).unwrap();
            assert_eq!(current.height, height);
            assert!(setup.verify(&current));
            assert_eq!(setup.key(), key);
        }
        let mut changed = current.clone();
        changed.height = 0;
        assert!(!setup.verify(&changed));
        changed = current;
        changed.statement[0] ^= 1;
        assert!(!setup.verify(&changed));
    }

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

    #[test]
    fn split_closure_directly_merges_base_proofs_and_rejects_unauthenticated_children() {
        parallel::init();
        trace::start();
        let noncanonical = S::input(F192::new(0, 0, 1));
        let mut wide = trace::take();
        wide.public = vec![noncanonical, noncanonical];
        assert!(SplitClosedSetup::from_program(wide).is_none());
        let canonical = base_relation(1, 1, 17);
        let setup = SplitClosedSetup::from_program(canonical).unwrap();
        let a = setup.prove_base(&base_relation(2, 4, 17)).unwrap();
        let b = setup.prove_base(&base_relation(3, 5, 17)).unwrap();
        assert_eq!(a.height, 0);
        assert_eq!(b.height, 0);
        assert!(setup.verify(&a) && setup.verify(&b));
        assert!(setup.prove_base(&base_relation(2, 4, 18)).is_none());
        assert!(setup.prove_base(&base_relation(2, 5, 17)).is_none());
        let mut wide = base_relation(2, 4, 17);
        wide.nodes[wide.public[0].0].value = F192::new(0, 0, 1);
        assert!(setup.prove_base(&wide).is_none());
        let parent = setup.prove_node(&a, &b).unwrap();
        assert_eq!(parent.height, 1);
        assert!(setup.verify(&parent));
        let mixed = setup.prove_node(&parent, &a).unwrap();
        assert_eq!(mixed.height, 2);
        assert!(setup.verify(&mixed));
        let repeated = setup.prove_node(&mixed, &parent).unwrap();
        assert_eq!(repeated.height, 3);
        assert!(setup.verify(&repeated));
        let mut wrong_height = a.clone();
        wrong_height.height = 1;
        assert!(!setup.verify(&wrong_height));
        let mut wrong_parent = parent.clone();
        wrong_parent.height = 0;
        assert!(!setup.verify(&wrong_parent));
        let mut wrong_statement = repeated.clone();
        wrong_statement.statement[0] ^= 1;
        assert!(!setup.verify(&wrong_statement));
        // Bypass host admission: a base certificate claimed at height > 0 or with
        // an invalid child proof must not satisfy the split node circuit.
        let forged_child = Certificate {
            height: 1,
            statement: a.statement,
            proof: a.proof.clone(),
        };
        let bad_program = record_split_node(
            &setup.base,
            setup.shape,
            &setup.fixed_public,
            &setup.node_key(),
            Some([&forged_child, &b]),
        );
        assert!(!bad_program.satisfied());
        let valid_program = record_split_node(
            &setup.base,
            setup.shape,
            &setup.fixed_public,
            &setup.node_key(),
            Some([&a, &b]),
        );
        let foreign = Setup::new(base_relation(1, 1, 18)).unwrap();
        let foreign_program = base_relation(2, 4, 18);
        let foreign_words: [F192; 2] = crate::private_recursion::outputs(&foreign_program).try_into().unwrap();
        let foreign_child = Certificate {
            height: 0,
            statement: fiat_shamir::merkle::scalars_to_hash(&foreign_words).unwrap(),
            proof: foreign.prove(&foreign_program, &foreign_words).unwrap(),
        };
        // Prove false base equations without the split API's host precheck.
        // The node circuit must reject this proof under the authorized base key.
        let invalid_base = base_relation(2, 5, 17);
        let invalid_words: [F192; 2] = crate::private_recursion::outputs(&invalid_base).try_into().unwrap();
        let invalid_child = Certificate {
            height: 0,
            statement: fiat_shamir::merkle::scalars_to_hash(&invalid_words).unwrap(),
            proof: setup.base.prove(&invalid_base, &invalid_words).unwrap(),
        };
        let mut malformed = vec![foreign_child, invalid_child];
        let mut changed = a.clone();
        changed.proof.stream[0] += F192::ONE;
        malformed.push(changed);
        let mut changed = a.clone();
        changed.proof.stream.pop();
        malformed.push(changed);
        let mut changed = a.clone();
        changed.proof.stream.push(F192::ZERO);
        malformed.push(changed);
        let mut changed = a.clone();
        changed.proof.merkle.pop();
        malformed.push(changed);
        let mut changed = a.clone();
        changed.statement[0] ^= 1;
        malformed.push(changed);
        for child in malformed {
            assert!(!setup.verify(&child));
            assert!(setup.prove_node(&child, &b).is_none());
            let program = record_split_node(
                &setup.base,
                setup.shape,
                &setup.fixed_public,
                &setup.node_key(),
                Some([&child, &b]),
            );
            assert!(valid_program.same_program(&program));
            assert!(!program.satisfied());
        }
        assert!(valid_program.same_program(&bad_program));
    }
}
