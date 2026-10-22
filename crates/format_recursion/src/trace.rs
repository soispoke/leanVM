use crate::boolean_field::{linear, mul};
use circuit_suite::{Ckt, Wire, Word, blake2s};
use flock::membership::Scalar;
use primitives::field::F192;
use std::{
    cell::RefCell,
    collections::HashMap,
    ops::{Add, Mul},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Constant,
    Input,
    Add(S, S),
    Mul(S, S),
    Frobenius(S),
    Slice(S, usize, usize),
    Pack(Vec<(S, usize)>),
    Hash(Vec<(S, usize)>),
    HashHigh(S),
    Select(S, S, S),
}

#[derive(Clone)]
pub struct Node {
    pub op: Op,
    pub value: F192,
}

#[derive(Default)]
pub struct Trace {
    pub nodes: Vec<Node>,
    pub checks: Vec<(S, S)>,
    pub public: Vec<S>,
    pub sections: Vec<(String, usize)>,
}

thread_local! {
    static TRACE: RefCell<Trace> = RefCell::default();
    // Only public constants are shared. Equal private input values must keep
    // separate identities, and never determine the recorded program's shape.
    static CONSTANTS: RefCell<HashMap<[u64; 3], S>> = RefCell::default();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S(pub usize);

pub fn start() {
    CONSTANTS.with(|c| c.borrow_mut().clear());
    TRACE.with(|t| *t.borrow_mut() = Trace::default());
}
pub fn take() -> Trace {
    CONSTANTS.with(|c| c.borrow_mut().clear());
    TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

pub fn mark(name: &str) {
    TRACE.with(|t| {
        let mut t = t.borrow_mut();
        let at = t.nodes.len();
        t.sections.push((name.to_owned(), at));
    });
}

fn node(op: Op, value: F192) -> S {
    TRACE.with(|t| {
        let mut t = t.borrow_mut();
        let id = S(t.nodes.len());
        t.nodes.push(Node { op, value });
        id
    })
}

impl S {
    pub fn value(self) -> F192 {
        TRACE.with(|t| t.borrow().nodes[self.0].value)
    }
    pub fn input(value: F192) -> Self {
        node(Op::Input, value)
    }
    pub fn c(value: F192) -> Self {
        CONSTANTS.with(|c| {
            *c.borrow_mut()
                .entry([value.c0, value.c1, value.c2])
                .or_insert_with(|| node(Op::Constant, value))
        })
    }
    pub fn u(value: u64) -> Self {
        Self::c(F192::new(value, 0, 0))
    }
    fn constant_value(self) -> Option<F192> {
        TRACE.with(|t| {
            let t = t.borrow();
            matches!(t.nodes[self.0].op, Op::Constant).then_some(t.nodes[self.0].value)
        })
    }
    pub fn slice(self, offset: usize, len: usize) -> Self {
        assert!(len <= 192 && offset + len <= 192);
        let x = self.value();
        let limbs = [x.c0, x.c1, x.c2];
        let mut out = [0u64; 3];
        for i in 0..len {
            out[i / 64] |= ((limbs[(offset + i) / 64] >> ((offset + i) % 64)) & 1) << (i % 64);
        }
        let value = F192::new(out[0], out[1], out[2]);
        if self.constant_value().is_some() {
            Self::c(value)
        } else {
            node(Op::Slice(self, offset, len), value)
        }
    }
    pub fn pack(parts: &[(S, usize)]) -> Self {
        assert!(parts.iter().map(|(_, n)| n).sum::<usize>() <= 192);
        let mut out = [0u64; 3];
        let mut offset = 0;
        for &(s, n) in parts {
            let x = s.value();
            let limbs = [x.c0, x.c1, x.c2];
            for i in 0..n {
                out[(offset + i) / 64] |= ((limbs[i / 64] >> (i % 64)) & 1) << ((offset + i) % 64);
            }
            offset += n;
        }
        node(Op::Pack(parts.to_vec()), F192::new(out[0], out[1], out[2]))
    }
    pub fn select(bit: S, a: S, b: S) -> S {
        assert!(bit.value() == F192::ZERO || bit.value() == F192::ONE);
        node(
            Op::Select(bit, a, b),
            if bit.value() == F192::ZERO {
                a.value()
            } else {
                b.value()
            },
        )
    }
    pub fn assert_eq(self, rhs: S) {
        TRACE.with(|t| t.borrow_mut().checks.push((self, rhs)));
    }
}

impl Add for S {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        if self == rhs {
            return S::u(0);
        }
        match (self.constant_value(), rhs.constant_value()) {
            (Some(a), Some(b)) => S::c(a + b),
            (Some(F192::ZERO), _) => rhs,
            (_, Some(F192::ZERO)) => self,
            _ => node(Op::Add(self, rhs), self.value() + rhs.value()),
        }
    }
}
impl Mul for S {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        match (self.constant_value(), rhs.constant_value()) {
            (Some(a), Some(b)) => S::c(a * b),
            (Some(F192::ZERO), _) | (_, Some(F192::ZERO)) => S::u(0),
            (Some(F192::ONE), _) => rhs,
            (_, Some(F192::ONE)) => self,
            _ => node(Op::Mul(self, rhs), self.value() * rhs.value()),
        }
    }
}
impl Scalar for S {
    fn constant(value: F192) -> Self {
        S::c(value)
    }
    fn frobenius(self) -> Self {
        if let Some(v) = self.constant_value() {
            S::c(v.frobenius())
        } else {
            node(Op::Frobenius(self), self.value().frobenius())
        }
    }
    fn is_nonzero(self) -> bool {
        // Advice is constrained, never trusted as a native acceptance decision.
        let inverse = S::input(self.value().inv());
        (self * inverse).assert_eq(S::u(1));
        true
    }
}

pub fn hash(parts: &[(S, usize)]) -> [S; 2] {
    let mut bytes = Vec::new();
    for &(s, len) in parts {
        assert!(len <= 24);
        let x = s.value();
        let words: Vec<u8> = [x.c0, x.c1, x.c2].iter().flat_map(|x| x.to_le_bytes()).collect();
        bytes.extend_from_slice(&words[..len]);
    }
    let digest = primitives::hash::hash(&bytes);
    let halves = fiat_shamir::merkle::hash_to_scalars(&digest);
    let lo = node(Op::Hash(parts.to_vec()), halves[0]);
    let hi = node(Op::HashHigh(lo), halves[1]);
    [lo, hi]
}

pub fn digest_constant(bytes: &[u8; 32]) -> [S; 2] {
    fiat_shamir::merkle::hash_to_scalars(bytes).map(S::c)
}

fn bits(value: F192) -> Word {
    [value.c0, value.c1, value.c2]
        .into_iter()
        .flat_map(|v| (0..64).map(move |k| Wire::constant((v >> k) & 1 == 1)))
        .collect()
}

pub struct Lowered {
    pub circuit: circuit_suite::Circuit,
    pub sources: Vec<circuit_suite::Src>,
    pub inputs: Vec<bool>,
    pub rows: usize,
    pub stages: Vec<(String, usize)>,
}

impl Trace {
    /// Concatenate fixed verifier circuits, keeping every child's public output.
    pub fn concatenate(traces: &[Trace]) -> Self {
        let mut out = Self::default();
        for (child, trace) in traces.iter().enumerate() {
            let offset = out.nodes.len();
            let shift = |s: S| S(s.0 + offset);
            for node in &trace.nodes {
                let op = match &node.op {
                    Op::Constant => Op::Constant,
                    Op::Input => Op::Input,
                    Op::Add(a, b) => Op::Add(shift(*a), shift(*b)),
                    Op::Mul(a, b) => Op::Mul(shift(*a), shift(*b)),
                    Op::Frobenius(a) => Op::Frobenius(shift(*a)),
                    Op::Slice(a, start, len) => Op::Slice(shift(*a), *start, *len),
                    Op::Pack(parts) => Op::Pack(parts.iter().map(|&(s, n)| (shift(s), n)).collect()),
                    Op::Hash(parts) => Op::Hash(parts.iter().map(|&(s, n)| (shift(s), n)).collect()),
                    Op::HashHigh(a) => Op::HashHigh(shift(*a)),
                    Op::Select(bit, a, b) => Op::Select(shift(*bit), shift(*a), shift(*b)),
                };
                out.nodes.push(Node { op, value: node.value });
            }
            out.checks
                .extend(trace.checks.iter().map(|&(a, b)| (shift(a), shift(b))));
            out.public.extend(trace.public.iter().copied().map(shift));
            out.sections.extend(
                trace
                    .sections
                    .iter()
                    .map(|(name, at)| (format!("child-{child}/{name}"), at + offset)),
            );
        }
        out
    }
    /// Bind an ordered list of child claims using the comparison harness encoding.
    pub fn bind_batch(self) -> Self {
        assert!(self.public.len().is_multiple_of(2) && !self.public.is_empty());
        let claims = self.public.clone();
        CONSTANTS.with(|c| c.borrow_mut().clear());
        TRACE.with(|t| *t.borrow_mut() = self);
        let domain = digest_constant(&primitives::hash::hash(b"matched-application-batch-v1"));
        let mut parts = vec![
            (domain[0], 16),
            (domain[1], 16),
            (S::u((claims.len() / 2) as u64), 16),
            (S::u(0), 16),
        ];
        parts.extend(claims.into_iter().map(|s| (s, 16)));
        let public = hash(&parts);
        let mut out = take();
        out.public = public.to_vec();
        out
    }
    pub fn operation_counts(&self) -> std::collections::BTreeMap<&'static str, usize> {
        let mut out = std::collections::BTreeMap::new();
        for n in &self.nodes {
            let name = match &n.op {
                Op::Constant => "constant",
                Op::Input => "input_scalar",
                Op::Add(..) => "field_add",
                Op::Mul(a, b) if a == b => "field_square",
                Op::Mul(a, b)
                    if matches!(self.nodes[a.0].op, Op::Constant) || matches!(self.nodes[b.0].op, Op::Constant) =>
                {
                    "constant_field_multiply"
                }
                Op::Mul(..) => "field_multiply",
                Op::Frobenius(..) => "frobenius",
                Op::Slice(..) => "bit_slice",
                Op::Pack(..) => "bit_pack",
                Op::Hash(..) => "blake2s_call",
                Op::HashHigh(..) => "hash_high_half",
                Op::Select(..) => "select",
            };
            *out.entry(name).or_insert(0) += 1;
        }
        out
    }

    pub fn satisfied(&self) -> bool {
        self.checks
            .iter()
            .all(|(a, b)| self.nodes[a.0].value == self.nodes[b.0].value)
    }
    pub fn hash_compressions(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| match &n.op {
                Op::Hash(parts) => parts.iter().map(|(_, len)| len).sum::<usize>().div_ceil(64).max(1),
                _ => 0,
            })
            .sum()
    }
    pub fn same_program(&self, other: &Self) -> bool {
        self.nodes.len() == other.nodes.len()
            && self.checks == other.checks
            && self.public == other.public
            && self
                .nodes
                .iter()
                .zip(&other.nodes)
                .all(|(a, b)| a.op == b.op && (!matches!(a.op, Op::Constant) || a.value == b.value))
    }
    pub fn lower(&self, row_limit: usize) -> Result<Lowered, (usize, usize)> {
        self.lower_impl(row_limit, false)
    }

    /// Optimistic capacity diagnostic only. Hash outputs are unconstrained inputs.
    /// The incomplete circuit is deliberately not returned to callers or proved.
    pub fn lower_hash_advice_diagnostic(&self, row_limit: usize) -> Result<(usize, usize), (usize, usize)> {
        self.lower_impl(row_limit, true)
            .map(|lowered| (lowered.rows, lowered.circuit.log_rows))
    }

    fn lower_impl(&self, row_limit: usize, hash_advice: bool) -> Result<Lowered, (usize, usize)> {
        let mut c = Ckt::new();
        let mut values: Vec<Word> = Vec::new();
        let mut inputs = Vec::new();
        let mut stages = Vec::new();
        let mut hash_outputs: std::collections::HashMap<usize, Word> = std::collections::HashMap::new();
        let mut rows_by_operation = std::collections::BTreeMap::new();
        for (index, node) in self.nodes.iter().enumerate() {
            let get = |s: S| &values[s.0];
            let before = c.rows();
            let word = match &node.op {
                Op::Constant => bits(node.value),
                Op::Input => {
                    inputs.extend(bits(node.value).iter().map(|w| w.as_const().unwrap()));
                    c.inputs(192)
                }
                Op::Add(a, b) => c.xor_word(get(*a), get(*b)),
                Op::Mul(a, b) if a == b => linear(&mut c, get(*a), |x| x * x),
                Op::Mul(a, b) if matches!(self.nodes[a.0].op, Op::Constant) => {
                    let k = self.nodes[a.0].value;
                    linear(&mut c, get(*b), |x| x * k)
                }
                Op::Mul(a, b) if matches!(self.nodes[b.0].op, Op::Constant) => {
                    let k = self.nodes[b.0].value;
                    linear(&mut c, get(*a), |x| x * k)
                }
                Op::Mul(a, b) => mul(&mut c, get(*a), get(*b)),
                Op::Frobenius(a) => linear(&mut c, get(*a), |x| x.frobenius()),
                Op::Slice(a, offset, len) => {
                    let mut w = get(*a)[*offset..offset + len].to_vec();
                    w.resize(192, Wire::ZERO);
                    w
                }
                Op::Pack(parts) => {
                    let mut w: Word = parts.iter().flat_map(|(a, n)| get(*a)[..*n].iter().copied()).collect();
                    w.resize(192, Wire::ZERO);
                    w
                }
                Op::Hash(parts) => {
                    let digest = if hash_advice {
                        let hi = self.nodes[index + 1].value;
                        let mut advice = bits(node.value)[..128].to_vec();
                        advice.extend_from_slice(&bits(hi)[..128]);
                        inputs.extend(advice.iter().map(|w| w.as_const().unwrap()));
                        c.inputs(256)
                    } else {
                        let message: Word = parts
                            .iter()
                            .flat_map(|(a, n)| get(*a)[..8 * n].iter().copied())
                            .collect();
                        blake2s::blake2s(&mut c, &message)
                    };
                    hash_outputs.insert(index, digest[128..].to_vec());
                    let mut w = digest[..128].to_vec();
                    w.resize(192, Wire::ZERO);
                    w
                }
                Op::HashHigh(a) => {
                    let mut w = hash_outputs.remove(&a.0).unwrap();
                    w.resize(192, Wire::ZERO);
                    w
                }
                Op::Select(bit, a, b) => (0..192).map(|i| c.mux(get(*bit)[0], get(*b)[i], get(*a)[i])).collect(),
            };
            values.push(word);
            let name = match &node.op {
                Op::Mul(a, b) if a == b => "field_square",
                Op::Mul(a, b)
                    if matches!(self.nodes[a.0].op, Op::Constant) || matches!(self.nodes[b.0].op, Op::Constant) =>
                {
                    "constant_field_multiply"
                }
                Op::Mul(..) => "field_multiply",
                Op::Add(..) => "field_add",
                Op::Frobenius(..) => "frobenius",
                Op::Select(..) => "select",
                Op::Hash(..) if hash_advice => "hash_advice",
                Op::Hash(..) => "hash",
                Op::Input => "input",
                _ => "layout",
            };
            *rows_by_operation.entry(name).or_insert(0usize) += c.rows() - before;
            if c.rows() > row_limit {
                eprintln!(
                    "{}",
                    serde_json::json!({"kind":"partial_lowering_costs", "hash_advice":hash_advice,
                    "nodes_lowered":index,"rows_by_operation":rows_by_operation})
                );
                return Err((index, c.rows()));
            }
            if index % 10000 == 0 {
                stages.push((format!("node-{index}"), c.rows()));
                eprintln!("lower node {index}/{}: {} rows", self.nodes.len(), c.rows());
            }
        }
        let checks: Word = self
            .checks
            .iter()
            .map(|(a, b)| c.eq(&values[a.0], &values[b.0]))
            .collect();
        let valid = c.all(&checks);
        let mut public: Word = self
            .public
            .iter()
            .flat_map(|s| values[s.0][..128].iter().copied())
            .collect();
        public.push(valid);
        public.resize(512, Wire::ZERO);
        let rows = c.rows();
        let (circuit, sources) = c.finish(&public);
        Ok(Lowered {
            circuit,
            sources,
            inputs,
            rows,
            stages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_suite::read_statement;

    #[test]
    fn constants_share_only_public_values_and_reset_with_each_trace() {
        start();
        let value = F192::new(17, 23, 41);
        let constant = S::c(value);
        assert_eq!(S::c(value), constant);
        let left = S::input(value);
        let right = S::input(value);
        assert_ne!(left, right);
        assert_ne!(left, constant);
        let first = take();
        assert_eq!(first.nodes.len(), 3);
        // Taking a trace clears the cache even without an explicit start.
        let new_constant = S::c(F192::ONE);
        assert_eq!(new_constant.0, 0);
        assert_eq!(new_constant.value(), F192::ONE);
        start();
        let next = S::c(value);
        assert_eq!(next.0, 0);
        assert_eq!(next.value(), value);
        assert_eq!(take().nodes.len(), 1);
    }

    #[test]
    fn constant_sharing_keeps_recorded_operations_independent_of_input_values() {
        let record = |value| {
            start();
            let input = S::input(value);
            let a = input + S::u(17);
            let b = input * S::u(17);
            let c = input + S::c(F192::new(0, 1, 0));
            let d = input * S::c(F192::new(0, 1, 0));
            let mut trace = take();
            trace.public.extend([a, b, c, d]);
            trace
        };
        let first = record(F192::ZERO);
        let second = record(F192::new(31, 37, 43));
        assert_eq!(first.public, second.public);
        assert_eq!(
            first.nodes.iter().map(|n| &n.op).collect::<Vec<_>>(),
            second.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
        assert_eq!(first.nodes.iter().filter(|n| n.op == Op::Constant).count(), 2);
        assert_eq!(first.nodes[first.public[0].0].value, F192::new(17, 0, 0));
        assert_eq!(
            second.nodes[second.public[1].0].value,
            F192::new(31, 37, 43) * F192::new(17, 0, 0)
        );
    }

    #[test]
    fn concatenation_preserves_all_dependencies_checks_and_outputs() {
        let traces: Vec<_> = (0..2)
            .map(|i| {
                start();
                let x = S::input(F192::new(i + 3, 0, 0));
                let y = x * x + S::u(1);
                let f = y.frobenius();
                let bit = x.slice(0, 1);
                let choice = S::select(bit, y, f);
                let packed = S::pack(&[(choice.slice(0, 64), 64)]);
                let output = hash(&[(packed, 8)]);
                y.assert_eq(S::c(y.value()));
                let mut t = take();
                t.public = output.to_vec();
                t
            })
            .collect();
        let joined = Trace::concatenate(&traces);
        assert_eq!(joined.nodes.len(), traces.iter().map(|t| t.nodes.len()).sum::<usize>());
        let values: Vec<_> = joined.nodes.iter().map(|n| n.value).collect();
        let public: Vec<_> = joined.public.iter().map(|s| values[s.0]).collect();
        assert_eq!(crate::replay::requests(&joined, &values, &public).unwrap().len(), 2);
        // Installing a detached trace must discard any unrelated active cache.
        start();
        for _ in 0..8 {
            S::input(F192::ZERO);
        }
        S::u(0);
        S::u(2);
        let bound = joined.bind_batch();
        let values: Vec<_> = bound.nodes.iter().map(|n| n.value).collect();
        let public: Vec<_> = bound.public.iter().map(|s| values[s.0]).collect();
        assert_eq!(crate::replay::requests(&bound, &values, &public).unwrap().len(), 3);
    }

    #[test]
    fn field_operations_match_native_and_bind_their_inputs() {
        let mut state = 0x123456789abcdef0u64;
        for _ in 0..8 {
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                state
            };
            let a = F192::new(next(), next(), next());
            let b = F192::new(next(), next(), next());
            start();
            let x = S::input(a);
            let y = S::input(b);
            let z = x * y;
            let q = x * x;
            let f = x.frobenius();
            z.assert_eq(S::c(a * b));
            q.assert_eq(S::c(a * a));
            f.assert_eq(S::c(a.frobenius()));
            let constant_product = x * S::c(b);
            constant_product.assert_eq(S::c(a * b));
            let trace = take();
            let lower = trace.lower(1 << 20).ok().unwrap();
            lower.circuit.check_wired().unwrap();
            let eval = |inputs: &[bool]| read_statement(&lower.circuit.values(inputs), &lower.sources)[0] & 1;
            assert_eq!(eval(&lower.inputs), 1);
            let mut bad = lower.inputs.clone();
            bad[17] = !bad[17];
            assert_eq!(eval(&bad), 0);
        }
    }

    #[test]
    fn hashes_match_native_across_block_boundaries() {
        for len in [0usize, 1, 63, 64, 65, 128] {
            start();
            let bytes: Vec<u8> = (0..len).map(|i| i.wrapping_mul(37) as u8).collect();
            let parts: Vec<_> = bytes
                .chunks(24)
                .map(|part| {
                    let mut padded = [0u8; 24];
                    padded[..part.len()].copy_from_slice(part);
                    let word = |i| u64::from_le_bytes(padded[i..i + 8].try_into().unwrap());
                    (S::input(F192::new(word(0), word(8), word(16))), part.len())
                })
                .collect();
            let digest = hash(&parts);
            let expected = digest_constant(&primitives::hash::hash(&bytes));
            for i in 0..2 {
                digest[i].assert_eq(expected[i]);
            }
            let trace = take();
            let lower = trace.lower(1 << 20).ok().unwrap();
            assert_eq!(
                read_statement(&lower.circuit.values(&lower.inputs), &lower.sources)[0],
                1
            );
        }
    }

    #[test]
    fn merkle_selection_uses_the_constrained_bit() {
        for bit in [0u64, 1] {
            start();
            let input = S::input(F192::new(bit, 0, 0));
            let left = S::input(F192::new(0x1234, 0x5678, 0));
            let right = S::input(F192::new(0x9abc, 0xdef0, 0));
            let selected = S::select(input.slice(0, 1), left, right);
            selected.assert_eq(S::c(if bit == 0 { left.value() } else { right.value() }));
            let trace = take();
            let lower = trace.lower(1 << 20).ok().unwrap();
            assert_eq!(
                read_statement(&lower.circuit.values(&lower.inputs), &lower.sources)[0],
                1
            );
            let mut bad = lower.inputs.clone();
            bad[0] = !bad[0];
            assert_eq!(read_statement(&lower.circuit.values(&bad), &lower.sources)[0], 0);
        }
    }

    #[test]
    fn nonzero_advice_is_constrained() {
        start();
        let x = S::input(F192::new(17, 39, 7));
        assert!(x.is_nonzero());
        let trace = take();
        let lower = trace.lower(1 << 20).ok().unwrap();
        let valid = |inputs: &[bool]| read_statement(&lower.circuit.values(inputs), &lower.sources)[0];
        assert_eq!(valid(&lower.inputs), 1);
        let mut bad = lower.inputs.clone();
        bad[192] = !bad[192];
        assert_eq!(valid(&bad), 0);
        start();
        let zero = S::input(F192::ZERO);
        assert!(zero.is_nonzero());
        assert!(!take().satisfied());
    }
}
