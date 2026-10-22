//! Private native-field lowering of the fixed trace language.
//!
//! Arithmetic constraints bind all projections and all BLAKE2s compression I/O.
//! A separate private bridge must prove the named compressions. This compiler
//! alone is not a proof system or a formal security certificate.

use crate::{
    native_arithmetic::Circuit,
    trace::{Op, S, Trace},
};
use flock::hash::{Compression, blake2s_compress, param_iv};
use primitives::field::F192;
use std::collections::{BTreeMap, BTreeSet};

pub struct Lowered {
    pub circuit: Circuit,
    pub connectors: Vec<[usize; 18]>,
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    /// The verifier fixes these anchors and constants before the original outputs.
    pub fixed_public: Vec<F192>,
    pub original_public_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub rows: usize,
    pub variables: usize,
    pub compressions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rows: 1 << 24,
            variables: 1 << 24,
            compressions: 1 << 16,
        }
    }
}

fn inferred_widths(program: &Trace) -> Vec<usize> {
    let mut widths = vec![192; program.nodes.len()];
    for &(a, b) in &program.checks {
        for (whole, projection) in [(a, b), (b, a)] {
            if let Some(node) = program.nodes.get(projection.0)
                && let Op::Slice(source, 0, width) = node.op
                && source == whole
                && width <= 192
                && whole.0 < program.nodes.len()
            {
                widths[whole.0] = widths[whole.0].min(width);
            }
        }
    }
    widths
}

struct Estimate {
    bound: Limits,
    widths: Vec<usize>,
    bits: Vec<bool>,
    limbs: Vec<bool>,
    pending: Vec<u8>,
    used: Vec<u8>,
}
impl Estimate {
    fn charge(&mut self, rows: usize, variables: usize) -> Option<()> {
        self.bound.rows = self.bound.rows.checked_add(rows)?;
        self.bound.variables = self.bound.variables.checked_add(variables)?;
        Some(())
    }
    fn project(&mut self, program: &Trace, source: S, at: usize) -> Option<()> {
        if source.0 >= at {
            return None;
        }
        if !self.bits[source.0] && !matches!(program.nodes[source.0].op, Op::Constant) {
            let width = self.widths[source.0];
            self.charge(2 * width + 1, 2 * width)?;
        }
        self.bits[source.0] = true;
        Some(())
    }
    fn limb_source(&mut self, program: &Trace, source: S, at: usize, words: usize) -> Option<()> {
        if source.0 >= at {
            return None;
        }
        if words == 0 {
            return Some(());
        }
        if !self.limbs[source.0] {
            if matches!(program.nodes[source.0].op, Op::Constant) {
                self.charge(0, 3)?;
            } else if self.widths[source.0] > 64 {
                if self.bits[source.0] {
                    self.charge(192, 195)?;
                } else {
                    self.charge(2, 4)?;
                    self.pending[source.0] = (1 << self.widths[source.0].div_ceil(64)) - 1;
                }
            }
            self.limbs[source.0] = true;
        }
        self.used[source.0] |= (1 << words) - 1;
        Some(())
    }
}

/// Checked allocation bound with aligned limb routing and shared bit caches.
/// Backend index limits must be checked separately on the actual returned shape.
fn preflight(program: &Trace, limits: Limits) -> Option<Limits> {
    let variables = program.nodes.len().checked_add(194)?;
    if variables > limits.variables || program.public.len() > limits.rows || program.checks.len() > limits.rows {
        return None;
    }
    let count = program.nodes.len();
    let mut e = Estimate {
        bound: Limits {
            rows: program.checks.len(),
            variables,
            compressions: 0,
        },
        widths: inferred_widths(program),
        bits: vec![false; count],
        limbs: vec![false; count],
        pending: vec![0; count],
        used: vec![0; count],
    };
    for (at, node) in program.nodes.iter().enumerate() {
        match &node.op {
            Op::Constant | Op::Add(..) | Op::Mul(..) => e.charge(1, 0)?,
            Op::Select(..) => e.charge(2, 1)?,
            Op::Frobenius(..) => e.charge(64, 63)?,
            Op::Slice(source, start, len) => {
                if start.checked_add(*len)? > 192 {
                    return None;
                }
                e.project(program, *source, at)?;
                e.charge(len.checked_add(1)?, len.checked_add(1)?)?;
                e.bits[at] = true;
            }
            Op::Pack(parts) => {
                let mut width = 0usize;
                for &(source, len) in parts {
                    width = width.checked_add(len)?;
                    if width > 192 {
                        return None;
                    }
                    e.project(program, source, at)?;
                }
                e.charge(width.checked_add(1)?, width.checked_add(1)?)?;
                e.bits[at] = true;
            }
            Op::Hash(parts) => {
                if program.nodes.get(at + 1)?.op != Op::HashHigh(S(at)) {
                    return None;
                }
                let aligned = parts.iter().all(|&(_, len)| len % 8 == 0);
                let mut bytes = 0usize;
                for &(source, len) in parts {
                    if len > 24 {
                        return None;
                    }
                    bytes = bytes.checked_add(len)?;
                    if aligned {
                        e.limb_source(program, source, at, len / 8)?;
                    } else {
                        e.project(program, source, at)?;
                    }
                }
                let count = bytes.div_ceil(64).max(1);
                e.bound.compressions = e.bound.compressions.checked_add(count)?;
                if aligned {
                    e.charge(2, count.checked_mul(6)?.checked_add(5)?)?;
                } else {
                    e.charge(
                        count.checked_mul(512)?.checked_add(2)?,
                        count.checked_mul(526)?.checked_add(5)?,
                    )?;
                }
                e.widths[at] = e.widths[at].min(128);
                e.widths[at + 1] = e.widths[at + 1].min(128);
                e.limbs[at] = true;
                e.limbs[at + 1] = true;
            }
            _ => (),
        }
        if e.bound.rows > limits.rows
            || e.bound.variables > limits.variables
            || e.bound.compressions > limits.compressions
        {
            return None;
        }
    }
    let pending: usize = e
        .pending
        .iter()
        .zip(&e.used)
        .map(|(&p, &u)| (p & !u).count_ones() as usize)
        .sum();
    e.charge(pending.checked_mul(129)?, pending.checked_mul(128)?)?;
    (e.bound.rows <= limits.rows
        && e.bound.variables <= limits.variables
        && e.bound.compressions <= limits.compressions)
        .then_some(e.bound)
}

/// Checked conservative operation count. This does not construct the circuit,
/// a witness or a backend index and is suitable for admission planning.
pub fn allocation_bound(program: &Trace) -> Option<Limits> {
    preflight(
        program,
        Limits {
            rows: usize::MAX,
            variables: usize::MAX,
            compressions: usize::MAX,
        },
    )
}

impl Lowered {
    /// Public input for the bridge: immutable anchors/constants, then the
    /// caller's expected original trace outputs. No private projections appear.
    pub fn expected_public(&self, outputs: &[F192]) -> Option<Vec<F192>> {
        if outputs.len() != self.original_public_len {
            return None;
        }
        let mut public = self.fixed_public.clone();
        public.extend_from_slice(outputs);
        Some(public)
    }
}

struct Compiler {
    rows: Vec<[usize; 4]>,
    values: Vec<F192>,
    constants: BTreeMap<(u64, u64, u64), usize>,
    public: Vec<usize>,
    bits: Vec<Option<Vec<usize>>>,
    constant_nodes: Vec<bool>,
    widths: Vec<usize>,
    limbs: Vec<Option<[usize; 3]>>,
    pending_limbs: Vec<usize>,
    typed: BTreeSet<usize>,
    connectors: Vec<[usize; 18]>,
    compressions: Vec<Compression>,
}

fn key(value: F192) -> (u64, u64, u64) {
    (value.c0, value.c1, value.c2)
}

fn basis(bit: usize) -> F192 {
    let mut limbs = [0; 3];
    limbs[bit / 64] = 1 << (bit % 64);
    F192::new(limbs[0], limbs[1], limbs[2])
}

fn pack32(a: u32, b: u32) -> u64 {
    u64::from(a) | (u64::from(b) << 32)
}

impl Compiler {
    fn variable(&mut self, value: F192) -> usize {
        let at = self.values.len();
        self.values.push(value);
        at
    }
    fn constant(&mut self, value: F192) -> usize {
        if let Some(&at) = self.constants.get(&key(value)) {
            return at;
        }
        let at = self.variable(value);
        self.constants.insert(key(value), at);
        self.public.push(at);
        at
    }
    fn equal(&mut self, a: usize, b: usize) {
        self.rows.push([a, 1, 0, b]);
    }
    fn boolean(&mut self, a: usize) {
        self.rows.push([a, a, a, 0]);
    }
    fn add(&mut self, a: usize, b: usize) -> usize {
        let out = self.variable(self.values[a] + self.values[b]);
        self.rows.push([a, 1, b, out]);
        out
    }
    /// Exact binary coefficient reconstruction, including an empty slice.
    fn reconstruct(&mut self, bits: &[usize]) -> usize {
        let fixed = bits
            .iter()
            .enumerate()
            .filter(|&(_, &bit)| bit == 1)
            .fold(F192::ZERO, |acc, (i, _)| acc + basis(i));
        let mut acc = self.constant(fixed);
        for (i, &bit) in bits.iter().enumerate() {
            if bit <= 1 {
                continue;
            }
            let coefficient = self.constant(basis(i));
            let out = self.variable(self.values[bit] * self.values[coefficient] + self.values[acc]);
            self.rows.push([bit, coefficient, acc, out]);
            acc = out;
        }
        acc
    }

    fn source_limbs(&mut self, source: usize) -> [usize; 3] {
        if let Some(limbs) = self.limbs[source] {
            return limbs;
        }
        let value = self.values[source + 2];
        let native = [value.c0, value.c1, value.c2];
        let limbs = if self.constant_nodes[source] {
            std::array::from_fn(|i| self.constant(F192::new(native[i], 0, 0)))
        } else if self.widths[source] <= 64 {
            // A fixed explicit source == Slice(source,0,width) check supplies
            // this range; the slice lowering also reconstructs the whole source.
            [source + 2, 0, 0]
        } else if let Some(bits) = self.bits[source].clone() {
            std::array::from_fn(|i| self.reconstruct(&bits[64 * i..64 * (i + 1)]))
        } else {
            let limbs = std::array::from_fn(|i| {
                if i * 64 >= self.widths[source] {
                    0
                } else {
                    let variable = self.variable(F192::new(native[i], 0, 0));
                    self.pending_limbs.push(variable);
                    variable
                }
            });
            let y = self.constant(F192::new(0, 1, 0));
            let y2 = self.constant(F192::new(0, 0, 1));
            let partial = self.variable(self.values[limbs[0]] + self.values[limbs[1]] * self.values[y]);
            self.rows.push([limbs[1], y, limbs[0], partial]);
            self.rows.push([limbs[2], y2, partial, source + 2]);
            limbs
        };
        self.limbs[source] = Some(limbs);
        limbs
    }

    fn constrain_unused_limbs(&mut self) {
        for variable in self.pending_limbs.clone() {
            if self.typed.contains(&variable) {
                continue;
            }
            let value = self.values[variable].c0;
            let bits: Vec<_> = (0..64)
                .map(|bit| {
                    let variable = self.variable(F192::new((value >> bit) & 1, 0, 0));
                    self.boolean(variable);
                    variable
                })
                .collect();
            let reconstructed = self.reconstruct(&bits);
            self.equal(reconstructed, variable);
        }
    }
    /// Every source has at most one full decomposition. High bits are never
    /// discarded: Boolean bits reconstruct the complete original field value.
    fn decompose(&mut self, source: usize) -> Vec<usize> {
        if let Some(bits) = &self.bits[source] {
            return bits.clone();
        }
        let value = self.values[source + 2];
        let limbs = [value.c0, value.c1, value.c2];
        if self.constant_nodes[source] {
            let bits: Vec<_> = (0..192).map(|i| ((limbs[i / 64] >> (i % 64)) & 1) as usize).collect();
            self.bits[source] = Some(bits.clone());
            return bits;
        }
        let mut bits: Vec<_> = (0..self.widths[source])
            .map(|i| {
                let bit = self.variable(F192::new((limbs[i / 64] >> (i % 64)) & 1, 0, 0));
                self.boolean(bit);
                bit
            })
            .collect();
        let reconstructed = self.reconstruct(&bits);
        self.equal(reconstructed, source + 2);
        bits.resize(192, 0);
        self.bits[source] = Some(bits.clone());
        bits
    }
    fn hash(&mut self, program: &Trace, at: usize, parts: &[(S, usize)]) -> Option<()> {
        if program.nodes.get(at + 1)?.op != Op::HashHigh(S(at)) {
            return None;
        }
        let aligned = parts.iter().all(|&(_, bytes)| bytes % 8 == 0);
        let mut message_bits = Vec::new();
        let mut message_words = Vec::new();
        let mut bytes = 0usize;
        for &(source, bytes) in parts {
            if source.0 >= at || bytes > 24 {
                return None;
            }
            if bytes == 0 {
                continue;
            }
            if aligned {
                message_words.extend_from_slice(&self.source_limbs(source.0)[..bytes / 8]);
            } else {
                message_bits.extend_from_slice(&self.decompose(source.0)[..8 * bytes]);
            }
        }
        for &(_, len) in parts {
            bytes = bytes.checked_add(len)?;
        }
        let count = bytes.div_ceil(64).max(1);
        let initial = param_iv();
        let mut cv: [usize; 4] =
            std::array::from_fn(|i| self.constant(F192::new(pack32(initial[2 * i], initial[2 * i + 1]), 0, 0)));
        let mut native_cv = initial;
        for block in 0..count {
            let words: [usize; 8] = if aligned {
                std::array::from_fn(|i| *message_words.get(block * 8 + i).unwrap_or(&0))
            } else {
                let start = 512 * block;
                let end = (start + 512).min(message_bits.len());
                let mut bits = message_bits[start.min(message_bits.len())..end].to_vec();
                bits.resize(512, 0);
                std::array::from_fn(|i| self.reconstruct(&bits[64 * i..64 * (i + 1)]))
            };
            self.typed.extend(words);
            let native_words: [u32; 16] =
                std::array::from_fn(|i| (self.values[words[i / 2]].c0 >> (32 * (i % 2))) as u32);
            let counter = ((block + 1) * 64).min(bytes) as u64;
            let flag = if block + 1 == count { u32::MAX } else { 0 };
            let compression = (native_cv, native_words, counter, flag, 0);
            let output = blake2s_compress(&native_cv, &native_words, counter, flag, 0);
            let outputs: [usize; 4] =
                std::array::from_fn(|i| self.variable(F192::new(pack32(output[2 * i], output[2 * i + 1]), 0, 0)));
            let t = self.constant(F192::new(counter, 0, 0));
            let flags = self.constant(F192::new(u64::from(flag), 0, 0));
            self.connectors.push(std::array::from_fn(|i| match i {
                0..4 => cv[i],
                4..8 => outputs[i - 4],
                8..16 => words[i - 8],
                16 => t,
                17 => flags,
                _ => unreachable!(),
            }));
            self.compressions.push(compression);
            self.typed.extend(outputs);
            cv = outputs;
            native_cv = output;
        }
        let y = self.constant(F192::new(0, 1, 0));
        self.rows.push([cv[1], y, cv[0], at + 2]);
        self.rows.push([cv[3], y, cv[2], at + 3]);
        // The bridge types each output as F64, and these equations combine two
        // such words. Any later decomposition still reconstructs the whole half.
        self.widths[at] = self.widths[at].min(128);
        self.widths[at + 1] = self.widths[at + 1].min(128);
        self.limbs[at] = Some([cv[0], cv[1], 0]);
        self.limbs[at + 1] = Some([cv[2], cv[3], 0]);
        Some(())
    }
}

/// Lower one witness for a trusted fixed program. Operations, equality checks,
/// public output positions and constant values must match the setup program.
/// Invalid computed values produce an unsatisfied witness, never new constraints.
pub fn lower(program: &Trace, witness: &Trace) -> Option<Lowered> {
    lower_with_limits(program, witness, Limits::default())
}

pub fn lower_with_limits(program: &Trace, witness: &Trace, limits: Limits) -> Option<Lowered> {
    if !program.same_program(witness) {
        return None;
    }
    preflight(program, limits)?;
    let widths = inferred_widths(program);
    let mut c = Compiler {
        rows: Vec::new(),
        values: vec![F192::ZERO, F192::ONE],
        constants: BTreeMap::from([(key(F192::ZERO), 0), (key(F192::ONE), 1)]),
        public: vec![0, 1],
        bits: vec![None; program.nodes.len()],
        constant_nodes: program.nodes.iter().map(|n| matches!(n.op, Op::Constant)).collect(),
        widths,
        limbs: vec![None; program.nodes.len()],
        pending_limbs: Vec::new(),
        typed: BTreeSet::from([0, 1]),
        connectors: Vec::new(),
        compressions: Vec::new(),
    };
    c.values.extend(witness.nodes.iter().map(|n| n.value));
    for (i, node) in program.nodes.iter().enumerate() {
        let source = |s: S| (s.0 < i).then_some(s.0 + 2);
        let z = i + 2;
        match &node.op {
            Op::Constant => {
                if let Some(&canonical) = c.constants.get(&key(node.value)) {
                    c.equal(canonical, z);
                } else {
                    c.public.push(z);
                    c.constants.insert(key(node.value), z);
                }
            }
            Op::Input => (),
            Op::Add(a, b) => c.rows.push([source(*a)?, 1, source(*b)?, z]),
            Op::Mul(a, b) => c.rows.push([source(*a)?, source(*b)?, 0, z]),
            Op::Frobenius(a) => {
                let mut value = source(*a)?;
                for step in 0..64 {
                    let out = if step == 63 {
                        z
                    } else {
                        c.variable(c.values[value] * c.values[value])
                    };
                    c.rows.push([value, value, 0, out]);
                    value = out;
                }
            }
            Op::Slice(a, start, len) => {
                source(*a)?;
                if start.checked_add(*len)? > 192 {
                    return None;
                }
                let bits = c.decompose(a.0);
                let mut output = bits[*start..start + len].to_vec();
                let out = c.reconstruct(&output);
                c.equal(out, z);
                output.resize(192, 0);
                c.bits[i] = Some(output);
            }
            Op::Pack(parts) => {
                let mut output = Vec::new();
                for &(a, len) in parts {
                    source(a)?;
                    if output.len().checked_add(len)? > 192 {
                        return None;
                    }
                    output.extend_from_slice(&c.decompose(a.0)[..len]);
                }
                let out = c.reconstruct(&output);
                c.equal(out, z);
                output.resize(192, 0);
                c.bits[i] = Some(output);
            }
            Op::Select(bit, a, b) => {
                let bit = source(*bit)?;
                let a = source(*a)?;
                let b = source(*b)?;
                c.boolean(bit);
                let difference = c.add(a, b);
                c.rows.push([bit, difference, a, z]);
            }
            Op::Hash(parts) => c.hash(program, i, parts)?,
            Op::HashHigh(a) => {
                if a.0.checked_add(1)? != i || !matches!(program.nodes.get(a.0)?.op, Op::Hash(_)) {
                    return None;
                }
            }
        }
    }
    for &(a, b) in &program.checks {
        if a.0 >= program.nodes.len() || b.0 >= program.nodes.len() {
            return None;
        }
        c.equal(a.0 + 2, b.0 + 2);
    }
    c.constrain_unused_limbs();
    let fixed_public = c.public.iter().map(|&i| c.values[i]).collect();
    for s in &program.public {
        if s.0 >= program.nodes.len() {
            return None;
        }
        c.public.push(s.0 + 2);
    }
    Some(Lowered {
        circuit: Circuit {
            variables: c.values.len(),
            rows: c.rows,
            public: c.public,
        },
        connectors: c.connectors,
        values: c.values,
        compressions: c.compressions,
        fixed_public,
        original_public_len: program.public.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{self, Node};
    use flock::membership::Scalar;

    fn rows_hold(lowered: &Lowered) -> bool {
        lowered
            .circuit
            .rows
            .iter()
            .all(|&[x, y, u, z]| lowered.values[x] * lowered.values[y] + lowered.values[u] == lowered.values[z])
    }
    fn connectors_hold(lowered: &Lowered) -> bool {
        lowered
            .connectors
            .iter()
            .zip(&lowered.compressions)
            .all(|(variables, block)| {
                let output = blake2s_compress(&block.0, &block.1, block.2, block.3, block.4);
                variables.iter().enumerate().all(|(i, &v)| {
                    let word = match i {
                        0..4 => pack32(block.0[2 * i], block.0[2 * i + 1]),
                        4..8 => pack32(output[2 * (i - 4)], output[2 * (i - 4) + 1]),
                        8..16 => pack32(block.1[2 * (i - 8)], block.1[2 * (i - 8) + 1]),
                        16 => block.2,
                        17 => pack32(block.3, block.4),
                        _ => unreachable!(),
                    };
                    lowered.values[v] == F192::new(word, 0, 0)
                })
            })
    }
    fn copy_trace(t: &Trace) -> Trace {
        Trace {
            nodes: t.nodes.clone(),
            checks: t.checks.clone(),
            public: t.public.clone(),
            sections: t.sections.clone(),
        }
    }
    fn public(t: &Trace) -> Vec<F192> {
        t.public.iter().map(|s| t.nodes[s.0].value).collect()
    }

    #[test]
    fn native_operations_and_private_projections_are_constrained() {
        trace::start();
        let x = S::input(F192::new(0xabcdef, 0x1234, 0x5678));
        let y = S::input(F192::new(0xfedcba, 7, 11));
        let selector = S::input(F192::ONE);
        let add = x + y;
        let mul = x * y;
        let frob = x.frobenius();
        let lo = x.slice(4, 70);
        let high = x.slice(128, 64);
        let packed = S::pack(&[(lo, 23), (y, 17), (high, 64)]);
        let selected = S::select(selector, packed, mul);
        let zero = S::pack(&[]);
        zero.assert_eq(S::u(0));
        let mut t = trace::take();
        t.public = vec![add, mul, frob, lo, high, packed, selected];
        let mut lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered));
        assert!(lowered.connectors.is_empty());
        assert_eq!(
            lowered.expected_public(&public(&t)).unwrap(),
            lowered
                .circuit
                .public
                .iter()
                .map(|&i| lowered.values[i])
                .collect::<Vec<_>>()
        );
        assert_eq!(lowered.original_public_len, 7);
        let original = lowered.values[x.0 + 2];
        lowered.values[x.0 + 2] += F192::new(0, 0, 1 << 63);
        assert!(!rows_hold(&lowered));
        lowered.values[x.0 + 2] = original;
        lowered.values[selector.0 + 2] = F192::new(2, 0, 0);
        assert!(!rows_hold(&lowered));
        for target in [lo, packed, frob, selected] {
            let mut witness = copy_trace(&t);
            witness.nodes[target.0].value += F192::ONE;
            assert!(!rows_hold(&lower(&t, &witness).unwrap()));
        }
    }

    #[test]
    fn decompositions_are_cached_and_boolean() {
        trace::start();
        let input = S::input(F192::new(17, 19, 23));
        input.slice(0, 64);
        input.slice(64, 128);
        let t = trace::take();
        let mut lowered = lower(&t, &t).unwrap();
        let bit_rows: Vec<_> = lowered
            .circuit
            .rows
            .iter()
            .filter(|r| r[0] == r[1] && r[1] == r[2] && r[3] == 0)
            .copied()
            .collect();
        assert_eq!(bit_rows.len(), 192);
        lowered.values[bit_rows[0][0]] = F192::new(2, 0, 0);
        assert!(!rows_hold(&lowered));
    }

    #[test]
    fn private_hash_routing_matches_native_boundaries_and_chains() {
        for bytes in [0usize, 1, 24, 63, 64, 65, 128, 129] {
            trace::start();
            let message: Vec<u8> = (0..bytes).map(|i| (i * 37 + 11) as u8).collect();
            let mut parts = Vec::new();
            for chunk in message.chunks(24) {
                let mut limbs = [0u64; 3];
                for (i, &byte) in chunk.iter().enumerate() {
                    limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
                }
                parts.push((S::input(F192::new(limbs[0], limbs[1], limbs[2])), chunk.len()));
            }
            let outputs = trace::hash(&parts);
            let mut t = trace::take();
            t.public = outputs.to_vec();
            let mut lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered));
            assert!(connectors_hold(&lowered));
            assert_eq!(lowered.compressions.len(), bytes.div_ceil(64).max(1));
            assert_eq!(
                fiat_shamir::merkle::scalars_to_hash(&[t.nodes[outputs[0].0].value, t.nodes[outputs[1].0].value])
                    .unwrap(),
                primitives::hash::hash(&message)
            );
            for pair in lowered.connectors.windows(2) {
                assert_eq!(pair[0][4..8], pair[1][..4]);
            }
            let end = lowered.connectors.len() - 1;
            let cv = lowered.connectors[end][0];
            lowered.values[cv] += F192::ONE;
            assert!(!connectors_hold(&lowered));
            if lowered.connectors.len() > 1 {
                assert!(rows_hold(&lowered));
            }
            let mut witness = copy_trace(&t);
            witness.nodes[outputs[0].0].value += F192::new(0, 0, 1);
            assert!(!rows_hold(&lower(&t, &witness).unwrap()));
        }
    }

    #[test]
    fn fixed_program_checks_and_constants_cannot_be_changed() {
        trace::start();
        let x = S::input(F192::ONE);
        x.assert_eq(S::u(1));
        let t = trace::take();
        let mut changed = copy_trace(&t);
        changed.checks.clear();
        assert!(lower(&t, &changed).is_none());
        changed = copy_trace(&t);
        changed.nodes[1].value = F192::ZERO;
        assert!(lower(&t, &changed).is_none());
        changed = copy_trace(&t);
        changed.nodes[x.0].value = F192::ZERO;
        assert!(!rows_hold(&lower(&t, &changed).unwrap()));
        changed = copy_trace(&t);
        changed.nodes[x.0].op = Op::Add(x, x);
        assert!(lower(&changed, &changed).is_none());
        let invalid = Trace {
            nodes: vec![Node {
                op: Op::HashHigh(S(0)),
                value: F192::ZERO,
            }],
            ..Trace::default()
        };
        assert!(lower(&invalid, &invalid).is_none());
    }

    #[test]
    fn preflight_rejects_small_budgets_and_reuses_projected_bits() {
        trace::start();
        let a = S::input(F192::new(99, 17, 23));
        let slice = a.slice(4, 16);
        let packed = S::pack(&[(slice, 8), (slice, 8)]);
        packed.slice(0, 16);
        let constant = S::u(33);
        trace::hash(&[(constant, 8)]);
        let t = trace::take();
        let lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        let bits = lowered
            .circuit
            .rows
            .iter()
            .filter(|r| r[0] == r[1] && r[1] == r[2] && r[3] == 0)
            .count();
        assert_eq!(bits, 192);
        for limits in [
            Limits {
                rows: 1,
                ..Limits::default()
            },
            Limits {
                variables: 1,
                ..Limits::default()
            },
            Limits {
                compressions: 0,
                ..Limits::default()
            },
        ] {
            assert!(lower_with_limits(&t, &t, limits).is_none());
        }
    }

    #[test]
    fn aligned_hashes_route_private_limbs_and_type_unused_words() {
        trace::start();
        let source = S::input(F192::new(11, 17, 23));
        let hash = trace::hash(&[(source, 24)]);
        trace::hash(&[(hash[0], 16), (hash[1], 16)]);
        let t = trace::take();
        let lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert!(lowered.circuit.rows.len() < 16);
        assert_eq!(lowered.connectors[1][8..12], lowered.connectors[0][4..8]);
        let bound = allocation_bound(&t).unwrap();
        assert!(lowered.circuit.rows.len() <= bound.rows && lowered.values.len() <= bound.variables);

        trace::start();
        let source = S::input(F192::new(11, 17, 23));
        trace::hash(&[(source, 8)]);
        let t = trace::take();
        let mut lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        let upper = lowered
            .circuit
            .rows
            .iter()
            .find(|r| r[3] == source.0 + 2 && lowered.values[r[1]] == F192::new(0, 0, 1))
            .unwrap()[0];
        let delta = F192::new(0, 1, 0);
        lowered.values[upper] += delta;
        lowered.values[source.0 + 2] += delta * F192::new(0, 0, 1);
        assert!(!rows_hold(&lowered));
    }

    #[test]
    fn explicit_width_checks_bind_all_original_high_bits() {
        trace::start();
        let source = S::input(F192::new(99, 0, 0));
        source.assert_eq(source.slice(0, 64));
        trace::hash(&[(source, 8)]);
        let t = trace::take();
        let lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(lowered.connectors[0][8], source.0 + 2);
        let bit_rows = lowered
            .circuit
            .rows
            .iter()
            .filter(|r| r[0] == r[1] && r[1] == r[2] && r[3] == 0)
            .count();
        assert_eq!(bit_rows, 64);
        let mut bad = copy_trace(&t);
        bad.nodes[source.0].value += F192::new(0, 0, 1);
        let lowered = lower(&t, &bad).unwrap();
        assert!(!rows_hold(&lowered));
    }
}
