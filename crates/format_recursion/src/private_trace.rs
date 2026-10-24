//! Private native-field lowering of the fixed trace language.
//!
//! Arithmetic constraints bind all projections and the selected native hash I/O.
//! A separate private bridge must prove the named compressions or permutations. This compiler
//! alone is not a proof system or a formal security certificate.

use crate::{
    native_arithmetic::Circuit,
    trace::{Op, S, Trace},
};
use flock::hash::Compression;
#[cfg(not(feature = "keccak-protocol"))]
use flock::hash::blake2s_compress;
#[cfg(not(feature = "keccak-protocol"))]
use flock::hash::param_iv;
use primitives::field::F192;
use std::collections::HashMap;

pub struct Lowered {
    pub circuit: Circuit,
    pub connectors: Vec<[usize; 18]>,
    pub keccak_connectors: Vec<[usize; 50]>,
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    pub permutations: Vec<flock::keccak::reduction::Permutation>,
    /// The verifier fixes these anchors and constants before the original outputs.
    pub fixed_public: Vec<F192>,
    pub original_public_len: usize,
    /// Operation rows and compression calls attributed to the recorder's sections.
    pub stage_census: Vec<(String, usize, usize)>,
    schedule: Vec<WitnessStep>,
}

// A setup-owned straight-line program computes fresh helper values. It does not
// change the circuit or omit constraints; every variable keeps its original ID.
#[cfg(not(feature = "keccak-protocol"))]
#[derive(Clone, Copy)]
enum PackedWord {
    Fixed(u64),
    Variable(usize),
}
#[cfg(not(feature = "keccak-protocol"))]
impl PackedWord {
    fn get(self, values: &[F192]) -> u64 {
        match self {
            Self::Fixed(word) => word,
            Self::Variable(at) => values[at].c0,
        }
    }
}
#[derive(Clone, Copy)]
enum ValueStep {
    Constant(F192),
    Add(usize, usize),
    MultiplyAdd(usize, usize, usize),
    Limb(usize, usize),
    Bit(usize, usize),
    #[cfg(not(feature = "keccak-protocol"))]
    CompressionOutput(usize),
    #[cfg(feature = "keccak-protocol")]
    PermutationOutput(usize),
}
#[cfg(not(feature = "keccak-protocol"))]
struct CompressionStep {
    cv: [usize; 4],
    message: [usize; 8],
    counter: PackedWord,
    flags: PackedWord,
}
enum WitnessStep {
    Value(ValueStep),
    // Boxing keeps the much more common scalar steps small.
    #[cfg(not(feature = "keccak-protocol"))]
    Compression(Box<CompressionStep>),
    #[cfg(feature = "keccak-protocol")]
    Permutation(Box<[usize; 25]>),
}
struct WitnessSchedule {
    steps: Vec<WitnessStep>,
    public: Vec<usize>,
    variables: usize,
}
pub(crate) struct PreparedWitness {
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    #[cfg(feature = "keccak-protocol")]
    pub permutations: Vec<flock::keccak::reduction::Permutation>,
    pub public: Vec<F192>,
}
impl WitnessSchedule {
    fn evaluate(&self, witness: &Trace) -> PreparedWitness {
        let mut values = Vec::with_capacity(self.variables);
        values.extend([F192::ZERO, F192::ONE]);
        values.extend(witness.nodes.iter().map(|node| node.value));
        #[allow(unused_mut)]
        let mut compressions = Vec::new();
        #[cfg(feature = "keccak-protocol")]
        let mut permutations = Vec::new();
        #[cfg(feature = "keccak-protocol")]
        let mut permuted = [0; 25];
        #[cfg(not(feature = "keccak-protocol"))]
        let mut output = [0u32; 8];
        for step in &self.steps {
            match step {
                WitnessStep::Value(step) => {
                    let value = match *step {
                        ValueStep::Constant(value) => value,
                        ValueStep::Add(a, b) => values[a] + values[b],
                        ValueStep::MultiplyAdd(a, b, c) => values[a] * values[b] + values[c],
                        ValueStep::Limb(at, limb) => {
                            let x = values[at];
                            F192::new([x.c0, x.c1, x.c2][limb], 0, 0)
                        }
                        ValueStep::Bit(at, bit) => {
                            let x = values[at];
                            F192::new(([x.c0, x.c1, x.c2][bit / 64] >> (bit % 64)) & 1, 0, 0)
                        }
                        #[cfg(feature = "keccak-protocol")]
                        ValueStep::PermutationOutput(word) => F192::new(permuted[word], 0, 0),
                        #[cfg(not(feature = "keccak-protocol"))]
                        ValueStep::CompressionOutput(word) => {
                            F192::new(pack32(output[2 * word], output[2 * word + 1]), 0, 0)
                        }
                    };
                    values.push(value);
                }
                #[cfg(feature = "keccak-protocol")]
                WitnessStep::Permutation(input) => {
                    let input = input.map(|at| values[at].c0);
                    permuted = flock::keccak::reduction::permute(&input);
                    permutations.push(input);
                }
                #[cfg(not(feature = "keccak-protocol"))]
                WitnessStep::Compression(compression) => {
                    let CompressionStep {
                        cv,
                        message,
                        counter,
                        flags,
                    } = **compression;
                    let initial = std::array::from_fn(|i| (values[cv[i / 2]].c0 >> (32 * (i % 2))) as u32);
                    let message = std::array::from_fn(|i| (values[message[i / 2]].c0 >> (32 * (i % 2))) as u32);
                    let counter = counter.get(&values);
                    let flags = flags.get(&values);
                    output = blake2s_compress(&initial, &message, counter, flags as u32, (flags >> 32) as u32);
                    compressions.push((initial, message, counter, flags as u32, (flags >> 32) as u32));
                }
            }
        }
        assert_eq!(values.len(), self.variables, "setup-owned witness schedule");
        let public = self.public.iter().map(|&at| values[at]).collect();
        PreparedWitness {
            values,
            compressions,
            #[cfg(feature = "keccak-protocol")]
            permutations,
            public,
        }
    }
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
            rows: 1 << 25,
            variables: 1 << 25,
            compressions: crate::private_bridge::MAX_BLOCKS,
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
    // These bounds follow from the enforced operations; no witness values are
    // used except immutable, public-pinned constants.
    for (at, node) in program.nodes.iter().enumerate() {
        let width = match &node.op {
            Op::Constant => {
                let v = node.value;
                if v.c2 != 0 {
                    192 - v.c2.leading_zeros() as usize
                } else if v.c1 != 0 {
                    128 - v.c1.leading_zeros() as usize
                } else {
                    64 - v.c0.leading_zeros() as usize
                }
            }
            Op::Hash(_) | Op::HashHigh(_) => 128,
            Op::Slice(_, _, len) => *len,
            Op::Pack(parts) => parts
                .iter()
                .try_fold(0usize, |w, (_, len)| w.checked_add(*len))
                .unwrap_or(192),
            Op::Add(a, b) if a.0 < at && b.0 < at => widths[a.0].max(widths[b.0]),
            Op::Select(_, a, b) if a.0 < at && b.0 < at => widths[a.0].max(widths[b.0]),
            _ => 192,
        };
        widths[at] = widths[at].min(width);
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
    origins: Vec<[Option<(usize, usize)>; 3]>,
    projected: Vec<u8>,
}
impl Estimate {
    fn charge(&mut self, rows: usize, variables: usize) -> Option<()> {
        self.bound.rows = self.bound.rows.checked_add(rows)?;
        self.bound.variables = self.bound.variables.checked_add(variables)?;
        Some(())
    }
    fn project(&mut self, program: &Trace, source: S, at: usize, start: usize, len: usize) -> Option<()> {
        if source.0 >= at || start.checked_add(len)? > 192 {
            return None;
        }
        if self.bits[source.0] || matches!(program.nodes[source.0].op, Op::Constant) || len == 0 {
            return Some(());
        }
        let width = self.widths[source.0];
        self.limb_view(program, source, at)?;
        for limb in start / 64..(start + len).div_ceil(64).min(width.div_ceil(64)) {
            if self.projected[source.0] & (1 << limb) == 0 {
                let bits = (width - 64 * limb).min(64);
                self.charge(2 * bits + 1, 2 * bits)?;
                self.projected[source.0] |= 1 << limb;
                // Boolean reconstruction supplies exact F64 typing itself.
                if let Some((origin, position)) = self.origins[source.0][limb] {
                    self.used[origin] |= 1 << position;
                }
            }
        }
        Some(())
    }
    fn limb_view(&mut self, program: &Trace, source: S, at: usize) -> Option<()> {
        if source.0 >= at {
            return None;
        }
        if self.limbs[source.0] {
            return Some(());
        }
        let width = self.widths[source.0];
        if matches!(program.nodes[source.0].op, Op::Constant) {
            self.charge(0, 3)?;
        } else {
            if self.bits[source.0] {
                self.charge(192, 195)?;
            } else {
                self.charge(2, 4)?;
                for limb in 0..width.div_ceil(64) {
                    let bits = (width - 64 * limb).min(64);
                    if bits < 64 {
                        self.charge(2 * bits + 1, 2 * bits)?;
                        self.projected[source.0] |= 1 << limb;
                    } else {
                        self.pending[source.0] |= 1 << limb;
                        self.origins[source.0][limb] = Some((source.0, limb));
                    }
                }
            }
        }
        self.limbs[source.0] = true;
        Some(())
    }
    fn limb_source(&mut self, program: &Trace, source: S, at: usize, words: usize) -> Option<()> {
        if words == 0 {
            return (source.0 < at).then_some(());
        }
        self.limb_view(program, source, at)?;
        for limb in 0..words {
            if let Some((origin, position)) = self.origins[source.0][limb] {
                self.used[origin] |= 1 << position;
            }
        }
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
        origins: vec![[None; 3]; count],
        projected: vec![0; count],
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
                if (*start == 0 && *len >= e.widths.get(source.0).copied()?) || (start % 64 == 0 && len % 64 == 0) {
                    e.limb_view(program, *source, at)?;
                    if *start == 0 && *len >= e.widths[source.0] {
                        e.origins[at] = e.origins[source.0];
                    } else {
                        for limb in 0..len / 64 {
                            e.origins[at][limb] = e.origins[source.0][start / 64 + limb];
                        }
                    }
                    e.limbs[at] = true;
                    e.charge(2, 1)?;
                } else {
                    e.project(program, *source, at, *start, *len)?;
                    e.charge(len.checked_add(1)?, len.checked_add(1)?)?;
                    e.bits[at] = true;
                }
            }
            Op::Pack(parts) => {
                let aligned = parts.iter().all(|(_, len)| len % 64 == 0);
                let mut width = 0usize;
                for &(source, len) in parts {
                    let offset = width;
                    width = width.checked_add(len)?;
                    if width > 192 {
                        return None;
                    }
                    if aligned {
                        e.limb_view(program, source, at)?;
                        for limb in 0..len / 64 {
                            e.origins[at][offset / 64 + limb] = e.origins[source.0][limb];
                        }
                    } else {
                        e.project(program, source, at, 0, len)?;
                    }
                }
                if aligned {
                    e.charge(2, 1)?;
                    e.limbs[at] = true;
                } else {
                    e.charge(width.checked_add(1)?, width.checked_add(1)?)?;
                    e.bits[at] = true;
                }
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
                        e.project(program, source, at, 0, 8 * len)?;
                    }
                }
                let count = if cfg!(feature = "keccak-protocol") {
                    bytes / 136 + 1
                } else {
                    bytes.div_ceil(64).max(1)
                };
                if cfg!(feature = "keccak-protocol") {
                    e.charge(count.checked_mul(80)?, count.checked_mul(80)?)?;
                }
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
    // Unused F64 limbs fill free input words of additional private compressions.
    // The bridge's existing compression relation supplies their exact typing.
    let typing = pending.div_ceil(14);
    e.bound.compressions = e.bound.compressions.checked_add(typing)?;
    if typing != 0 {
        e.charge(0, typing.checked_mul(4)?.checked_add(6)?)?;
    }
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

/// Dense variable identities permit constant-time membership without tree
/// allocation. This set never determines circuit traversal or variable order.
#[derive(Default)]
struct VariableSet(Vec<bool>);
impl VariableSet {
    fn insert(&mut self, at: usize) -> bool {
        if at >= self.0.len() {
            self.0.resize(at + 1, false);
        }
        !std::mem::replace(&mut self.0[at], true)
    }
    fn contains(&self, at: &usize) -> bool {
        self.0.get(*at).copied().unwrap_or(false)
    }
    fn extend(&mut self, values: impl IntoIterator<Item = usize>) {
        for at in values {
            self.insert(at);
        }
    }
    fn anchors() -> Self {
        Self(vec![true, true])
    }
}

struct Compiler {
    schedule: Vec<WitnessStep>,
    rows: Vec<[usize; 4]>,
    values: Vec<F192>,
    constants: HashMap<(u64, u64, u64), usize>,
    constant_variables: VariableSet,
    public: Vec<usize>,
    bits: Vec<Option<Vec<usize>>>,
    limb_bits: Vec<[Option<Vec<usize>>; 3]>,
    constant_nodes: Vec<bool>,
    widths: Vec<usize>,
    limbs: Vec<Option<[usize; 3]>>,
    pending_limbs: Vec<usize>,
    typed: VariableSet,
    booleans: VariableSet,
    differences: HashMap<(usize, usize), usize>,
    connectors: Vec<[usize; 18]>,
    compressions: Vec<Compression>,
    permutations: Vec<flock::keccak::reduction::Permutation>,
    keccak_connectors: Vec<[usize; 50]>,
}

fn key(value: F192) -> (u64, u64, u64) {
    (value.c0, value.c1, value.c2)
}

fn basis(bit: usize) -> F192 {
    let mut limbs = [0; 3];
    limbs[bit / 64] = 1 << (bit % 64);
    F192::new(limbs[0], limbs[1], limbs[2])
}

#[cfg(not(feature = "keccak-protocol"))]
fn pack32(a: u32, b: u32) -> u64 {
    u64::from(a) | (u64::from(b) << 32)
}

impl Compiler {
    fn variable(&mut self, value: F192, step: ValueStep) -> usize {
        self.schedule.push(WitnessStep::Value(step));
        let at = self.values.len();
        self.values.push(value);
        at
    }
    fn constant(&mut self, value: F192) -> usize {
        if let Some(&at) = self.constants.get(&key(value)) {
            return at;
        }
        let at = self.variable(value, ValueStep::Constant(value));
        self.constants.insert(key(value), at);
        self.constant_variables.insert(at);
        self.public.push(at);
        at
    }
    fn equal(&mut self, a: usize, b: usize) {
        self.rows.push([a, 1, 0, b]);
    }
    fn boolean(&mut self, a: usize) {
        if a > 1 && self.booleans.insert(a) {
            self.rows.push([a, a, a, 0]);
        }
    }
    fn difference(&mut self, a: usize, b: usize) -> usize {
        let pair = (a.min(b), a.max(b));
        if let Some(&out) = self.differences.get(&pair) {
            return out;
        }
        let out = self.add(a, b);
        self.differences.insert(pair, out);
        out
    }
    fn add(&mut self, a: usize, b: usize) -> usize {
        #[cfg(feature = "keccak-protocol")]
        {
            if a == 0 {
                return b;
            }
            if b == 0 {
                return a;
            }
            if a == b {
                return 0;
            }
            if self.constant_variables.contains(&a) && self.constant_variables.contains(&b) {
                return self.constant(self.values[a] + self.values[b]);
            }
        }
        let out = self.variable(self.values[a] + self.values[b], ValueStep::Add(a, b));
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
            let out = self.variable(
                self.values[bit] * self.values[coefficient] + self.values[acc],
                ValueStep::MultiplyAdd(bit, coefficient, acc),
            );
            self.rows.push([bit, coefficient, acc, out]);
            acc = out;
        }
        acc
    }

    /// Recombine typed (or pending-typed) F64 words into the entire target.
    fn join_limbs(&mut self, limbs: [usize; 3], target: usize) {
        let [lo, mid, hi] = limbs;
        if mid == 0 && hi == 0 {
            self.equal(lo, target);
        } else {
            let y = self.constant(F192::new(0, 1, 0));
            if hi == 0 {
                self.rows.push([mid, y, lo, target]);
            } else {
                let y2 = self.constant(F192::new(0, 0, 1));
                let partial = self.variable(
                    self.values[lo] + self.values[mid] * self.values[y],
                    ValueStep::MultiplyAdd(mid, y, lo),
                );
                self.rows.push([mid, y, lo, partial]);
                self.rows.push([hi, y2, partial, target]);
            }
        }
    }

    fn source_limbs(&mut self, source: usize) -> [usize; 3] {
        if let Some(limbs) = self.limbs[source] {
            return limbs;
        }
        let value = self.values[source + 2];
        let native = [value.c0, value.c1, value.c2];
        let limbs = if self.constant_nodes[source] {
            std::array::from_fn(|i| self.constant(F192::new(native[i], 0, 0)))
        } else if let Some(bits) = self.bits[source].clone() {
            std::array::from_fn(|i| self.reconstruct(&bits[64 * i..64 * (i + 1)]))
        } else if self.widths[source] == 64 {
            // The bridge supplies F64 typing if connected; otherwise the final
            // fallback enforces it. Explicit range checks cannot become vacuous.
            self.pending_limbs.push(source + 2);
            [source + 2, 0, 0]
        } else {
            let limbs = std::array::from_fn(|i| {
                if i * 64 >= self.widths[source] {
                    0
                } else {
                    let variable = self.variable(F192::new(native[i], 0, 0), ValueStep::Limb(source + 2, i));
                    let bits = (self.widths[source] - 64 * i).min(64);
                    if bits < 64 {
                        let mut projection: Vec<_> = (0..bits)
                            .map(|bit| {
                                let b = self.variable(
                                    F192::new((native[i] >> bit) & 1, 0, 0),
                                    ValueStep::Bit(source + 2, 64 * i + bit),
                                );
                                self.boolean(b);
                                b
                            })
                            .collect();
                        let reconstructed = self.reconstruct(&projection);
                        self.equal(reconstructed, variable);
                        projection.resize(64, 0);
                        self.limb_bits[source][i] = Some(projection);
                        self.typed.insert(variable);
                    } else {
                        self.pending_limbs.push(variable);
                    }
                    variable
                }
            });
            self.join_limbs(limbs, source + 2);
            limbs
        };
        self.limbs[source] = Some(limbs);
        limbs
    }

    /// Batch remaining range checks into the existing private compression
    /// relation. Its chaining value, message, counter and both flags are free
    /// inputs, so one compression types fourteen F64 words. This is not a
    /// standard hash invocation: no fixed-IV or final-flag claim is made.
    /// Outputs remain private and otherwise unused.
    /// Derive F64 membership from key-fixed constants, Boolean constraints and
    /// existing equations a*b+c=d. Private values never drive type inference.
    #[cfg(feature = "keccak-merkle-cap")]
    fn infer_subfield_types(&mut self) {
        for (&(_, mid, hi), &at) in &self.constants {
            if mid == 0 && hi == 0 {
                self.typed.insert(at);
            }
        }
        for (at, &bit) in self.booleans.0.iter().enumerate() {
            if bit {
                self.typed.insert(at);
            }
        }
        loop {
            let mut changed = false;
            for &[a, b, c, d] in &self.rows {
                let ta = self.typed.contains(&a);
                let tb = self.typed.contains(&b);
                let tc = self.typed.contains(&c);
                let td = self.typed.contains(&d);
                if ta && tb && tc {
                    changed |= self.typed.insert(d);
                }
                if ta && tb && td {
                    changed |= self.typed.insert(c);
                }
                if b == 1 && tc && td {
                    changed |= self.typed.insert(a);
                }
                if a == 1 && tc && td {
                    changed |= self.typed.insert(b);
                }
            }
            if !changed {
                break;
            }
        }
    }

    #[cfg(feature = "keccak-protocol")]
    fn constrain_unused_limbs(&mut self) {
        #[cfg(feature = "keccak-merkle-cap")]
        self.infer_subfield_types();
        let mut pending: Vec<_> = self
            .pending_limbs
            .iter()
            .copied()
            .filter(|v| !self.typed.contains(v))
            .collect();
        pending.sort_unstable();
        pending.dedup();
        for chunk in pending.chunks(25) {
            let input_vars = std::array::from_fn(|i| *chunk.get(i).unwrap_or(&0));
            let input = input_vars.map(|v| self.values[v].c0);
            let output = flock::keccak::reduction::permute(&input);
            self.schedule.push(WitnessStep::Permutation(Box::new(input_vars)));
            let outputs: [usize; 25] =
                std::array::from_fn(|i| self.variable(F192::new(output[i], 0, 0), ValueStep::PermutationOutput(i)));
            self.keccak_connectors.push(std::array::from_fn(|i| {
                if i < 25 { input_vars[i] } else { outputs[i - 25] }
            }));
            self.permutations.push(input);
            self.typed.extend(input_vars);
            self.typed.extend(outputs);
        }
    }

    #[cfg(not(feature = "keccak-protocol"))]
    fn constrain_unused_limbs(&mut self) {
        let mut pending: Vec<_> = self
            .pending_limbs
            .iter()
            .copied()
            .filter(|v| !self.typed.contains(v))
            .collect();
        // Preserve the previous ascending traversal exactly, including aliases.
        pending.sort_unstable();
        pending.dedup();
        for chunk in pending.chunks(14) {
            let words: [usize; 14] = std::array::from_fn(|i| *chunk.get(i).unwrap_or(&0));
            let initial = std::array::from_fn(|i| (self.values[words[i / 2]].c0 >> (32 * (i % 2))) as u32);
            let message = std::array::from_fn(|i| (self.values[words[4 + i / 2]].c0 >> (32 * (i % 2))) as u32);
            let counter = self.values[words[12]].c0;
            let flags = self.values[words[13]].c0;
            let compression = (initial, message, counter, flags as u32, (flags >> 32) as u32);
            let output = blake2s_compress(&initial, &message, counter, flags as u32, (flags >> 32) as u32);
            self.schedule.push(WitnessStep::Compression(Box::new(CompressionStep {
                cv: std::array::from_fn(|i| words[i]),
                message: std::array::from_fn(|i| words[4 + i]),
                counter: PackedWord::Variable(words[12]),
                flags: PackedWord::Variable(words[13]),
            })));
            let outputs: [usize; 4] = std::array::from_fn(|i| {
                self.variable(
                    F192::new(pack32(output[2 * i], output[2 * i + 1]), 0, 0),
                    ValueStep::CompressionOutput(i),
                )
            });
            self.connectors.push(std::array::from_fn(|i| match i {
                0..4 => words[i],
                4..8 => outputs[i - 4],
                8..16 => words[i - 4],
                16 => words[12],
                17 => words[13],
                _ => unreachable!(),
            }));
            self.compressions.push(compression);
            self.typed.extend(words);
            self.typed.extend(outputs);
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
                let bit = self.variable(
                    F192::new((limbs[i / 64] >> (i % 64)) & 1, 0, 0),
                    ValueStep::Bit(source + 2, i),
                );
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
    /// Decompose only the F64 limbs touched by this projection. Omitted
    /// limbs retain the exact typing obligation from `source_limbs`; the
    /// private bridge batches those obligations if no hash consumes them.
    fn range_bits(&mut self, source: usize, start: usize, len: usize) -> Vec<usize> {
        if len == 0 {
            return Vec::new();
        }
        if self.bits[source].is_some() || self.constant_nodes[source] {
            return self.decompose(source)[start..start + len].to_vec();
        }
        let limbs = self.source_limbs(source);
        for (limb, &variable) in limbs
            .iter()
            .enumerate()
            .take((start + len).div_ceil(64))
            .skip(start / 64)
        {
            if self.limb_bits[source][limb].is_none() {
                let bits = if self.constant_variables.contains(&variable) {
                    (0..64)
                        .map(|i| ((self.values[variable].c0 >> i) & 1) as usize)
                        .collect()
                } else if limb * 64 >= self.widths[source] {
                    vec![0; 64]
                } else {
                    let value = self.values[variable].c0;
                    let width = (self.widths[source] - 64 * limb).min(64);
                    let mut bits: Vec<_> = (0..width)
                        .map(|i| {
                            let bit = self.variable(F192::new((value >> i) & 1, 0, 0), ValueStep::Bit(variable, i));
                            self.boolean(bit);
                            bit
                        })
                        .collect();
                    let reconstructed = self.reconstruct(&bits);
                    self.equal(reconstructed, variable);
                    self.typed.insert(variable);
                    bits.resize(64, 0);
                    bits
                };
                self.limb_bits[source][limb] = Some(bits);
            }
        }
        (start..start + len)
            .map(|bit| self.limb_bits[source][bit / 64].as_ref().unwrap()[bit % 64])
            .collect()
    }

    #[cfg(feature = "keccak-protocol")]
    fn hash(&mut self, program: &Trace, at: usize, parts: &[(S, usize)]) -> Option<()> {
        if program.nodes.get(at + 1)?.op != Op::HashHigh(S(at)) {
            return None;
        }
        let aligned = parts.iter().all(|&(_, bytes)| bytes % 8 == 0);
        let mut words = Vec::new();
        let mut bits = Vec::new();
        let mut bytes = 0usize;
        for &(source, len) in parts {
            if source.0 >= at || len > 24 {
                return None;
            }
            bytes = bytes.checked_add(len)?;
            if aligned {
                words.extend_from_slice(&self.source_limbs(source.0)[..len / 8]);
            } else {
                bits.extend(self.range_bits(source.0, 0, 8 * len));
            }
        }
        if aligned {
            words.push(self.constant(F192::ONE));
        } else {
            bits.push(1);
            bits.resize(bits.len().next_multiple_of(64), 0);
            for chunk in bits.chunks(64) {
                words.push(self.reconstruct(chunk));
            }
        }
        let blocks = bytes / 136 + 1;
        words.resize(blocks * 17, 0);
        let last_pad = self.constant(F192::new(1u64 << 63, 0, 0));
        let last = words.len() - 1;
        words[last] = self.add(words[last], last_pad);
        let mut state = [0; 25];
        for block in 0..blocks {
            for lane in 0..17 {
                state[lane] = self.add(state[lane], words[block * 17 + lane]);
            }
            self.typed.extend(state);
            let input = state.map(|v| self.values[v].c0);
            let output = flock::keccak::reduction::permute(&input);
            let fixed = state.iter().all(|v| self.constant_variables.contains(v));
            let retain = !fixed || (self.permutations.is_empty() && block + 1 == blocks);
            if retain {
                self.schedule.push(WitnessStep::Permutation(Box::new(state)));
            }
            let outputs = std::array::from_fn(|i| {
                if fixed {
                    self.constant(F192::new(output[i], 0, 0))
                } else {
                    self.variable(F192::new(output[i], 0, 0), ValueStep::PermutationOutput(i))
                }
            });
            if retain {
                self.keccak_connectors
                    .push(std::array::from_fn(|i| if i < 25 { state[i] } else { outputs[i - 25] }));
                self.permutations.push(input);
            }
            self.typed.extend(outputs);
            state = outputs;
        }
        let y = self.constant(F192::new(0, 1, 0));
        self.rows.push([state[1], y, state[0], at + 2]);
        self.rows.push([state[3], y, state[2], at + 3]);
        Some(())
    }

    #[cfg(not(feature = "keccak-protocol"))]
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
                message_bits.extend_from_slice(&self.range_bits(source.0, 0, 8 * bytes));
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
            // Only variable identities known to be public-pinned constants
            // permit folding. Witness words (including zero-valued words) never
            // decide circuit shape. A fixed prefix yields a fixed CV for the
            // first nonconstant block, preserving the exact BLAKE2s chaining.
            let fixed = cv.iter().chain(&words).all(|v| self.constant_variables.contains(v));
            let retain = !fixed || (self.compressions.is_empty() && block + 1 == count);
            if retain {
                self.schedule.push(WitnessStep::Compression(Box::new(CompressionStep {
                    cv,
                    message: words,
                    counter: PackedWord::Fixed(counter),
                    flags: PackedWord::Fixed(u64::from(flag)),
                })));
            }
            let outputs: [usize; 4] = std::array::from_fn(|i| {
                let value = F192::new(pack32(output[2 * i], output[2 * i + 1]), 0, 0);
                if fixed {
                    self.constant(value)
                } else {
                    self.variable(value, ValueStep::CompressionOutput(i))
                }
            });
            // The existing private bridge requires a nonempty compression
            // schedule. Retain one valid fixed terminal block when necessary;
            // subsequent fixed blocks need no additional compression proof.
            if retain {
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
            }
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

/// An immutable trusted program and its witness-independent admission/fusion
/// analysis. Ownership prevents a cached plan from being paired with a different
/// program. Every witness still passes the complete structural identity check.
pub struct PreparedProgram {
    program: Trace,
    analysis: Analysis,
    schedule: Option<WitnessSchedule>,
}

struct Analysis {
    widths: Vec<usize>,
    fused: Vec<Option<(S, S, S)>>,
    skipped: Vec<bool>,
}

impl PreparedProgram {
    pub fn new(program: Trace) -> Option<Self> {
        let analysis = analyze(&program, Limits::default())?;
        Some(Self {
            program,
            analysis,
            schedule: None,
        })
    }
    pub(crate) fn lower_setup(&mut self) -> Option<Lowered> {
        let mut lower = lower_analyzed(&self.program, &self.program, &self.analysis)?;
        self.schedule = Some(WitnessSchedule {
            steps: std::mem::take(&mut lower.schedule),
            public: lower.circuit.public.clone(),
            variables: lower.circuit.variables,
        });
        Some(lower)
    }
    pub(crate) fn prepare_witness(&self, witness: &Trace) -> Option<PreparedWitness> {
        if !self.program.same_program(witness) {
            return None;
        }
        Some(self.schedule.as_ref()?.evaluate(witness))
    }
    pub fn lower(&self, witness: &Trace) -> Option<Lowered> {
        if !self.program.same_program(witness) {
            return None;
        }
        lower_analyzed(&self.program, witness, &self.analysis)
    }
}

pub fn lower_with_limits(program: &Trace, witness: &Trace, limits: Limits) -> Option<Lowered> {
    if !program.same_program(witness) {
        return None;
    }
    let analysis = analyze(program, limits)?;
    lower_analyzed(program, witness, &analysis)
}

fn analyze(program: &Trace, limits: Limits) -> Option<Analysis> {
    preflight(program, limits)?;
    let widths = inferred_widths(program);
    // A product used only by one addition can be enforced directly by one
    // multiply-add row. Count every semantic use, including public outputs,
    // equality checks, hash parts and projections; witness values never decide
    // fusion. The eliminated product variable is not referenced by the circuit.
    let mut uses = vec![0usize; program.nodes.len()];
    let mut use_node = |s: S| -> Option<()> {
        *uses.get_mut(s.0)? = uses[s.0].checked_add(1)?;
        Some(())
    };
    for node in &program.nodes {
        match &node.op {
            Op::Constant | Op::Input => (),
            Op::Add(a, b) | Op::Mul(a, b) => {
                use_node(*a)?;
                use_node(*b)?;
            }
            Op::Frobenius(a) | Op::Slice(a, ..) | Op::HashHigh(a) => use_node(*a)?,
            Op::Pack(parts) | Op::Hash(parts) => {
                for &(a, _) in parts {
                    use_node(a)?;
                }
            }
            Op::Select(bit, a, b) => {
                use_node(*bit)?;
                use_node(*a)?;
                use_node(*b)?;
            }
        }
    }
    for &(a, b) in &program.checks {
        use_node(a)?;
        use_node(b)?;
    }
    for &a in &program.public {
        use_node(a)?;
    }
    let mut fused = vec![None; program.nodes.len()];
    let mut skipped = vec![false; program.nodes.len()];
    for (at, node) in program.nodes.iter().enumerate() {
        if let Op::Add(a, b) = node.op {
            for (product, other) in [(a, b), (b, a)] {
                if product.0 < at
                    && uses[product.0] == 1
                    && let Op::Mul(x, y) = program.nodes[product.0].op
                {
                    fused[at] = Some((x, y, other));
                    skipped[product.0] = true;
                    break;
                }
            }
        }
    }
    Some(Analysis { widths, fused, skipped })
}

fn lower_analyzed(program: &Trace, witness: &Trace, analysis: &Analysis) -> Option<Lowered> {
    let Analysis { widths, fused, skipped } = analysis;
    let mut c = Compiler {
        schedule: Vec::new(),
        rows: Vec::new(),
        values: vec![F192::ZERO, F192::ONE],
        constants: HashMap::from([(key(F192::ZERO), 0), (key(F192::ONE), 1)]),
        constant_variables: VariableSet::anchors(),
        public: vec![0, 1],
        bits: vec![None; program.nodes.len()],
        limb_bits: vec![std::array::from_fn(|_| None); program.nodes.len()],
        constant_nodes: program.nodes.iter().map(|n| matches!(n.op, Op::Constant)).collect(),
        widths: widths.clone(),
        limbs: vec![None; program.nodes.len()],
        pending_limbs: Vec::new(),
        typed: VariableSet::anchors(),
        booleans: VariableSet::default(),
        differences: HashMap::new(),
        connectors: Vec::new(),
        compressions: Vec::new(),
        permutations: Vec::new(),
        keccak_connectors: Vec::new(),
    };
    c.values.extend(witness.nodes.iter().map(|n| n.value));
    let mut stage_census = Vec::new();
    let mut stage = (String::from("unsectioned"), 0usize, 0usize);
    let mut section = 0;
    for (i, node) in program.nodes.iter().enumerate() {
        while section < program.sections.len() && program.sections[section].1 == i {
            stage_census.push((
                stage.0,
                c.rows.len() - stage.1,
                (c.compressions.len() + c.permutations.len()) - stage.2,
            ));
            stage = (
                program.sections[section].0.clone(),
                c.rows.len(),
                (c.compressions.len() + c.permutations.len()),
            );
            section += 1;
        }
        let source = |s: S| (s.0 < i).then_some(s.0 + 2);
        let z = i + 2;
        match &node.op {
            Op::Constant => {
                if let Some(&canonical) = c.constants.get(&key(node.value)) {
                    c.equal(canonical, z);
                } else {
                    c.public.push(z);
                    c.constants.insert(key(node.value), z);
                    c.constant_variables.insert(z);
                }
            }
            Op::Input => (),
            Op::Add(a, b) => {
                if let Some((x, y, u)) = fused[i] {
                    c.rows.push([source(x)?, source(y)?, source(u)?, z]);
                } else {
                    c.rows.push([source(*a)?, 1, source(*b)?, z]);
                }
            }
            Op::Mul(a, b) => {
                // Validate even an eliminated operation's source ordering.
                let x = source(*a)?;
                let y = source(*b)?;
                if !skipped[i] {
                    c.rows.push([x, y, 0, z]);
                }
            }
            Op::Frobenius(a) => {
                let mut value = source(*a)?;
                for step in 0..64 {
                    let out = if step == 63 {
                        z
                    } else {
                        c.variable(
                            c.values[value] * c.values[value],
                            ValueStep::MultiplyAdd(value, value, 0),
                        )
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
                if (*start == 0 && *len >= c.widths[a.0]) || (start % 64 == 0 && len % 64 == 0) {
                    let source = c.source_limbs(a.0);
                    let mut limbs = [0; 3];
                    if *start == 0 && *len >= c.widths[a.0] {
                        limbs = source;
                        c.limb_bits[i] = c.limb_bits[a.0].clone();
                    } else {
                        limbs[..len / 64].copy_from_slice(&source[start / 64..(start + len) / 64]);
                        for limb in 0..len / 64 {
                            c.limb_bits[i][limb] = c.limb_bits[a.0][start / 64 + limb].clone();
                        }
                    }
                    c.join_limbs(limbs, z);
                    c.limbs[i] = Some(limbs);
                } else {
                    let mut output = c.range_bits(a.0, *start, *len);
                    let out = c.reconstruct(&output);
                    c.equal(out, z);
                    output.resize(192, 0);
                    c.bits[i] = Some(output);
                }
            }
            Op::Pack(parts) => {
                let aligned = parts.iter().all(|(_, len)| len % 64 == 0);
                let mut width = 0usize;
                let mut limbs = [0; 3];
                let mut output = Vec::new();
                for &(a, len) in parts {
                    source(a)?;
                    let next = width.checked_add(len)?;
                    if next > 192 {
                        return None;
                    }
                    if aligned {
                        limbs[width / 64..next / 64].copy_from_slice(&c.source_limbs(a.0)[..len / 64]);
                        for limb in 0..len / 64 {
                            c.limb_bits[i][width / 64 + limb] = c.limb_bits[a.0][limb].clone();
                        }
                    } else {
                        output.extend_from_slice(&c.range_bits(a.0, 0, len));
                    }
                    width = next;
                }
                if aligned {
                    c.join_limbs(limbs, z);
                    c.limbs[i] = Some(limbs);
                } else {
                    let out = c.reconstruct(&output);
                    c.equal(out, z);
                    output.resize(192, 0);
                    c.bits[i] = Some(output);
                }
            }
            Op::Select(bit, a, b) => {
                let bit = source(*bit)?;
                let a = source(*a)?;
                let b = source(*b)?;
                c.boolean(bit);
                let difference = c.difference(a, b);
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
    stage_census.push((
        stage.0,
        c.rows.len() - stage.1,
        (c.compressions.len() + c.permutations.len()) - stage.2,
    ));
    let check_start = c.rows.len();
    for &(a, b) in &program.checks {
        if a.0 >= program.nodes.len() || b.0 >= program.nodes.len() {
            return None;
        }
        c.equal(a.0 + 2, b.0 + 2);
    }
    let check_blocks = c.compressions.len() + c.permutations.len();
    c.constrain_unused_limbs();
    stage_census.push((
        String::from("final-equalities-and-unused-limbs"),
        c.rows.len() - check_start,
        c.compressions.len() + c.permutations.len() - check_blocks,
    ));
    let fixed_public = c.public.iter().map(|&i| c.values[i]).collect();
    for s in &program.public {
        if s.0 >= program.nodes.len() {
            return None;
        }
        c.public.push(s.0 + 2);
    }
    Some(Lowered {
        schedule: c.schedule,
        circuit: Circuit {
            variables: c.values.len(),
            rows: c.rows,
            public: c.public,
        },
        connectors: c.connectors,
        values: c.values,
        compressions: c.compressions,
        permutations: c.permutations,
        keccak_connectors: c.keccak_connectors,
        fixed_public,
        original_public_len: program.public.len(),
        stage_census,
    })
}

// These fixtures exercise the legacy BLAKE2s application/bridge backend.
#[cfg(all(test, not(feature = "keccak-protocol")))]
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
    fn prepared_program_matches_reference_and_binds_structure_and_outputs() {
        fn witness(seed: u64) -> Trace {
            trace::start();
            let x = S::input(F192::new(seed + 3, 17, 19));
            let y = S::input(F192::new(seed + 23, 29, 31));
            let bit = S::input(F192::new(seed & 1, 0, 0));
            let result = S::select(bit, x * y + x, y);
            let packed = S::pack(&[(x.slice(0, 64), 64), (result.slice(0, 128), 128)]);
            let digest = trace::hash(&[(packed, 24), (S::u(71), 8)]);
            let mut t = trace::take();
            t.public = digest.to_vec();
            t
        }
        let template = witness(0);
        let mut prepared = PreparedProgram::new(copy_trace(&template)).unwrap();
        assert!(prepared.prepare_witness(&template).is_none());
        prepared.lower_setup().unwrap();
        for seed in 1..9 {
            let fresh = witness(seed);
            let reference = lower(&template, &fresh).unwrap();
            let cached = prepared.lower(&fresh).unwrap();
            let fast = prepared.prepare_witness(&fresh).unwrap();
            assert_eq!(fast.values, reference.values);
            assert_eq!(fast.compressions, reference.compressions);
            assert_eq!(
                fast.public,
                reference
                    .circuit
                    .public
                    .iter()
                    .map(|&v| reference.values[v])
                    .collect::<Vec<_>>()
            );
            assert!(rows_hold(&cached) && connectors_hold(&cached));
            assert_eq!(reference.circuit.rows, cached.circuit.rows);
            assert_eq!(reference.circuit.public, cached.circuit.public);
            assert_eq!(reference.values, cached.values);
            assert_eq!(reference.connectors, cached.connectors);
            assert_eq!(reference.compressions, cached.compressions);
            assert_eq!(reference.fixed_public, cached.fixed_public);
            let mut altered = copy_trace(&fresh);
            altered.public.reverse();
            assert!(prepared.lower(&altered).is_none());
            assert!(prepared.prepare_witness(&altered).is_none());
            altered = copy_trace(&fresh);
            let constant = altered.nodes.iter_mut().find(|node| node.op == Op::Constant).unwrap();
            constant.value += F192::ONE;
            assert!(prepared.lower(&altered).is_none());
            assert!(prepared.prepare_witness(&altered).is_none());
            altered = copy_trace(&fresh);
            altered.checks.push((S(0), S(1)));
            assert!(prepared.lower(&altered).is_none());
            assert!(prepared.prepare_witness(&altered).is_none());
            altered = copy_trace(&fresh);
            altered.nodes[0].op = Op::Constant;
            assert!(prepared.lower(&altered).is_none());
            assert!(prepared.prepare_witness(&altered).is_none());
            altered = copy_trace(&fresh);
            altered.nodes[altered.public[0].0].value += F192::new(0, 0, 1);
            let bad = prepared.lower(&altered).unwrap();
            assert!(!rows_hold(&bad) || !connectors_hold(&bad));
        }
    }

    #[test]
    fn witness_schedule_matches_all_helper_values_for_hashes_projections_and_frobenius() {
        fn witness(seed: u64) -> Trace {
            trace::start();
            let x = S::input(F192::new(seed.wrapping_mul(31), seed ^ 71, seed.wrapping_add(91)));
            let y = S::input(F192::new(seed.wrapping_add(17), seed.wrapping_mul(23), seed ^ 37));
            let selector = S::input(F192::new(seed & 1, 0, 0));
            let wide = S::select(selector, (x * y).frobenius() + x, y);
            let packed = S::pack(&[(x.slice(5, 17), 17), (y.slice(11, 31), 31), (wide.slice(0, 144), 144)]);
            // Fold a fixed full block before a private unaligned tail.
            let mut parts = vec![(S::c(F192::new(19, 23, 0)), 16); 4];
            parts.extend([(packed, 24), (y, 17)]);
            let digest = trace::hash(&parts);
            let fixed = trace::hash(&[(S::u(71), 8)]);
            let empty = trace::hash(&[]);
            // A range-checked word unused by a hash needs fallback compression typing.
            let unused = S::input(F192::new(seed, 0, 0));
            unused.assert_eq(unused.slice(0, 64));
            let mut trace = trace::take();
            trace.public.extend(digest);
            trace.public.extend(fixed);
            trace.public.extend(empty);
            trace.public.push(wide);
            trace
        }
        let template = witness(0);
        let mut prepared = PreparedProgram::new(copy_trace(&template)).unwrap();
        prepared.lower_setup().unwrap();
        for seed in [0, 1, 17, 0x123456789abcdef, u64::MAX] {
            let fresh = witness(seed);
            let compare = |trace: &Trace| {
                let reference = lower(&template, trace).unwrap();
                let fast = prepared.prepare_witness(trace).unwrap();
                assert_eq!(reference.values, fast.values);
                assert_eq!(reference.compressions, fast.compressions);
                assert_eq!(
                    reference
                        .circuit
                        .public
                        .iter()
                        .map(|&v| reference.values[v])
                        .collect::<Vec<_>>(),
                    fast.public
                );
                reference
            };
            let reference = compare(&fresh);
            assert!(rows_hold(&reference) && connectors_hold(&reference));
            for at in (0..fresh.nodes.len()).step_by(7) {
                if matches!(fresh.nodes[at].op, Op::Constant) {
                    continue;
                }
                let mut bad = copy_trace(&fresh);
                bad.nodes[at].value += F192::new(3, 5, 7);
                compare(&bad);
            }
        }
    }

    #[test]
    fn lookup_tables_preserve_variable_and_constraint_order() {
        trace::start();
        let selector = S::input(F192::ONE);
        let mut parts = Vec::new();
        for i in 0..20 {
            let input = S::input(F192::new(i + 17, 0, 0));
            input.assert_eq(input.slice(0, 64));
            let constant = S::u(i + 37);
            let left = S::select(selector, input, constant);
            let right = S::select(selector, constant, input);
            parts.extend([(left, 8), (right, 8)]);
        }
        let result = trace::hash(&parts);
        let mut program = trace::take();
        program.public = result.to_vec();
        let reference = lower(&program, &program).unwrap();
        // Each lowering instantiates independently seeded hash tables. Neither
        // iteration order nor hash seeds may affect any generated artifact.
        for _ in 0..8 {
            let repeated = lower(&program, &program).unwrap();
            assert_eq!(reference.circuit.rows, repeated.circuit.rows);
            assert_eq!(reference.circuit.public, repeated.circuit.public);
            assert_eq!(reference.values, repeated.values);
            assert_eq!(reference.connectors, repeated.connectors);
            assert_eq!(reference.compressions, repeated.compressions);
            assert_eq!(reference.fixed_public, repeated.fixed_public);
        }
    }

    #[test]
    fn typing_compression_uses_all_fourteen_free_input_words() {
        trace::start();
        let mut originals = Vec::new();
        let mut projections = Vec::new();
        for i in 0..14 {
            let input = S::input(F192::new(0x12345678abcdef00u64.wrapping_mul(i + 1), 0, 0));
            let low = input.slice(0, 64);
            input.assert_eq(low);
            originals.push(input);
            projections.push(low);
        }
        let program = trace::take();
        let mut lowered = lower(&program, &program).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(lowered.compressions.len(), 1);
        let slots = [0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        for (i, slot) in slots.into_iter().enumerate() {
            assert_eq!(lowered.connectors[0][slot], originals[i].0 + 2);
            // Equality/range-hint constraints alone cannot enforce F64: keep
            // them satisfied while putting the same high limb in both wires.
            lowered.values[originals[i].0 + 2] += F192::new(0, 1, 0);
            lowered.values[projections[i].0 + 2] += F192::new(0, 1, 0);
            assert!(rows_hold(&lowered));
            assert!(!connectors_hold(&lowered));
            lowered.values[originals[i].0 + 2] += F192::new(0, 1, 0);
            lowered.values[projections[i].0 + 2] += F192::new(0, 1, 0);
        }
        let outputs = Vec::new();
        let public = lowered.expected_public(&outputs).unwrap();
        let bridge = crate::private_bridge::PrivateBridge::new(lowered.circuit, lowered.connectors).unwrap();
        let proof = bridge.prove(&lowered.values, &lowered.compressions, &[71; 32]).unwrap();
        assert!(bridge.verify(&public, &[71; 32], &proof));
        assert!(crate::private_verifier::record(&bridge, &public, &[71; 32], &proof).satisfied());
    }

    #[test]
    fn multiply_add_fusion_preserves_observable_intermediates_and_inputs() {
        for expose_product in [false, true] {
            trace::start();
            let x = S::input(F192::new(7, 11, 13));
            let y = S::input(F192::new(17, 19, 23));
            let u = S::input(F192::new(29, 31, 37));
            let product = x * y;
            let result = product + u;
            let mut program = trace::take();
            program.public = if expose_product {
                vec![result, product]
            } else {
                vec![result]
            };
            let mut lowered = lower(&program, &program).unwrap();
            assert!(rows_hold(&lowered));
            assert_eq!(lowered.circuit.rows.len(), if expose_product { 2 } else { 1 });
            for variable in [x, y, u, result] {
                let original = lowered.values[variable.0 + 2];
                lowered.values[variable.0 + 2] += F192::ONE;
                assert!(!rows_hold(&lowered));
                lowered.values[variable.0 + 2] = original;
            }
            if expose_product {
                lowered.values[product.0 + 2] += F192::ONE;
                assert!(!rows_hold(&lowered));
            }
            // A check is also a semantic use, even when its two sides match.
            program.checks.push((product, product));
            let checked = lower(&program, &program).unwrap();
            assert!(checked.circuit.rows.iter().any(|row| row[3] == product.0 + 2));
        }
    }

    #[test]
    fn opposite_selections_share_checks_without_freeing_the_selector() {
        trace::start();
        let bit = S::input(F192::ONE);
        let a = S::input(F192::new(17, 19, 23));
        let b = S::input(F192::new(29, 31, 37));
        let left = S::select(bit, a, b);
        let right = S::select(bit, b, a);
        let mut program = trace::take();
        program.public = vec![left, right];
        let mut lowered = lower(&program, &program).unwrap();
        assert!(rows_hold(&lowered));
        assert_eq!(lowered.circuit.rows.len(), 4);
        assert_eq!(
            lowered
                .circuit
                .rows
                .iter()
                .filter(|row| row[0] == row[1] && row[1] == row[2] && row[3] == 0)
                .count(),
            1
        );
        lowered.values[bit.0 + 2] = F192::new(2, 0, 0);
        assert!(!rows_hold(&lowered));
        lowered.values[bit.0 + 2] = F192::ONE;
        for variable in [a, b, left, right] {
            let original = lowered.values[variable.0 + 2];
            lowered.values[variable.0 + 2] += F192::ONE;
            assert!(!rows_hold(&lowered));
            lowered.values[variable.0 + 2] = original;
        }
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
        assert!(connectors_hold(&lowered));
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
        input.slice(0, 63);
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
        assert_eq!(bit_rows.len(), 64);
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
            let hash_count = bytes.div_ceil(64).max(1);
            assert!(lowered.compressions.len() >= hash_count);
            assert_eq!(
                fiat_shamir::merkle::scalars_to_hash(&[t.nodes[outputs[0].0].value, t.nodes[outputs[1].0].value])
                    .unwrap(),
                primitives::protocol_hash::hash(&message)
            );
            for pair in lowered.connectors[..hash_count].windows(2) {
                assert_eq!(pair[0][4..8], pair[1][..4]);
            }
            let end = hash_count - 1;
            let cv = lowered.connectors[end][0];
            lowered.values[cv] += F192::ONE;
            assert!(!connectors_hold(&lowered));
            if hash_count > 1 {
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
        assert_eq!(bits, 64);
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
    fn fixed_hash_prefixes_are_folded_but_private_zero_words_are_not() {
        for bytes in [65usize, 128, 129, 256] {
            trace::start();
            let zero = S::u(0);
            let private = S::input(F192::ZERO);
            let mut parts = vec![(zero, 8); bytes / 8];
            if !bytes.is_multiple_of(8) {
                parts.push((zero, bytes % 8));
            }
            let final_index = parts.len() - 1;
            parts[final_index].0 = private;
            let outputs = trace::hash(&parts);
            let mut t = trace::take();
            t.public = outputs.to_vec();
            let lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered) && connectors_hold(&lowered));
            check_bound(&t, &lowered);
            // Every complete fixed block is absent. A partial private source
            // can also require typing its unused high limbs.
            let native_hash_blocks = lowered
                .compressions
                .iter()
                .filter(|block| block.2 == bytes as u64)
                .count();
            assert_eq!(native_hash_blocks, 1);
            assert!(lowered.compressions.len() <= 2);
            // The nonconstant block is retained even when its witness is zero.
            let mut changed = copy_trace(&t);
            changed.nodes[private.0].value = F192::ONE;
            let alternate = lower(&t, &changed).unwrap();
            assert_eq!(lowered.circuit.rows, alternate.circuit.rows);
            assert_eq!(lowered.connectors, alternate.connectors);
            assert!(!rows_hold(&alternate));
            assert_eq!(
                fiat_shamir::merkle::scalars_to_hash(&[t.nodes[outputs[0].0].value, t.nodes[outputs[1].0].value])
                    .unwrap(),
                primitives::protocol_hash::hash(&vec![0; bytes])
            );
        }
    }

    #[test]
    fn fully_fixed_hashes_keep_one_bridge_block_and_bind_outputs() {
        trace::start();
        let zero = S::u(0);
        let first = trace::hash(&[(zero, 8); 32]);
        let second = trace::hash(&[(first[0], 16), (first[1], 16)]);
        second[0].slice(5, 17);
        let t = trace::take();
        let lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(lowered.compressions.len(), 1);
        assert_eq!(boolean_rows(&lowered), 0);
        check_bound(&t, &lowered);
        let mut changed = copy_trace(&t);
        changed.nodes[first[0].0].value += F192::ONE;
        let alternate = lower(&t, &changed).unwrap();
        assert_eq!(lowered.circuit.rows, alternate.circuit.rows);
        assert_eq!(lowered.connectors, alternate.connectors);
        assert!(!rows_hold(&alternate));
    }

    #[test]
    fn all_widths_have_exact_sparse_projections_and_checked_bounds() {
        for width in 0usize..=192 {
            trace::start();
            let native = [0xa9876543210fedcbu64, 0xfedcba9876543210, 0x123456789abcdef0];
            let words: [u64; 3] = std::array::from_fn(|i| {
                let len = width.saturating_sub(64 * i).min(64);
                native[i] & if len == 64 { u64::MAX } else { (1 << len) - 1 }
            });
            let source = S::input(F192::new(words[0], words[1], words[2]));
            source.assert_eq(source.slice(0, width));
            for (start, len) in [(0, 1), (31, 7), (61, 8), (126, 3), (190, 2)] {
                let part = source.slice(start, len);
                S::pack(&[(part, len), (source, len)]);
            }
            trace::hash(&[(source, 1)]);
            let t = trace::take();
            let lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered) && connectors_hold(&lowered), "width {width}");
            check_bound(&t, &lowered);
            assert!(
                boolean_rows(&lowered) <= width,
                "width {width}: {} Boolean rows",
                boolean_rows(&lowered)
            );
        }
    }

    #[test]
    fn sparse_projections_only_decompose_touched_typed_limbs() {
        for (start, len, expected_bits) in [(1, 8, 64), (61, 8, 128), (129, 31, 64)] {
            trace::start();
            let source = S::input(F192::new(0x89abcdef12345678, 0xfedcba9876543210, 0x123456789abcdef0));
            let first = source.slice(start, len);
            let again = source.slice(start, len);
            let packed = S::pack(&[(first, len), (again, len)]);
            let mut t = trace::take();
            t.public = vec![first, again, packed];
            let mut lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered) && connectors_hold(&lowered));
            assert_eq!(boolean_rows(&lowered), expected_bits);
            assert!(lowered.circuit.rows.len() < 2 * expected_bits + 4 * len + 16);
            check_bound(&t, &lowered);
            // Every omitted limb remains F64-typed by a private compression.
            assert!(!lowered.compressions.is_empty());
            for target in [first, again, packed] {
                let mut bad = copy_trace(&t);
                bad.nodes[target.0].value += F192::ONE;
                assert!(!rows_hold(&lower(&t, &bad).unwrap()));
            }
            // In particular high extension coefficients cannot hide in an
            // omitted limb, even if the source reconstruction is adjusted.
            let typing = lowered.connectors.last().unwrap();
            let omitted = typing[..4]
                .iter()
                .chain(&typing[8..])
                .copied()
                .find(|&v| v > 1)
                .unwrap();
            let delta = F192::new(0, 1, 0);
            lowered.values[omitted] += delta;
            assert!(!rows_hold(&lowered) || !connectors_hold(&lowered));
        }
    }

    #[test]
    fn sparse_projections_and_hashes_keep_exact_full_source_semantics() {
        for bytes in [1usize, 7, 9, 17, 23] {
            trace::start();
            let source = S::input(F192::new(11, 17, 23));
            trace::hash(&[(source, bytes)]);
            source.slice(7, 9);
            source.slice(64, 128);
            source.slice(2, 190);
            let t = trace::take();
            let lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered) && connectors_hold(&lowered));
            assert_eq!(boolean_rows(&lowered), 192);
            check_bound(&t, &lowered);
            let mut bad = copy_trace(&t);
            bad.nodes[source.0].value += F192::new(0, 0, 1 << 63);
            let changed = lower(&t, &bad).unwrap();
            assert!(!rows_hold(&changed) || !connectors_hold(&changed));
            assert_eq!(lowered.circuit.rows, changed.circuit.rows);
            assert_eq!(lowered.connectors, changed.connectors);
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
        assert!(!rows_hold(&lowered) || !connectors_hold(&lowered));
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
        assert_eq!(bit_rows, 0);
        let mut malicious = lower(&t, &t).unwrap();
        malicious.values[source.0 + 2] += F192::new(0, 0, 1);
        malicious.values[t.checks[0].1.0 + 2] += F192::new(0, 0, 1);
        assert!(rows_hold(&malicious)); // equalities alone permit this
        assert!(!connectors_hold(&malicious)); // private bridge rejects non-F64
        let mut bad = copy_trace(&t);
        bad.nodes[source.0].value += F192::new(0, 0, 1);
        let lowered = lower(&t, &bad).unwrap();
        assert!(!rows_hold(&lowered));
    }
    fn boolean_rows(lowered: &Lowered) -> usize {
        lowered
            .circuit
            .rows
            .iter()
            .filter(|r| r[0] == r[1] && r[1] == r[2] && r[3] == 0)
            .count()
    }

    fn check_bound(t: &Trace, lowered: &Lowered) {
        let bound = allocation_bound(t).unwrap();
        assert!(
            lowered.circuit.rows.len() <= bound.rows,
            "rows {} > {}",
            lowered.circuit.rows.len(),
            bound.rows
        );
        assert!(lowered.compressions.len() <= bound.compressions);
        assert!(
            lowered.values.len() <= bound.variables,
            "variables {} > {}",
            lowered.values.len(),
            bound.variables
        );
    }

    #[test]
    fn aligned_slices_and_packs_reuse_bridge_typing_and_preserve_shape() {
        for width in [64, 128, 192] {
            trace::start();
            let source = S::input(F192::new(
                11,
                if width >= 128 { 17 } else { 0 },
                if width == 192 { 23 } else { 0 },
            ));
            source.assert_eq(source.slice(0, width));
            let tail = source.slice(64, 128);
            let low = source.slice(0, 64);
            let packed = S::pack(&[(low, 64), (tail, 128)]);
            trace::hash(&[(packed, 24)]);
            let t = trace::take();
            let lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered) && connectors_hold(&lowered));
            assert_eq!(boolean_rows(&lowered), 0);
            assert!(lowered.circuit.rows.len() < 16);
            check_bound(&t, &lowered);
            let mut bad = copy_trace(&t);
            bad.nodes[packed.0].value += F192::new(0, 0, 1 << 63);
            assert!(!rows_hold(&lower(&t, &bad).unwrap()));
            let mut changed = copy_trace(&t);
            changed.nodes[source.0].value += F192::ONE;
            let alternate = lower(&t, &changed).unwrap();
            assert_eq!(lowered.circuit.rows, alternate.circuit.rows);
            assert_eq!(lowered.circuit.public, alternate.circuit.public);
            assert_eq!(lowered.connectors, alternate.connectors);
        }
    }

    #[test]
    fn range_checks_use_private_typing_and_exact_partial_words() {
        for width in [32, 64, 96, 128, 192] {
            trace::start();
            let source = S::input(F192::new(
                11,
                if width > 64 { 17 } else { 0 },
                if width > 128 { 23 } else { 0 },
            ));
            source.assert_eq(source.slice(0, width));
            let t = trace::take();
            let mut lowered = lower(&t, &t).unwrap();
            assert!(rows_hold(&lowered));
            assert_eq!(boolean_rows(&lowered), width % 64);
            assert!(connectors_hold(&lowered));
            check_bound(&t, &lowered);
            // Change both original nodes coherently: native equations plus
            // private bridge typing must forbid values outside the range.
            let projection = t.checks[0].1;
            let delta = basis(width.min(191));
            if width < 192 {
                lowered.values[source.0 + 2] += delta;
                lowered.values[projection.0 + 2] += delta;
                assert!(!rows_hold(&lowered) || !connectors_hold(&lowered));
            }
        }
    }

    #[test]
    fn aligned_slice_types_omitted_source_limbs_and_rejects_compensating_high_bits() {
        trace::start();
        let source = S::input(F192::new(11, 17, 23));
        let middle = source.slice(64, 64);
        trace::hash(&[(middle, 8)]);
        let t = trace::take();
        let mut lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(boolean_rows(&lowered), 0);
        check_bound(&t, &lowered);
        // Move a high extension-field value into an omitted limb and adjust
        // the complete source equation. Private bridge F64 typing rejects it.
        let hi_row = lowered
            .circuit
            .rows
            .iter()
            .find(|r| r[3] == source.0 + 2 && lowered.values[r[1]] == F192::new(0, 0, 1))
            .unwrap();
        let high = hi_row[0];
        let delta = F192::new(0, 1, 0);
        lowered.values[high] += delta;
        lowered.values[source.0 + 2] += delta * F192::new(0, 0, 1);
        assert!(!rows_hold(&lowered) || !connectors_hold(&lowered));
    }

    #[test]
    fn packed_hash_halves_and_selects_keep_native_widths() {
        trace::start();
        let input = S::input(F192::new(11, 17, 23));
        let h = trace::hash(&[(input, 24)]);
        let selector = S::input(F192::ONE);
        let selected = S::select(selector, h[0], h[1]);
        let xor = selected + h[1];
        let packed = S::pack(&[(xor, 128), (h[1], 64)]);
        trace::hash(&[(packed, 24)]);
        let t = trace::take();
        let lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(boolean_rows(&lowered), 1); // selector only
        assert!(lowered.circuit.rows.len() < 24);
        check_bound(&t, &lowered);
    }
    #[test]
    fn private_range_typing_batches_fourteen_unique_words_and_checks_budget() {
        trace::start();
        for value in 11..26 {
            let word = S::input(F192::new(value, 0, 0));
            let projection = word.slice(0, 64);
            word.assert_eq(projection);
            // Reuse aliases: no duplicate pending range check is needed.
            projection.slice(0, 64);
        }
        let t = trace::take();
        let mut lowered = lower(&t, &t).unwrap();
        assert!(rows_hold(&lowered) && connectors_hold(&lowered));
        assert_eq!(lowered.compressions.len(), 2);
        assert_eq!(boolean_rows(&lowered), 0);
        assert!(lowered.connectors[1][1..4].iter().all(|&v| v == 0));
        assert!(lowered.connectors[1][8..18].iter().all(|&v| v == 0));
        check_bound(&t, &lowered);
        let bound = allocation_bound(&t).unwrap();
        assert_eq!(bound.compressions, 2);
        assert!(
            lower_with_limits(
                &t,
                &t,
                Limits {
                    compressions: 1,
                    ..Limits::default()
                }
            )
            .is_none()
        );
        let output = lowered.connectors[0][4];
        lowered.values[output] += F192::ONE;
        assert!(rows_hold(&lowered));
        assert!(!connectors_hold(&lowered));
    }
}

#[cfg(all(test, feature = "keccak-protocol"))]
mod keccak_protocol_tests {
    use super::*;
    use crate::keccak_bridge::KeccakBridge;

    fn program(bytes: usize, seed: u64) -> Trace {
        crate::trace::start();
        let parts: Vec<_> = (0..bytes)
            .collect::<Vec<_>>()
            .chunks(24)
            .map(|chunk| {
                let mut encoded = [0; 24];
                for (j, &i) in chunk.iter().enumerate() {
                    encoded[j] = (i as u64 + seed) as u8;
                }
                let limb = |j| u64::from_le_bytes(encoded[j..j + 8].try_into().unwrap());
                (S::input(F192::new(limb(0), limb(8), limb(16))), chunk.len())
            })
            .collect();
        let digest = crate::trace::hash(&parts);
        let mut out = crate::trace::take();
        out.public = digest.to_vec();
        out
    }

    #[test]
    fn keccak_configuration_refuses_blake_only_and_mixed_hash_rows() {
        let circuit = Circuit {
            variables: 2,
            rows: vec![],
            public: vec![0, 1],
        };
        assert!(crate::private_bridge::PrivateBridge::new(circuit.clone(), vec![[0; 18]]).is_none());
        assert!(KeccakBridge::new_mixed(circuit, vec![[0; 50]], vec![[0; 18]]).is_none());
    }

    #[test]
    fn fixed_prefix_folding_keeps_private_zero_inputs_dynamic() {
        fn make(private: bool, value: u64) -> Trace {
            crate::trace::start();
            let prefix = S::c(F192::ZERO);
            let value = if private {
                S::input(F192::new(value, 0, 0))
            } else {
                S::u(value)
            };
            let mut parts = vec![(prefix, 24); 17];
            parts.push((value, 8));
            let digest = crate::trace::hash(&parts);
            let mut t = crate::trace::take();
            t.public = digest.to_vec();
            t
        }
        let fixed = make(false, 0);
        let fixed_lower = lower(&fixed, &fixed).unwrap();
        assert_eq!(fixed_lower.permutations.len(), 1);
        let zero = make(true, 0);
        let fresh = make(true, 7);
        assert!(zero.same_program(&fresh));
        let mut setup = PreparedProgram::new(zero).unwrap();
        let template = setup.lower_setup().unwrap();
        let witness = setup.prepare_witness(&fresh).unwrap();
        assert_eq!(template.permutations.len(), witness.permutations.len());
        assert_ne!(template.permutations, witness.permutations);
        let bridge = KeccakBridge::new(template.circuit.clone(), template.keccak_connectors.clone()).unwrap();
        let context = primitives::protocol_hash::hash(b"fixed-prefix-fresh-witness");
        let proof = bridge.prove(&witness.values, &witness.permutations, &context).unwrap();
        assert!(bridge.verify(&witness.public, &context, &proof));
        let mut wrong = witness.public.clone();
        *wrong.last_mut().unwrap() += F192::ONE;
        assert!(!bridge.verify(&wrong, &context, &proof));
    }

    #[test]
    fn native_keccak_lowering_padding_schedule_and_verifier_rejections() {
        for bytes in [0, 1, 64, 135, 136, 137, 272] {
            let original = program(bytes, 7);
            let mut prepared = PreparedProgram::new(original.clone()).unwrap();
            let lowered = prepared.lower_setup().unwrap();
            assert!(lowered.compressions.is_empty());
            assert!(lowered.connectors.is_empty());
            assert!(lowered.permutations.len() > bytes / 136);
            assert!(
                lowered
                    .circuit
                    .rows
                    .iter()
                    .all(
                        |&[a, b, u, d]| lowered.values[a] * lowered.values[b] + lowered.values[u] == lowered.values[d]
                    )
            );
            let bridge = KeccakBridge::new(lowered.circuit.clone(), lowered.keccak_connectors.clone()).unwrap();
            let fresh = program(bytes, 19);
            let witness = prepared.prepare_witness(&fresh).unwrap();
            let context = primitives::protocol_hash::hash(b"native-keccak-compiler-test");
            let proof = bridge.prove(&witness.values, &witness.permutations, &context).unwrap();
            assert!(bridge.verify(&witness.public, &context, &proof));
            assert!(!bridge.verify(&witness.public, &[99; 32], &proof));
            let mut tampered = proof.clone();
            tampered.stream[0] += F192::ONE;
            assert!(!bridge.verify(&witness.public, &context, &tampered));
            let mut wrong_path = proof.clone();
            let path = wrong_path
                .merkle
                .iter_mut()
                .find(|p| !p.sibling_hashes.is_empty())
                .unwrap();
            path.sibling_hashes[0][0] ^= 1;
            assert!(!bridge.verify(&witness.public, &context, &wrong_path));
            let mut false_permutations = witness.permutations.clone();
            false_permutations[0][0] ^= 1;
            let forged = bridge
                .prove_mixed_without_prechecks_for_tests(&witness.values, &false_permutations, &[], &context)
                .unwrap();
            assert!(!bridge.verify(&witness.public, &context, &forged));
        }
    }
}
