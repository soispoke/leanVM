//! Standard sparse R1CS lowering for row-format measurements.
//! Native BLAKE2s remains a separate, unchanged Flock relation.

use crate::native_arithmetic::Circuit;
use crate::row_hash::{Block as Compression, Connectors, PORTS};
use primitives::field::F192;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

pub mod deferred;
pub mod first;
pub mod fold;
pub mod generator;
pub mod spartan;
pub mod tree;

/// Record one synthetic sparse-index PCS component, excluding memory checks.
pub fn record_sparse_pcs_component(
    proof: &fiat_shamir::transcript::Proof,
    columns: &[usize],
    nlog: usize,
    words: usize,
) -> serde_json::Value {
    use crate::{
        trace::{self, S},
        verifier::{Transcript, eq, verify_basis_opening_lanes_rate},
    };
    trace::start();
    let label = b"conditional-sparse-pcs-components-v1";
    let parts: Vec<_> = label
        .chunks(24)
        .map(|chunk| {
            let mut bytes = [0; 24];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let limb = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
            (S::c(F192::new(limb(0), limb(8), limb(16))), chunk.len())
        })
        .collect();
    let seed = trace::hash(&parts);
    let mut t = Transcript::from_state(proof, seed);
    let root = t.root();
    let point: Vec<_> = (0..nlog).map(|_| t.sample()).collect();
    let beta = t.sample();
    let target = t.next();
    let log_n = words.next_power_of_two().trailing_zeros() as usize;
    let lanes = words >> (log_n - pcs::whir::INITIAL_FOLDING_FACTOR);
    verify_basis_opening_lanes_rate(&mut t, log_n, 2, lanes, root, target, |x| {
        let mut result = S::u(0);
        let mut at = 0;
        let mut power = S::u(1);
        for &l in columns {
            let selector = x[l..].iter().enumerate().fold(S::u(1), |s, (j, &v)| {
                s * if (at >> (j + l)) & 1 == 1 { v } else { S::u(1) + v }
            });
            result = result + power * selector * eq(&point[..l], &x[..l]);
            at += 1usize << l;
            power = power * beta;
        }
        result
    });
    t.finish();
    let mut program = trace::take();
    program.public = seed.to_vec();
    assert!(program.satisfied());
    let lower = crate::private_trace::lower(&program, &program).unwrap();
    serde_json::json!({"native_rows":lower.circuit.rows.len(),"compressions":lower.compressions.len(),"kind":"synthetic PCS verifier component; excludes SPARK memory/product checks"})
}

pub type Form = Vec<(usize, F192)>;

#[derive(Clone, Default)]
pub struct Matrix {
    pub offsets: Vec<usize>,
    pub entries: Form,
}

impl Matrix {
    fn push(&mut self, form: Form) {
        self.offsets.push(self.entries.len());
        self.entries.extend(form);
    }
    fn finish(&mut self) {
        self.offsets.push(self.entries.len());
    }
    pub fn rows(&self) -> usize {
        self.offsets.len() - 1
    }
    pub fn row(&self, r: usize) -> &[(usize, F192)] {
        &self.entries[self.offsets[r]..self.offsets[r + 1]]
    }
    pub fn product(&self, z: &[F192], rows: usize) -> Vec<F192> {
        parallel::map_collect(rows, |r| {
            if r >= self.rows() {
                return F192::ZERO;
            }
            self.row(r)
                .iter()
                .fold(F192::ZERO, |s, &(c, v)| s + spartan::scaled(v, z[c]))
        })
    }
}

#[derive(Clone)]
pub enum Origin {
    Variable(usize),
    Constant(F192),
}

pub struct R1cs {
    pub matrices: [Matrix; 3],
    pub origins: Vec<Origin>,
    pub public_len: usize,
    pub public_log: usize,
    pub port_start: usize,
    pub block_log: usize,
    pub actual_blocks: usize,
    pub eliminated_definitions: usize,
    pub original_rows: usize,
    pub original_variables: usize,
    pub pure_add_rows: usize,
    pub linear_rows: usize,
}

fn sum(forms: impl IntoIterator<Item = (Arc<Form>, F192)>) -> Form {
    let mut out = BTreeMap::new();
    for (form, scale) in forms {
        for &(i, c) in form.iter() {
            let entry = out.entry(i).or_insert(F192::ZERO);
            *entry += c * scale;
        }
    }
    out.into_iter().filter(|&(_, c)| c != F192::ZERO).collect()
}

struct Expand<'a> {
    defs: &'a [Option<Vec<(usize, F192)>>],
    fixed: &'a HashMap<usize, F192>,
    cache: Vec<Option<Arc<Form>>>,
}
impl Expand<'_> {
    fn at(&mut self, id: usize) -> Arc<Form> {
        if let Some(form) = &self.cache[id] {
            return form.clone();
        }
        let form = if let Some(&v) = self.fixed.get(&id) {
            if v == F192::ZERO { Vec::new() } else { vec![(1, v)] }
        } else if let Some(def) = &self.defs[id] {
            let def = def.clone();
            let parts: Vec<_> = def.iter().map(|&(i, c)| (self.at(i), c)).collect();
            sum(parts)
        } else {
            vec![(id, F192::ONE)]
        };
        let form = Arc::new(form);
        self.cache[id] = Some(form.clone());
        form
    }
}

fn remap(form: &[(usize, F192)], map: &[usize]) -> Form {
    let mut out: Form = form.iter().map(|&(i, c)| (map[i], c)).collect();
    out.sort_unstable_by_key(|&(i, _)| i);
    out
}

impl R1cs {
    /// Fixed constants are a trusted prefix of the source circuit's public inputs.
    /// The remaining public inputs are the instance's outputs.
    pub fn lower(
        circuit: &Circuit,
        connectors: &[Connectors],
        values: &[F192],
        fixed_len: usize,
        affine: bool,
    ) -> Self {
        Self::lower_bounded(
            circuit,
            connectors,
            values,
            fixed_len,
            if affine { usize::MAX } else { 0 },
        )
    }
    pub fn lower_bounded(
        circuit: &Circuit,
        connectors: &[Connectors],
        values: &[F192],
        fixed_len: usize,
        max_terms: usize,
    ) -> Self {
        assert!(fixed_len >= 2 && fixed_len <= circuit.public.len());
        assert_eq!(values.len(), circuit.variables);
        assert_eq!(&circuit.public[..2], &[0, 1]);
        let fixed: HashMap<_, _> = circuit.public[..fixed_len].iter().map(|&i| (i, values[i])).collect();
        assert_eq!(fixed[&0], F192::ZERO);
        assert_eq!(fixed[&1], F192::ONE);
        let mut defs = vec![None; circuit.variables];
        let mut used = vec![false; circuit.variables];
        let mut assigned = vec![false; circuit.variables];
        let mut removed = vec![false; circuit.rows.len()];
        let mut pure_add_rows = 0;
        for (r, &[a, b, u, d]) in circuit.rows.iter().enumerate() {
            if (a == 1 || b == 1) && a != 0 && b != 0 && u != 0 {
                pure_add_rows += 1;
            }
            let factor = fixed
                .get(&a)
                .map(|&k| (b, k))
                .or_else(|| fixed.get(&b).map(|&k| (a, k)));
            if max_terms > 0
                && !used[d]
                && !assigned[d]
                && !fixed.contains_key(&d)
                && d != a
                && d != b
                && d != u
                && let Some((v, k)) = factor
            {
                let form = |id| {
                    if let Some(&value) = fixed.get(&id) {
                        Arc::new(if value == F192::ZERO { vec![] } else { vec![(1, value)] })
                    } else {
                        Arc::new(defs[id].clone().unwrap_or_else(|| vec![(id, F192::ONE)]))
                    }
                };
                let candidate = sum([(form(v), k), (form(u), F192::ONE)]);
                if candidate.len() <= max_terms {
                    defs[d] = Some(candidate);
                    removed[r] = true;
                }
            }
            for i in [a, b, u] {
                used[i] = true;
            }
            assigned[d] = true;
        }
        let public_len = 1 + circuit.public.len() - fixed_len;
        let public_log = public_len.next_power_of_two().trailing_zeros() as usize;
        let blocks = connectors.len().max(128).next_power_of_two();
        let port_start = (1usize << public_log).next_multiple_of(blocks);
        let mut origins = vec![Origin::Constant(F192::ZERO); port_start];
        origins[0] = Origin::Constant(F192::ONE);
        let mut map = vec![usize::MAX; circuit.variables];
        map[1] = 0;
        for (j, &id) in circuit.public[fixed_len..].iter().enumerate() {
            origins[j + 1] = Origin::Variable(id);
            if defs[id].is_none() && !fixed.contains_key(&id) {
                map[id] = j + 1;
            }
        }
        let padding = crate::row_hash::padding();
        for slot in 0..PORTS {
            for block in 0..blocks {
                origins.push(
                    connectors
                        .get(block)
                        .map_or(Origin::Constant(F192::new(padding[slot], 0, 0)), |io| {
                            Origin::Variable(io[slot])
                        }),
                );
            }
        }
        let mut expand = Expand {
            defs: &defs,
            fixed: &fixed,
            cache: vec![None; circuit.variables],
        };
        let mut symbolic: Vec<[Arc<Form>; 3]> = Vec::new();
        let mut linear_rows = 0;
        let one = Arc::new(vec![(1, F192::ONE)]);
        let zero = Arc::new(Vec::new());
        for (r, &[a, b, u, d]) in circuit.rows.iter().enumerate() {
            if removed[r] {
                continue;
            }
            let fa = expand.at(a);
            let fb = expand.at(b);
            let fc = Arc::new(sum([(expand.at(u), F192::ONE), (expand.at(d), F192::ONE)]));
            let scalar = |f: &Form| {
                if f.is_empty() {
                    Some(F192::ZERO)
                } else if f.len() == 1 && f[0].0 == 1 {
                    Some(f[0].1)
                } else {
                    None
                }
            };
            if let Some((s, t)) = scalar(&fa)
                .map(|k| (fb.clone(), k))
                .or_else(|| scalar(&fb).map(|k| (fa.clone(), k)))
            {
                let relation = Arc::new(sum([(s, t), (fc, F192::ONE)]));
                if !relation.is_empty() {
                    symbolic.push([relation, one.clone(), zero.clone()]);
                    linear_rows += 1;
                }
            } else {
                symbolic.push([fa, fb, fc]);
            }
        }
        // Public and hash ports are materialized even if their source definitions were substituted.
        let mut materialized = Vec::new();
        for (j, &id) in circuit.public[fixed_len..].iter().enumerate() {
            materialized.push((j + 1, expand.at(id)));
        }
        for slot in 0..PORTS {
            for block in 0..blocks {
                let form = connectors.get(block).map_or_else(
                    || {
                        Arc::new(if padding[slot] == 0 {
                            vec![]
                        } else {
                            vec![(1, F192::new(padding[slot], 0, 0))]
                        })
                    },
                    |io| expand.at(io[slot]),
                );
                materialized.push((port_start + slot * blocks + block, form));
            }
        }
        for row in &symbolic {
            for form in row {
                for &(id, _) in form.iter() {
                    if map[id] == usize::MAX {
                        map[id] = origins.len();
                        origins.push(Origin::Variable(id));
                    }
                }
            }
        }
        for (_, form) in &materialized {
            for &(id, _) in form.iter() {
                if map[id] == usize::MAX {
                    map[id] = origins.len();
                    origins.push(Origin::Variable(id));
                }
            }
        }
        let mut matrices = std::array::from_fn(|_| Matrix::default());
        for row in symbolic {
            for (m, form) in matrices.iter_mut().zip(row) {
                m.push(remap(&form, &map));
            }
        }
        for (dest, form) in materialized {
            let mut relation: BTreeMap<usize, F192> = remap(&form, &map).into_iter().collect();
            *relation.entry(dest).or_insert(F192::ZERO) += F192::ONE;
            let relation: Form = relation.into_iter().filter(|&(_, c)| c != F192::ZERO).collect();
            if !relation.is_empty() {
                matrices[0].push(relation);
                matrices[1].push(vec![(0, F192::ONE)]);
                matrices[2].push(vec![]);
                linear_rows += 1;
            }
        }
        for m in &mut matrices {
            m.finish();
        }
        Self {
            matrices,
            origins,
            public_len,
            public_log,
            port_start,
            block_log: blocks.trailing_zeros() as usize,
            actual_blocks: connectors.len(),
            eliminated_definitions: removed.iter().filter(|&&x| x).count(),
            original_rows: circuit.rows.len(),
            original_variables: circuit.variables,
            pure_add_rows,
            linear_rows,
        }
    }
    pub fn witness(&self, source: &[F192]) -> Vec<F192> {
        self.origins
            .iter()
            .map(|o| match *o {
                Origin::Variable(i) => source[i],
                Origin::Constant(v) => v,
            })
            .collect()
    }
    pub fn rows(&self) -> usize {
        self.matrices[0].rows()
    }
    pub fn satisfied(&self, z: &[F192]) -> bool {
        (0..self.rows()).all(|r| {
            let [a, b, c] = self
                .matrices
                .each_ref()
                .map(|m| m.row(r).iter().fold(F192::ZERO, |s, &(i, c)| s + c * z[i]));
            a * b == c
        })
    }
    pub fn census(&self) -> serde_json::Value {
        serde_json::json!({"source_rows":self.original_rows,"source_variables":self.original_variables,
            "pure_add_rows":self.pure_add_rows,"pure_add_share":self.pure_add_rows as f64/self.original_rows.max(1) as f64,
            "eliminated_definitions":self.eliminated_definitions,"constraints":self.rows(),
            "linear_constraints":self.linear_rows,"nonzeros":self.matrices.each_ref().map(|m|m.entries.len()),
            "witness_length_f192":self.origins.len(),"witness_padded_f192":self.origins.len().next_power_of_two(),
            "public_length":self.public_len,"hash_port_start":self.port_start,"native_compressions":self.actual_blocks,
            "hash_slots":1usize<<self.block_log,
            "max_row_nonzeros":self.matrices.iter().map(|m|(0..m.rows()).map(|r|m.row(r).len()).max().unwrap_or(0)).max()})
    }
}

/// The shared source fixtures are exported once and used by every row backend.
pub struct Source {
    pub circuit: Circuit,
    pub connectors: Vec<Connectors>,
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    pub fixed_len: usize,
    pub rebuild: Box<dyn Fn() -> (Vec<F192>, Vec<Compression>)>,
}

impl Source {
    /// Digest only the fixed graph, public layout/constants and native hash routing.
    pub fn program_digest(&self) -> [u8; 32] {
        let mut h = primitives::protocol_hash::Hasher::new();
        h.update(b"standard-row-format-source-v1");
        for n in [
            self.circuit.variables,
            self.circuit.rows.len(),
            self.circuit.public.len(),
            self.fixed_len,
            self.connectors.len(),
        ] {
            h.update(&(n as u64).to_le_bytes());
        }
        for row in &self.circuit.rows {
            for &id in row {
                h.update(&(id as u64).to_le_bytes());
            }
        }
        for &id in &self.circuit.public {
            h.update(&(id as u64).to_le_bytes());
        }
        for &id in &self.circuit.public[..self.fixed_len] {
            for v in [self.values[id].c0, self.values[id].c1, self.values[id].c2] {
                h.update(&v.to_le_bytes());
            }
        }
        for io in &self.connectors {
            for &id in io {
                h.update(&(id as u64).to_le_bytes());
            }
        }
        h.finalize()
    }
}

#[cfg(not(feature = "keccak-protocol"))]
pub fn shielded_source(seed: usize) -> Source {
    let payload = circuit_suite::shielded_blake2s::leanvm_input(seed);
    let b = crate::shielded_application::application_vm(&payload).0;
    let (circuit, connectors) = b.export_protocol_circuit();
    let fixed_len = circuit.public.len() - 4;
    let rebuild = Box::new(move || {
        let b = crate::shielded_application::application_vm(&payload).0;
        (b.values.clone(), b.protocol_blocks())
    });
    Source {
        circuit,
        connectors,
        values: b.values.clone(),
        compressions: b.protocol_blocks(),
        fixed_len,
        rebuild,
    }
}

/// Protocol-hash membership of a private 32-byte leaf in a depth-16 binary tree.
/// Sibling order is selected by sixteen Boolean private path bits.
pub fn merkle_source(seed: usize) -> Source {
    fn build(seed: usize) -> crate::native_hash::Builder {
        let mut b = crate::native_hash::Builder::default();
        let leaf: Vec<_> = (0..4)
            .map(|i| b.input((seed as u64).wrapping_mul(0x10001) + i + 17))
            .collect();
        let mut node = b.hash_words(&leaf);
        for level in 0..16 {
            let bit = b.input(((seed + level) & 1) as u64);
            b.boolean(bit);
            let sibling: [crate::native_hash::Word; 4] =
                std::array::from_fn(|i| b.input((seed as u64 + 3) * 0x1000001 + (level * 4 + i) as u64));
            let left: [crate::native_hash::Word; 4] = std::array::from_fn(|i| b.select(bit, sibling[i], node[i]));
            let right: [crate::native_hash::Word; 4] = std::array::from_fn(|i| b.select(bit, node[i], sibling[i]));
            node = b.hash_words(&left.into_iter().chain(right).collect::<Vec<_>>());
        }
        for word in node {
            b.expose(word);
        }
        b
    }
    let b = build(seed);
    let (circuit, connectors) = b.export_protocol_circuit();
    let fixed_len = circuit.public.len() - 4;
    Source {
        circuit,
        connectors,
        values: b.values.clone(),
        compressions: b.protocol_blocks(),
        fixed_len,
        rebuild: Box::new(move || {
            let b = build(seed);
            (b.values.clone(), b.protocol_blocks())
        }),
    }
}

#[cfg(not(feature = "keccak-protocol"))]
pub fn source(case: &str) -> Source {
    if case == "shielded" {
        return shielded_source(0);
    }
    assert_eq!(case, "merge");
    let mut b = crate::native_hash::Builder::default();
    let message: Vec<_> = (0..8)
        .map(|i| b.constant(u64::from_le_bytes(std::array::from_fn(|j| ((i * 8 + j) % 251) as u8))))
        .collect();
    let h = b.hash_words(&message);
    let length = b.constant(64);
    let mut statement = vec![length];
    statement.extend(h);
    let output = b.hash_words(&statement);
    for w in output {
        b.expose(w);
    }
    let bridge = b.setup().unwrap();
    let public = b.public_values();
    let context = primitives::protocol_hash::hash(b"hometurf-native-hash-application-v1");
    let proof = bridge.prove(&b.values, &b.compressions, &context).unwrap();
    assert!(bridge.verify(&public, &context, &proof));
    let statement: [u8; 32] = public[public.len() - 4..]
        .iter()
        .flat_map(|w| w.c0.to_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let cert = crate::closed_recursion::Certificate {
        height: 0,
        statement,
        proof,
    };
    let trace =
        crate::closed_recursion::record_native_first(&bridge, &public[..public.len() - 4], &context, [&cert, &cert]);
    assert!(trace.satisfied());
    let lower = crate::private_trace::lower(&trace, &trace).unwrap();
    assert!(
        lower.keccak_connectors.is_empty(),
        "sparse BLAKE source cannot discard Keccak obligations"
    );
    let fixed_len = lower.fixed_public.len();
    let prefix = public[..public.len() - 4].to_vec();
    let rebuild = Box::new(move || {
        let trace = crate::closed_recursion::record_native_first(&bridge, &prefix, &context, [&cert, &cert]);
        let lower = crate::private_trace::lower(&trace, &trace).unwrap();
        assert!(
            lower.keccak_connectors.is_empty(),
            "sparse BLAKE source cannot discard Keccak obligations"
        );
        (lower.values, lower.compressions)
    });
    Source {
        circuit: lower.circuit,
        connectors: lower.connectors,
        values: lower.values,
        compressions: lower.compressions,
        fixed_len,
        rebuild,
    }
}

#[cfg(feature = "keccak-protocol")]
pub fn shielded_source(seed: usize) -> Source {
    use circuit_suite::Workload;
    use circuit_suite::shielded_keccak::ShieldedTransfer;
    let mut c = circuit_suite::Ckt::new();
    c.enable_native_keccak();
    let public = ShieldedTransfer::build(&mut c);
    let (circuit, outputs, calls) = c.finish_native_keccak(&public);
    let circuit = Arc::new(circuit);
    let outputs = Arc::new(outputs);
    let calls = Arc::new(calls);
    let make = move || {
        let instance = ShieldedTransfer::instance(seed as u64);
        let mut b = crate::native_hash::Builder::default();
        let inputs: Vec<_> = instance.inputs.iter().map(|&x| b.input(u64::from(x))).collect();
        let bits = crate::boolean_application::lower_with_keccak(&mut b, &circuit, &outputs, &inputs, &calls);
        let one = b.one();
        b.assert_eq(bits[256], one);
        let mut words = Vec::new();
        for chunk in bits[..256].chunks(64) {
            words.push(b.pack(chunk));
        }
        let digest = b.hash_words(&words);
        let expected = primitives::protocol_hash::hash(&instance.statement[..32]);
        let actual: Vec<_> = digest.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
        assert_eq!(actual, expected);
        for word in digest {
            b.expose(word);
        }
        b
    };
    let b = make();
    let (circuit, connectors) = b.export_protocol_circuit();
    let fixed_len = circuit.public.len() - 4;
    Source {
        circuit,
        connectors,
        compressions: b.protocol_blocks(),
        values: b.values,
        fixed_len,
        rebuild: Box::new(move || {
            let b = make();
            (b.values.clone(), b.protocol_blocks())
        }),
    }
}

#[cfg(feature = "keccak-protocol")]
pub fn source(case: &str) -> Source {
    if case == "shielded" {
        return shielded_source(0);
    }
    assert_eq!(
        case, "merkle",
        "legacy fixed BLAKE merge fixture is unavailable in the Keccak configuration"
    );
    merkle_source(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_affine_lowering_preserves_shared_definitions_and_rejects_changed_product() {
        let c = Circuit {
            variables: 8,
            public: vec![0, 1, 7],
            rows: vec![[2, 1, 3, 4], [4, 1, 2, 5], [5, 3, 0, 6], [6, 1, 4, 7]],
        };
        let v = vec![
            F192::ZERO,
            F192::ONE,
            F192::new(3, 0, 0),
            F192::new(5, 0, 0),
            F192::new(6, 0, 0),
            F192::new(5, 0, 0),
            F192::new(17, 0, 0),
            F192::new(23, 0, 0),
        ];
        // Compute in the actual binary field, rather than integer arithmetic.
        let mut v = v;
        v[4] = v[2] + v[3];
        v[5] = v[4] + v[2];
        v[6] = v[5] * v[3];
        v[7] = v[6] + v[4];
        let r = R1cs::lower(&c, &[[0; PORTS]], &v, 2, true);
        let mut z = r.witness(&v);
        assert!(r.satisfied(&z));
        z[1] += F192::ONE;
        assert!(!r.satisfied(&z));
        assert!(r.eliminated_definitions >= 2);
    }
}
