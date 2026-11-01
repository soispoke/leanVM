//! One fixed merge circuit for wallet+wallet, wallet+node and node+node.
//! Every child uses one public, bounded proof layout. All identities are data.
use super::{
    deferred::{self, WireClaim, literal},
    first,
    fold::Reduction,
    generator::Generator,
    spartan::{DeferredClaim, Setup},
    tree::{self, Certificate, Schema, Slot, Statement},
};
use crate::trace::{self, S, Trace, hash};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use primitives::field::F192;

fn boolean(x: S) {
    (x * (x + S::u(1))).assert_eq(S::u(0));
}
fn digest<const N: usize>(schema: Schema<N>, children: [&Certificate; 2]) -> Hash {
    let mut bytes = b"r1cs-universal-ordered-tree-v1".to_vec();
    for (r, c) in schema.shapes {
        bytes.extend((r as u64).to_le_bytes());
        bytes.extend((c as u64).to_le_bytes());
    }
    for child in children {
        let mut public = vec![F192::ONE];
        public.extend(schema.fields(&child.statement));
        bytes.extend(first::child_digest(&child.key, &public));
    }
    primitives::protocol_hash::hash(&bytes)
}
/// `fresh_slots` is witness advice, subsequently one-hot checked in the circuit.
/// Slot assignments are shared by both children; different identities in one slot reject.
pub fn inputs<const N: usize>(
    schema: Schema<N>,
    children: [&Certificate; 2],
    fresh: [DeferredClaim; 2],
    fresh_slots: [usize; 2],
) -> (Vec<Slot>, Vec<usize>, Hash) {
    let mut inputs = Vec::new();
    let mut routes = Vec::new();
    for i in 0..2 {
        assert!(fresh_slots[i] < N);
        assert!(schema.well_formed(&children[i].statement));
        for (slot, claim) in children[i].statement.slots.iter().enumerate() {
            inputs.push(claim.clone());
            routes.push(slot);
        }
        for slot in 0..N {
            inputs.push(Slot {
                active: slot == fresh_slots[i],
                claim: fresh[i].clone(),
            });
            routes.push(slot);
        }
    }
    (inputs, routes, digest(schema, children))
}
/// No native prover precheck is used here. Every child proof and claim is replayed.
pub fn record<const N: usize>(
    schema: Schema<N>,
    shape: &Setup,
    children: [&Certificate; 2],
    fresh_slots: [usize; 2],
    context: &Hash,
    reduction: &Reduction,
) -> Trace {
    assert!(N >= 3 && schema.shapes.iter().all(|s| *s == schema.shapes[0]));
    trace::start();
    let mut inputs = Vec::new();
    let mut active = Vec::new();
    let mut routes = Vec::new();
    let mut parts = literal(b"r1cs-universal-ordered-tree-v1");
    for (r, c) in schema.shapes {
        parts.push((S::u(r as u64), 8));
        parts.push((S::u(c as u64), 8));
    }
    for (child_index, child) in children.into_iter().enumerate() {
        let identity = hash_to_scalars(&child.key).map(S::input);
        let fields: Vec<_> = schema.fields(&child.statement).into_iter().map(S::input).collect();
        let kind = fields[0];
        boolean(kind);
        let mut public = vec![S::u(1)];
        public.extend_from_slice(&fields);
        let (fresh, child_digest) = deferred::verify_shape_in_rows(shape, identity, &public, context, &child.proof);
        parts.extend(child_digest.map(|v| (v, 16)));
        let mut cursor = 3;
        for slot in 0..N {
            let on = fields[cursor];
            cursor += 1;
            boolean(on);
            // A wallet leaves no inherited obligations: only its fresh matrix claim.
            ((S::u(1) + kind) * on).assert_eq(S::u(0));
            let (r, c) = schema.shapes[slot];
            let key = [fields[cursor], fields[cursor + 1]];
            cursor += 2;
            let rp = fields[cursor..cursor + r].to_vec();
            cursor += r;
            let cp = fields[cursor..cursor + c].to_vec();
            cursor += c;
            let values = fields[cursor..cursor + 3].try_into().unwrap();
            cursor += 3;
            let claim = WireClaim {
                app_key: key,
                row_point: rp,
                col_point: cp,
                matrix_values: values,
            };
            for v in claim.flatten() {
                ((S::u(1) + on) * v).assert_eq(S::u(0));
            }
            inputs.push(claim);
            active.push(on);
            routes.push(slot);
        }
        let mut selected = S::u(0);
        for slot in 0..N {
            let on = S::input(F192::new(u64::from(fresh_slots[child_index] == slot), 0, 0));
            boolean(on);
            // Characteristic-two parity alone would allow three selections.
            (selected * on).assert_eq(S::u(0));
            selected = selected + on;
            inputs.push(fresh.clone());
            active.push(on);
            routes.push(slot);
        }
        selected.assert_eq(S::u(1));
    }
    let digest = hash(&parts);
    let mut enabled = [S::u(0); N];
    let mut keys = [[S::u(0); 2]; N];
    for ((claim, &on), &slot) in inputs.iter().zip(&active).zip(&routes) {
        for j in 0..2 {
            (enabled[slot] * on * (keys[slot][j] + claim.app_key[j])).assert_eq(S::u(0));
        }
        let choose = (S::u(1) + enabled[slot]) * on;
        for j in 0..2 {
            keys[slot][j] = keys[slot][j] + choose * claim.app_key[j];
        }
        enabled[slot] = enabled[slot] + choose;
    }
    for i in 0..N {
        for j in i + 1..N {
            let diff = [keys[i][0] + keys[j][0], keys[i][1] + keys[j][1]];
            let selector = S::input(F192::new(u64::from(diff[0].value() == F192::ZERO), 0, 0));
            boolean(selector);
            let d = diff[0] + selector * (diff[0] + diff[1]);
            let inv = S::input(if d.value() == F192::ZERO {
                F192::ZERO
            } else {
                d.value().inv()
            });
            (enabled[i] * enabled[j] * (d * inv + S::u(1))).assert_eq(S::u(0));
        }
    }
    let output = tree::verify_fold(
        schema,
        &inputs,
        &active,
        &routes,
        keys,
        enabled,
        digest,
        &reduction.proof,
    );
    let mut public = vec![S::u(1), digest[0], digest[1]];
    for i in 0..N {
        public.push(enabled[i]);
        public.extend(output[i].flatten());
    }
    let mut program = trace::take();
    program.public = public;
    program
}
/// Full acceptance with every inherited and fresh matrix obligation settled.
/// Registry authentication is a separate mandatory boundary, not prover advice.
pub fn verify_root<const N: usize>(
    schema: Schema<N>,
    aggregate: &first::SparseSetup,
    expected: &Hash,
    statement: &Statement,
    context: &Hash,
    proof: &Proof,
    registry: [Option<&Generator>; N],
) -> bool {
    if !statement.kind || &statement.digest != expected || !schema.well_formed(statement) {
        return false;
    }
    let Some(own) = aggregate.verify(&schema.fields(statement), context, proof) else {
        return false;
    };
    for (slot, g) in statement.slots.iter().zip(registry) {
        if slot.active && !g.is_some_and(|g| g.settle(&slot.claim)) {
            return false;
        }
    }
    aggregate.generator.settle(&own)
}

/// Wrap a 32-byte (four base-field word) wallet statement into the common
/// public layout. Empty inherited slots are constrained constants, not advice.
/// Application identity changes to name this exact transformed generator.
pub fn wallet_source<const N: usize>(mut source: super::Source, schema: Schema<N>) -> super::Source {
    let outputs: [usize; 4] = source.circuit.public[source.fixed_len..]
        .try_into()
        .expect("32-byte wallet statement");
    let basis = source.values.len();
    source.values.push(F192::new(0, 1, 0));
    source.circuit.public.truncate(source.fixed_len);
    source.circuit.public.push(basis);
    source.fixed_len += 1;
    let rebuild = source.rebuild;
    let extend = move |mut values: Vec<F192>| {
        values.push(F192::new(0, 1, 0));
        for i in 0..2 {
            values.push(values[outputs[2 * i]] + values[outputs[2 * i + 1]] * F192::new(0, 1, 0));
        }
        values
    };
    source.values = extend(source.values[..basis].to_vec());
    source.circuit.variables += 3;
    for i in 0..2 {
        source
            .circuit
            .rows
            .push([outputs[2 * i + 1], basis, outputs[2 * i], basis + 1 + i]);
    }
    source.circuit.public.extend([0, basis + 1, basis + 2]);
    for (r, c) in schema.shapes {
        source.circuit.public.extend(std::iter::repeat_n(0, 6 + r + c));
    }
    source.rebuild = Box::new(move || {
        let (values, blocks) = rebuild();
        (extend(values), blocks)
    });
    source
}
/// Public envelope: every proof uses identical dimensions, ports and public layout.
/// Overflow rejects at setup; it never truncates an application or changes the key.
pub fn wallet_setup(source: &super::Source, row_log: usize, col_log: usize, block_log: usize) -> (Setup, Generator) {
    let mut r = super::R1cs::lower_bounded_with_blocks(
        &source.circuit,
        &source.connectors,
        &source.values,
        source.fixed_len,
        8,
        1 << block_log,
    );
    assert_eq!(r.block_log, block_log, "hash schedule exceeds frozen envelope");
    r.pad_dimensions(row_log, col_log);
    let setup = Setup::new(r, false);
    let mut generator = Generator::new_with_blocks(source, 8, setup.key, 1 << block_log);
    generator.row_log = row_log;
    generator.col_log = col_log;
    (setup, generator)
}

/// Canonical generator data excludes every nonconstant witness value.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Description {
    pub version: u32,
    pub circuit: crate::native_arithmetic::Circuit,
    #[cfg_attr(feature = "keccak-protocol", serde(with = "connector_serde"))]
    pub connectors: Vec<crate::row_hash::Connectors>,
    pub fixed_len: usize,
    pub fixed_values: Vec<F192>,
}
impl Description {
    pub fn from_source(source: &super::Source) -> Self {
        Self {
            version: if cfg!(feature = "keccak-protocol") { 2 } else { 1 },
            circuit: source.circuit.clone(),
            connectors: source.connectors.clone(),
            fixed_len: source.fixed_len,
            fixed_values: source.circuit.public[..source.fixed_len]
                .iter()
                .map(|&i| source.values[i])
                .collect(),
        }
    }
    /// Structural/resource admission for the frozen native graph grammar.
    pub fn validate(&self, max_log: usize, max_blocks: usize) -> bool {
        let Some(limit) = 1usize.checked_shl(max_log as u32) else {
            return false;
        };
        self.version == if cfg!(feature = "keccak-protocol") { 2 } else { 1 }
            && self.circuit.variables >= 2
            && self.circuit.variables <= limit
            && self.circuit.rows.len() <= limit
            && self.connectors.len() <= max_blocks
            && self.fixed_len >= 2
            && self.fixed_len <= 4096
            && self.circuit.public.len() == self.fixed_len + 4
            && self.fixed_values.len() == self.fixed_len
            && self.circuit.public[..2] == [0, 1]
            && self.fixed_values[..2] == [F192::ZERO, F192::ONE]
            && self.circuit.public.iter().all(|&i| i < self.circuit.variables)
            && self.circuit.rows.iter().flatten().all(|&i| i < self.circuit.variables)
            && self.connectors.iter().flatten().all(|&i| i < self.circuit.variables)
            && self.circuit.public[..self.fixed_len]
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.fixed_len
    }
    pub fn source(&self) -> super::Source {
        assert_eq!(self.version, if cfg!(feature = "keccak-protocol") { 2 } else { 1 });
        assert!(self.fixed_len >= 2 && self.fixed_len <= self.circuit.public.len());
        assert_eq!(self.fixed_values.len(), self.fixed_len);
        let mut values = vec![F192::ZERO; self.circuit.variables];
        for (&i, &v) in self.circuit.public[..self.fixed_len].iter().zip(&self.fixed_values) {
            values[i] = v;
        }
        super::Source {
            circuit: self.circuit.clone(),
            connectors: self.connectors.clone(),
            fixed_len: self.fixed_len,
            values,
            compressions: Vec::new(),
            rebuild: Box::new(|| unreachable!("generator has no witness")),
        }
    }
    pub fn application_id(&self) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        Keccak256::digest(bincode::serialize(self).unwrap()).into()
    }
}
/// Strip dummy setup proof values from the retained aggregate generator.
pub fn canonical_trace(mut trace: Trace) -> Trace {
    for node in &mut trace.nodes {
        if !matches!(node.op, crate::trace::Op::Constant) {
            node.value = F192::ZERO;
        }
    }
    trace
}

fn final_label(certificate: &Certificate) -> Hash {
    let mut bytes = b"r1cs-universal-root-finalization-v1".to_vec();
    bytes.extend(bincode::serialize(certificate).unwrap());
    primitives::protocol_hash::hash(&bytes)
}
/// Fold the carried and fresh aggregate evaluations after the outer proof.
/// This sidecar is part of the forwarded certificate and its generation cost.
pub fn finalize<const N: usize>(
    schema: Schema<N>,
    aggregate: &first::SparseSetup,
    certificate: &Certificate,
    context: &Hash,
) -> Option<Reduction> {
    if N < 3
        || !certificate.statement.kind
        || certificate.key != aggregate.setup.key
        || !schema.well_formed(&certificate.statement)
    {
        return None;
    }
    let own = aggregate.verify(&schema.fields(&certificate.statement), context, &certificate.proof)?;
    let carried = &certificate.statement.slots[N - 1];
    if !carried.active || carried.claim.app_key != aggregate.setup.key {
        return None;
    }
    Some(super::fold::prove_generated(
        &[&aggregate.setup],
        &[&aggregate.generator],
        &[carried.claim.clone(), own],
        &final_label(certificate),
    ))
}
/// Root settles the aggregate identity once even when it occurs at two points.
/// Every application identity still settles; the sidecar cannot omit an input.
pub fn verify_root_finalized<const N: usize>(
    schema: Schema<N>,
    aggregate: &first::SparseSetup,
    expected: &Hash,
    certificate: &Certificate,
    context: &Hash,
    registry: [Option<&Generator>; N],
    finalization: Option<&Reduction>,
) -> bool {
    if N < 3
        || !certificate.statement.kind
        || certificate.key != aggregate.setup.key
        || &certificate.statement.digest != expected
        || !schema.well_formed(&certificate.statement)
    {
        return false;
    }
    let Some(own) = aggregate.verify(&schema.fields(&certificate.statement), context, &certificate.proof) else {
        return false;
    };
    for (i, slot) in certificate.statement.slots[..N - 1].iter().enumerate() {
        if slot.active
            && (slot.claim.app_key == aggregate.setup.key || !registry[i].is_some_and(|g| g.settle(&slot.claim)))
        {
            return false;
        }
    }
    let carried = &certificate.statement.slots[N - 1];
    if carried.active {
        if carried.claim.app_key != aggregate.setup.key {
            return false;
        }
        let Some(finalization) = finalization else {
            return false;
        };
        let Some(claims) = super::fold::verify_native(
            &[&aggregate.setup],
            &[carried.claim.clone(), own],
            &final_label(certificate),
            finalization,
        ) else {
            return false;
        };
        aggregate.generator.settle(&claims[0])
    } else {
        finalization.is_none() && aggregate.generator.settle(&own)
    }
}

#[cfg(feature = "keccak-protocol")]
mod connector_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &[crate::row_hash::Connectors], s: S) -> Result<S::Ok, S::Error> {
        value.iter().map(|a| a.to_vec()).collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<crate::row_hash::Connectors>, D::Error> {
        Vec::<Vec<usize>>::deserialize(d)?
            .into_iter()
            .map(|v| {
                v.try_into()
                    .map_err(|_| serde::de::Error::custom("wrong protocol connector count"))
            })
            .collect()
    }
}

#[cfg(test)]
mod description_tests {
    use super::*;
    #[test]
    fn external_generator_admission_checks_bounds_anchors_and_indices() {
        let source = super::super::merkle_source(3);
        let mut description = Description::from_source(&source);
        assert!(description.validate(22, 1 << 15));
        let saved = description.circuit.variables;
        description.circuit.variables = usize::MAX;
        assert!(!description.validate(22, 1 << 15));
        description.circuit.variables = saved;
        description.fixed_values[0] = F192::ONE;
        assert!(!description.validate(22, 1 << 15));
        description.fixed_values[0] = F192::ZERO;
        let saved = description.circuit.rows[0][0];
        description.circuit.rows[0][0] = description.circuit.variables;
        assert!(!description.validate(22, 1 << 15));
        description.circuit.rows[0][0] = saved;
        let saved = description.connectors[0][0];
        description.connectors[0][0] = description.circuit.variables;
        assert!(!description.validate(22, 1 << 15));
        description.connectors[0][0] = saved;
        assert!(!description.validate(22, 0));
        assert!(description.validate(22, 1 << 15));
    }
}
