//! Fixed-shape carried-claim node. Keys are witness data, settled by the root.
use super::{
    deferred::{self, WireClaim, literal, plain_round},
    fold::{self, Reduction},
    generator::Generator,
    spartan::{DeferredClaim, Setup},
};
use crate::{
    trace::{self, S, Trace, hash},
    verifier::{Transcript, eq, powers},
};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::{Challenger, Proof, ProverState, Transmitter},
};
use primitives::{field::F192, multilinear::eq_table};

/// Two application shapes and the first/node wrapper shapes. Shape is a
/// protocol parameter; application identities do not appear in the circuit.
#[derive(Clone, Copy)]
pub struct Schema {
    pub shapes: [(usize, usize); 4],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Slot {
    pub active: bool,
    pub claim: DeferredClaim,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Statement {
    pub kind: bool,
    pub digest: Hash,
    pub slots: Vec<Slot>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Certificate {
    pub key: Hash,
    pub statement: Statement,
    pub proof: Proof,
}
impl Schema {
    pub fn empty(&self, slot: usize) -> Slot {
        let (r, c) = self.shapes[slot];
        Slot {
            active: false,
            claim: DeferredClaim {
                app_key: [0; 32],
                row_point: vec![F192::ZERO; r],
                col_point: vec![F192::ZERO; c],
                matrix_values: [F192::ZERO; 3],
            },
        }
    }
    pub fn fields(&self, s: &Statement) -> Vec<F192> {
        assert_eq!(s.slots.len(), 4);
        let mut out = vec![F192::new(u64::from(s.kind), 0, 0)];
        out.extend(hash_to_scalars(&s.digest));
        for (i, slot) in s.slots.iter().enumerate() {
            assert_eq!((slot.claim.row_point.len(), slot.claim.col_point.len()), self.shapes[i]);
            out.push(F192::new(u64::from(slot.active), 0, 0));
            out.extend(
                super::first::output_fields(&[0; 32], std::slice::from_ref(&slot.claim))
                    .into_iter()
                    .skip(2),
            );
        }
        out
    }
    pub fn wrap_first(&self, mut program: Trace, digest: Hash, carried: &[DeferredClaim]) -> (Trace, Statement) {
        assert!(carried.len() <= 2);
        let old = program.public.clone();
        let mut slots: Vec<_> = (0..4).map(|i| self.empty(i)).collect();
        for (i, c) in carried.iter().enumerate() {
            slots[i] = Slot {
                active: true,
                claim: c.clone(),
            };
        }
        let statement = Statement {
            kind: false,
            digest,
            slots,
        };
        trace::resume(program);
        let mut public = vec![S::u(0), old[0], old[1]];
        let mut cursor = 2;
        for i in 0..4 {
            public.push(S::u(u64::from(i < carried.len())));
            let count = 5 + self.shapes[i].0 + self.shapes[i].1;
            if i < carried.len() {
                public.extend_from_slice(&old[cursor..cursor + count]);
                cursor += count;
            } else {
                public.extend((0..count).map(|_| S::u(0)));
            }
        }
        program = trace::take();
        program.public = public;
        (program, statement)
    }
}
fn boolean(s: S) {
    (s * (s + S::u(1))).assert_eq(S::u(0));
}
fn input_key(k: &Hash) -> [S; 2] {
    hash_to_scalars(k).map(S::input)
}
fn node_digest(schema: Schema, children: [&Certificate; 2]) -> Hash {
    let mut bytes = b"r1cs-carried-tree-node-v1".to_vec();
    for (r, c) in schema.shapes {
        bytes.extend((r as u64).to_le_bytes());
        bytes.extend((c as u64).to_le_bytes());
    }
    for child in children {
        let mut public = vec![F192::ONE];
        public.extend(schema.fields(&child.statement));
        bytes.extend(super::first::child_digest(&child.key, &public));
    }
    primitives::hash::hash(&bytes)
}
// The ordered digest already commits shape, child kind, identities, every
// carried slot and its active bit. Only the fresh proof-derived claims need
// additional binding here. Each occurs twice for routing, so absorb it once.
fn label(inputs: &[Slot], digest: &Hash) -> Vec<u8> {
    let claims = [inputs[4].claim.clone(), inputs[10].claim.clone()];
    let mut out = fold::label(&claims, digest);
    out.extend(b"tree-digest-bound-slots-v2");
    out
}
fn label_rows(inputs: &[WireClaim], _active: &[S], digest: [S; 2]) -> Vec<(S, usize)> {
    let claims = [inputs[4].clone(), inputs[10].clone()];
    let mut out = fold::label_rows(&claims, digest);
    out.extend(literal(b"tree-digest-bound-slots-v2"));
    out
}
fn lift(point: &[S], k: usize) -> S {
    point[k..].iter().fold(S::u(1), |a, &x| a * (S::u(1) + x))
}

/// All carried slots and both fresh outer claims, routed without native admission.
pub fn inputs(schema: Schema, children: [&Certificate; 2], fresh: [DeferredClaim; 2]) -> (Vec<Slot>, Vec<usize>, Hash) {
    let mut inputs = Vec::new();
    let mut routes = Vec::new();
    for (i, child) in children.iter().enumerate() {
        for (j, slot) in child.statement.slots.iter().enumerate() {
            inputs.push(slot.clone());
            routes.push(j);
        }
        for slot in [2, 3] {
            inputs.push(Slot {
                active: child.statement.kind == (slot == 3),
                claim: fresh[i].clone(),
            });
            routes.push(slot);
        }
    }
    (inputs, routes, node_digest(schema, children))
}
/// Native prover. Inactive slots never walk a source or allocate dense tables.
pub fn prove(
    schema: Schema,
    registry: [Option<(&Setup, &Generator)>; 4],
    inputs: &[Slot],
    routes: &[usize],
    digest: &Hash,
) -> Reduction {
    let mut ps = ProverState::from_label(&label(inputs, digest));
    let theta = ps.sample();
    let theta2 = theta * theta;
    let theta3 = theta2 * theta;
    let mut power = F192::ONE;
    let mut target = F192::ZERO;
    let mut pairs = Vec::new();
    for (input, &slot) in inputs.iter().zip(routes) {
        if input.active {
            let (setup, g) = registry[slot].expect("active application generator");
            assert_eq!(setup.key, input.claim.app_key);
            assert_eq!(schema.shapes[slot], (g.row_log, g.col_log));
            let u = fold::weighted_eq(&input.claim.row_point, power);
            let poly = g.row_product(&eq_table(&input.claim.col_point), theta);
            pairs.push((u, poly));
            let v = input.claim.matrix_values;
            target += power * (v[0] + theta * v[1] + theta2 * v[2]);
        } else {
            pairs.push((vec![F192::ZERO], vec![F192::ZERO]));
        }
        power *= theta3;
    }
    let rlog = schema.shapes.iter().map(|p| p.0).max().unwrap();
    let clog = schema.shapes.iter().map(|p| p.1).max().unwrap();
    let (rp, row_target) = fold::sumcheck(&mut pairs, rlog, true, target, &mut ps);
    let mut columns = Vec::new();
    for slot in 0..4 {
        if let Some((_, g)) = registry[slot] {
            let products = g.column_products(&eq_table(&rp[..g.row_log]));
            let poly = parallel::map_collect(1 << g.col_log, |i| {
                products[0][i] + theta * products[1][i] + theta2 * products[2][i]
            });
            let mut weight = vec![F192::ZERO; 1 << g.col_log];
            for (i, input) in inputs
                .iter()
                .enumerate()
                .filter(|(i, c)| routes[*i] == slot && c.active)
            {
                let w = fold::weighted_eq(&input.claim.col_point, pairs[i].0[0]);
                parallel::chunks_mut(&mut weight, 4096, |chunk, out| {
                    for (k, v) in out.iter_mut().enumerate() {
                        *v += w[chunk * 4096 + k];
                    }
                });
            }
            columns.push((poly, weight));
        } else {
            columns.push((vec![F192::ZERO], vec![F192::ZERO]));
        }
    }
    let (cp, _) = fold::sumcheck(&mut columns, clog, false, row_target, &mut ps);
    let carried = (0..4)
        .map(|slot| {
            let mut claim = schema.empty(slot).claim;
            if let Some((setup, g)) = registry[slot] {
                claim.app_key = setup.key;
                claim.row_point = rp[..g.row_log].to_vec();
                claim.col_point = cp[..g.col_log].to_vec();
                claim.matrix_values = g.evaluate(&claim.row_point, &claim.col_point);
            }
            ps.add_scalars(&claim.matrix_values);
            claim
        })
        .collect();
    Reduction {
        proof: ps.into_proof(),
        carried,
    }
}
fn verify_fold(
    schema: Schema,
    inputs: &[WireClaim],
    active: &[S],
    routes: &[usize],
    keys: [[S; 2]; 4],
    enabled: [S; 4],
    digest: [S; 2],
    proof: &Proof,
) -> Vec<WireClaim> {
    let seed = hash(&label_rows(inputs, active, digest));
    let mut t = Transcript::from_state(proof, seed);
    let theta = t.sample();
    let theta2 = theta * theta;
    let theta3 = theta2 * theta;
    let pw = powers(theta3, inputs.len());
    let mut running = inputs.iter().zip(active).zip(&pw).fold(S::u(0), |s, ((c, &a), &p)| {
        s + a * p * (c.matrix_values[0] + theta * c.matrix_values[1] + theta2 * c.matrix_values[2])
    });
    let rlog = schema.shapes.iter().map(|p| p.0).max().unwrap();
    let clog = schema.shapes.iter().map(|p| p.1).max().unwrap();
    let mut phase = |n| {
        (0..n)
            .map(|_| {
                let q = plain_round(&mut t, running);
                let x = t.sample();
                running = q.iter().rev().fold(S::u(0), |s, &c| c + x * s);
                x
            })
            .collect::<Vec<_>>()
    };
    let rp = phase(rlog);
    let cp = phase(clog);
    let output: Vec<_> = (0..4)
        .map(|slot| {
            let (r, c) = schema.shapes[slot];
            let values = std::array::from_fn(|_| t.next());
            for v in values {
                (v * (S::u(1) + enabled[slot])).assert_eq(S::u(0));
            }
            WireClaim {
                app_key: keys[slot],
                row_point: rp[..r].iter().map(|&v| v * enabled[slot]).collect(),
                col_point: cp[..c].iter().map(|&v| v * enabled[slot]).collect(),
                matrix_values: values,
            }
        })
        .collect();
    let mut total = S::u(0);
    for (((c, &a), &p), &slot) in inputs.iter().zip(active).zip(&pw).zip(routes) {
        for j in 0..2 {
            (a * (c.app_key[j] + keys[slot][j])).assert_eq(S::u(0));
        }
        let (r, co) = schema.shapes[slot];
        let v = output[slot].matrix_values;
        total = total
            + a * p
                * eq(&c.row_point, &rp[..r])
                * lift(&rp, r)
                * eq(&c.col_point, &cp[..co])
                * lift(&cp, co)
                * (v[0] + theta * v[1] + theta2 * v[2]);
    }
    total.assert_eq(running);
    t.finish();
    output
}

/// Replay both sparse child proofs in full. The fixed child layout is shared
/// by first and node wrappers; their identities are carried, never host-trusted.
pub fn record(
    schema: Schema,
    shape: &Setup,
    children: [&Certificate; 2],
    context: &Hash,
    reduction: &Reduction,
) -> Trace {
    trace::start();
    let mut inputs = Vec::new();
    let mut active = Vec::new();
    let mut routes = Vec::new();
    let mut parts = literal(b"r1cs-carried-tree-node-v1");
    for (r, c) in schema.shapes {
        parts.push((S::u(r as u64), 8));
        parts.push((S::u(c as u64), 8));
    }
    for child in children {
        let identity = input_key(&child.key);
        let fields: Vec<_> = schema.fields(&child.statement).into_iter().map(S::input).collect();

        let kind = fields[0];
        boolean(kind);
        let mut public = vec![S::u(1)];
        public.extend_from_slice(&fields);
        let (fresh, child_digest) = deferred::verify_shape_in_rows(shape, identity, &public, context, &child.proof);
        parts.extend(child_digest.map(|v| (v, 16)));
        let mut cursor = 3;
        for slot in 0..4 {
            let on = fields[cursor];
            cursor += 1;
            boolean(on);
            let (r, c) = schema.shapes[slot];
            let key = [fields[cursor], fields[cursor + 1]];
            cursor += 2;
            let row_point = fields[cursor..cursor + r].to_vec();
            cursor += r;
            let col_point = fields[cursor..cursor + c].to_vec();
            cursor += c;
            let matrix_values = fields[cursor..cursor + 3].try_into().unwrap();
            cursor += 3;
            let claim = WireClaim {
                app_key: key,
                row_point,
                col_point,
                matrix_values,
            };
            for v in claim.flatten() {
                ((S::u(1) + on) * v).assert_eq(S::u(0));
            }
            // First wrappers cannot arrive with prior wrapper obligations.
            if slot >= 2 {
                ((S::u(1) + kind) * on).assert_eq(S::u(0));
            }
            inputs.push(claim);
            active.push(on);
            routes.push(slot);
        }
        for slot in [2, 3] {
            inputs.push(fresh.clone());
            active.push(if slot == 2 { S::u(1) + kind } else { kind });
            routes.push(slot);
        }
    }
    let digest = hash(&parts);
    let mut enabled = [S::u(0); 4];
    let mut keys = [[S::u(0); 2]; 4];
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
    // Distinct active slots must name distinct identities. The inverse advice
    // proves a differing limb, rather than assuming a host-side set operation.
    for i in 0..4 {
        for j in i + 1..4 {
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
    let output = verify_fold(
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
    for i in 0..4 {
        public.push(enabled[i]);
        public.extend(output[i].flatten());
    }
    let mut program = trace::take();
    program.public = public;
    program
}

pub fn statement(schema: Schema, digest: Hash, inputs: &[Slot], routes: &[usize], reduction: &Reduction) -> Statement {
    let slots = (0..4)
        .map(|slot| Slot {
            active: inputs.iter().enumerate().any(|(i, c)| routes[i] == slot && c.active),
            claim: reduction.carried[slot].clone(),
        })
        .collect();
    let s = Statement {
        kind: true,
        digest,
        slots,
    };
    let _ = schema.fields(&s);
    s
}

impl Schema {
    pub fn well_formed(&self, statement: &Statement) -> bool {
        if statement.slots.len() != 4 {
            return false;
        }
        for (i, slot) in statement.slots.iter().enumerate() {
            let c = &slot.claim;
            if (c.row_point.len(), c.col_point.len()) != self.shapes[i] {
                return false;
            }
            if !slot.active
                && (c.app_key != [0; 32]
                    || c.row_point
                        .iter()
                        .chain(&c.col_point)
                        .chain(&c.matrix_values)
                        .any(|&v| v != F192::ZERO))
            {
                return false;
            }
            if slot.active
                && (c.app_key == [0; 32]
                    || statement.slots[..i]
                        .iter()
                        .any(|other| other.active && other.claim.app_key == c.app_key))
            {
                return false;
            }
        }
        true
    }
}
/// Trusted root registry binds the generator and its role for every active
/// identity. The sparse node proof's fresh matrix obligation is settled too.
pub fn verify_root(
    schema: Schema,
    node: &super::first::SparseSetup,
    expected_digest: &Hash,
    statement: &Statement,
    context: &Hash,
    proof: &Proof,
    registry: [Option<&Generator>; 4],
) -> bool {
    if !statement.kind || &statement.digest != expected_digest || !schema.well_formed(statement) {
        return false;
    }
    let Some(own) = node.verify(&schema.fields(statement), context, proof) else {
        return false;
    };
    for (slot, g) in statement.slots.iter().zip(registry) {
        if slot.active && !g.is_some_and(|g| g.settle(&slot.claim)) {
            return false;
        }
    }
    node.generator.settle(&own)
}
