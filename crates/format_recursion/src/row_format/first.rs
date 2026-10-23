//! First-level measurement circuit with carried sparse-matrix claims.
use super::{
    deferred::{self, WireClaim, literal},
    fold::{self, Reduction},
    spartan::{DeferredClaim, Setup},
};
use crate::{
    private_recursion,
    trace::{self, S, Trace, hash},
};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use primitives::field::F192;

pub fn child_digest(key: &Hash, public: &[F192]) -> Hash {
    let mut bytes = b"r1cs-deferred-child-statement-v1".to_vec();
    bytes.extend(key);
    bytes.extend((public.len() as u64).to_le_bytes());
    for x in public {
        for v in [x.c0, x.c1, x.c2] {
            bytes.extend(v.to_le_bytes());
        }
    }
    primitives::protocol_hash::hash(&bytes)
}
pub fn statement_digest(setups: [&Setup; 2], public: [&[F192]; 2]) -> Hash {
    let mut bytes = b"r1cs-deferred-first-statement-v1".to_vec();
    bytes.extend(2u64.to_le_bytes());
    for i in 0..2 {
        bytes.extend(child_digest(&setups[i].key, public[i]));
    }
    primitives::protocol_hash::hash(&bytes)
}
pub fn output_fields(digest: &Hash, claims: &[DeferredClaim]) -> Vec<F192> {
    hash_to_scalars(digest)
        .into_iter()
        .chain(claims.iter().flat_map(|c| {
            hash_to_scalars(&c.app_key)
                .into_iter()
                .chain(c.row_point.iter().copied())
                .chain(c.col_point.iter().copied())
                .chain(c.matrix_values)
        }))
        .collect()
}

pub fn record(
    apps: &[&Setup],
    child_apps: [usize; 2],
    identities: [&Hash; 2],
    public: [&[F192]; 2],
    context: &Hash,
    proofs: [&Proof; 2],
    reduction: &Reduction,
) -> Trace {
    trace::start();
    let mut inputs = Vec::new();
    let mut digests = Vec::new();
    for i in 0..2 {
        let (claim, digest) =
            deferred::verify_in_rows(apps[child_apps[i]], identities[i], public[i], context, proofs[i]);
        inputs.push(claim);
        digests.extend(digest);
    }
    let mut parts = literal(b"r1cs-deferred-first-statement-v1");
    parts.push((S::u(2), 8));
    parts.extend(digests.into_iter().map(|s| (s, 16)));
    let digest = hash(&parts);
    trace::mark("matrix-fold-input-binding");
    let output = fold::verify_rows(apps, &child_apps, &inputs, digest, &reduction.proof);
    let mut program = trace::take();
    program.public = digest
        .into_iter()
        .chain(output.iter().flat_map(WireClaim::flatten))
        .collect();
    program
}

/// Native root checks the merge proof and settles one claim per known app.
/// Generators have no stored sparse matrices.
pub fn verify_root(
    merge: &private_recursion::Setup,
    digest: &Hash,
    claims: &[DeferredClaim],
    proof: &Proof,
    generators: &[&super::generator::Generator],
) -> bool {
    if claims.len() != generators.len() {
        return false;
    }
    if !merge.verify(&output_fields(digest, claims), proof) {
        return false;
    }
    claims.iter().zip(generators).all(|(c, g)| g.settle(c))
}

#[cfg(test)]
mod tests {
    use super::super::{R1cs, Source, generator::Generator};
    use super::*;
    fn source(seed: u64) -> Source {
        let mut b = crate::native_hash::Builder::default();
        let a = b.input(seed + 3);
        let c = b.input(seed + 5);
        let p = b.gate(a, c, b.zero());
        for w in b.hash_words(&[a, c, p]) {
            b.expose(w);
        }
        let (circuit, connectors) = b.export_circuit();
        let fixed_len = circuit.public.len() - 4;
        Source {
            circuit,
            connectors,
            values: b.values,
            compressions: b.compressions,
            fixed_len,
            rebuild: Box::new(|| unreachable!()),
        }
    }
    #[test]
    fn carried_first_level_settles_and_refuses_wrong_value_and_application() {
        parallel::init();
        let src = source(0);
        let make = |ccs| {
            Setup::new(
                R1cs::lower_bounded(&src.circuit, &src.connectors, &src.values, src.fixed_len, 8),
                ccs,
            )
        };
        let a = make(false);
        let b = make(true);
        let public = a.public(&src.values);
        let ctx = [43; 32];
        let pa = a.prove(&src.values, &src.compressions, &ctx);
        let pb = b.prove(&src.values, &src.compressions, &ctx);
        for mixed in [false, true] {
            let apps = if mixed { vec![&a, &b] } else { vec![&a] };
            let indices = if mixed { [0, 1] } else { [0, 0] };
            let p2 = if mixed { &pb } else { &pa };
            let children = [apps[indices[0]], apps[indices[1]]];
            let fresh = vec![
                a.claim(&a.verify_deferred(&public, &ctx, &pa, false).unwrap()),
                children[1].claim(&children[1].verify_deferred(&public, &ctx, p2, false).unwrap()),
            ];
            let digest = statement_digest(children, [&public, &public]);
            let reduction = fold::prove(&apps, &fresh, &digest);
            let generated: Vec<_> = apps.iter().map(|s| Generator::new(&src, 8, s.key)).collect();
            let gs: Vec<_> = generated.iter().collect();
            let alternate = fold::prove_generated(&apps, &gs, &fresh, &digest);
            assert_eq!(
                bincode::serialize(&reduction).unwrap(),
                bincode::serialize(&alternate).unwrap()
            );

            assert!(fold::record(&apps, &fresh, &digest, &reduction).satisfied());
            let trace = record(
                &apps,
                indices,
                [&a.key, &children[1].key],
                [&public, &public],
                &ctx,
                [&pa, p2],
                &reduction,
            );
            assert!(trace.satisfied());
            let output = output_fields(&digest, &reduction.carried);
            assert_eq!(
                trace.public.iter().map(|s| trace.nodes[s.0].value).collect::<Vec<_>>(),
                output
            );
            let merge = private_recursion::Setup::new(trace.clone()).unwrap();
            let proof = merge.prove(&trace, &output).unwrap();
            let generators: Vec<_> = apps.iter().map(|s| Generator::new(&src, 8, s.key)).collect();
            let gs: Vec<_> = generators.iter().collect();
            assert!(verify_root(&merge, &digest, &reduction.carried, &proof, &gs));
            let mut bad = reduction.clone();
            bad.carried[0].matrix_values[0] += F192::ONE;
            assert!(!fold::record(&apps, &fresh, &digest, &bad).satisfied());
            assert!(!verify_root(&merge, &digest, &bad.carried, &proof, &gs));
            let mut bad = reduction.clone();
            bad.carried[0].app_key[0] ^= 1;
            assert!(!verify_root(&merge, &digest, &bad.carried, &proof, &gs));
            let mut fresh_bad = fresh.clone();
            fresh_bad[0].matrix_values[2] += F192::ONE;
            assert!(!fold::record(&apps, &fresh_bad, &digest, &reduction).satisfied());
            if mixed {
                assert!(
                    !record(
                        &apps,
                        indices,
                        [&b.key, &a.key],
                        [&public, &public],
                        &ctx,
                        [&pa, p2],
                        &reduction
                    )
                    .satisfied()
                );
            }
            let mut unknown = a.key;
            unknown[0] ^= 1;
            assert!(
                !record(
                    &apps,
                    indices,
                    [&unknown, &children[1].key],
                    [&public, &public],
                    &ctx,
                    [&pa, p2],
                    &reduction
                )
                .satisfied()
            );
        }
    }
}

pub fn record_direct(children: [&Setup; 2], public: [&[F192]; 2], context: &Hash, proofs: [&Proof; 2]) -> Trace {
    trace::start();
    let mut digests = Vec::new();
    for i in 0..2 {
        let (claim, digest) = deferred::verify_in_rows(children[i], &children[i].key, public[i], context, proofs[i]);
        trace::mark("direct-matrix-evaluation");
        deferred::settle_in_rows(children[i], &claim);
        digests.extend(digest);
    }
    let mut parts = literal(b"r1cs-deferred-first-statement-v1");
    parts.push((S::u(2), 8));
    parts.extend(digests.into_iter().map(|s| (s, 16)));
    let digest = hash(&parts);
    let mut program = trace::take();
    program.public = digest.to_vec();
    program
}

/// A prepared sparse prover for this first-level circuit, sharing the existing
/// witness schedule with the fixed-gate comparison backend.
pub struct SparseSetup {
    pub setup: Setup,
    pub generator: super::generator::Generator,
    program: crate::private_trace::PreparedProgram,
}
impl SparseSetup {
    pub fn new(program: Trace, ccs: bool) -> Option<Self> {
        let mut program = crate::private_trace::PreparedProgram::new(program)?;
        let lower = program.lower_setup()?;
        let source = super::Source {
            fixed_len: lower.fixed_public.len(),
            circuit: lower.circuit,
            connectors: lower.connectors,
            values: lower.values,
            compressions: lower.compressions,
            rebuild: Box::new(|| unreachable!()),
        };
        let r = super::R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8);
        let setup = Setup::new(r, ccs);
        let generator = super::generator::Generator::new(&source, 8, setup.key);
        Some(Self {
            setup,
            generator,
            program,
        })
    }
    pub fn prove(&self, witness: &Trace, context: &Hash) -> Option<Proof> {
        let values = self.program.prepare_witness(witness)?;
        Some(self.setup.prove(&values.values, &values.compressions, context))
    }
    pub fn verify(&self, outputs: &[F192], context: &Hash, proof: &Proof) -> Option<DeferredClaim> {
        let mut public = vec![F192::ONE];
        public.extend_from_slice(outputs);
        let verified = self.setup.verify_deferred(&public, context, proof, false)?;
        Some(self.setup.claim(&verified))
    }
}
