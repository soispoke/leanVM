use circuit_suite::{Circuit, Src, Workload, read_statement};
use fiat_shamir::transcript::Proof;
use flock::{
    membership::Statement,
    quotient::{self, Index, Oracle, opening},
};
use format_recursion::Child;
use primitives::field::F64;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::{marker::PhantomData, time::Instant};

pub struct Application<W> {
    circuit: Circuit,
    sources: Vec<Src>,
    index: Index,
    wiring: opening::Committed,
    pub id: [u8; 32],
    workload: PhantomData<W>,
}

pub struct Created {
    pub child: Child,
    pub claim: [u8; 32],
    pub report: serde_json::Value,
}

impl<W: Workload> Application<W> {
    pub fn new() -> Self {
        let (circuit, sources, _) = circuit_suite::build::<W>();
        circuit.check_wired().expect("application wiring");
        assert!(circuit.log_rows + 5 <= quotient::domain::BASIS, "quotient capacity");
        let index = Index::new(&circuit);
        let wiring = opening::commit(index.table());
        let mut identity = b"structured-r1cs-v1/gf64/upstream-tower/full-adder-6/copy/public-8x128".to_vec();
        identity.extend(quotient::domain::beta()[1].0.to_le_bytes());
        identity.extend((circuit.log_rows as u64).to_le_bytes());
        for s in &circuit.sigma {
            identity.extend(s.to_le_bytes());
        }
        Self {
            circuit,
            sources,
            index,
            wiring,
            id: primitives::protocol_hash::hash(&identity),
            workload: PhantomData,
        }
    }

    pub fn expected_claim(&self, seed: u64) -> [u8; 32] {
        let instance = W::instance(seed);
        let statement = Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        let mut bytes = self.id.to_vec();
        for half in statement.halves() {
            bytes.extend(half.c0.to_le_bytes());
            bytes.extend(half.c1.to_le_bytes());
        }
        primitives::protocol_hash::hash(&bytes)
    }

    pub fn create(&self, seed: u64) -> Created {
        // Independent application reference and its public statement are outside
        // the proof timer. Witness evaluation is timed separately below.
        let instance = W::instance(seed);
        assert_eq!(
            read_statement(&self.circuit.values(&instance.inputs), &self.sources),
            instance.statement
        );
        let statement = Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        let start = Instant::now();
        let cells = self.circuit.cells(&instance.inputs);
        let mut rng = StdRng::seed_from_u64(seed);
        let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
        let witness_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let mut committed = Vec::new();
        let proved = quotient::prove_with(
            Oracle::Blake2s,
            &self.circuit,
            &self.index,
            &self.wiring.root,
            &statement,
            &cells,
            &masks,
            &mut |table| {
                let c = opening::commit(table);
                let root = c.root;
                committed.push(c);
                root
            },
        );
        let piop_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let openings: [Proof; 3] = [
            opening::open(
                &proved.witness,
                &committed[0],
                std::slice::from_ref(&proved.claims.witness),
            ),
            opening::open(
                self.index.table(),
                &self.wiring,
                std::slice::from_ref(&proved.claims.wiring),
            ),
            opening::open(
                &proved.quotient,
                &committed[1],
                &[proved.claims.quotient.clone(), proved.claims.sum.clone()],
            ),
        ];
        let opening_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let (roots, claims) = quotient::verify_with(
            Oracle::Blake2s,
            &self.wiring.root,
            &statement,
            &proved.proof,
            self.circuit.log_rows,
        )
        .expect("client PIOP verification");
        assert_eq!(roots, [committed[0].root, committed[1].root]);
        assert_eq!(claims, proved.claims);
        let raw = [
            opening::verification_trace(
                &proved.witness.layout,
                &roots[0],
                std::slice::from_ref(&claims.witness),
                &openings[0],
            )
            .unwrap(),
            opening::verification_trace(
                &self.index.table().layout,
                &self.wiring.root,
                std::slice::from_ref(&claims.wiring),
                &openings[1],
            )
            .unwrap(),
            opening::verification_trace(
                &proved.quotient.layout,
                &roots[1],
                &[claims.quotient, claims.sum],
                &openings[2],
            )
            .unwrap(),
        ];
        let verify_ms = start.elapsed().as_secs_f64() * 1000.;
        let proof_bytes = bincode::serialize(&(&proved.proof, &openings)).unwrap();
        let digest = primitives::protocol_hash::hash(&proof_bytes);
        let mut claim_bytes = self.id.to_vec();
        for half in statement.halves() {
            claim_bytes.extend(half.c0.to_le_bytes());
            claim_bytes.extend(half.c1.to_le_bytes());
        }
        let claim = primitives::protocol_hash::hash(&claim_bytes);
        // Transport includes the application identity and its public statement.
        let certificate_bytes = 96 + proof_bytes.len();
        let report = serde_json::json!({
            "kind":"client", "workload":W::NAME, "seed":seed,
            "log_rows":self.circuit.log_rows, "app_id":self.id, "index_root":self.wiring.root,
            "witness_ms":witness_ms, "piop_ms":piop_ms, "opening_ms":opening_ms,
            "create_ms":witness_ms+piop_ms+opening_ms, "verify_ms":verify_ms,
            "certificate_bytes":certificate_bytes, "proof_digest":digest,
            "reference_checked":true, "status":"verified",
        });
        Created {
            claim,
            child: Child {
                log_rows: self.circuit.log_rows,
                index_root: self.wiring.root,
                statement,
                piop: proved.proof,
                openings: raw,
            },
            report,
        }
    }
}
