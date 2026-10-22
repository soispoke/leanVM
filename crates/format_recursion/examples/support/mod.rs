use circuit_suite::{Ckt, Wire, read_statement};
use fiat_shamir::transcript::RawProof;
use flock::{
    membership::Statement,
    quotient::{self, Index, Oracle, opening},
};
use format_recursion::Child;
use primitives::field::F64;
use rand::{RngCore, SeedableRng, rngs::StdRng};

#[allow(dead_code)]
pub struct Fixture {
    pub child: Child,
    pub proved: quotient::Proved,
    pub index: Index,
    pub wiring: opening::Committed,
    pub committed: Vec<opening::Committed>,
    pub openings: Vec<fiat_shamir::transcript::Proof>,
    pub app_id: [u8; 32],
}
pub fn child(seed: u64) -> Child {
    fixture(seed).child
}
pub fn fixture(seed: u64) -> Fixture {
    let mut c = Ckt::new();
    let a = c.inputs(64);
    let b = c.inputs(64);
    let mut public = c.add(&a, &b);
    public.extend(c.xor_word(&a, &b));
    public.resize(512, Wire::ZERO);
    let (circuit, srcs) = c.finish(&public);
    let mut rng = StdRng::seed_from_u64(seed);
    let inputs: Vec<bool> = (0..128).map(|_| rng.next_u32() & 1 == 1).collect();
    let st = read_statement(&circuit.values(&inputs), &srcs);
    let statement = Statement {
        y: st[..32].try_into().unwrap(),
        root: st[32..].try_into().unwrap(),
    };
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
    let mut committed = Vec::new();
    let p = quotient::prove_with(
        Oracle::Blake2s,
        &circuit,
        &index,
        &wiring.root,
        &statement,
        &circuit.cells(&inputs),
        &masks,
        &mut |table| {
            let c = opening::commit(table);
            let root = c.root;
            committed.push(c);
            root
        },
    );
    let openings = vec![
        opening::open(&p.witness, &committed[0], std::slice::from_ref(&p.claims.witness)),
        opening::open(index.table(), &wiring, std::slice::from_ref(&p.claims.wiring)),
        opening::open(
            &p.quotient,
            &committed[1],
            &[p.claims.quotient.clone(), p.claims.sum.clone()],
        ),
    ];
    let raw: [RawProof; 3] = [
        opening::verification_trace(
            &p.witness.layout,
            &committed[0].root,
            std::slice::from_ref(&p.claims.witness),
            &openings[0],
        )
        .unwrap(),
        opening::verification_trace(
            &index.table().layout,
            &wiring.root,
            std::slice::from_ref(&p.claims.wiring),
            &openings[1],
        )
        .unwrap(),
        opening::verification_trace(
            &p.quotient.layout,
            &committed[1].root,
            &[p.claims.quotient.clone(), p.claims.sum.clone()],
            &openings[2],
        )
        .unwrap(),
    ];
    // Native acceptance is checked before compiling, rather than treated as a circuit input.
    quotient::verify_with(Oracle::Blake2s, &wiring.root, &statement, &p.proof, circuit.log_rows).unwrap();
    let mut identity = b"structured-r1cs-v1/gf64/upstream-tower/full-adder-6/copy/public-8x128".to_vec();
    identity.extend(quotient::domain::beta()[1].0.to_le_bytes());
    identity.extend((circuit.log_rows as u64).to_le_bytes());
    for s in &circuit.sigma {
        identity.extend(s.to_le_bytes());
    }
    let child = Child {
        log_rows: circuit.log_rows,
        index_root: wiring.root,
        statement,
        piop: p.proof.clone(),
        openings: raw,
    };
    Fixture {
        child,
        proved: p,
        index,
        wiring,
        committed,
        openings,
        app_id: primitives::hash::hash(&identity),
    }
}
