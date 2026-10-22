use circuit_suite::{Ckt, Wire, read_statement};
use fiat_shamir::transcript::RawProof;
use flock::{
    membership::Statement,
    quotient::{self, Index, Oracle, opening},
};
use format_recursion::{Child, record};
use primitives::field::F64;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn child(seed: u64) -> Child {
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
    let openings = [
        opening::open(&p.witness, &committed[0], std::slice::from_ref(&p.claims.witness)),
        opening::open(index.table(), &wiring, std::slice::from_ref(&p.claims.wiring)),
        opening::open(
            &p.quotient,
            &committed[1],
            &[p.claims.quotient.clone(), p.claims.sum.clone()],
        ),
    ];
    let raw: [RawProof; 3] = [
        opening::verification_trace(&p.witness.layout, &committed[0].root, &[p.claims.witness], &openings[0]).unwrap(),
        opening::verification_trace(&index.table().layout, &wiring.root, &[p.claims.wiring], &openings[1]).unwrap(),
        opening::verification_trace(
            &p.quotient.layout,
            &committed[1].root,
            &[p.claims.quotient, p.claims.sum],
            &openings[2],
        )
        .unwrap(),
    ];
    // Native acceptance is checked before compiling, rather than treated as a circuit input.
    quotient::verify_with(Oracle::Blake2s, &wiring.root, &statement, &p.proof, circuit.log_rows).unwrap();
    Child {
        log_rows: circuit.log_rows,
        index_root: wiring.root,
        statement,
        piop: p.proof,
        openings: raw,
    }
}

fn main() {
    parallel::init();
    let args: Vec<String> = std::env::args().collect();
    let row_limit = args
        .iter()
        .position(|s| s == "--row-limit")
        .map_or(1 << 23, |i| args[i + 1].parse().unwrap());
    let t = Instant::now();
    let mut child = child(20261022);
    let reference = record(&child);
    assert!(reference.satisfied(), "complete verifier trace rejects honest proof");
    let other = record(&self::child(20261023));
    assert!(other.satisfied());
    assert!(reference.same_program(&other), "proof contents changed the circuit");
    let mut negatives = 0;
    let mut check = |child: &Child| {
        let bad = record(child);
        assert!(reference.same_program(&bad), "proof-dependent circuit shape");
        assert!(!bad.satisfied(), "accepted tampered child");
        negatives += 1;
    };
    child.statement.y[0] ^= 1;
    check(&child);
    child.statement.y[0] ^= 1;
    for i in 0..2 {
        child.piop.stream[i].c2 ^= 1;
        check(&child);
        child.piop.stream[i].c2 ^= 1;
    }
    for i in [0usize, 4, 8] {
        child.piop.stream[i].c0 ^= 1;
        check(&child);
        child.piop.stream[i].c0 ^= 1;
    }
    for opening in 0..3 {
        let last = child.openings[opening].stream.len() - 1;
        for at in [0, last] {
            child.openings[opening].stream[at].c0 ^= 1;
            check(&child);
            child.openings[opening].stream[at].c0 ^= 1;
        }
        child.openings[opening].merkle[0].leaf_data[0].0 ^= 1;
        check(&child);
        child.openings[opening].merkle[0].leaf_data[0].0 ^= 1;
        child.openings[opening].merkle[0].path[0][0] ^= 1;
        check(&child);
        child.openings[opening].merkle[0].path[0][0] ^= 1;
    }
    println!(
        "{}",
        serde_json::json!({"kind":"trace","child_log_rows":child.log_rows,"nodes":reference.nodes.len(),"checks":reference.checks.len(),"hash_compressions":reference.hash_compressions(),"negative_cases":negatives,"fresh_proof_same_circuit":true,"operations":reference.operation_counts(),"sections":reference.sections,"elapsed_ms":t.elapsed().as_millis()})
    );
    if args.iter().any(|x| x == "--trace-only") {
        return;
    }
    let t = Instant::now();
    match reference.lower(row_limit) {
        Err((node, rows)) => {
            let section = reference
                .sections
                .iter()
                .rev()
                .find(|(_, start)| *start <= node)
                .map(|(name, _)| name.as_str());
            println!(
                "{}",
                serde_json::json!({"kind":"capacity","status":"row_limit_exceeded","outer_proof_produced":false,"row_limit":row_limit,"rows_so_far":rows,"nodes_lowered":node,"total_nodes":reference.nodes.len(),"section":section,"elapsed_ms":t.elapsed().as_millis()})
            );
        }
        Ok(lowered) => {
            lowered.circuit.check_wired().unwrap();
            let values = lowered.circuit.values(&lowered.inputs);
            let statement = read_statement(&values, &lowered.sources);
            assert_eq!(statement[32], 1, "Boolean verifier rejected an honest child");
            assert_eq!(&statement[33..], &[0u8; 31]);
            println!(
                "{}",
                serde_json::json!({"kind":"circuit","rows_used":lowered.rows,"log_rows":lowered.circuit.log_rows,"inputs":lowered.inputs.len(),"statement":statement.to_vec(),"elapsed_ms":t.elapsed().as_millis()})
            );
        }
    }
}
