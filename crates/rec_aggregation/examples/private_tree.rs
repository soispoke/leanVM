//! Local same-backend recursion smoke run; not an official recursion.fast entry.
use bench::{Jemalloc, Plan};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::Proof,
};
use format_recursion::{
    private_recursion::{self as recursive, Setup},
    private_trace, recursion_fast,
    trace::Op,
};

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |key: &str, default: usize| {
        args.windows(2)
            .find(|a| a[0] == key)
            .map(|a| a[1].parse().expect("integer argument"))
            .unwrap_or(default)
    };
    let depth = arg("--depth", 2);
    let chain = arg("--chain", 16);
    assert!((1..=3).contains(&depth));
    assert!(chain <= recursion_fast::CHAIN_CAP as usize);
    parallel::init();
    let plan = Plan::new(1, 0);
    let mut children = Vec::<(Hash, Proof)>::new();
    let leaf_program = recursive::leaf(&[0; 32], chain).unwrap();
    let bound = private_trace::allocation_bound(&leaf_program);
    println!(
        "{}",
        serde_json::json!({"kind":"leaf_trace","nodes":leaf_program.nodes.len(),
        "compressions":leaf_program.hash_compressions(),
        "lowering_bound":bound.map(|b|serde_json::json!({"rows":b.rows,"variables":b.variables,"compressions":b.compressions}))})
    );
    let Some(mut setup) = Setup::new(leaf_program) else {
        println!(
            "{}",
            serde_json::json!({"kind":"capacity_limit","level":0,"status":"incomplete",
            "message":"leaf compiler or experimental index limit reached; no proof produced"})
        );
        std::process::exit(2);
    };
    println!(
        "{}",
        serde_json::json!({"kind":"setup","level":0,"rows":1usize<<setup.bridge.index.log_rows,
        "compressions":setup.bridge.n_blocks,"native_shape":setup.bridge.index.shape(),"official_score":false})
    );
    for i in 0..1usize << depth {
        let start = primitives::hash::hash(&(i as u64 + 20261022).to_le_bytes());
        let digest = recursion_fast::expected_leaf(&start, chain as u64).unwrap();
        let t = recursive::leaf(&start, chain).unwrap();
        assert_eq!(recursive::outputs(&t), hash_to_scalars(&digest));
        let public = hash_to_scalars(&digest);
        let (proof, proving) = plan.measure_quiet(|_| setup.prove(&t, &public).expect("leaf proof within cap"));
        let (ok, verification) = plan.measure_quiet(|_| setup.verify(&public, &proof));
        assert!(ok);
        println!(
            "{}",
            serde_json::json!({"kind":"proof","level":0,"index":i,"proving_s":proving.mean(),
            "verification_ms":1000.0*verification.mean(),"proof_bytes":recursive::encode(&proof).unwrap().len(),"verified":true})
        );
        children.push((digest, proof));
    }
    for level in 1..=depth {
        let record =
            |a: &(Hash, Proof), b: &(Hash, Proof)| recursive::node((&setup, &a.0, &a.1), (&setup, &b.0, &b.1)).unwrap();
        let prototype = record(&children[0], &children[1]);
        let bound = private_trace::allocation_bound(&prototype);
        let mut operations = std::collections::BTreeMap::<String, usize>::new();
        for node in &prototype.nodes {
            let name = match &node.op {
                Op::Constant => "constant".to_owned(),
                Op::Input => "input".to_owned(),
                Op::Add(..) => "add".to_owned(),
                Op::Mul(..) => "multiply".to_owned(),
                Op::Frobenius(..) => "frobenius".to_owned(),
                Op::Slice(_, start, len) => format!("slice_{start}_{len}"),
                Op::Pack(parts) => format!("pack_{:?}", parts.iter().map(|p| p.1).collect::<Vec<_>>()),
                Op::Hash(parts) => if parts.iter().all(|p| p.1 % 8 == 0) {
                    "hash_aligned"
                } else {
                    "hash_unaligned"
                }
                .to_owned(),
                Op::HashHigh(..) => "hash_high".to_owned(),
                Op::Select(..) => "select".to_owned(),
            };
            *operations.entry(name).or_default() += 1;
        }
        println!(
            "{}",
            serde_json::json!({"kind":"node_trace","level":level,"nodes":prototype.nodes.len(),
            "compressions":prototype.hash_compressions(),"checks":prototype.checks.len(),"operations":operations,
            "lowering_bound":bound.map(|b|serde_json::json!({"rows":b.rows,"variables":b.variables,"compressions":b.compressions}))})
        );
        let Some(parent) = Setup::new(prototype) else {
            println!(
                "{}",
                serde_json::json!({"kind":"capacity_limit","level":level,"status":"incomplete",
                "message":"private compiler or experimental index limit reached; no proof produced"})
            );
            std::process::exit(2);
        };
        println!(
            "{}",
            serde_json::json!({"kind":"setup","level":level,"rows":1usize<<parent.bridge.index.log_rows,
            "compressions":parent.bridge.n_blocks,"native_shape":parent.bridge.index.shape(),"official_score":false})
        );
        let mut next = Vec::new();
        for (i, pair) in children.as_chunks::<2>().0.iter().enumerate() {
            let t = record(&pair[0], &pair[1]);
            assert!(t.satisfied());
            let digest = recursion_fast::node_statement(&pair[0].0, &pair[1].0);
            let public = hash_to_scalars(&digest);
            assert_eq!(recursive::outputs(&t), public);
            let (proof, proving) = plan.measure_quiet(|_| parent.prove(&t, &public).expect("node proof within cap"));
            let (ok, verification) = plan.measure_quiet(|_| parent.verify(&public, &proof));
            assert!(ok);
            let mut wrong = public;
            wrong[0] += primitives::field::F192::ONE;
            assert!(!parent.verify(&wrong, &proof));
            println!(
                "{}",
                serde_json::json!({"kind":"proof","level":level,"index":i,"proving_s":proving.mean(),
                "verification_ms":1000.0*verification.mean(),"proof_bytes":recursive::encode(&proof).unwrap().len(),"verified":true})
            );
            next.push((digest, proof));
        }
        children = next;
        setup = parent;
    }
    assert_eq!(children.len(), 1);
    println!(
        "{}",
        serde_json::json!({"kind":"complete","levels":depth,"chain":chain,"status":"locally_verified",
        "root":children[0].0,"same_backend":true,"single_fixed_circuit":false,"lean_certificate":false,
        "oracle_mode":"existing untagged BLAKE2s; challenge ROM adapter pending","official_score":false})
    );
}
