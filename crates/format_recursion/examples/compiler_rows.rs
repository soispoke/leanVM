//! Compiler-row census and time to mempool-ready proof for split-closure base certificates.
mod native_application_support;
use circuit_suite::Workload;
use format_recursion::{closed_recursion::SplitClosedSetup, private_trace, trace::Op};
use native_application_support::Application;
use std::{collections::BTreeMap, time::Instant};
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn run<W: Workload>(trim: bool, prove: bool) {
    let app = Application::<W>::new().with_trimming(trim);
    let created = app.create(20261023);
    let mut gates = BTreeMap::<&str, usize>::new();
    for node in &created.trace.nodes {
        let kind = match node.op {
            Op::Constant => "constant",
            Op::Input => "boolean_input",
            Op::Add(..) => "add",
            Op::Mul(..) => "mul",
            Op::Pack(..) => "pack",
            Op::Hash(..) => "hash",
            Op::HashHigh(..) => "hash_high",
            Op::Slice(..) => "slice",
            Op::Select(..) => "select",
            Op::Frobenius(..) => "frobenius",
        };
        *gates.entry(kind).or_default() += 1;
    }
    let lower = private_trace::lower(&created.trace, &created.trace).expect("lowering");
    println!(
        "{}",
        serde_json::json!({"workload":W::NAME,"trim":trim,"trace":created.report,
        "gates":gates,"arithmetic_rows":lower.circuit.rows.len(),
        "compressions":lower.compressions.len(),"checks":created.trace.checks.len(),
        "cpus":"24-35","threads":12})
    );
    drop(lower);
    if prove {
        let setup = SplitClosedSetup::from_program(created.trace.clone()).expect("split setup");
        // Canonical setup is preprocessing. Include all per-proof witness work,
        // including instance construction and reference evaluation, in the wallet timer.
        let witness_start = Instant::now();
        let witness = app.create(20261024);
        let witness_ms = witness_start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let proof = setup.prove_base(&witness.trace).expect("base proof");
        let bytes = proof.encode().expect("wallet certificate");
        let ms = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(proof.statement, witness.claim);
        let verify_start = Instant::now();
        assert!(setup.verify(&proof));
        let native_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.;
        println!(
            "{}",
            serde_json::json!({"kind":"mempool_ready_proof","workload":W::NAME,"trim":trim,
            "witness_ms":witness_ms,"proof_ms":ms,"time_to_mempool_ready_proof_ms":witness_ms+ms,
            "proof_bytes":bytes.len(),"native_verify_ms":native_verify_ms,
            "base_shape":format!("{:?}", setup.base_shape()),"cpus":"24-35","threads":12,"verified":true})
        );
    }
}
fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let trim = args.iter().any(|a| a == "--trim");
    let prove = args.iter().any(|a| a == "--prove");
    match args.get(1).map(String::as_str).unwrap_or("") {
        "blake64" => run::<circuit_suite::blake2s::Blake2s64>(trim, prove),
        "blake1k" => run::<circuit_suite::blake2s::Blake2sOneKiB>(trim, prove),
        "sha1k" => run::<circuit_suite::sha256::Sha256OneKiB>(trim, prove),
        "keccak1k" => run::<circuit_suite::keccak::Keccak256OneKiB>(trim, prove),
        "shielded" => run::<circuit_suite::shielded::ShieldedTransfer>(trim, prove),
        "falcon" => run::<circuit_suite::falcon::Falcon512>(trim, prove),
        "mpt" => run::<circuit_suite::mpt::MptStorageProof>(trim, prove),
        _ => panic!("unknown workload"),
    }
}
