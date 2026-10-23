//! Matched compiler-row census and native proving screen, without recursive setup.
mod native_application_support;
use circuit_suite::Workload;
use format_recursion::{private_recursion::Setup, private_trace, trace::Op};
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
        let setup = Setup::new(created.trace.clone()).expect("setup");
        let words = fiat_shamir::merkle::hash_to_scalars(&created.claim);
        let start = Instant::now();
        let proof = setup.prove(&created.trace, &words).expect("proof");
        let ms = start.elapsed().as_secs_f64() * 1000.;
        assert!(setup.verify(&words, &proof));
        println!(
            "{}",
            serde_json::json!({"workload":W::NAME,"trim":trim,"proof_ms":ms,"verified":true})
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
