//! Compiler-row census and time to mempool-ready proof for split-closure base certificates.
mod native_application_support;
use circuit_suite::Workload;
use format_recursion::{
    closed_recursion::{Certificate, SplitClosedSetup},
    native_arithmetic::MAX_LOG_ROWS,
    private_bridge::PrivateShape,
    private_recursion::Setup,
    private_trace,
    trace::Op,
};
use native_application_support::Application;
use std::{collections::BTreeMap, time::Instant};
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn argument(name: &str) -> Option<String> {
    std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn seed() -> u64 {
    argument("--seed").map_or(20261024, |value| value.parse().expect("witness seed"))
}

fn memory_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("process status")
        .lines()
        .find(|line| line.starts_with(field))
        .expect("memory field")
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn save_certificate(bytes: &[u8]) {
    if let Some(path) = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == "--out-certificate")
        .map(|pair| pair[1].clone())
    {
        std::fs::write(path, bytes).expect("save wallet certificate");
    }
}

// Separate process: no aggregator key is ever built or retained here.
// The backend and envelope match prove_base; exported bytes are checked against it.
fn wallet_resources<W: Workload>(trim: bool) {
    let start = Instant::now();
    let app = Application::<W>::new().with_trimming(trim);
    let canonical = app.create(20261023);
    let setup = Setup::new(canonical.trace).expect("wallet base key");
    let setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let setup_peak_kib = memory_kib("VmHWM:");
    println!(
        "{}",
        serde_json::json!({"role":"ONE-TIME setup", "kind":"wallet_key_setup",
        "workload":W::NAME,"trim":trim,"wallet_key_setup_ms":setup_ms,
        "cpus":"24-35","threads":parallel::num_threads(),
        "wallet_key_setup_peak_rss_kib":setup_peak_kib,"base_key":setup.bridge.index.root,
        "scope":"application circuit, canonical witness, base key; no aggregator node key"})
    );
    // Linux documents value 5 as resetting the process RSS high-water mark.
    std::fs::write("/proc/self/clear_refs", "5").expect("reset transaction RSS peak");
    let baseline_kib = memory_kib("VmRSS:");
    let witness_start = Instant::now();
    let witness = app.create(seed());
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1000.;
    let proof_start = Instant::now();
    assert!(witness.trace.satisfied());
    let words = fiat_shamir::merkle::hash_to_scalars(&witness.claim);
    let certificate = Certificate {
        height: 0,
        statement: witness.claim,
        proof: setup.prove(&witness.trace, &words).expect("wallet proof"),
    };
    let bytes = certificate.encode().expect("wallet bytes");
    let proof_ms = proof_start.elapsed().as_secs_f64() * 1000.;
    let peak_kib = memory_kib("VmHWM:");
    println!(
        "{}",
        serde_json::json!({"role":"WALLET", "kind":"wallet_transaction_ram",
        "workload":W::NAME,"trim":trim,"transaction_peak_rss_kib":peak_kib,
        "cpus":"24-35","threads":parallel::num_threads(),
        "transaction_start_rss_kib":baseline_kib,"transaction_additional_peak_rss_kib":peak_kib.saturating_sub(baseline_kib),
        "proof_bytes":bytes.len(),"certificate_hash":primitives::protocol_hash::hash(&bytes),
        "scope":"transaction phase RSS with wallet base key resident; setup high-water reset; no node key"})
    );
    let verify_start = Instant::now();
    assert!(setup.verify(&words, &certificate.proof));
    println!(
        "{}",
        serde_json::json!({"role":"MEMPOOL NODE","kind":"wallet_resource_verification",
        "workload":W::NAME,"trim":trim,"native_verify_ms":verify_start.elapsed().as_secs_f64()*1000.,
        "cpus":"24-35","threads":parallel::num_threads()})
    );
    println!(
        "{}",
        serde_json::json!({"role":"WALLET","kind":"wallet_only_mempool_ready_proof",
        "workload":W::NAME,"trim":trim,"seed":seed(),"witness_ms":witness_ms,"proof_ms":proof_ms,
        "time_to_mempool_ready_proof_ms":witness_ms+proof_ms,"proof_bytes":bytes.len(),
        "certificate_hash":primitives::protocol_hash::hash(&bytes),"base_key":setup.bridge.index.root,
        "base_shape":format!("{:?}",setup.bridge.verifier_shape()),"verified":true,
        "cpus":"24-35","threads":parallel::num_threads(),
        "scope":"base key only; complete backend proof and Certificate envelope; byte reconciliation required"})
    );
    save_certificate(&bytes);
}

fn leaf_merge<W: Workload>(trim: bool) {
    let start = Instant::now();
    let app = Application::<W>::new().with_trimming(trim);
    let canonical = app.create(20261023);
    let setup = SplitClosedSetup::from_program(canonical.trace).expect("split setup");
    drop(app);
    println!(
        "{}",
        serde_json::json!({"role":"ONE-TIME setup","kind":"merge_key_setup","workload":W::NAME,
        "trim":trim,"elapsed_ms":start.elapsed().as_secs_f64()*1000.,
        "cpus":"24-35","threads":parallel::num_threads(),
        "base_key":setup.base_key(),"node_key":setup.node_key(),
        "base_shape":format!("{:?}",setup.base_shape()),"node_shape":format!("{:?}",setup.node_shape())})
    );
    let read = |name| {
        let bytes = std::fs::read(argument(name).expect("certificate path")).expect("read certificate");
        Certificate::decode(&bytes).expect("decode certificate")
    };
    if argument("--verify-certificate").is_some() {
        let proof = read("--verify-certificate");
        let start = Instant::now();
        assert!(setup.verify(&proof));
        println!(
            "{}",
            serde_json::json!({"role":"MEMPOOL NODE","kind":"independent_merge_verification",
            "workload":W::NAME,"trim":trim,"height":proof.height,
            "native_verify_ms":start.elapsed().as_secs_f64()*1000.,
            "cpus":"24-35","threads":parallel::num_threads(),"verified":true})
        );
        return;
    }
    let left = read("--left-certificate");
    let right = read("--right-certificate");
    assert_eq!((left.height, right.height), (0, 0));
    assert_ne!(
        left.statement, right.statement,
        "use two distinct incoming transactions"
    );
    let start = Instant::now();
    assert!(setup.verify(&left));
    assert!(setup.verify(&right));
    let incoming_verify_ms = start.elapsed().as_secs_f64() * 1000.;
    std::fs::write("/proc/self/clear_refs", "5").expect("reset merge RSS peak");
    let baseline = memory_kib("VmRSS:");
    let start = Instant::now();
    // This call still checks both children before recording their verification.
    let proof = setup.prove_node(&left, &right).expect("two incoming base proofs merge");
    let core_ms = start.elapsed().as_secs_f64() * 1000.;
    let bytes = proof.encode().expect("merged certificate bytes");
    let merge_ms = start.elapsed().as_secs_f64() * 1000.;
    let peak = memory_kib("VmHWM:");
    assert_eq!(proof.height, 1);
    assert_eq!(
        proof.statement,
        format_recursion::recursion_fast::node_statement(&left.statement, &right.statement)
    );
    let start = Instant::now();
    assert!(setup.verify(&proof));
    let root_verify_ms = start.elapsed().as_secs_f64() * 1000.;
    save_certificate(&bytes);
    println!(
        "{}",
        serde_json::json!({"role":"AGGREGATOR","canonical_role":"MEMPOOL NODE",
        "kind":"leaf_merge","workload":W::NAME,"trim":trim,
        "merge2to1_leaf_ms":merge_ms,"merge_core_ms":core_ms,"merged_proof_bytes":bytes.len(),
        "merge_peak_rss_kib":peak,"merge_start_rss_kib":baseline,
        "incoming_pair_verify_ms":incoming_verify_ms,"merged_native_verify_ms":root_verify_ms,
        "base_key":setup.base_key(),"node_key":setup.node_key(),
        "certificate_hash":primitives::protocol_hash::hash(&bytes),"verified":true,
        "heterogeneous_merge":false,"cpus":"24-35","threads":parallel::num_threads(),
        "scope":"two distinct SHA256 base proofs; prove_node with both child checks and output serialization; setup excluded"})
    );
}

fn run<W: Workload>(trim: bool, prove: bool) {
    if std::env::args().any(|a| a == "--leaf-merge") {
        leaf_merge::<W>(trim);
        return;
    }
    if std::env::args().any(|a| a == "--wallet-resources") {
        wallet_resources::<W>(trim);
        return;
    }
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
    if std::env::args().any(|a| a == "--capacity-check") {
        let blocks = lower.compressions.len().max(128).next_power_of_two();
        let public_rows = (lower.circuit.public.len() + 18).next_power_of_two();
        let required = (public_rows + lower.circuit.rows.len()).next_multiple_of(blocks) + 6 * blocks;
        let shape = PrivateShape::for_circuit(
            lower.circuit.rows.len(),
            lower.circuit.public.len(),
            lower.compressions.len(),
        );
        println!(
            "{}",
            serde_json::json!({"role":"ONE-TIME setup","kind":"capacity_check","workload":W::NAME,
            "trim":trim,"compiler_rows":lower.circuit.rows.len(),"required_index_rows":required,
            "padded_log_rows":required.next_power_of_two().trailing_zeros(),
            "backend_cap_rows":1usize<<MAX_LOG_ROWS,"backend_cap_log_rows":MAX_LOG_ROWS,
            "admissible":shape.is_some(),"cpus":"24-35","threads":parallel::num_threads()})
        );
        return;
    }
    println!(
        "{}",
        serde_json::json!({"role":"ONE-TIME setup","scope":"static circuit metadata","workload":W::NAME,"trim":trim,"trace":created.report,
        "gates":gates,"arithmetic_rows":lower.circuit.rows.len(),
        "compressions":lower.compressions.len(),"checks":created.trace.checks.len(),
        "cpus":"24-35","threads":12})
    );
    drop(lower);
    if prove {
        let split_setup_start = Instant::now();
        let setup = SplitClosedSetup::from_program(created.trace.clone()).expect("split setup");
        println!(
            "{}",
            serde_json::json!({"role":"ONE-TIME setup","kind":"full_split_setup",
            "workload":W::NAME,"trim":trim,"elapsed_ms":split_setup_start.elapsed().as_secs_f64()*1000.,
            "scope":"base and aggregator node keys; excludes initial circuit/canonical creation"})
        );
        // Canonical setup is preprocessing. Include all per-proof witness work,
        // including instance construction and reference evaluation, in the wallet timer.
        let witness_start = Instant::now();
        let witness = app.create(seed());
        let witness_ms = witness_start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let proof = setup.prove_base(&witness.trace).expect("base proof");
        let bytes = proof.encode().expect("wallet certificate");
        let ms = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(proof.statement, witness.claim);
        let verify_start = Instant::now();
        assert!(setup.verify(&proof));
        let native_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.;
        save_certificate(&bytes);
        println!(
            "{}",
            serde_json::json!({"role":"MEMPOOL NODE","kind":"native_verification",
            "workload":W::NAME,"trim":trim,"native_verify_ms":native_verify_ms})
        );
        println!(
            "{}",
            serde_json::json!({"role":"WALLET","kind":"mempool_ready_proof","workload":W::NAME,"trim":trim,
            "witness_ms":witness_ms,"proof_ms":ms,"time_to_mempool_ready_proof_ms":witness_ms+ms,
            "proof_bytes":bytes.len(),
            "base_shape":format!("{:?}", setup.base_shape()),
            "base_key":setup.base_key(),"node_key":setup.node_key(),
            "certificate_hash":primitives::protocol_hash::hash(&bytes),"cpus":"24-35","threads":12,"verified":true})
        );
    }
}
fn main() {
    parallel::init();
    assert_eq!(
        parallel::num_threads(),
        12,
        "this research screen requires exactly twelve workers"
    );
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
