//! One application role per process, using the existing prover trace tree.
#[path = "../../format_recursion/examples/application_support/mod.rs"]
mod application_support;
#[path = "../../format_recursion/examples/native_application_support/mod.rs"]
mod native_application_support;

use bench::{Jemalloc, Plan};
use circuit_suite::Workload;
use format_recursion::{
    closed_recursion::{Certificate, SplitClosedSetup},
    private_recursion::Setup,
};
use std::{path::Path, time::Instant};

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

fn save(path: Option<&Path>, certificate: &Certificate) {
    if let Some(path) = path {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&certificate.encode().unwrap())
            .unwrap();
    }
}

fn run<W: Workload>(role: &str, seed: u64, input: Option<&Path>, output: Option<&Path>, height: u32) {
    let plan = Plan::new(1, 0);
    if role == "quotient-client" {
        let application = {
            let _quiet = bench::suppress_tracing();
            application_support::Application::<W>::new()
        };
        let created = tracing::info_span!("Quotient client including reference and verification")
            .in_scope(|| application.create(seed));
        assert_eq!(created.claim, application.expected_claim(seed));
        assert_eq!(
            created.child.log_rows,
            created.report["log_rows"].as_u64().unwrap() as usize
        );
        println!("{}", created.report);
        return;
    }
    let setup_start = Instant::now();
    let (application, canonical) = {
        let _quiet = bench::suppress_tracing();
        let application = native_application_support::Application::<W>::new();
        let canonical = application.create(20261023);
        (application, canonical.trace)
    };
    if role == "native-client" {
        let setup = {
            let _quiet = bench::suppress_tracing();
            Setup::new(canonical).unwrap()
        };
        println!(
            "{}",
            serde_json::json!({"kind":"role_setup","role":role,"workload":W::NAME,
            "setup_ms":setup_start.elapsed().as_secs_f64()*1000.,"key":setup.bridge.index.root,
            "shape":format!("{:?}",setup.bridge.verifier_shape()),"index":setup.bridge.index.shape()})
        );
        let created =
            tracing::info_span!("Native application witness and reference").in_scope(|| application.create(seed));
        println!("{}", created.report);
        let words = fiat_shamir::merkle::hash_to_scalars(&created.claim);
        let (certificate, proving) = plan.measure_quiet(|_| {
            tracing::info_span!("Native client proof").in_scope(|| {
                assert!(created.trace.satisfied());
                Certificate {
                    height: 0,
                    statement: created.claim,
                    proof: setup.prove(&created.trace, &words).unwrap(),
                }
            })
        });
        let (verified, verification) = plan.measure_quiet(|_| setup.verify(&words, &certificate.proof));
        assert!(verified);
        save(output, &certificate);
        println!(
            "{}",
            serde_json::json!({"kind":"role_measurement","role":role,"workload":W::NAME,"seed":seed,
            "application_proof_ms":proving.mean()*1000.,"native_trace_creation_ms":created.report["native_trace_creation_ms"],
            "verify_ms":verification.mean()*1000.,"certificate_bytes":certificate.encode().unwrap().len(),
            "certificate_digest":primitives::hash::hash(&certificate.encode().unwrap()),
            "statement":certificate.statement,"peak_rss_bytes":bench::peak_rss_bytes(),"status":"verified"})
        );
    } else {
        assert_eq!(role, "merge");
        assert!((1..=3).contains(&height));
        let setup = {
            let _quiet = bench::suppress_tracing();
            SplitClosedSetup::from_program(canonical).unwrap()
        };
        println!(
            "{}",
            serde_json::json!({"kind":"role_setup","role":role,"workload":W::NAME,
            "setup_ms":setup_start.elapsed().as_secs_f64()*1000.,"base_key":setup.base_key(),"node_key":setup.node_key(),
            "base_shape":format!("{:?}",setup.base_shape()),"node_shape":format!("{:?}",setup.node_shape())})
        );
        let input = input.expect("merge requires --input with saved application_tree certificates");
        let read = |name| Certificate::decode(&std::fs::read(input.join(name)).unwrap()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(input.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["base_key"], serde_json::json!(setup.base_key()));
        assert_eq!(manifest["node_key"], serde_json::json!(setup.node_key()));
        assert_eq!(manifest["workload"], W::NAME);
        let left = read(if height == 1 {
            "app-0-0.cert".to_owned()
        } else {
            format!("node-0-{}.cert", height - 1)
        });
        let right = read("app-0-1.cert".to_owned());
        assert_eq!(left.height, height - 1);
        assert_eq!(right.height, 0);
        let (certificate, proving) = plan.measure_quiet(|_| setup.prove_node(&left, &right).unwrap());
        let (verified, verification) = plan.measure_quiet(|_| setup.verify(&certificate));
        assert!(verified);
        assert_eq!(certificate.height, height);
        assert_eq!(
            certificate.statement,
            format_recursion::recursion_fast::node_statement(&left.statement, &right.statement)
        );
        save(output, &certificate);
        println!(
            "{}",
            serde_json::json!({"kind":"role_measurement","role":role,"workload":W::NAME,"height":height,
            "merge_ms":proving.mean()*1000.,"verify_ms":verification.mean()*1000.,
            "certificate_bytes":certificate.encode().unwrap().len(),
            "certificate_digest":primitives::hash::hash(&certificate.encode().unwrap()),
            "statement":certificate.statement,"peak_rss_bytes":bench::peak_rss_bytes(),"status":"verified"})
        );
    }
}

fn main() {
    bench::init_tracing_from_env();
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let arg = |key: &str, default: &str| {
        args.windows(2)
            .find(|p| p[0] == key)
            .map_or_else(|| default.to_owned(), |p| p[1].clone())
    };
    let role = arg("--role", "native-client");
    assert!(["native-client", "quotient-client", "merge"].contains(&role.as_str()));
    let seed = arg("--seed", "20261024").parse().unwrap();
    let height = arg("--height", "1").parse().unwrap();
    let input = args.windows(2).find(|p| p[0] == "--input").map(|p| Path::new(&p[1]));
    let output = args.windows(2).find(|p| p[0] == "--out").map(|p| Path::new(&p[1]));
    match arg("--workload", "blake2s-1kib").as_str() {
        "blake2s-64b" => run::<circuit_suite::blake2s::Blake2s64>(&role, seed, input, output, height),
        "blake2s-1kib" => run::<circuit_suite::blake2s::Blake2sOneKiB>(&role, seed, input, output, height),
        "sha256-1kib" => run::<circuit_suite::sha256::Sha256OneKiB>(&role, seed, input, output, height),
        "keccak256-1KiB" => run::<circuit_suite::keccak::Keccak256OneKiB>(&role, seed, input, output, height),
        "mpt-storage-proof" => run::<circuit_suite::mpt::MptStorageProof>(&role, seed, input, output, height),
        "shielded-transfer" => run::<circuit_suite::shielded::ShieldedTransfer>(&role, seed, input, output, height),
        "falcon512" => run::<circuit_suite::falcon::Falcon512>(&role, seed, input, output, height),
        other => panic!("unknown application {other}"),
    }
}
