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

fn report(mut value: serde_json::Value) {
    value["threads"] = parallel::num_threads().into();
    value["cpus"] = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:").map(|s| s.trim().to_owned()))
        })
        .into();
    println!("{value}");
}

fn hash_arg(flag: &str) -> [u8; 32] {
    let args: Vec<_> = std::env::args().collect();
    let hex = args
        .windows(2)
        .find(|pair| pair[0] == flag)
        .expect("required statement and pinned base key")[1]
        .as_str();
    assert!(
        hex.is_ascii() && hex.len() == 64,
        "hash must be 64 hexadecimal characters"
    );
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hexadecimal hash"))
}

fn save(path: Option<&Path>, bytes: &[u8]) {
    if let Some(path) = path {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
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
        report(created.report.clone());
        return;
    }
    let setup_start = Instant::now();
    let (application, canonical) = {
        let _quiet = bench::suppress_tracing();
        let application = native_application_support::Application::<W>::new();
        let canonical = application.create(20261023);
        (application, canonical.trace)
    };
    if role == "native-client" || role == "mempool" {
        let setup = {
            let _quiet = bench::suppress_tracing();
            Setup::new(canonical).unwrap()
        };
        report(serde_json::json!({"kind":"role_setup","role":role,"workload":W::NAME,
            "setup_ms":setup_start.elapsed().as_secs_f64()*1000.,"key":setup.bridge.index.root,
            "shape":format!("{:?}",setup.bridge.verifier_shape()),"index":setup.bridge.index.shape()}));
        if role == "mempool" {
            let bytes = std::fs::read(input.expect("mempool requires --input certificate")).unwrap();
            let expected = hash_arg("--statement");
            let pinned_base_key = hash_arg("--base-key");
            assert_eq!(setup.bridge.index.root, pinned_base_key, "trusted base key mismatch");
            let words = fiat_shamir::merkle::hash_to_scalars(&expected);
            let (verified, verification) = plan.measure_quiet(|_| {
                let certificate = Certificate::decode(&bytes).unwrap();
                certificate.height == 0 && certificate.statement == expected && setup.verify(&words, &certificate.proof)
            });
            assert!(verified);
            report(
                serde_json::json!({"kind":"role_measurement","role":role,"workload":W::NAME,
                "native_verification_ms":verification.mean()*1000.,"mempool_verify_ms":verification.mean()*1000.,
                "mempool_proof_bytes":bytes.len(),"verification_process":"standalone",
                "statement":expected,"pinned_base_key":pinned_base_key,
                "certificate_digest":primitives::hash::hash(&bytes),
                "peak_mempool_ram_bytes":bench::peak_rss_bytes(),"status":"verified"}),
            );
            return;
        }
        let created =
            tracing::info_span!("Native application witness and reference").in_scope(|| application.create(seed));
        report(created.report.clone());
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
        let (verified, _) = plan.measure_quiet(|_| setup.verify(&words, &certificate.proof));
        assert!(verified);
        let encoding_start = Instant::now();
        let bytes = certificate.encode().unwrap();
        let encoding_ms = encoding_start.elapsed().as_secs_f64() * 1000.;
        save(output, &bytes);
        report(
            serde_json::json!({"kind":"role_measurement","role":role,"workload":W::NAME,"seed":seed,
            "witness_ms":created.report["native_trace_creation_ms"],"proof_creation_ms":proving.mean()*1000.,
            "encoding_ms":encoding_ms,"time_to_mempool_ready_proof_ms":
                created.report["native_trace_creation_ms"].as_f64().unwrap()+proving.mean()*1000.+encoding_ms,
            "wallet_prove_s":(created.report["native_trace_creation_ms"].as_f64().unwrap()+proving.mean()*1000.+encoding_ms)/1000.,
            "wallet_proof_bytes":bytes.len(),"mempool_proof_bytes":bytes.len(),
            "wallet_peak_rss_kib":bench::peak_rss_bytes()/1024,"certificate_digest":primitives::hash::hash(&bytes),
            "statement":certificate.statement,"peak_client_ram_bytes":bench::peak_rss_bytes(),"status":"verified"}),
        );
    } else {
        assert_eq!(role, "merge");
        assert!((1..=3).contains(&height));
        let setup = {
            let _quiet = bench::suppress_tracing();
            SplitClosedSetup::from_program(canonical).unwrap()
        };
        report(serde_json::json!({"kind":"role_setup","role":role,"workload":W::NAME,
            "setup_ms":setup_start.elapsed().as_secs_f64()*1000.,"base_key":setup.base_key(),"node_key":setup.node_key(),
            "base_shape":format!("{:?}",setup.base_shape()),"node_shape":format!("{:?}",setup.node_shape())}));
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
        let encoding_start = Instant::now();
        let bytes = certificate.encode().unwrap();
        let encoding_ms = encoding_start.elapsed().as_secs_f64() * 1000.;
        save(output, &bytes);
        report(
            serde_json::json!({"kind":"role_measurement","role":role,"workload":W::NAME,"height":height,
            "merge_time_ms":proving.mean()*1000.,"merge2to1_leaf_s":(height==1).then_some(proving.mean()),
            "left_height":left.height,"right_height":right.height,
            "native_verification_ms":verification.mean()*1000.,"verification_process":"same_process_diagnostic",
            "encoding_ms":encoding_ms,"merged_proof_bytes":bytes.len(),
            "certificate_digest":primitives::hash::hash(&bytes),
            "statement":certificate.statement,"merge_peak_rss_kib":bench::peak_rss_bytes()/1024,
            "peak_aggregator_ram_bytes":bench::peak_rss_bytes(),"status":"verified"}),
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
    assert!(["native-client", "quotient-client", "mempool", "merge"].contains(&role.as_str()));
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
