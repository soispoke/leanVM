//! Native application proofs merged directly under a separate recursive node key.
mod native_application_support;
use circuit_suite::Workload;
use format_recursion::closed_recursion::{Certificate, SplitClosedSetup};
use native_application_support::Application;
use std::{path::Path, time::Instant};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn run<W: Workload>(samples: usize, seed: u64, client_only: bool, output: Option<&Path>, verify: Option<&Path>) {
    let start = Instant::now();
    let application = Application::<W>::new();
    println!(
        "{}",
        serde_json::json!({"kind":"client_setup", "workload":W::NAME,
        "elapsed_ms":start.elapsed().as_secs_f64()*1000., "app_id":application.id})
    );
    if std::env::args().any(|a| a == "--diagnose-capacity") {
        let canonical = application.create(seed);
        println!(
            "{}",
            serde_json::json!({"kind":"capacity_diagnostic", "workload":W::NAME,
            "trace_nodes":canonical.trace.nodes.len(), "checks":canonical.trace.checks.len(),
            "allocation_bound":format!("{:?}",format_recursion::private_trace::allocation_bound(&canonical.trace))})
        );
        let lowered = format_recursion::private_trace::lower(&canonical.trace, &canonical.trace);
        println!(
            "{}",
            serde_json::json!({"kind":"lowering_diagnostic", "workload":W::NAME,
            "lowered":lowered.as_ref().map(|l|serde_json::json!({"rows":l.circuit.rows.len(),
            "variables":l.circuit.variables, "compressions":l.compressions.len(),
            "shape":format!("{:?}",format_recursion::private_bridge::PrivateShape::for_circuit(
                l.circuit.rows.len(),l.circuit.public.len(),l.compressions.len()))}))})
        );
        return;
    }
    let setup = if client_only {
        None
    } else {
        let canonical = application.create(seed);
        println!(
            "{}",
            serde_json::json!({"kind":"canonical_client", "measurement":canonical.report})
        );
        let program = canonical.trace;
        assert!(program.satisfied());
        let start = Instant::now();
        let setup = SplitClosedSetup::from_program(program).expect("application verifier closes");
        println!(
            "{}",
            serde_json::json!({"kind":"recursive_setup", "workload":W::NAME,
            "elapsed_ms":start.elapsed().as_secs_f64()*1000., "node_key":setup.node_key(),"base_key":setup.base_key(),
            "base_shape":format!("{:?}",setup.base_shape()),"node_shape":format!("{:?}",setup.node_shape())})
        );
        Some(setup)
    };
    if let Some(directory) = verify {
        let setup = setup.as_ref().expect("verification requires recursive setup");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest,
            serde_json::json!({"workload":W::NAME,"samples":samples,"seed":seed,"node_key":setup.node_key(),"base_key":setup.base_key()})
        );
        let mut checked = 0;
        for sample in 0..samples {
            let mut leaves = Vec::new();
            for leaf in 0..2 {
                let bytes = std::fs::read(directory.join(format!("app-{sample}-{leaf}.cert"))).unwrap();
                let certificate = Certificate::decode(&bytes).unwrap();
                assert_eq!(certificate.height, 0);
                assert_eq!(
                    certificate.statement,
                    application.expected_claim(seed + 1 + 2 * sample as u64 + leaf)
                );
                assert!(setup.verify(&certificate));
                checked += 1;
                leaves.push(certificate);
            }
            let mut statement = leaves[0].statement;
            for height in 1..=3 {
                statement = format_recursion::recursion_fast::node_statement(&statement, &leaves[1].statement);
                let bytes = std::fs::read(directory.join(format!("node-{sample}-{height}.cert"))).unwrap();
                let certificate = Certificate::decode(&bytes).unwrap();
                assert_eq!(certificate.height, height);
                assert_eq!(certificate.statement, statement);
                assert!(setup.verify(&certificate));
                checked += 1;
            }
        }
        println!(
            "{}",
            serde_json::json!({"kind":"independent_verification","workload":W::NAME,"certificates":checked,"status":"verified"})
        );
        return;
    }
    if let Some(directory) = output {
        let setup = setup.as_ref().expect("certificate output requires recursive setup");
        std::fs::create_dir(directory).expect("fresh evidence directory");
        std::fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"workload":W::NAME,"samples":samples,"seed":seed,"node_key":setup.node_key(),"base_key":setup.base_key()}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    for sample in 0..samples {
        let mut adapted = Vec::new();
        for leaf in 0..2 {
            let mut created = application.create(seed + 1 + 2 * sample as u64 + leaf);
            created.report["sample"] = sample.into();
            created.report["leaf"] = leaf.into();
            println!("{}", created.report);
            if let Some(setup) = &setup {
                let start = Instant::now();
                let trace = created.trace;
                assert!(trace.satisfied());
                let certificate = setup.prove_base(&trace).expect("native application proof");
                let application_proof_ms = start.elapsed().as_secs_f64() * 1000.;
                assert_eq!(certificate.statement, created.claim);
                let start = Instant::now();
                assert!(setup.verify(&certificate));
                let verify_ms = start.elapsed().as_secs_f64() * 1000.;
                println!(
                    "{}",
                    serde_json::json!({"kind":"application_proof", "workload":W::NAME,
                    "sample":sample,"leaf":leaf,"application_proof_ms":application_proof_ms,"base_adaptation_ms":0.0,"base_adaptation_proofs":0,"verify_ms":verify_ms,
                    "certificate_bytes":certificate.encode().unwrap().len(), "height":certificate.height, "statement":certificate.statement,"status":"verified"})
                );
                if let Some(directory) = output {
                    std::fs::write(
                        directory.join(format!("app-{sample}-{leaf}.cert")),
                        certificate.encode().unwrap(),
                    )
                    .unwrap();
                }
                adapted.push(certificate);
            }
        }
        if let Some(setup) = &setup {
            let mut current = adapted[0].clone();
            for height in 1..=3 {
                let start = Instant::now();
                let next = setup
                    .prove_node(&current, &adapted[1])
                    .expect("repeated and mixed height merge");
                let merge_ms = start.elapsed().as_secs_f64() * 1000.;
                assert_eq!(next.height, height);
                assert_eq!(
                    next.statement,
                    format_recursion::recursion_fast::node_statement(&current.statement, &adapted[1].statement)
                );
                let start = Instant::now();
                assert!(setup.verify(&next));
                let verify_ms = start.elapsed().as_secs_f64() * 1000.;
                println!(
                    "{}",
                    serde_json::json!({"kind":"merge", "workload":W::NAME,
                    "sample":sample,"height":height,"merge_ms":merge_ms,"verify_ms":verify_ms,
                    "certificate_bytes":next.encode().unwrap().len(),"node_key":setup.node_key(),"base_key":setup.base_key(),"shape":format!("{:?}",setup.node_shape()),"status":"verified"})
                );
                if let Some(directory) = output {
                    std::fs::write(
                        directory.join(format!("node-{sample}-{height}.cert")),
                        next.encode().unwrap(),
                    )
                    .unwrap();
                }
                current = next;
            }
            let mut bad = current.clone();
            bad.statement[0] ^= 1;
            assert!(!setup.verify(&bad));
            assert!(setup.prove_node(&bad, &adapted[0]).is_none());
            bad = current.clone();
            bad.height -= 1;
            assert!(!setup.verify(&bad));
            bad = current;
            bad.proof.stream[0] += primitives::field::F192::ONE;
            assert!(!setup.verify(&bad));
        }
    }
    println!(
        "{}",
        serde_json::json!({"kind":"complete","workload":W::NAME,
        "client_only":client_only,"samples":samples,"peak_rss_kib":peak_rss_kib(),
        "status":if client_only {"witness_reference_checked"} else {"verified"}})
    );
}

fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let arg = |key: &str, default: &str| {
        args.windows(2)
            .find(|p| p[0] == key)
            .map_or_else(|| default.to_owned(), |p| p[1].clone())
    };
    let name = arg("--workload", "sha256-1kib");
    let samples: usize = arg("--samples", "1").parse().unwrap();
    assert!(samples > 0);
    let seed: u64 = arg("--seed", "20261023").parse().unwrap();
    let client_only = args.iter().any(|a| a == "--client-only");
    let output = args
        .windows(2)
        .find(|p| p[0] == "--out")
        .map(|p| std::path::PathBuf::from(&p[1]));
    let verify = args
        .windows(2)
        .find(|p| p[0] == "--verify")
        .map(|p| std::path::PathBuf::from(&p[1]));
    assert!(!(client_only && (output.is_some() || verify.is_some())));
    assert!(!(output.is_some() && verify.is_some()));
    match name.as_str() {
        "blake2s-64b" => {
            run::<circuit_suite::blake2s::Blake2s64>(samples, seed, client_only, output.as_deref(), verify.as_deref())
        }
        "blake2s-1kib" => run::<circuit_suite::blake2s::Blake2sOneKiB>(
            samples,
            seed,
            client_only,
            output.as_deref(),
            verify.as_deref(),
        ),
        "sha256-1kib" => {
            run::<circuit_suite::sha256::Sha256OneKiB>(samples, seed, client_only, output.as_deref(), verify.as_deref())
        }
        "keccak256-1KiB" => run::<circuit_suite::keccak::Keccak256OneKiB>(
            samples,
            seed,
            client_only,
            output.as_deref(),
            verify.as_deref(),
        ),
        "shielded-transfer" => run::<circuit_suite::shielded::ShieldedTransfer>(
            samples,
            seed,
            client_only,
            output.as_deref(),
            verify.as_deref(),
        ),
        "falcon512" => {
            run::<circuit_suite::falcon::Falcon512>(samples, seed, client_only, output.as_deref(), verify.as_deref())
        }
        "mpt-storage-proof" => {
            run::<circuit_suite::mpt::MptStorageProof>(samples, seed, client_only, output.as_deref(), verify.as_deref())
        }
        "ecdsa-secp256k1" => {
            run::<circuit_suite::secp256k1::Ecdsa>(samples, seed, client_only, output.as_deref(), verify.as_deref())
        }
        "poseidon-bn254" => run::<circuit_suite::poseidon::PoseidonSponge<1024>>(
            samples,
            seed,
            client_only,
            output.as_deref(),
            verify.as_deref(),
        ),
        other => panic!("unknown application {other}"),
    }
}
