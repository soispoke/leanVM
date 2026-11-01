//! Fresh-process wallet and verifier harness. Inputs are the shared L6 fixtures.
use leanvm::{Output, Program, Proof, Prover, Rate};
use leanvm_guest::PublicValues;
use serde_json::json;
use std::{fs, path::Path, time::Instant};

#[global_allocator]
static ALLOC: bench::Jemalloc = bench::Jemalloc;

mod exact_fixture;
fn fixture(workload: &str) -> (Vec<u64>, [u64; 4]) {
    match workload {
        "shielded" => {
            let payload: [u8; 1680] = keccakapps_host::leanvm_input(20261024).try_into().unwrap();
            let statement = keccakapps::shielded_statement(&payload);
            let advice = payload
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| u64::from_le_bytes(*b))
                .collect();
            let mut public = PublicValues::new();
            public.commit(&statement);
            (advice, public.digest())
        }
        "merkle" => {
            let input = keccakapps_host::merkle_input(1);
            let statement = keccakapps::merkle_root(&input).unwrap();
            let mut public = PublicValues::new();
            public.commit(&statement);
            (input.to_vec(), public.digest())
        }
        "keccak1k" => {
            // Exact circuit_suite::Keccak256OneKiB splitmix64 fixture.
            let bytes = keccakapps_host::seeded_bytes(20261024, 1024);
            let input: Vec<u64> = bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| u64::from_le_bytes(*b))
                .collect();
            let statement = leanvm_guest::keccak::keccak256(&input, 1024);
            let mut public = PublicValues::new();
            public.commit(&statement);
            (input, public.digest())
        }
        "falcon-l6" => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let advice = exact_fixture::FALCON_ADVICE.to_vec();
            let mut bytes = vec![9u8];
            for w in &advice[..112] {
                bytes.extend(w.to_be_bytes());
            }
            for w in &advice[112..116] {
                bytes.extend(w.to_le_bytes());
            }
            let mut h = sha3::Shake256::default();
            h.update(&bytes);
            let mut digest = [0u8; 32];
            h.finalize_xof().read(&mut digest);
            let mut statement = [0u64; 8];
            for (i, b) in digest.as_chunks::<8>().0.iter().enumerate() {
                statement[i] = u64::from_le_bytes(*b);
            }
            statement[4] = 1;
            let mut public = PublicValues::new();
            public.commit(&statement);
            (advice, public.digest())
        }
        "mpt-l6" => {
            let mut public = PublicValues::new();
            public.commit(&exact_fixture::MPT_STATEMENT);
            (exact_fixture::MPT_ADVICE.to_vec(), public.digest())
        }
        "falcon" => {
            let run = falcon_host::batch(1);
            (run.advice, run.expected)
        }
        "mpt" => {
            let run = stateproof_host::reads(1);
            (run.advice, run.expected)
        }
        _ => panic!("unknown workload {workload}"),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 5, "workload mode elf receipt-prefix");
    let (workload, mode, elf, prefix) = (&args[1], &args[2], &args[3], &args[4]);
    let program = Program::from_elf(&fs::read(elf).unwrap()).unwrap();
    let proof_file = format!("{prefix}.proof");
    let output_file = format!("{prefix}.output");
    match mode.as_str() {
        "prove" | "measure" | "reject-path" | "reject-witness" => {
            let start = Instant::now();
            let (mut advice, expected) = fixture(workload);
            if mode == "reject-witness" {
                match workload.as_str() {
                    "falcon-l6" => advice[116] ^= 1,
                    "mpt-l6" => advice[14] ^= 1,
                    _ => panic!("exact fixture required"),
                }
                assert!(program.measure(&advice).is_err());
                println!(
                    "{}",
                    json!({"kind":"rejection","workload":workload,"invalid_witness_rejected":true})
                );
                return;
            }
            if mode == "reject-path" {
                if workload == "merkle" {
                    advice[4] ^= 1;
                } else if workload == "shielded" {
                    advice[(136 + 84) / 8] ^= 1 << (8 * ((136 + 84) % 8));
                } else {
                    panic!("path workload required");
                }
            }
            if mode == "measure" {
                let stats = program.measure(&advice).unwrap();
                println!(
                    "{}",
                    json!({"kind":"measure","workload":workload,"cycles":stats.cycles(),"committed_words":stats.committed,"tables":stats.base_counts.as_slice()})
                );
            } else {
                let run = Prover::new(Rate::new(2).unwrap()).prove(&program, &advice).unwrap();
                let elapsed = start.elapsed().as_secs_f64();
                if mode == "reject-path" {
                    assert_ne!(run.output, expected);
                    assert!(program.verify(Output::new(expected), &run.proof).is_err());
                    println!(
                        "{}",
                        json!({"kind":"rejection","workload":workload,"wrong_path_rejected":true})
                    );
                    return;
                }
                assert_eq!(run.output, expected);
                let bytes = run.proof.to_bytes();
                fs::write(&proof_file, &bytes).unwrap();
                fs::write(&output_file, serde_json::to_vec(run.output.words()).unwrap()).unwrap();
                println!(
                    "{}",
                    json!({"kind":"wallet","workload":workload,"wallet_prove_s":elapsed,"proof_bytes":bytes.len(),"cycles":run.stats.cycles(),"committed_words":run.stats.committed,"base_counts":run.stats.base_counts.as_slice(),"leaf_log_inv_rate":2,"protocol_hash":"keccak256","application_hash":"keccak"})
                );
            }
        }
        "verify" | "reject-proof" => {
            let output: [u64; 4] = serde_json::from_slice(&fs::read(&output_file).unwrap()).unwrap();
            let mut proof = Proof::from_bytes(&fs::read(&proof_file).unwrap()).unwrap();
            if mode == "reject-proof" {
                proof.0.stream[0] += primitives::field::F192::ONE;
            }
            let start = Instant::now();
            let result = program.verify(Output::new(output), &proof);
            let ms = start.elapsed().as_secs_f64() * 1000.;
            if mode == "reject-proof" {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
            println!(
                "{}",
                json!({"kind":mode,"workload":workload,"verify_ms":ms,"accepted":mode=="verify"})
            );
        }
        _ => panic!("unknown mode"),
    }
    assert!(Path::new(elf).exists());
}
