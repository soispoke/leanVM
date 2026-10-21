//! Track A evaluator binary (see `experiments/pcs-r1cs/challenge/README.md`).
//!
//! `workload` and `clients` run from the frozen reference build, `aggregate` from the
//! candidate build (the only timed step), and `verify` from the reference build again,
//! which recompiles the aggregate program itself. A candidate therefore changes nothing
//! that the verifier checks: a different program changes the transcript seed and fails.
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use flock::membership::DEPTH;
use leanvm_core::cpu;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::Serialize;
use shared::{apps::*, *};
use std::{path::Path, time::Instant};

fn read<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> T {
    bincode::deserialize(&std::fs::read(path).expect("read artifact")).expect("decode artifact")
}
fn write(path: impl AsRef<Path>, value: &impl Serialize) {
    std::fs::write(path, bincode::serialize(value).unwrap()).expect("write artifact");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("workload") => {
            let mut rng = StdRng::seed_from_u64(arg(&args, "--seed").parse().unwrap());
            let n: usize = arg(&args, "--fan-in").parse().unwrap();
            assert!(n >= 1, "a workload has at least one application");
            let witnesses: Vec<Witness> = (0..n)
                .map(|_| {
                    let mut bytes = || {
                        let mut b = [0; 32];
                        rng.fill_bytes(&mut b);
                        b
                    };
                    Witness {
                        x: bytes(),
                        siblings: (0..DEPTH).map(|_| bytes()).collect(),
                        directions: rng.next_u32(),
                    }
                })
                .collect();
            write(arg(&args, "--out"), &witnesses);
        }
        Some("clients") => {
            // What an application's device does: witness, PIOP and openings, then the node's admission.
            let (_, oracle) = interface(&args);
            let s = setup();
            let layouts = layouts();
            let mut rng = StdRng::from_os_rng();
            let witnesses: Vec<Witness> = read(arg(&args, "--workload"));
            let clients: Vec<Client> = witnesses
                .iter()
                .map(|w| {
                    let (client, [witness_us, piop_us, opening_us]) = prove_client(&s, oracle, w, &mut rng);
                    let t = Instant::now();
                    assert!(admit(&s, &layouts, oracle, &client).is_some(), "an honest client proof is admitted");
                    println!(
                        "{}",
                        serde_json::json!({"kind": "client", "interface": arg(&args, "--interface"), "witness_us": witness_us, "piop_us": piop_us, "opening_us": opening_us, "client_us": witness_us + piop_us + opening_us, "admission_us": elapsed(t), "peak_rss_kib": peak_rss_kib()})
                    );
                    client
                })
                .collect();
            write(arg(&args, "--out"), &clients);
        }
        Some("aggregate") => {
            // The candidate's timed step: admission, guest preparation and proving.
            let mode = interface(&args);
            let full = mode.0;
            let s = setup();
            let layouts = layouts();
            let clients: Vec<Client> = read(arg(&args, "--clients"));
            let admitted: Vec<_> = clients
                .iter()
                .map(|c| admit(&s, &layouts, mode.1, c).expect("admissible client proof"))
                .collect();
            let template = program(&s, mode, &admitted);
            let mut prog = template.clone();
            for (c, (opened, raws)) in clients.iter().zip(&admitted) {
                let mut p = template.clone();
                install_witness(&mut p, opened, raws, &statement(c), &c.piop);
                prog.append_witness_from(&p);
            }
            let (proof, stats) =
                cpu::prove(&prog, public(&s, full, &clients, &admitted), LOG_INV_RATE).expect("aggregate proof");
            write(arg(&args, "--out"), &proof);
            println!(
                "{}",
                serde_json::json!({"base_cycles": stats.base_counts.iter().sum::<usize>(), "committed": stats.committed, "code_len": prog.code_len(), "stats": stats.details()})
            );
        }
        Some("verify") => {
            let mode = interface(&args);
            let full = mode.0;
            let s = setup();
            let layouts = layouts();
            let clients: Vec<Client> = read(arg(&args, "--clients"));
            let proof: cpu::Proof = read(arg(&args, "--proof"));
            let admitted: Option<Vec<_>> = clients.iter().map(|c| admit(&s, &layouts, mode.1, c)).collect();
            let Some(admitted) = admitted else {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "reason": "client proof rejected"})
                );
                std::process::exit(1);
            };
            let prog = program(&s, mode, &admitted);
            let public = public(&s, full, &clients, &admitted);
            let t = Instant::now();
            let rate = cpu::verify(&prog, &public, &proof).ok().map(|v| v.log_inv_rate);
            let ok = rate == Some(LOG_INV_RATE);
            let verify_us = elapsed(t);
            // Each application's execution: the EVM call whose emitted claims the aggregate must cover.
            let code = if full {
                claim_contract(&s.app_id)
            } else {
                evm::quotient::contract(&s.wiring.root, LOG_ROWS).code
            };
            let mut gas = 0;
            for (c, (opened, _)) in clients.iter().zip(&admitted) {
                let data = if full {
                    [c.y, c.root].concat()
                } else {
                    evm::quotient::calldata(&statement(c), &c.piop)
                };
                let claim = if full {
                    r1cs::public_claim(&s.app_id, &statement(c))
                } else {
                    pcs_public(opened)
                };
                gas += execution(full, &code, &data, &s.app_id, &s.wiring.root, claim).2;
            }
            println!(
                "{}",
                serde_json::json!({"ok": ok, "verified": rate.is_some(), "log_inv_rate": rate, "verify_us": verify_us, "proof_bytes": bincode::serialize(&proof).unwrap().len(), "execution_gas": gas, "fan_in": clients.len()})
            );
            std::process::exit(i32::from(!ok));
        }
        _ => panic!("usage: challenge workload|clients|aggregate|verify ..."),
    }
}
