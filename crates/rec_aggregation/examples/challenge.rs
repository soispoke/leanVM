//! Track A evaluator binary (see `experiments/pcs-r1cs/challenge/README.md`).
//!
//! `workload` and `clients` run from the frozen reference build, `aggregate` from the
//! candidate build (the only timed step), and `verify` from the reference build again,
//! which recompiles the aggregate program itself. A candidate therefore changes nothing
//! that the verifier checks: a different program changes the transcript seed and fails.
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use fiat_shamir::transcript::{Proof, RawProof};
use flock::{
    membership::{DEPTH, Secret, Statement},
    quotient::{self, Index, Table, circuit, opening},
};
use leanvm_core::cpu;
use primitives::field::{F64, F192};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use shared::*;
use std::{path::Path, time::Instant};

const LOG_ROWS: usize = 20;
/// The baseline PCS rate; the verifier rejects any other, all being 128-bit but trading proof size for speed.
const LOG_INV_RATE: usize = 2;

#[derive(Serialize, Deserialize)]
struct Witness {
    x: [u8; 32],
    siblings: Vec<[u8; 32]>,
    directions: u32,
}
/// One application's client proof, as a node receives it.
#[derive(Serialize, Deserialize)]
struct Client {
    y: [u8; 32],
    root: [u8; 32],
    piop: Proof,
    openings: [Proof; 3],
}
struct Setup {
    circuit: circuit::Circuit,
    index: Index,
    wiring: opening::Committed,
    app_id: [u8; 32],
}
fn setup() -> Setup {
    let circuit = circuit::membership();
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let app_id = r1cs::identity(&circuit);
    Setup {
        circuit,
        index,
        wiring,
        app_id,
    }
}
fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|p| p[0] == name)
        .map(|p| p[1].clone())
        .unwrap_or_else(|| panic!("missing {name}"))
}
fn read<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> T {
    bincode::deserialize(&std::fs::read(path).expect("read artifact")).expect("decode artifact")
}
fn write(path: impl AsRef<Path>, value: &impl Serialize) {
    std::fs::write(path, bincode::serialize(value).unwrap()).expect("write artifact");
}
fn statement(c: &Client) -> Statement {
    Statement { y: c.y, root: c.root }
}
fn full(args: &[String]) -> bool {
    match arg(args, "--interface").as_str() {
        "pcs" => false,
        "r1cs" => true,
        other => panic!("unknown interface {other}"),
    }
}

/// Native admission: the PIOP and all three openings, returning the aggregate's inputs.
fn admit<'a>(s: &'a Setup, layouts: &'a [opening::Layout; 2], c: &Client) -> Option<(Vec<Opened<'a>>, Vec<RawProof>)> {
    let (roots, claims) = quotient::verify(&s.wiring.root, &statement(c), &c.piop, LOG_ROWS).ok()?;
    let opened: Vec<Opened> = [
        (&layouts[0], roots[0], vec![claims.witness]),
        (&s.index.table().layout, s.wiring.root, vec![claims.wiring]),
        (&layouts[1], roots[1], vec![claims.quotient, claims.sum]),
    ]
    .into_iter()
    .zip(&c.openings)
    .map(|((layout, root, claims), proof)| Opened {
        layout,
        root,
        claims,
        proof: proof.clone(),
    })
    .collect();
    let raws = opened
        .iter()
        .map(|o| opening::verification_trace(o.layout, &o.root, &o.claims, &o.proof))
        .collect::<Option<Vec<_>>>()?;
    Some((opened, raws))
}
fn layouts() -> [opening::Layout; 2] {
    [quotient::witness_layout(LOG_ROWS), quotient::quotient_layout(LOG_ROWS)]
}
/// The aggregate's public input: the ordered list of per-application claims.
fn public(s: &Setup, full: bool, clients: &[Client], admitted: &[(Vec<Opened>, Vec<RawProof>)]) -> [F192; 2] {
    let claims: Vec<_> = clients
        .iter()
        .zip(admitted)
        .map(|(c, (opened, _))| {
            if full {
                r1cs::public_claim(&s.app_id, &statement(c))
            } else {
                pcs_public(opened)
            }
        })
        .collect();
    batch_public(&claims)
}
fn program(s: &Setup, full: bool, admitted: &[(Vec<Opened>, Vec<RawProof>)]) -> cpu::Program {
    let (opened, raws) = &admitted[0];
    for (_, rs) in admitted {
        for (a, b) in rs.iter().zip(raws) {
            assert_eq!(
                a.stream.len(),
                b.stream.len(),
                "every application has the compiled shape"
            );
        }
    }
    build(opened, raws, &s.wiring.root, &s.app_id, full, admitted.len())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("workload") => {
            let mut rng = StdRng::seed_from_u64(arg(&args, "--seed").parse().unwrap());
            let n: usize = arg(&args, "--fan-in").parse().unwrap();
            assert!(n >= 2, "a batch aggregates at least two applications");
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
            let s = setup();
            let mut rng = StdRng::from_os_rng();
            let witnesses: Vec<Witness> = read(arg(&args, "--workload"));
            let clients: Vec<Client> = witnesses
                .iter()
                .map(|w| {
                    let secret = Secret {
                        x: w.x,
                        siblings: w.siblings.clone().try_into().expect("Merkle depth"),
                        directions: w.directions,
                    };
                    let st = secret.statement();
                    let cells = s.circuit.cells(&circuit::membership_inputs(&secret));
                    let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
                    let mut committed = Vec::new();
                    let mut commit = |table: &Table| {
                        let c = opening::commit(table);
                        let root = c.root;
                        committed.push(c);
                        root
                    };
                    let p = quotient::prove(&s.circuit, &s.index, &s.wiring.root, &st, &cells, &masks, &mut commit);
                    Client {
                        y: st.y,
                        root: st.root,
                        piop: p.proof,
                        openings: [
                            opening::open(&p.witness, &committed[0], std::slice::from_ref(&p.claims.witness)),
                            opening::open(s.index.table(), &s.wiring, std::slice::from_ref(&p.claims.wiring)),
                            opening::open(&p.quotient, &committed[1], &[p.claims.quotient, p.claims.sum]),
                        ],
                    }
                })
                .collect();
            write(arg(&args, "--out"), &clients);
        }
        Some("aggregate") => {
            // The candidate's timed step: admission, guest preparation and proving.
            let full = full(&args);
            let s = setup();
            let layouts = layouts();
            let clients: Vec<Client> = read(arg(&args, "--clients"));
            let admitted: Vec<_> = clients
                .iter()
                .map(|c| admit(&s, &layouts, c).expect("admissible client proof"))
                .collect();
            let template = program(&s, full, &admitted);
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
            let full = full(&args);
            let s = setup();
            let layouts = layouts();
            let clients: Vec<Client> = read(arg(&args, "--clients"));
            let proof: cpu::Proof = read(arg(&args, "--proof"));
            let admitted: Option<Vec<_>> = clients.iter().map(|c| admit(&s, &layouts, c)).collect();
            let Some(admitted) = admitted else {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "reason": "client proof rejected"})
                );
                std::process::exit(1);
            };
            let prog = program(&s, full, &admitted);
            let public = public(&s, full, &clients, &admitted);
            let t = Instant::now();
            let ok = cpu::verify(&prog, &public, &proof).is_ok_and(|v| v.log_inv_rate == LOG_INV_RATE);
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
                serde_json::json!({"ok": ok, "verify_us": verify_us, "proof_bytes": bincode::serialize(&proof).unwrap().len(), "execution_gas": gas, "fan_in": clients.len()})
            );
            std::process::exit(i32::from(!ok));
        }
        _ => panic!("usage: challenge workload|clients|aggregate|verify ..."),
    }
}
