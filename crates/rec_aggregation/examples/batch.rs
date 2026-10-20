//! Independent application proofs, one aggregate, identical inputs on both paths.
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use fiat_shamir::transcript::RawProof;
use flock::{
    membership::{Secret, Statement},
    quotient::{self, Index, Oracle, Table, circuit, opening},
};
use leanvm_core::cpu;
use primitives::field::F64;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use shared::*;
use std::time::Instant;
struct Fixture {
    statement: Statement,
    proved: quotient::Proved,
    committed: Vec<opening::Committed>,
    openings: Vec<fiat_shamir::transcript::Proof>,
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let samples = args
        .windows(2)
        .find(|p| p[0] == "--samples")
        .map(|p| p[1].parse::<usize>().unwrap())
        .unwrap_or(3);
    let n = args
        .windows(2)
        .find(|p| p[0] == "--fan-in")
        .map(|p| p[1].parse::<usize>().unwrap())
        .unwrap_or(2);
    assert!(n >= 2);
    let seed = args
        .windows(2)
        .find(|p| p[0] == "--seed")
        .map(|p| p[1].parse::<u64>().unwrap())
        .unwrap_or(99127);
    // `--oracle blake2s` proves applications on the VM's BLAKE2s transcript, which only an aggregate can check.
    let oracle = oracle_arg(&args);
    let mut rng = StdRng::seed_from_u64(seed);
    let t = Instant::now();
    let circuit = circuit::membership();
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let app_id = r1cs::identity(&circuit);
    let pcs_code = evm::quotient::contract(&wiring.root, 20).code;
    let r1cs_code = claim_contract(&app_id);
    let setup_us = elapsed(t);
    for sample in 0..=samples {
        let mut fixtures = Vec::new();
        let mut client_us = 0.0;
        let mut witness_us = 0.0;
        let mut piop_prove_us = 0.0;
        let mut opening_prove_us = 0.0;
        for _ in 0..n {
            let mut bytes = || {
                let mut b = [0; 32];
                rng.fill_bytes(&mut b);
                b
            };
            let secret = Secret {
                x: bytes(),
                siblings: std::array::from_fn(|_| bytes()),
                directions: rng.next_u32(),
            };
            let statement = secret.statement();
            let t = Instant::now();
            let cells = circuit.cells(&circuit::membership_inputs(&secret));
            let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
            let w = elapsed(t);
            witness_us += w;
            r1cs::check(&circuit, &cells, &statement).unwrap();
            let t = Instant::now();
            let mut committed = Vec::new();
            let mut commit = |table: &Table| {
                let c = opening::commit(table);
                let root = c.root;
                committed.push(c);
                root
            };
            let proved = quotient::prove_with(
                oracle,
                &circuit,
                &index,
                &wiring.root,
                &statement,
                &cells,
                &masks,
                &mut commit,
            );
            let p = elapsed(t);
            piop_prove_us += p;
            let t = Instant::now();
            let openings = vec![
                opening::open(
                    &proved.witness,
                    &committed[0],
                    std::slice::from_ref(&proved.claims.witness),
                ),
                opening::open(index.table(), &wiring, std::slice::from_ref(&proved.claims.wiring)),
                opening::open(
                    &proved.quotient,
                    &committed[1],
                    &[proved.claims.quotient.clone(), proved.claims.sum.clone()],
                ),
            ];
            let o = elapsed(t);
            opening_prove_us += o;
            client_us += w + p + o;
            fixtures.push(Fixture {
                statement,
                proved,
                committed,
                openings,
            });
        }
        let opened: Vec<Vec<Opened>> = fixtures
            .iter()
            .map(|f| {
                vec![
                    Opened {
                        layout: &f.proved.witness.layout,
                        root: f.committed[0].root,
                        claims: vec![f.proved.claims.witness.clone()],
                        proof: f.openings[0].clone(),
                    },
                    Opened {
                        layout: &index.table().layout,
                        root: wiring.root,
                        claims: vec![f.proved.claims.wiring.clone()],
                        proof: f.openings[1].clone(),
                    },
                    Opened {
                        layout: &f.proved.quotient.layout,
                        root: f.committed[1].root,
                        claims: vec![f.proved.claims.quotient.clone(), f.proved.claims.sum.clone()],
                        proof: f.openings[2].clone(),
                    },
                ]
            })
            .collect();
        let t = Instant::now();
        for f in &fixtures {
            let (roots, claims) =
                quotient::verify_with(oracle, &wiring.root, &f.statement, &f.proved.proof, 20).unwrap();
            assert_eq!(claims, f.proved.claims);
            assert_eq!(roots, [f.committed[0].root, f.committed[1].root]);
        }
        let admission_piop_us = elapsed(t);
        let t = Instant::now();
        let raws: Vec<Vec<RawProof>> = opened
            .iter()
            .map(|app| {
                app.iter()
                    .map(|o| opening::verification_trace(o.layout, &o.root, &o.claims, &o.proof).unwrap())
                    .collect()
            })
            .collect();
        let admission_openings_us = elapsed(t);
        let modes: &[bool] = match (oracle, sample % 2) {
            (Oracle::Blake2s, _) => &[true],
            _ if args.iter().any(|a| a == "--pcs") => &[false],
            _ if args.iter().any(|a| a == "--r1cs") => &[true],
            (_, 0) => &[false, true],
            _ => &[true, false],
        };
        for &full in modes {
            let t = Instant::now();
            let template = build(&opened[0], &raws[0], &wiring.root, &app_id, full, oracle, n);
            let compile_us = elapsed(t);
            // Compiled shape must cover each input, not just the first proof.
            for rs in &raws {
                for (a, b) in rs.iter().zip(&raws[0]) {
                    assert_eq!(a.stream.len(), b.stream.len());
                }
            }
            let t = Instant::now();
            let mut program = template.clone();
            for ((f, os), rs) in fixtures.iter().zip(&opened).zip(&raws) {
                let mut p = template.clone();
                install_witness(&mut p, os, rs, &f.statement, &f.proved.proof);
                program.append_witness_from(&p);
            }
            let hint_prep_us = elapsed(t);
            let claims: Vec<_> = fixtures
                .iter()
                .zip(&opened)
                .map(|(f, os)| {
                    if full {
                        r1cs::public_claim(&app_id, &f.statement)
                    } else {
                        pcs_public(os)
                    }
                })
                .collect();
            let public = batch_public(&claims);
            let t = Instant::now();
            program.execute(public).expect("batch guest");
            let guest_execute_us = elapsed(t);
            let mut evm_us = 0.0;
            let mut coverage_us = 0.0;
            let mut gas = 0;
            let mut calldata_bytes = 0;
            let mut transaction_gas = 0;
            for (f, claim) in fixtures.iter().zip(&claims) {
                let data = if full {
                    [f.statement.y, f.statement.root].concat()
                } else {
                    evm::quotient::calldata(&f.statement, &f.proved.proof)
                };
                let (e, c, g) = execution(
                    full,
                    if full { &r1cs_code } else { &pcs_code },
                    &data,
                    &app_id,
                    &wiring.root,
                    *claim,
                );
                evm_us += e;
                coverage_us += c;
                gas += g;
                calldata_bytes += data.len();
                transaction_gas += evm::machine::transaction_gas(&data, g, 40);
            }
            let t = Instant::now();
            assert_eq!(batch_public(&claims), public);
            coverage_us += elapsed(t);
            let mut negative_cases = 0;
            if sample == 0 {
                let mut reordered = claims.clone();
                reordered.swap(0, 1);
                assert_ne!(batch_public(&reordered), public);
                assert!(program.execute(batch_public(&reordered)).is_err());
                negative_cases += 1;
                assert!(program.execute(batch_public(&claims[..n - 1])).is_err());
                negative_cases += 1;
                let mut duplicate = claims.clone();
                duplicate[n - 1] = duplicate[0];
                assert!(program.execute(batch_public(&duplicate)).is_err());
                negative_cases += 1;
            }
            eprintln!("batch sample={sample} full={full} code={}", program.code_len());
            if args.iter().any(|a| a == "--dry-run") {
                // The exact committed shape of the proof this run would need, without proving it.
                let exec = program.execute(public).expect("batch guest");
                let layout = cpu::layout(
                    &program.prog,
                    exec.mem.len().trailing_zeros() as usize,
                    exec.taus(),
                    public,
                );
                let committed: usize = layout
                    .placements
                    .iter()
                    .filter(|p| !p.is_virtual())
                    .map(|p| 1usize << p.n_vars)
                    .sum();
                println!(
                    "{}",
                    serde_json::json!({"kind":"dry-run","fan_in":n,"interface":interface_name(full, oracle),"base_cycles":exec.base_counts.iter().sum::<usize>(),"base_counts":exec.base_counts,"taus":exec.taus(),"log_mem":exec.mem.len().trailing_zeros(),"committed":committed,"log_committed":(committed as f64).log2(),"mu":layout.shape.mu,"code_len":program.code_len(),"memory_cells":exec.mem_used,"negative_guest_cases":negative_cases})
                );
                continue;
            }
            let t = Instant::now();
            let (proof, stats) = match cpu::prove(&program, public, 2) {
                Ok(result) => result,
                Err(cpu::ProveError::WitnessOutOfRange { log_committed }) => {
                    println!(
                        "{}",
                        serde_json::json!({"kind":"capacity", "status":"unsupported", "fan_in":n,
                        "interface":interface_name(full, oracle), "sample":sample, "log_committed":log_committed})
                    );
                    continue;
                }
                Err(error) => panic!("batch aggregate: {error}"),
            };
            let aggregate_prove_us = elapsed(t);
            let t = Instant::now();
            cpu::verify(&program, &public, &proof).expect("batch verification");
            let aggregate_verify_us = elapsed(t);
            let serial_warm_us = client_us
                + admission_piop_us
                + admission_openings_us
                + hint_prep_us
                + evm_us
                + coverage_us
                + aggregate_prove_us
                + aggregate_verify_us;
            println!(
                "{}",
                serde_json::json!({"kind":"sample","fan_in":n,"sample":sample,"warmup":sample==0,"interface":interface_name(full, oracle),"shared_setup_us":setup_us,"client_us":client_us,"witness_us":witness_us,"piop_prove_us":piop_prove_us,"opening_prove_us":opening_prove_us,"admission_piop_us":admission_piop_us,"admission_openings_us":admission_openings_us,"compile_us":compile_us,"hint_prep_us":hint_prep_us,"guest_execute_diagnostic_us":guest_execute_us,"evm_with_context_us":evm_us,"coverage_us":coverage_us,"execution_gas":gas,"calldata_bytes":calldata_bytes,"eip7623_transaction_gas":transaction_gas,"aggregate_prove_us":aggregate_prove_us,"aggregate_verify_us":aggregate_verify_us,"serial_warm_us":serial_warm_us,"serial_cold_us":serial_warm_us+setup_us+compile_us,"negative_guest_cases":negative_cases,"base_cycles":stats.base_counts.iter().sum::<usize>(),"base_counts":stats.base_counts,"padded_cycles":stats.cycles,"memory_cells":stats.mem_used,"code_len":program.code_len(),"aggregate_transport_bytes":bincode::serialize(&proof).unwrap().len(),"stats":stats.details()})
            );
        }
    }
}
