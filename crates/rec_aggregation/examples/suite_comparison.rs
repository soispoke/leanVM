//! Paired PCS / R1CS measurements on the circuit suite. Each client proof is independently verified.
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use circuit_suite::{Circuit, Instance, Src, Workload};
use flock::{
    membership::Statement,
    quotient::{self, Index, Table, opening},
};
use leanvm_core::cpu;
use primitives::field::{F64, F192};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use shared::*;
use std::time::Instant;

macro_rules! dispatch {
    ($name:expr, $f:ident $(, $arg:expr)*) => {
        match $name {
            "blake2s-1kib" => $f::<circuit_suite::blake2s::Blake2sOneKiB>($($arg),*),
            "sha256-1kib" => $f::<circuit_suite::sha256::Sha256OneKiB>($($arg),*),
            "keccak256-1KiB" => $f::<circuit_suite::keccak::Keccak256OneKiB>($($arg),*),
            "shielded-transfer" => $f::<circuit_suite::shielded::ShieldedTransfer>($($arg),*),
            "falcon512" => $f::<circuit_suite::falcon::Falcon512>($($arg),*),
            "mpt-storage-proof" => $f::<circuit_suite::mpt::MptStorageProof>($($arg),*),
            "ecdsa-secp256k1" => $f::<circuit_suite::secp256k1::Ecdsa>($($arg),*),
            "poseidon-bn254" => $f::<circuit_suite::poseidon::PoseidonSponge<1024>>($($arg),*),
            other => panic!("unknown workload {other}"),
        }
    };
}
fn instance<W: Workload>(seed: u64) -> Instance {
    W::instance(seed)
}
fn get_circuit(name: &str) -> (Circuit, Vec<Src>, usize) {
    dispatch!(name, circuit_suite_build)
}
fn circuit_suite_build<W: Workload>() -> (Circuit, Vec<Src>, usize) {
    circuit_suite::build::<W>()
}
fn get_instance(name: &str, seed: u64) -> Instance {
    dispatch!(name, instance, seed)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args
        .windows(2)
        .find(|p| p[0] == "--samples")
        .map(|p| p[1].parse::<usize>().unwrap())
        .unwrap_or(3);
    let skip_negative = args.iter().any(|a| a == "--skip-negative");
    let seed = args
        .windows(2)
        .find(|p| p[0] == "--seed")
        .map(|p| p[1].parse::<u64>().unwrap())
        .unwrap_or(902);
    let oracle = oracle_arg(&args);
    let mut rng = StdRng::seed_from_u64(seed);
    let t = Instant::now();
    let name = args.windows(2).find(|p| p[0] == "--workload").expect("--workload NAME")[1].as_str();
    let (circuit, srcs, _) = get_circuit(name);
    circuit.check_wired().expect("well-formed circuit");
    if circuit.log_rows + 5 > quotient::domain::BASIS {
        println!(
            "{}",
            serde_json::json!({"kind":"capacity", "status":"unsupported", "workload":name,
            "log_rows":circuit.log_rows, "maximum_log_rows":quotient::domain::BASIS-5,
            "reason":"quotient prover evaluation domain exceeds its implemented Cantor basis"})
        );
        return;
    }
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let app_id = r1cs::identity(&circuit);
    let pcs_code = evm::quotient::contract(&wiring.root, circuit.log_rows).code;
    let r1cs_code = claim_contract(&app_id);
    let shared_setup_us = elapsed(t);
    for data in [vec![], vec![0; 63], vec![0; 65]] {
        assert!(evm::machine::call(&r1cs_code, &data).output.is_none());
    }
    println!(
        "{}",
        serde_json::json!({"kind":"setup","workload":name,"log_rows":circuit.log_rows,"shared_setup_us":shared_setup_us,"upstream":"651453c6839de98566c18e94d058507c9ff8920b","app_id":app_id,"rows":1usize<<circuit.log_rows,"r1cs_gate_constraints":6usize<<circuit.log_rows,"copy_constraints":circuit.sigma.len(),"public_constraints":1024,"samples":samples,"warmup_samples":1})
    );
    for sample in 0..=samples {
        let instance = get_instance(name, seed + sample as u64);
        assert_eq!(
            circuit_suite::read_statement(&circuit.values(&instance.inputs), &srcs),
            instance.statement,
            "circuit output must match the independent reference"
        );
        let statement = Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        let t = Instant::now();
        let cells = circuit.cells(&instance.inputs);
        let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
        let witness_us = elapsed(t);
        let t = Instant::now();
        r1cs::check(&circuit, &cells, &statement).expect("application R1CS witness");
        let reference_check_us = elapsed(t);
        if sample == 0 && !skip_negative {
            let mut bad = statement;
            bad.y[0] ^= 1;
            assert!(r1cs::check(&circuit, &cells, &bad).is_err());
            let mut bad_cells = cells.clone();
            bad_cells[3] += F64::ONE;
            assert!(r1cs::check(&circuit, &bad_cells, &statement).is_err());
        }
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
        let piop_prove_us = elapsed(t);
        let t = Instant::now();
        let mut opened = Vec::new();
        for (table, c, claims) in [
            (&proved.witness, &committed[0], vec![proved.claims.witness.clone()]),
            (index.table(), &wiring, vec![proved.claims.wiring.clone()]),
            (
                &proved.quotient,
                &committed[1],
                vec![proved.claims.quotient.clone(), proved.claims.sum.clone()],
            ),
        ] {
            let proof = opening::open(table, c, &claims);
            opened.push(Opened {
                layout: &table.layout,
                root: c.root,
                claims,
                proof,
            });
        }
        let opening_prove_us = elapsed(t);
        let client_us = witness_us + piop_prove_us + opening_prove_us;
        // Both interfaces admit exactly the same native proof, retaining authenticated
        // Merkle expansions for aggregation rather than doing that work a second time.
        let t = Instant::now();
        let (roots, claims) =
            quotient::verify_with(oracle, &wiring.root, &statement, &proved.proof, circuit.log_rows).unwrap();
        assert_eq!(claims, proved.claims);
        assert_eq!(roots, [committed[0].root, committed[1].root]);
        let admission_piop_us = elapsed(t);
        let t = Instant::now();
        let raws: Vec<_> = opened
            .iter()
            .map(|o| opening::verification_trace(o.layout, &o.root, &o.claims, &o.proof).expect("native admission"))
            .collect();
        let admission_openings_us = elapsed(t);
        let mode_order = if sample % 2 == 0 { [false, true] } else { [true, false] };
        for full in mode_order {
            let vm = oracle == quotient::Oracle::Blake2s;
            if (args.iter().any(|a| a == "--full") || vm) && !full || args.iter().any(|a| a == "--pcs") && full {
                continue;
            }
            let t = Instant::now();
            let mut program = build_for_rows(&opened, &raws, &wiring.root, &app_id, full, oracle, 1, circuit.log_rows);
            let compile_us = elapsed(t);
            let t = Instant::now();
            install_witness(&mut program, &opened, &raws, &statement, &proved.proof);
            let hint_prep_us = elapsed(t);
            let public = if full {
                r1cs::public_claim(&app_id, &statement)
            } else {
                pcs_public(&opened)
            };
            let t = Instant::now();
            program.execute(public).expect("valid aggregate guest");
            let guest_execute_us = elapsed(t);
            let negatives = if sample == 0 && !skip_negative {
                adversarial(
                    &program,
                    &opened,
                    &raws,
                    &statement,
                    &proved.proof,
                    public,
                    full,
                    &app_id,
                )
            } else {
                0
            };
            let code = if full { &r1cs_code } else { &pcs_code };
            let calldata = if full {
                [statement.y, statement.root].concat()
            } else {
                evm::quotient::calldata(&statement, &proved.proof)
            };
            let (evm_with_context_us, coverage_us, execution_gas) =
                execution_for_rows(full, code, &calldata, &app_id, &wiring.root, public, circuit.log_rows);
            eprintln!(
                "sample={sample} full={full} code={} negatives={negatives}",
                program.code_len()
            );
            let t = Instant::now();
            let (proof, stats) = cpu::prove(&program, public, 2).expect("aggregate proof");
            let aggregate_prove_us = elapsed(t);
            let t = Instant::now();
            cpu::verify(&program, &public, &proof).expect("aggregate verification");
            let aggregate_verify_us = elapsed(t);
            if sample == 0 && !skip_negative {
                let mut wrong = public;
                wrong[0] += F192::ONE;
                assert!(cpu::verify(&program, &wrong, &proof).is_err());
            }
            let serialized = bincode::serialize(&proof).unwrap();
            let serial_warm_us = client_us
                + admission_piop_us
                + admission_openings_us
                + hint_prep_us
                + aggregate_prove_us
                + aggregate_verify_us
                + evm_with_context_us
                + coverage_us;
            println!(
                "{}",
                serde_json::json!({"kind":"sample","workload":name,"log_rows":circuit.log_rows,"sample":sample,"warmup":sample==0,"interface":interface_name(full, oracle),"statement":statement.halves().iter().map(|x|[x.c0,x.c1]).collect::<Vec<_>>(),"witness_us":witness_us,"piop_prove_us":piop_prove_us,"opening_prove_us":opening_prove_us,"client_us":client_us,"reference_r1cs_check_us":reference_check_us,"admission_piop_us":admission_piop_us,"admission_openings_us":admission_openings_us,"compile_us":compile_us,"hint_prep_us":hint_prep_us,"guest_execute_diagnostic_us":guest_execute_us,"aggregate_prove_us":aggregate_prove_us,"aggregate_verify_us":aggregate_verify_us,"evm_with_context_us":evm_with_context_us,"coverage_us":coverage_us,"execution_gas":execution_gas,"calldata_bytes":calldata.len(),"eip7623_transaction_gas":evm::machine::transaction_gas(&calldata,execution_gas,40),"serial_warm_us":serial_warm_us,"serial_cold_us":serial_warm_us+shared_setup_us+compile_us,"negative_guest_cases":negatives,"aggregate_transport_bytes":serialized.len(),"code_len":program.code_len(),"base_cycles":stats.base_counts.iter().sum::<usize>(),"base_counts":stats.base_counts,"padded_cycles":stats.cycles,"memory_cells":stats.mem_used,"stats":stats.details()})
            );
        }
    }
}
