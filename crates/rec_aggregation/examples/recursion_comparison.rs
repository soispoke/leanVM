//! Matched child-verifier aggregation, using the same BLAKE2s child proofs.
#[allow(dead_code)]
#[path = "../../format_recursion/examples/support/mod.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use format_recursion::{native_recursion, record_bound, replay, trace::Trace};
use leanvm_core::cpu;
use std::time::Instant;
fn opened(f: &fixture::Fixture) -> Vec<shared::Opened<'_>> {
    vec![
        shared::Opened {
            layout: &f.proved.witness.layout,
            root: f.committed[0].root,
            claims: vec![f.proved.claims.witness.clone()],
            proof: f.openings[0].clone(),
        },
        shared::Opened {
            layout: &f.index.table().layout,
            root: f.wiring.root,
            claims: vec![f.proved.claims.wiring.clone()],
            proof: f.openings[1].clone(),
        },
        shared::Opened {
            layout: &f.proved.quotient.layout,
            root: f.committed[1].root,
            claims: vec![f.proved.claims.quotient.clone(), f.proved.claims.sum.clone()],
            proof: f.openings[2].clone(),
        },
    ]
}
fn trace(fs: &[fixture::Fixture]) -> Trace {
    let traces: Vec<_> = fs.iter().map(|f| record_bound(&f.child, &f.app_id)).collect();
    if traces.len() == 1 {
        traces.into_iter().next().unwrap()
    } else {
        Trace::concatenate(&traces).bind_batch()
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |key: &str, default: &str| {
        args.windows(2)
            .find(|p| p[0] == key)
            .map(|p| p[1].clone())
            .unwrap_or_else(|| default.into())
    };
    let n: usize = arg("--fan-in", "1").parse().unwrap();
    assert!([1, 2, 4, 8].contains(&n));
    let samples: usize = arg("--samples", "3").parse().unwrap();
    assert!(samples > 0);
    let backend = arg("--backend", "native");
    assert!(["native", "vm"].contains(&backend.as_str()));
    parallel::init();
    let initial: Vec<_> = (0..n).map(|i| fixture::fixture(20261022 + i as u64)).collect();
    let start = Instant::now();
    let native = if backend == "native" {
        let t = trace(&initial);
        let values: Vec<_> = t.nodes.iter().map(|n| n.value).collect();
        let public: Vec<_> = t.public.iter().map(|s| values[s.0]).collect();
        let requests = replay::requests(&t, &values, &public).unwrap();
        Some(native_recursion::Setup::new(t, &requests).expect("native setup"))
    } else {
        None
    };
    let vm = if backend == "vm" {
        let f = &initial[0];
        Some(shared::build_for_rows(
            &opened(f),
            &f.child.openings,
            &f.child.index_root,
            &f.app_id,
            true,
            flock::quotient::Oracle::Blake2s,
            n,
            f.child.log_rows,
        ))
    } else {
        None
    };
    let setup_ms = start.elapsed().as_secs_f64() * 1000.;
    println!(
        "{}",
        serde_json::json!({"kind":"setup","backend":backend,"fan_in":n,"setup_ms":setup_ms,"child_log_rows":initial[0].child.log_rows,"native_shape":native.as_ref().map(|s|s.index.shape()),"native_log_rows":native.as_ref().map(|s|s.index.log_rows),"vm_code_len":vm.as_ref().map(|p|p.code_len()),"oracle":"blake2s","recursion_depth":1})
    );
    drop(initial);
    for sample in 0..=samples {
        let fs: Vec<_> = (0..n)
            .map(|i| fixture::fixture(20270000 + sample as u64 * 8 + i as u64))
            .collect();
        let claims: Vec<_> = fs
            .iter()
            .map(|f| shared::r1cs::public_claim(&f.app_id, &f.child.statement))
            .collect();
        let public = if n == 1 {
            claims[0]
        } else {
            shared::batch_public(&claims)
        };
        let public_digest: Vec<_> = public.iter().flat_map(|x| [x.c0, x.c1, x.c2]).collect();
        let child_proof_digests: Vec<_> = fs
            .iter()
            .map(|f| primitives::hash::hash(&bincode::serialize(&(&f.child.piop, &f.child.openings)).unwrap()))
            .collect();
        let start = Instant::now();
        if let Some(setup) = &native {
            let t = trace(&fs);
            assert_eq!(t.public.iter().map(|s| t.nodes[s.0].value).collect::<Vec<_>>(), public);
            let prep_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            let proof = setup.prove(&t, &public).expect("native proof");
            let prove_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            assert!(setup.verify(&public, &proof));
            let verify_ms = start.elapsed().as_secs_f64() * 1000.;
            let total_bytes = bincode::serialized_size(&proof).unwrap();
            let mut negatives = 0;
            if sample == 0 {
                let mut wrong = public;
                wrong[0] += primitives::field::F192::ONE;
                assert!(!setup.verify(&wrong, &proof));
                negatives += 1;
                let mut bad = proof.clone();
                bad.requests[0].message[0] ^= 1;
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                let mut bad = proof.clone();
                bad.requests[0].digest[0] ^= 1;
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                let mut bad = proof.clone();
                bad.arithmetic.stream[0] += primitives::field::F192::ONE;
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                let mut bad = proof.clone();
                bad.hashes.pop();
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                let mut bad = proof.clone();
                bad.hashes.push(proof.hashes[0].clone());
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                let mut bad = proof.clone();
                bad.hashes[0].proof.stream[0] += primitives::field::F192::ONE;
                assert!(!setup.verify(&public, &bad));
                negatives += 1;
                if proof.hashes.len() > 1 {
                    let mut bad = proof.clone();
                    bad.hashes.swap(0, 1);
                    assert!(!setup.verify(&public, &bad));
                    negatives += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({"kind":"sample","backend":backend,"fan_in":n,"sample":sample,"warmup":sample==0,"public":public_digest,"child_proof_digests":child_proof_digests,"prep_ms":prep_ms,"prove_ms":prove_ms,"verify_ms":verify_ms,"total_certificate_bytes":total_bytes,"hash_batches":proof.hashes.len(),"hash_request_bytes":bincode::serialized_size(&proof.requests).unwrap(),"hash_proof_and_chaining_advice_bytes":bincode::serialized_size(&proof.hashes).unwrap(),"arithmetic_proof_bytes":bincode::serialized_size(&proof.arithmetic).unwrap(),"negative_cases":negatives,"trace_values_disclosed":false,"status":"verified"})
            );
        } else {
            let template = vm.as_ref().unwrap();
            let mut program = template.clone();
            for f in &fs {
                let mut p = template.clone();
                shared::install_witness(&mut p, &opened(f), &f.child.openings, &f.child.statement, &f.child.piop);
                program.append_witness_from(&p);
            }
            let prep_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            let (proof, stats) = match cpu::prove(&program, public, 2) {
                Ok(r) => r,
                Err(cpu::ProveError::WitnessOutOfRange { log_committed }) => {
                    println!(
                        "{}",
                        serde_json::json!({"kind":"capacity","backend":backend,"fan_in":n,"status":"unsupported","log_committed":log_committed})
                    );
                    return;
                }
                Err(e) => panic!("VM proof: {e}"),
            };
            let prove_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            cpu::verify(&program, &public, &proof).expect("VM verification");
            let verify_ms = start.elapsed().as_secs_f64() * 1000.;
            let mut negatives = 0;
            if sample == 0 {
                let mut wrong = public;
                wrong[0] += primitives::field::F192::ONE;
                assert!(cpu::verify(&program, &wrong, &proof).is_err());
                negatives += 1;
            }
            println!(
                "{}",
                serde_json::json!({"kind":"sample","backend":backend,"fan_in":n,"sample":sample,"warmup":sample==0,"public":public_digest,"child_proof_digests":child_proof_digests,"prep_ms":prep_ms,"prove_ms":prove_ms,"verify_ms":verify_ms,"total_certificate_bytes":bincode::serialized_size(&proof).unwrap(),"base_cycles":stats.base_counts.iter().sum::<usize>(),"padded_cycles":stats.cycles,"negative_cases":negatives,"status":"verified"})
            );
        }
    }
}
