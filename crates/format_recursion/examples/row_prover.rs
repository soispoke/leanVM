use fiat_shamir::transcript::Proof;
use format_recursion::{
    private_bridge::PrivateBridge,
    row_format::{self, R1cs, spartan},
};
use primitives::field::F192;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn memory(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|s| s.starts_with(field))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let format = &args[2];
    let mode = &args[3];
    let path = &args[4];
    let cap = args.get(5).map_or(8, |s| s.parse().unwrap());
    let fixture_start = Instant::now();
    let source = row_format::source(case);
    let fixture_s = fixture_start.elapsed().as_secs_f64();
    let source_program_digest: String = source.program_digest().iter().map(|b| format!("{b:02x}")).collect();
    let context = primitives::hash::hash(b"standard-row-format-comparison-v1");
    let setup_start = Instant::now();
    if format == "A" {
        let setup = PrivateBridge::new(source.circuit.clone(), source.connectors.clone()).unwrap();
        let public: Vec<_> = source.circuit.public.iter().map(|&i| source.values[i]).collect();
        let setup_s = setup_start.elapsed().as_secs_f64();
        let shape = setup.verifier_shape();
        if mode == "verify" {
            let encoded = std::fs::read(path).unwrap();
            let start = Instant::now();
            let proof: Proof = bincode::deserialize(&encoded).unwrap();
            assert!(setup.verify(&public, &context, &proof));
            let verify_ms = start.elapsed().as_secs_f64() * 1000.;
            let mut wrong = public.clone();
            *wrong.last_mut().unwrap() += F192::ONE;
            assert!(!setup.verify(&wrong, &context, &proof));
            let mut bad = proof.clone();
            bad.stream[0] += F192::ONE;
            assert!(!setup.verify(&public, &context, &bad));
            // Measure the current sparse-index verification as recorded inside a merge.
            let trace = format_recursion::private_verifier::record(&setup, &public, &context, &proof);
            assert!(trace.satisfied());
            let lower = format_recursion::private_trace::lower(&trace, &trace).unwrap();
            println!(
                "{}",
                serde_json::json!({"case":case,"format":format,"source_program_digest":source_program_digest,"verify_ms":verify_ms,"proof_bytes":encoded.len(),"setup_s":setup_s,"fixture_s":fixture_s,"full_verifier_rows":lower.circuit.rows.len(),"full_verifier_compressions":lower.compressions.len(),"stage_census":lower.stage_census,"shape":format!("{shape:?}"),"verified":true})
            );
            return;
        }
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let start_rss = memory("VmRSS:");
        let start = Instant::now();
        let (values, compressions) = (source.rebuild)();
        let witness_s = start.elapsed().as_secs_f64();
        let proof = setup.prove(&values, &compressions, &context).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        let wallet_s = start.elapsed().as_secs_f64();
        let rss = memory("VmHWM:");
        std::fs::write(path, &bytes).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"case":case,"format":format,"source_program_digest":source_program_digest,"wallet_s":wallet_s,"source_witness_s":witness_s,"peak_rss_kib":rss,"start_rss_kib":start_rss,"additional_peak_rss_kib":rss.saturating_sub(start_rss),"proof_bytes":bytes.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"constraints":setup.index.shape().1,"r1cs_shadow_nonzeros":setup.index.r1cs_shadow_nonzeros(),"witness_variables_f192":setup.index.shape().0,"source_rows":source.circuit.rows.len(),"compressions":compressions.len(),"shape":format!("{shape:?}"),"setup_s":setup_s,"fixture_s":fixture_s})
        );
    } else {
        assert!(format == "B" || format == "C");
        let r = R1cs::lower_bounded(
            &source.circuit,
            &source.connectors,
            &source.values,
            source.fixed_len,
            cap,
        );
        let census = r.census();
        assert!(r.satisfied(&r.witness(&source.values)));
        let setup = spartan::Setup::new(r, format == "C");
        let public = setup.public(&source.values);
        let setup_s = setup_start.elapsed().as_secs_f64();
        if mode == "verify" || mode == "matrix-record" {
            let bytes = std::fs::read(path).unwrap();
            let start = Instant::now();
            let proof: Proof = bincode::deserialize(&bytes).unwrap();
            let verified = setup.verify(&public, &context, &proof).unwrap();
            let verify_ms = start.elapsed().as_secs_f64() * 1000.;
            if mode == "matrix-record" {
                println!(
                    "{}",
                    serde_json::json!({"case":case,"format":format,"source_program_digest":source_program_digest,"matrix_recording":setup.recorded_matrix_census(&verified)})
                );
                return;
            }
            let start = Instant::now();
            let _ = std::hint::black_box(setup.matrix_evals(&verified.row_point, &verified.col_point));
            let matrix_eval_ms = start.elapsed().as_secs_f64() * 1000.;
            let mut wrong = public.clone();
            *wrong.last_mut().unwrap() += F192::ONE;
            assert!(setup.verify(&wrong, &context, &proof).is_none());
            let mut bad = proof.clone();
            bad.stream[0] += F192::ONE;
            assert!(setup.verify(&public, &context, &bad).is_none());
            println!(
                "{}",
                serde_json::json!({"case":case,"format":format,"source_program_digest":source_program_digest,"verify_ms":verify_ms,"matrix_eval_ms":matrix_eval_ms,"proof_bytes":bytes.len(),"setup_s":setup_s,"fixture_s":fixture_s,"matrix_census":setup.matrix_gate_census(),"verified":true,"ccs_sets":if format=="C"{Some(vec![vec![0,1],vec![2]])}else{None}})
            );
            return;
        }
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let start_rss = memory("VmRSS:");
        let start = Instant::now();
        let (values, compressions) = (source.rebuild)();
        let witness_s = start.elapsed().as_secs_f64();
        let proof = setup.prove(&values, &compressions, &context);
        let bytes = bincode::serialize(&proof).unwrap();
        let wallet_s = start.elapsed().as_secs_f64();
        let rss = memory("VmHWM:");
        std::fs::write(path, &bytes).unwrap();
        assert!(setup.verify(&public, &context, &proof).is_some());
        println!(
            "{}",
            serde_json::json!({"case":case,"format":format,"source_program_digest":source_program_digest,"affine_cap":cap,"wallet_s":wallet_s,"source_witness_s":witness_s,"peak_rss_kib":rss,"start_rss_kib":start_rss,"additional_peak_rss_kib":rss.saturating_sub(start_rss),"proof_bytes":bytes.len(),"committed_words":setup.committed_words,"census":census,"matrix_census":setup.matrix_gate_census(),"setup_s":setup_s,"fixture_s":fixture_s,"ccs_sets":if format=="C"{Some(vec![vec![0,1],vec![2]])}else{None}})
        );
    }
}
