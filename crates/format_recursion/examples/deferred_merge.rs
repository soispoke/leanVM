use format_recursion::{
    private_recursion, private_trace,
    row_format::{self, R1cs, first, fold, generator::Generator, spartan::Setup},
    trace::Trace,
};
use primitives::field::F192;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn rss(field: &str) -> u64 {
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
enum Backend {
    Fixed(private_recursion::Setup),
    Sparse(first::SparseSetup),
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let format = &args[2];
    let outer = &args[3];
    let mode = &args[4];
    let mixed = case == "mixed" || case == "merkle";
    assert!(mixed || case == "same");
    assert!(format == "B" || format == "C");
    assert!(outer == "A" || outer == "B");
    assert!(mode == "carried" || mode == "direct");
    let context = primitives::protocol_hash::hash(b"r1cs-deferred-measurement-v1");
    let source0 = row_format::shielded_source(0);
    let source1 = if case == "merkle" {
        row_format::merkle_source(1)
    } else if mixed {
        row_format::source("merge")
    } else {
        row_format::shielded_source(1)
    };
    let make = |s: &row_format::Source| {
        Setup::new(
            R1cs::lower_bounded(&s.circuit, &s.connectors, &s.values, s.fixed_len, 8),
            format == "C",
        )
    };
    let setup0 = make(&source0);
    let setup1 = if mixed {
        Some(make(&source1))
    } else {
        assert_eq!(source0.program_digest(), source1.program_digest());
        None
    };
    let second = setup1.as_ref().unwrap_or(&setup0);
    let apps = if mixed { vec![&setup0, second] } else { vec![&setup0] };
    let indices = if mixed { [0, 1] } else { [0, 0] };
    let children = [&setup0, second];
    let sources = [&source0, &source1];
    let public = [setup0.public(&source0.values), second.public(&source1.values)];
    let publics = [public[0].as_slice(), public[1].as_slice()];
    let mut proofs = Vec::new();
    let mut wallets = Vec::new();
    for i in 0..2 {

        let start_rss = rss("VmRSS:");
        let start = Instant::now();
        let (values, blocks) = (sources[i].rebuild)();
        let witness_s = start.elapsed().as_secs_f64();
        let proof = children[i].prove(&values, &blocks, &context);
        let bytes = bincode::serialize(&proof).unwrap();
        let wallet_s = start.elapsed().as_secs_f64();
        wallets.push(serde_json::json!({"child":i,"wallet_s":wallet_s,"source_witness_s":witness_s,"proof_bytes":bytes.len(),"words":children[i].committed_words,"peak_rss_kib":rss("VmHWM:"),"additional_peak_rss_kib":rss("VmHWM:").saturating_sub(start_rss)}));
        proofs.push(proof);
    }
    let ps = [&proofs[0], &proofs[1]];
    let fresh: Vec<_> = (0..2)
        .map(|i| children[i].claim(&children[i].verify_deferred(publics[i], &context, ps[i], false).unwrap()))
        .collect();
    let digest = first::statement_digest(children, publics);
    let generators: Vec<_> = apps
        .iter()
        .enumerate()
        .map(|(i, s)| Generator::new(sources[if i == 0 { 0 } else { 1 }], 8, s.key))
        .collect();
    let gs: Vec<_> = generators.iter().collect();
    let reduction = fold::prove_generated(&apps, &gs, &fresh, &digest);
    let record = |r: &fold::Reduction| -> Trace {
        if mode == "carried" {
            first::record(&apps, indices, [&setup0.key, &second.key], publics, &context, ps, r)
        } else {
            first::record_direct(children, publics, &context, ps)
        }
    };
    let canonical = record(&reduction);
    assert!(canonical.satisfied());
    let lower = private_trace::lower(&canonical, &canonical).unwrap();
    let rows = lower.circuit.rows.len();
    let compressions = lower.compressions.len();
    let permutations = lower.permutations.len();
    let stages = lower.stage_census;
    drop(lower.circuit);
    drop(lower.values);
    drop(lower.connectors);
    drop(lower.compressions);
    let start = Instant::now();
    let backend = if outer == "A" {
        Backend::Fixed(private_recursion::Setup::new(canonical.clone()).unwrap())
    } else {
        Backend::Sparse(first::SparseSetup::new(canonical.clone(), format == "C").unwrap())
    };
    let setup_s = start.elapsed().as_secs_f64();
    let words = match &backend {
        Backend::Fixed(b) => {
            let s = b.bridge.verifier_shape();
            s.committed_lanes() * (1usize << (s.stack_log - pcs::whir::INITIAL_FOLDING_FACTOR))
        }
        Backend::Sparse(s) => s.setup.committed_words,
    };

    let start_rss = rss("VmRSS:");
    let start = Instant::now();
    let fresh: Vec<_> = (0..2)
        .map(|i| children[i].claim(&children[i].verify_deferred(publics[i], &context, ps[i], false).unwrap()))
        .collect();
    let admission_s = start.elapsed().as_secs_f64();
    let fold_start = Instant::now();
    let reduction = if mode == "carried" {
        fold::prove_generated(&apps, &gs, &fresh, &digest)
    } else {
        reduction
    };
    let fold_s = fold_start.elapsed().as_secs_f64();
    let record_start = Instant::now();
    let trace = record(&reduction);
    let record_s = record_start.elapsed().as_secs_f64();
    assert!(trace.same_program(&canonical));
    let outputs = private_recursion::outputs(&trace);
    let proof_start = Instant::now();
    let proof = match &backend {
        Backend::Fixed(b) => b.prove(&trace, &outputs).unwrap(),
        Backend::Sparse(s) => s.prove(&trace, &context).unwrap(),
    };
    let bytes = bincode::serialize(&proof).unwrap();
    let prover_s = proof_start.elapsed().as_secs_f64();
    let merge_s = start.elapsed().as_secs_f64();
    let peak = rss("VmHWM:");
    let start = Instant::now();
    let own_claim = match &backend {
        Backend::Fixed(b) => {
            assert!(b.verify(&outputs, &proof));
            None
        }
        Backend::Sparse(s) => Some(s.verify(&outputs, &context, &proof).unwrap()),
    };
    let core_verify_ms = start.elapsed().as_secs_f64() * 1000.;
    let own_settle_ms = if let Backend::Sparse(s) = &backend {
        let start = Instant::now();
        assert!(s.generator.settle(own_claim.as_ref().unwrap()));
        Some(start.elapsed().as_secs_f64() * 1000.)
    } else {
        None
    };
    let mut settlements = Vec::new();
    if mode == "carried" {
        assert_eq!(outputs, first::output_fields(&digest, &reduction.carried));
        for (i, g) in generators.iter().enumerate() {
            let start = Instant::now();
            assert!(g.settle(&reduction.carried[i]));
            let ms = start.elapsed().as_secs_f64() * 1000.;
            let mut wrong = reduction.carried[i].clone();
            wrong.matrix_values[0] += F192::ONE;
            assert!(!g.settle(&wrong));
            let mut wrong = reduction.carried[i].clone();
            wrong.app_key[0] ^= 1;
            assert!(!g.settle(&wrong));
            settlements.push(serde_json::json!({"app":if i==0{"shielded"}else{case.as_str()},"ms":ms,"rows":g.rows()}));
        }
    }
    let complete_root_start = Instant::now();
    if mode == "carried" {
        match &backend {
            Backend::Sparse(s) => assert!(first::verify_sparse_root(s, &context, &digest, &reduction.carried, &proof, &gs)),
            Backend::Fixed(s) => assert!(first::verify_root(s, &digest, &reduction.carried, &proof, &gs)),
        }
    }
    let complete_root_ms = complete_root_start.elapsed().as_secs_f64()*1000.;
    let mut wrong = outputs.clone();
    *wrong.last_mut().unwrap() += F192::ONE;
    match &backend {
        Backend::Fixed(b) => assert!(!b.verify(&wrong, &proof)),
        Backend::Sparse(s) => assert!(s.verify(&wrong, &context, &proof).is_none()),
    }
    if mode == "carried" {
        let mut wrong_identity = outputs.clone();
        wrong_identity[2] += F192::ONE;
        match &backend {
            Backend::Fixed(b) => assert!(!b.verify(&wrong_identity, &proof)),
            Backend::Sparse(s) => assert!(s.verify(&wrong_identity, &context, &proof).is_none()),
        }
    }
    let carried_bytes = if mode == "carried" { outputs[2..].len() * 24 } else { 0 };
    let claim_shape = |c: &row_format::spartan::DeferredClaim| serde_json::json!({"row_log":c.row_point.len(),"col_log":c.col_point.len(),"statement_bytes":24*(2+c.row_point.len()+c.col_point.len()+3),"packed_bytes":32+24*(c.row_point.len()+c.col_point.len()+3)});
    let carried_shapes: Vec<_> = reduction.carried.iter().map(claim_shape).collect();
    let own_shape = own_claim.as_ref().map(claim_shape);
    let sparse_shape = match &backend {
        Backend::Sparse(s) => Some(
            serde_json::json!({"constraints":s.setup.r1cs.rows(),"witness_f192":s.setup.r1cs.origins.len(),"row_log":s.setup.row_log,"col_log":s.setup.z_log}),
        ),
        Backend::Fixed(_) => None,
    };
    println!(
        "{}",
        serde_json::json!({"case":case,"carried_shapes":carried_shapes,"own_claim_shape":own_shape,"sparse_shape":sparse_shape,"format":format,"outer_backend":outer,"mode":mode,"wallets":wallets,"merge_s":merge_s,"native_child_checks_s":admission_s,"fold_prover_s":fold_s,"record_s":record_s,"outer_prover_s":prover_s,"rows":rows,"compressions":compressions,"permutations":permutations,"committed_words":words,"proof_bytes":bytes.len(),"core_verify_ms":core_verify_ms,"complete_root_ms":complete_root_ms,"own_merge_matrix_settle_ms":own_settle_ms,"root_settlements":settlements,"carried_claim_bytes":carried_bytes,"application_digest_bytes":32,"setup_s":setup_s,"peak_rss_kib":peak,"additional_peak_rss_kib":peak.saturating_sub(start_rss),"stage_census":stages,"fold_proof_bytes":bincode::serialize(&reduction.proof).unwrap().len(),"outer_matrix_deferred":outer=="B","source_program_digests":sources.iter().map(|s|s.program_digest().iter().map(|b|format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>(),"verified":true})
    );
}
