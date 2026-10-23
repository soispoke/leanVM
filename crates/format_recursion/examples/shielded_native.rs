use format_recursion::native_hash::Builder;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn application(seed: usize) -> Builder {
    format_recursion::shielded_application::application_vm(&circuit_suite::shielded_blake2s::leanvm_input(seed)).0
}

fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let bytes: usize = args[2].parse().unwrap();
    let path = &args[3];
    let canonical = application(bytes);
    let setup = canonical.setup().unwrap();
    let public = canonical.public_values();
    let digest =
        circuit_suite::shielded_blake2s::reference::verify(&circuit_suite::shielded_blake2s::leanvm_input(bytes))
            .unwrap();
    let digest = primitives::hash::hash(&digest);
    let expected: Vec<_> = digest
        .chunks(8)
        .map(|b| primitives::field::F192::new(u64::from_le_bytes(b.try_into().unwrap()), 0, 0))
        .collect();
    assert_eq!(&public[public.len() - 4..], expected.as_slice());
    assert_eq!(canonical.compressions.len(), 106);
    let context = primitives::hash::hash(b"hometurf-native-hash-application-v1");
    if mode == "merge" {
        use format_recursion::{
            private_recursion::{self, Setup},
            private_verifier,
        };
        let left = application(0);
        let right = application(1);
        let left_public = left.public_values();
        let right_public = right.public_values();
        let left_proof = setup.prove(&left.values, &left.compressions, &context).unwrap();
        let right_proof = setup.prove(&right.values, &right.compressions, &context).unwrap();
        assert!(setup.verify(&left_public, &context, &left_proof));
        assert!(setup.verify(&right_public, &context, &right_proof));
        let canonical = private_verifier::record_application_pair(
            &setup,
            [&left_public, &right_public],
            &context,
            [&left_proof, &right_proof],
        )
        .unwrap();
        assert!(canonical.satisfied());
        let merge_setup = Setup::new(canonical).unwrap();
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let start = Instant::now();
        let trace = private_verifier::record_application_pair(
            &setup,
            [&left_public, &right_public],
            &context,
            [&left_proof, &right_proof],
        )
        .unwrap();
        let output = private_recursion::outputs(&trace);
        let proof = merge_setup.prove(&trace, &output).unwrap();
        let encoded = private_recursion::encode(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        assert!(merge_setup.verify(&output, &proof));
        let mut bad = proof.clone();
        bad.stream[0] += primitives::field::F192::ONE;
        assert!(!merge_setup.verify(&output, &bad));
        let mut wrong = output.clone();
        wrong[0] += primitives::field::F192::ONE;
        assert!(!merge_setup.verify(&wrong, &proof));
        let shape = merge_setup.bridge.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"merge2to1_s":elapsed,"proof_bytes":encoded.len(),"shape":format!("{shape:?}"),"distinct_children":true})
        );
        return;
    }
    if mode == "prove" {
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let start = Instant::now();
        let witness = application(bytes);
        let proof = setup.prove(&witness.values, &witness.compressions, &context).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let rss = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap();
        std::fs::write(path, &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"wallet_peak_rss_kib":rss,"proof_bytes":encoded.len(),"compressions":witness.compressions.len(),"gate_rows":witness.rows(),"native_log_rows":shape.index.log_rows,"hash_block_log":shape.block_log,"committed_words":shape.committed_lanes()*(1usize << (shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))})
        );
    } else {
        let bytes = std::fs::read(path).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&bytes).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.0})
        );
        let mut wrong = public;
        let last = wrong.len() - 1;
        wrong[last] += primitives::field::F192::ONE;
        assert!(!setup.verify(&wrong, &context, &proof));
        let mut tampered = proof.clone();
        tampered.stream[0] += primitives::field::F192::ONE;
        assert!(!setup.verify(&canonical.public_values(), &context, &tampered));
        println!("tampered proof and wrong digest rejected");
    }
}
