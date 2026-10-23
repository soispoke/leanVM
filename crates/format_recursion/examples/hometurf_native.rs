use format_recursion::hometurf_application::create;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let merkle = args[2] == "merkle";
    assert!(merkle || args[2] == "hashchain");
    let count: usize = args[3].parse().unwrap();
    let canonical = create(merkle, count, false);
    let public = canonical.builder.public_values();
    let output = canonical.output;
    let setup = canonical.builder.setup().unwrap();
    let context = primitives::protocol_hash::hash(b"hometurf-native-chain-merkle-v1");
    if args[1] == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = create(merkle, count, false);
        let proof = setup
            .prove(&witness.builder.values, &witness.builder.compressions, &context)
            .unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        std::fs::write(&args[4], &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"proof_bytes":encoded.len(),"output":output,"compressions":witness.builder.compressions.len(),"arithmetic_rows":witness.builder.rows(),"native_log_rows":shape.index.log_rows,"hash_block_log":shape.block_log,"committed_words":shape.committed_lanes()*(1usize << (shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))})
        );
    } else {
        let encoded = std::fs::read(&args[4]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.0,"output":output})
        );
    }
}
