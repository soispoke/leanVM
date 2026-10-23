use format_recursion::xmss_application::{create, fixture};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let fixture = fixture();
    let canonical = create(&fixture);
    assert!(canonical.builder.satisfied());
    assert_eq!(
        canonical.output,
        [
            16814765567871573320,
            5643609832429911137,
            18313627300063359640,
            15515260675635821613
        ]
    );
    let public = canonical.builder.public_values();
    let output = canonical.output;
    let setup = canonical.builder.setup().unwrap();
    let context = primitives::protocol_hash::hash(b"hometurf-native-xmss-v1");
    if args[1] == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = create(&fixture);
        let proof = setup
            .prove(&witness.builder.values, &witness.builder.compressions, &context)
            .unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let seconds = start.elapsed().as_secs_f64();
        std::fs::write(&args[2], &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":seconds,"proof_bytes":encoded.len(),"compressions":witness.builder.compressions.len(),"arithmetic_rows":witness.builder.rows(),"native_log_rows":shape.index.log_rows,"hash_block_log":shape.block_log,"committed_words":shape.committed_lanes()*(1usize << (shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"output":output})
        );
    } else {
        let encoded = std::fs::read(&args[2]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.0,"output":output})
        );
    }
}
