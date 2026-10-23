use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let payload = circuit_suite::shielded_blake2s::leanvm_input(0);
    let canonical = format_recursion::shielded_word::application(&payload);
    let public = canonical.b.public_values();
    let setup = canonical.setup().unwrap();
    let shape = setup.verifier_shape();
    let context = primitives::hash::hash(b"shielded-shared-word-tables");
    if args[1] == "prove" {
        drop(canonical);
        let start = Instant::now();
        let c = format_recursion::shielded_word::application(&payload);
        let proof = setup
            .prove_mixed(&c.b.values, &c.b.permutations, &c.b.compressions, &context)
            .unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let wallet = start.elapsed().as_secs_f64();
        std::fs::write(&args[2], &encoded).unwrap();
        println!(
            "{}",
            serde_json::json!({"kind":"wallet","wallet_prove_s":wallet,"rows":c.b.rows(),"queries":c.query_count(),"proof_bytes":encoded.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"compressions":c.b.compressions.len(),"keccak_anchor":true})
        );
    } else {
        let encoded = std::fs::read(&args[2]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"kind":"verify","verify_ms":start.elapsed().as_secs_f64()*1000.0})
        );
    }
}
