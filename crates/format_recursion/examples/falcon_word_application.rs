use format_recursion::falcon_word;
fn main() {
    parallel::init();
    let (original, _, _) = circuit_suite::build::<circuit_suite::falcon::Falcon512>();
    let identity = format_recursion::application_lowering::identity(&original);
    let fixture = &circuit_suite::falcon::fixtures()[0];
    let (c, stages) = falcon_word::application(fixture, identity);
    for s in stages {
        println!(
            "{}",
            serde_json::json!({"part":s.name,"rows":s.rows,"queries":s.queries})
        );
    }
    assert!(c.b.satisfied());
    let context = primitives::hash::hash(b"falcon512-keccak-rows-word-tables");
    let setup_start = std::time::Instant::now();
    let setup = c.setup().expect("fixed shared-table schedule and joint PCS layout");
    let setup_s = setup_start.elapsed().as_secs_f64();
    let public = c.b.public_values();
    let prove_start = std::time::Instant::now();
    let proof = setup
        .prove_mixed(&c.b.values, &c.b.permutations, &c.b.compressions, &context)
        .expect("honest word-lowered Falcon witness");
    let wallet_s = prove_start.elapsed().as_secs_f64();
    let encoded = bincode::serialize(&proof).unwrap();
    let verify_start = std::time::Instant::now();
    let verified = setup.verify(&public, &context, &proof);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    assert!(verified);
    println!(
        "{}",
        serde_json::json!({"rows":c.b.rows(),"queries":c.query_count(),"permutations":c.b.permutations.len(),"arithmetic_satisfied":true,"setup_s":setup_s,"wallet_s":wallet_s,"proof_bytes":encoded.len(),"verify_ms":verify_ms,"complete_falcon":true})
    );
}
