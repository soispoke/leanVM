use circuit_suite::Workload;
use format_recursion::sha256_word;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let (original, _, _) = circuit_suite::build::<circuit_suite::sha256::Sha256OneKiB>();
    let identity = format_recursion::application_lowering::identity(&original);
    let instance = circuit_suite::sha256::Sha256OneKiB::instance(0);
    let message: Vec<u8> = instance
        .inputs
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bits| bits.iter().enumerate().fold(0, |v, (i, &bit)| v | (u8::from(bit) << i)))
        .collect();
    let canonical = sha256_word::application(&message, identity);
    let mut expected = identity.to_vec();
    for half in instance.statement.as_chunks::<16>().0.iter() {
        expected.extend(half.iter().rev());
    }
    let expected = primitives::hash::hash(&expected);
    let public = canonical.b.public_values();
    let actual: Vec<_> = public[public.len() - 4..]
        .iter()
        .flat_map(|w| w.c0.to_le_bytes())
        .collect();
    assert_eq!(actual, expected, "independent SHA-256 canonical claim");
    let context = primitives::hash::hash(b"sha256-shared-word-tables");
    let start = Instant::now();
    let setup = canonical
        .setup()
        .expect("fixed shared-table schedule and joint PCS layout");
    let shape = setup.verifier_shape();
    println!(
        "{}",
        serde_json::json!({"kind":"setup","setup_s":start.elapsed().as_secs_f64(),"shape":format!("{shape:?}")})
    );
    if args[1] == "prove" {
        drop(canonical);
        let start = Instant::now();
        let c = sha256_word::application(&message, identity);
        let proof = setup
            .prove_mixed(&c.b.values, &c.b.permutations, &c.b.compressions, &context)
            .expect("honest SHA-256 witness");
        let encoded = bincode::serialize(&proof).unwrap();
        let wallet = start.elapsed().as_secs_f64();
        std::fs::write(&args[2], &encoded).unwrap();
        println!(
            "{}",
            serde_json::json!({"kind":"wallet","wallet_prove_s":wallet,"proof_bytes":encoded.len(),"rows":c.b.rows(),"queries":c.query_count(),"permutations":c.b.permutations.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))})
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
