use format_recursion::falcon_word;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let (original, _, _) = circuit_suite::build::<circuit_suite::falcon::Falcon512>();
    let identity = format_recursion::application_lowering::identity(&original);
    let fixture = &circuit_suite::falcon::fixtures()[0];
    let (canonical, _) = falcon_word::application(fixture, identity);
    let mut pk_message =
        circuit_suite::falcon::native::pk_bytes(&circuit_suite::falcon::Params::falcon512(), &fixture.h);
    pk_message.extend(&fixture.msg);
    let mut statement = circuit_suite::falcon::native::shake256(&pk_message, 32);
    statement.resize(64, 0);
    statement[32] = 1;
    let mut expected = identity.to_vec();
    for half in statement.as_chunks::<16>().0.iter() {
        expected.extend(half.iter().rev());
    }
    let expected = primitives::hash::hash(&expected);
    let public = canonical.b.public_values();
    let actual: Vec<_> = public[public.len() - 4..]
        .iter()
        .flat_map(|w| w.c0.to_le_bytes())
        .collect();
    assert_eq!(actual, expected, "independent canonical Falcon claim");
    let context = primitives::hash::hash(b"falcon512-keccak-rows-word-tables");
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
        let (c, _) = falcon_word::application(fixture, identity);
        let proof = setup
            .prove_mixed(&c.b.values, &c.b.permutations, &c.b.compressions, &context)
            .expect("honest Falcon witness");
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
