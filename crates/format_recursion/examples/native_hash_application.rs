use format_recursion::native_hash::Builder;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn application(bytes: usize) -> Builder {
    assert!(bytes > 0 && bytes.is_multiple_of(64));
    let mut b = Builder::default();
    let message: Vec<_> = (0..bytes / 8)
        .map(|i| {
            let word = std::array::from_fn(|j| ((i * 8 + j) % 251) as u8);
            b.constant(u64::from_le_bytes(word))
        })
        .collect();
    let h = b.hash_words(&message);
    let length = b.constant(bytes as u64);
    let mut statement = vec![length];
    statement.extend(h);
    let output = b.hash_words(&statement);
    for word in output {
        b.expose(word);
    }
    b
}

fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let bytes: usize = args[2].parse().unwrap();
    let path = &args[3];
    let canonical = application(bytes);
    let setup = canonical.setup().unwrap();
    let public = canonical.public_values();
    let reference = primitives::hash::hash(&(0..bytes).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let mut claim = (bytes as u64).to_le_bytes().to_vec();
    claim.extend(reference);
    let expected_digest = primitives::hash::hash(&claim);
    let expected: Vec<_> = expected_digest
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| primitives::field::F192::new(u64::from_le_bytes(*w), 0, 0))
        .collect();
    assert_eq!(&public[public.len() - 4..], expected);
    let context = primitives::hash::hash(b"hometurf-native-hash-application-v1");
    if mode == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = application(bytes);
        let proof = setup.prove(&witness.values, &witness.compressions, &context).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        std::fs::write(path, &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"output":expected_digest.as_chunks::<8>().0.iter().map(|w|u64::from_le_bytes(*w)).collect::<Vec<_>>(),"proof_bytes":encoded.len(),"compressions":witness.compressions.len(),"native_log_rows":shape.index.log_rows,"hash_block_log":shape.block_log,"committed_words":shape.committed_lanes()*(1usize << (shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))})
        );
    } else {
        let encoded = std::fs::read(path).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.0})
        );
        let mut wrong = public;
        let last = wrong.len() - 1;
        wrong[last] += primitives::field::F192::ONE;
        assert!(!setup.verify(&wrong, &context, &proof));
    }
}
