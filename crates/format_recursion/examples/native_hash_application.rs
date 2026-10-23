use format_recursion::native_hash::Builder;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn application(bytes: usize) -> Builder {
    assert!(bytes > 0 && bytes.is_multiple_of(64));
    let mut b = Builder::default();
    let iv = flock::hash::param_iv();
    let mut h = std::array::from_fn(|i| b.constant(u64::from(iv[2 * i]) | (u64::from(iv[2 * i + 1]) << 32)));
    for block in 0..bytes / 64 {
        let m = std::array::from_fn(|i| {
            let word = std::array::from_fn(|j| ((block * 64 + i * 8 + j) % 251) as u8);
            b.input(u64::from_le_bytes(word))
        });
        let counter = b.constant(((block + 1) * 64) as u64);
        let flags = b.constant(if block + 1 == bytes / 64 {
            u64::from(u32::MAX)
        } else {
            0
        });
        h = b.compress(h, m, counter, flags);
    }
    for word in h {
        b.expose(word);
    }
    b
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
    let reference = primitives::hash::hash(&(0..bytes).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let expected: Vec<_> = reference
        .chunks_exact(8)
        .map(|word| primitives::field::F192::new(u64::from_le_bytes(word.try_into().unwrap()), 0, 0))
        .collect();
    assert_eq!(&public[public.len() - 4..], expected);
    let context = primitives::hash::hash(b"hometurf-native-hash-application-v1");
    if mode == "prove" {
        let start = Instant::now();
        let witness = application(bytes);
        let proof = setup.prove(&witness.values, &witness.compressions, &context).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let encoded = bincode::serialize(&proof).unwrap();
        std::fs::write(path, &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"proof_bytes":encoded.len(),"compressions":witness.compressions.len(),"native_log_rows":shape.index.log_rows,"hash_block_log":shape.block_log,"committed_words":shape.committed_lanes()*(1usize << (shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))})
        );
    } else {
        let proof = bincode::deserialize(&std::fs::read(path).unwrap()).unwrap();
        let start = Instant::now();
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
