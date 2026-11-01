//! Isolated native relation screens; these do not change the production PCS.
use format_recursion::native_hash::Builder;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn application(arity: usize, leaf_bytes: usize, seed: u64) -> Builder {
    let mut b = Builder::default();
    let leaf: Vec<_> = (0..leaf_bytes / 8).map(|i| b.input(seed + i as u64)).collect();
    let mut node = b.keccak256_words(&leaf);
    let depth = if arity == 2 { 16 } else { 8 };
    for level in 0..depth {
        let index = b.input((seed + level as u64) % arity as u64);
        let bits = b.bits(index, arity.trailing_zeros() as usize);
        let mut words = Vec::new();
        for slot in 0..arity {
            let mut active = b.one();
            for (i, bit) in bits.iter().enumerate() {
                let factor = if slot & (1 << i) != 0 {
                    *bit
                } else {
                    b.gate(*bit, b.one(), b.one())
                };
                active = b.gate(active, factor, b.zero());
            }
            for (i, current) in node.iter().enumerate() {
                let sibling = b.input(seed + 1000 + (level * 100 + slot * 4 + i) as u64);
                words.push(b.select(active, sibling, *current));
            }
        }
        let bytes: Vec<_> = words.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
        let expected = circuit_suite::keccak::keccak256_native(&bytes);
        node = b.keccak256_words(&words);
        let actual: Vec<_> = node.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
        assert_eq!(actual, expected);
    }
    for word in node {
        b.expose(word);
    }
    b
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let arity: usize = args[1].parse().unwrap();
    let leaf_bytes: usize = args[2].parse().unwrap();
    assert!([2, 4].contains(&arity) && [32, 128].contains(&leaf_bytes));
    let canonical = application(arity, leaf_bytes, 1);
    let setup = canonical.setup_keccak().unwrap();
    let public = canonical.public_values();
    drop(canonical);
    let context = primitives::protocol_hash::hash(b"keccak-layout-isolated-screen-v1");
    let start = Instant::now();
    let witness = application(arity, leaf_bytes, 1);
    let proof = setup.prove(&witness.values, &witness.permutations, &context).unwrap();
    let prove_s = start.elapsed().as_secs_f64();
    let bytes = bincode::serialize(&proof).unwrap().len();
    let start = Instant::now();
    assert!(setup.verify(&public, &context, &proof));
    let verify_ms = start.elapsed().as_secs_f64() * 1000.;
    let mut wrong = public.clone();
    *wrong.last_mut().unwrap() += primitives::field::F192::ONE;
    assert!(!setup.verify(&wrong, &context, &proof));
    let shape = setup.verifier_shape();
    println!(
        "{}",
        serde_json::json!({"arity":arity,"leaf_bytes":leaf_bytes,"prove_s":prove_s,"verify_ms":verify_ms,"proof_bytes":bytes,"rows":witness.rows(),"permutations":witness.permutations.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"verified":true,"scope":"isolated relation screen, not a changed PCS or merge"})
    );
}
