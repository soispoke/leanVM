//! Amortized native row cost, including arithmetic connectors and PCS padding.
use format_recursion::native_hash::Builder;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn create(keccak: bool, count: usize) -> Builder {
    let mut b = Builder::default();
    let mut last = Vec::new();
    for row in 0..count {
        if keccak {
            let input = std::array::from_fn(|lane|b.input(((row*25+lane) as u64).wrapping_mul(0x9e3779b97f4a7c15)));
            last = b.keccak_f(input)[..4].to_vec();
        } else {
            let iv = flock::hash::param_iv();
            let h = std::array::from_fn(|i|b.constant(u64::from(iv[2*i])|(u64::from(iv[2*i+1])<<32)));
            let m = std::array::from_fn(|lane|b.input(((row*8+lane) as u64).wrapping_mul(0x9e3779b97f4a7c15)));
            let counter = b.constant(64);
            let flags = b.constant(u64::from(u32::MAX));
            last = b.compress(h,m,counter,flags).to_vec();
        }
    }
    for word in last { b.expose(word); }
    b
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(),12);
    let args: Vec<_> = std::env::args().collect();
    let keccak = args[1] == "keccak";
    let count: usize = args[2].parse().unwrap();
    let canonical = create(keccak,count);
    let context = [93;32];
    if keccak {
        let setup = canonical.setup_keccak().unwrap();
        drop(canonical);
        let start = Instant::now();
        let b = create(true,count);
        let proof = setup.prove(&b.values,&b.permutations,&context).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let shape = setup.verifier_shape();
        println!("{}",serde_json::json!({"hash":"keccak","rows":count,"rate_bytes_per_row":136,"wallet_prove_s":elapsed,"proof_bytes":bytes.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))}));
        assert!(setup.verify(&b.public_values(),&context,&proof));
    } else {
        let setup = canonical.setup().unwrap();
        drop(canonical);
        let start = Instant::now();
        let b = create(false,count);
        let proof = setup.prove(&b.values,&b.compressions,&context).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let shape = setup.verifier_shape();
        println!("{}",serde_json::json!({"hash":"blake2s","rows":count,"rate_bytes_per_row":64,"wallet_prove_s":elapsed,"proof_bytes":bytes.len(),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR))}));
        assert!(setup.verify(&b.public_values(),&context,&proof));
    }
}
