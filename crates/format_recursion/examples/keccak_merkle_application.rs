//! Application hash-row experiment. Transcript and WHIR remain BLAKE2s.
use format_recursion::native_hash::{Builder, Word};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn application(seed: u64) -> Builder {
    let mut b = Builder::default();
    let leaf: Vec<_> = (0..4).map(|i| b.input(seed.wrapping_mul(0x10001) + i + 17)).collect();
    let mut node = b.keccak256_words(&leaf);
    let mut expected = circuit_suite::keccak::keccak256_native(
        &leaf
            .iter()
            .flat_map(|&w| b.value(w).c0.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    for level in 0..16u64 {
        let bit_value = (seed + level) & 1;
        let bit = b.input(bit_value);
        let sibling: [Word; 4] = std::array::from_fn(|i| b.input((seed + 3) * 0x1000001 + level * 4 + i as u64));
        let left: [Word; 4] = std::array::from_fn(|i| b.select(bit, sibling[i], node[i]));
        let right: [Word; 4] = std::array::from_fn(|i| b.select(bit, node[i], sibling[i]));
        let sibling_bytes: Vec<_> = sibling.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
        let bytes = if bit_value == 1 {
            [expected.as_slice(), sibling_bytes.as_slice()].concat()
        } else {
            [sibling_bytes.as_slice(), expected.as_slice()].concat()
        };
        expected = circuit_suite::keccak::keccak256_native(&bytes);
        node = b.keccak256_words(&left.into_iter().chain(right).collect::<Vec<_>>());
    }
    let actual: Vec<_> = node.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
    assert_eq!(actual, expected);
    for word in node {
        b.expose(word);
    }
    b
}
fn peak_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|s| {
            s.strip_prefix("VmHWM:")
                .map(|v| v.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let seed = args.get(3).map_or(20261024, |s| s.parse().unwrap());
    let canonical = application(seed);
    let setup = canonical.setup_keccak().unwrap();
    let public = canonical.public_values();
    let context = primitives::protocol_hash::hash(b"hometurf-keccak-merkle-depth16-v1");
    if mode == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = application(seed);
        let proof = setup.prove(&witness.values, &witness.permutations, &context).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        std::fs::write(&args[2], &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"wallet_peak_rss_kib":peak_rss(),"proof_bytes":encoded.len(),"permutations":witness.permutations.len(),"arithmetic_rows":witness.rows(),"padded_arithmetic_rows":1usize<<shape.index.log_rows,"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"shape":format!("{shape:?}"),"raw_digest":public[public.len()-4..].iter().flat_map(|v| v.c0.to_le_bytes()).collect::<Vec<_>>()})
        );
    } else {
        let encoded = std::fs::read(&args[2]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.,"peak_rss_kib":peak_rss()})
        );
    }
}
