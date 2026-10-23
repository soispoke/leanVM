//! Full joint native arithmetic/BLAKE2s/fixed-table lookup benchmark.
use circuit_suite::shielded_blake2s::{leanvm_input, reference};
use format_recursion::private_bridge::lookup::LookupBridge;
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let path = &args[2];
    let payload = leanvm_input(0);
    let digest = primitives::hash::hash(&reference::verify(&payload).unwrap());
    let start = Instant::now();
    let setup = LookupBridge::new(&payload).unwrap();
    eprintln!("setup_s={}", start.elapsed().as_secs_f64());
    let context = primitives::hash::hash(b"shielded-lookup-benchmark-v1");
    if mode == "prove" {
        let start = Instant::now();
        let proof = setup.prove(&payload, &context).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let rss: u64 = status
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        std::fs::write(path, &encoded).unwrap();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"wallet_peak_rss_kib":rss,"proof_bytes":encoded.len(),"committed_words":setup.committed_words(),"padded_arithmetic_rows":setup.arithmetic_rows_padded(),"threads":parallel::num_threads(),"cpus":"24-35","compressions":106})
        );
    } else {
        let bytes = std::fs::read(path).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&bytes).unwrap();
        assert!(setup.verify(&digest, &context, &proof));
        let elapsed = start.elapsed().as_secs_f64() * 1000.;
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(!setup.verify(&wrong, &context, &proof));
        let mut bad = proof.clone();
        bad.stream[0] += primitives::field::F192::ONE;
        assert!(!setup.verify(&digest, &context, &bad));
        println!(
            "{}",
            serde_json::json!({"mempool_verify_ms":elapsed,"wrong_digest_rejected":true,"tampered_proof_rejected":true})
        );
    }
}
