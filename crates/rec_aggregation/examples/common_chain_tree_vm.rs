//! Matched tagged hash-chain tree with one VM program/key for every node.
use bench::{Jemalloc, Plan};
use rec_aggregation::aggregation::common_chain_tree::{Setup, TreeProof};
use serde_json::json;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

fn main() {
    bench::init_tracing_from_env();
    let args: Vec<_> = std::env::args().collect();
    let argument = |key: &str, default| {
        args.windows(2)
            .find(|pair| pair[0] == key)
            .map_or(default, |pair| pair[1].parse::<usize>().unwrap())
    };
    let depth = argument("--depth", 2);
    let chain = argument("--chain", 16);
    let rate = argument("--log-inv-rate", leanvm_core::pcs::TEST_LOG_INV_RATE);
    assert!((1..=8).contains(&depth));
    let certificate_dir = args
        .windows(2)
        .find(|pair| pair[0] == "--certificate-dir")
        .map(|pair| std::path::Path::new(&pair[1]));
    if let Some(dir) = certificate_dir {
        std::fs::create_dir_all(dir).unwrap();
    }
    let certificate = |proof: &TreeProof, level: usize, index: usize| {
        let bytes = proof.encode().unwrap();
        if let Some(dir) = certificate_dir {
            std::fs::write(dir.join(format!("{level}-{index}.bin")), &bytes).unwrap();
        }
        (bytes.len(), primitives::hash::hash(&bytes))
    };
    parallel::init();
    let plan = Plan::new(1, 0);
    let (setup, timing) = plan.measure_quiet(|_| Setup::new(chain, rate));
    println!(
        "{}",
        json!({"kind":"setup", "backend":"vm", "chain":chain, "depth":depth, "key":setup.key(),
        "setup_s":timing.mean(), "code_len":setup.code_len(), "log_inv_rate":rate, "official_score":false})
    );
    let start = primitives::hash::hash(&20261022u64.to_le_bytes());
    if args.iter().any(|a| a == "--shape") {
        let _ = setup.prepare_leaf(&start);
        return;
    }
    let mut current = Vec::<TreeProof>::new();
    for i in 0..1usize << depth {
        let start = primitives::hash::hash(&(i as u64 + 20261022).to_le_bytes());
        let ((proof, stats), creation) = plan.measure_quiet(|_| setup.prepare_leaf(&start).prove().unwrap());
        let (ok, verification) = plan.measure_quiet(|_| setup.verify(&proof).is_ok());
        assert!(ok);
        let (certificate_bytes, certificate_digest) = certificate(&proof, 0, i);
        println!(
            "{}",
            json!({"kind":"proof", "level":0, "index":i, "height":proof.height, "start":start,
            "statement":proof.statement, "creation_s":creation.mean(), "verification_s":verification.mean(),
            "certificate_bytes":certificate_bytes, "certificate_digest":certificate_digest, "stream_scalars":proof.stream_scalars(),
            "merkle_phases":proof.merkle_phases(), "base_cycles":stats.base_counts.iter().sum::<usize>(),
            "padded_cycles":stats.cycles, "verified":ok})
        );
        current.push(proof);
    }
    for level in 1..=depth {
        let mut next = Vec::new();
        for (i, pair) in current.chunks(2).enumerate() {
            assert_eq!(pair.len(), 2);
            let ((proof, stats), creation) =
                plan.measure_quiet(|_| setup.prepare_node(&pair[0], &pair[1]).unwrap().prove().unwrap());
            let (ok, verification) = plan.measure_quiet(|_| setup.verify(&proof).is_ok());
            assert!(ok);
            let (certificate_bytes, certificate_digest) = certificate(&proof, level, i);
            println!(
                "{}",
                json!({"kind":"proof", "level":level, "index":i, "height":proof.height,
                "statement":proof.statement, "creation_s":creation.mean(), "verification_s":verification.mean(),
                "certificate_bytes":certificate_bytes, "certificate_digest":certificate_digest, "stream_scalars":proof.stream_scalars(),
                "merkle_phases":proof.merkle_phases(), "base_cycles":stats.base_counts.iter().sum::<usize>(),
                "padded_cycles":stats.cycles, "verified":ok})
            );
            next.push(proof);
        }
        current = next;
    }
    assert_eq!(current.len(), 1);
    let mut wrong = current[0].clone();
    wrong.statement[0] ^= 1;
    assert!(setup.verify(&wrong).is_err());
    wrong = current[0].clone();
    wrong.height += 1;
    assert!(setup.verify(&wrong).is_err());
    println!(
        "{}",
        json!({"kind":"complete", "backend":"vm", "chain":chain, "depth":depth,
        "root":current[0].statement, "key":setup.key(), "height":current[0].height,
        "single_fixed_circuit":true, "deferred_claims_per_polynomial":1,
        "status":"locally_verified", "official_score":false})
    );
}
