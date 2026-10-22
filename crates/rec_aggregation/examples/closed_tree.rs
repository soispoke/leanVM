//! Small-tree measurement of the single-key recursive construction.
use bench::{Jemalloc, Plan};
use format_recursion::closed_recursion::ClosedSetup;
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
    assert!((1..=8).contains(&depth));
    parallel::init();
    let plan = Plan::new(1, 0);
    let (setup, timing) = plan.measure_quiet(|_| ClosedSetup::new(chain).expect("closed shape must stabilize"));
    let shape = setup.shape();
    println!(
        "{}",
        json!({"kind":"setup", "chain":chain, "depth":depth, "key":setup.key(), "setup_s":timing.mean(),
        "native_rows":1usize<<shape.index.log_rows, "public_len":shape.index.public_len, "blocks":shape.n_blocks,
        "block_log":shape.block_log, "connector_start":shape.connector_start, "q_offset":shape.q_offset, "stack_log":shape.stack_log,
        "official_score":false})
    );
    let mut current = Vec::new();
    for i in 0..1usize << depth {
        let start = primitives::hash::hash(&(i as u64 + 20261022).to_le_bytes());
        let (proof, creation) = plan.measure_quiet(|_| setup.prove_leaf(&start).unwrap());
        let (ok, verification) = plan.measure_quiet(|_| setup.verify(&proof));
        assert!(ok);
        println!(
            "{}",
            json!({"kind":"proof", "level":0, "index":i, "height":proof.height, "start":start,
            "statement":proof.statement, "creation_s":creation.mean(), "verification_s":verification.mean(),
            "certificate_bytes":proof.encode().unwrap().len(), "stream_scalars":proof.proof.stream.len(),
            "merkle_phases":proof.proof.merkle.len(), "verified":ok})
        );
        current.push(proof);
    }
    for level in 1..=depth {
        let mut next = Vec::new();
        for (i, pair) in current.chunks(2).enumerate() {
            assert_eq!(pair.len(), 2);
            let (proof, creation) = plan.measure_quiet(|_| setup.prove_node(&pair[0], &pair[1]).unwrap());
            let (ok, verification) = plan.measure_quiet(|_| setup.verify(&proof));
            assert!(ok);
            println!(
                "{}",
                json!({"kind":"proof", "level":level, "index":i, "height":proof.height,
                "statement":proof.statement, "creation_s":creation.mean(), "verification_s":verification.mean(),
                "certificate_bytes":proof.encode().unwrap().len(), "stream_scalars":proof.proof.stream.len(),
                "merkle_phases":proof.proof.merkle.len(), "verified":ok})
            );
            next.push(proof);
        }
        current = next;
    }
    assert_eq!(current.len(), 1);
    let mut wrong = current[0].clone();
    wrong.statement[0] ^= 1;
    assert!(!setup.verify(&wrong));
    wrong = current[0].clone();
    wrong.height += 1;
    assert!(!setup.verify(&wrong));
    println!(
        "{}",
        json!({"kind":"complete", "chain":chain, "depth":depth, "root":current[0].statement,
        "key":setup.key(), "height":current[0].height, "status":"locally_verified"})
    );
}
