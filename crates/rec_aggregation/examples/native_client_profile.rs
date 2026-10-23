//! One native client proof, with fixed inputs and existing prover tracing spans.
use bench::{Jemalloc, Plan};
use format_recursion::{
    private_recursion::{self, Setup},
    recursion_fast,
};
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

fn main() {
    bench::init_tracing_from_env();
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let number = |flag: &str, default: usize| {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map_or(default, |pair| pair[1].parse().expect("integer argument"))
    };
    let chain = number("--chain", 16384);
    let seed = number("--seed", 20261024) as u64;
    let start = primitives::hash::hash(&seed.to_le_bytes());
    let setup_start = Instant::now();
    let canonical = private_recursion::leaf(&[0; 32], chain).expect("bounded chain");
    let setup = Setup::new(canonical).expect("native client setup");
    println!(
        "{}",
        serde_json::json!({"kind":"client_profile_setup", "chain":chain,
        "seed":seed,"setup_ms":setup_start.elapsed().as_secs_f64()*1000.,
        "shape":format!("{:?}",setup.bridge.verifier_shape()),"index_shape":setup.bridge.index.shape(),
        "key":setup.bridge.index.root,"tracing":std::env::var_os("BENCH_TRACING").is_some()})
    );
    let preparation = Instant::now();
    let witness =
        tracing::info_span!("Record client witness").in_scope(|| private_recursion::leaf(&start, chain).unwrap());
    let preparation_ms = preparation.elapsed().as_secs_f64() * 1000.;
    let expected = recursion_fast::expected_leaf(&start, chain as u64).unwrap();
    let public = fiat_shamir::merkle::hash_to_scalars(&expected);
    assert_eq!(private_recursion::outputs(&witness), public);
    let plan = Plan::new(1, 0);
    let (proof, proving) = plan.measure_quiet(|_| setup.prove(&witness, &public).unwrap());
    let (verified, verification) = plan.measure_quiet(|_| setup.verify(&public, &proof));
    assert!(verified);
    let encoded = private_recursion::encode(&proof).unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"client_profile", "chain":chain,"seed":seed,
        "witness_trace_ms":preparation_ms,"application_proof_ms":proving.mean()*1000.,
        "verify_ms":verification.mean()*1000.,"proof_bytes":encoded.len(),
        "proof_digest":primitives::hash::hash(&encoded),"statement":expected,
        "trace_nodes":witness.nodes.len(),"hash_compressions":witness.hash_compressions(),
        "peak_rss_bytes":bench::peak_rss_bytes(),"verified":true,
        "scope":"one native client proof; no recursive node or adaptation proof; no repeated samples"})
    );
}
