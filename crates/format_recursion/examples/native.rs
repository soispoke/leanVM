mod support;
use format_recursion::{native_recursion, public_plan, record, replay};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
use primitives::field::F192;
fn main() {
    parallel::init();
    let child = support::child(20261022);
    let trace = record(&child);
    let vals: Vec<_> = trace.nodes.iter().map(|n| n.value).collect();
    let public: Vec<F192> = trace.public.iter().map(|s| vals[s.0]).collect();
    let requests = replay::requests(&trace, &vals, &public).unwrap();
    let known = public_plan::values(&trace, &requests).expect("public projections");
    for (i, value) in known.iter().enumerate() {
        if let Some(v) = value {
            assert_eq!(*v, vals[i], "node {i}");
        }
    }
    public_plan::check_projections(&trace, &known).expect("projected inputs isolated");
    println!(
        "{}",
        serde_json::json!({"kind":"public_plan","known_nodes":known.iter().filter(|v|v.is_some()).count(),"nodes":known.len(),"requests":requests.len()})
    );
    let start = Instant::now();
    let setup = native_recursion::Setup::new(trace, &requests).unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"native_setup","elapsed_ms":start.elapsed().as_millis(),"log_rows":setup.index.log_rows,"shape":setup.index.shape()})
    );
    let fresh = record(&support::child(20261023));
    let public: Vec<_> = fresh.public.iter().map(|s| fresh.nodes[s.0].value).collect();
    let start = Instant::now();
    let proof = setup.prove(&fresh, &public).unwrap();
    let prove_ms = start.elapsed().as_millis();
    let start = Instant::now();
    assert!(setup.verify(&public, &proof));
    println!(
        "{}",
        serde_json::json!({"kind":"native_recursion","status":"verified","prove_ms":prove_ms,"verify_ms":start.elapsed().as_millis(),"arithmetic_proof_bytes":bincode::serialized_size(&proof.arithmetic).unwrap(),"hash_proof_and_chaining_advice_bytes":bincode::serialized_size(&proof.hashes).unwrap(),"total_certificate_bytes":bincode::serialized_size(&proof).unwrap(),"public_hash_request_bytes":proof.requests.iter().map(|r|r.message.len()+32).sum::<usize>(),"trace_values_disclosed":false})
    );
}
