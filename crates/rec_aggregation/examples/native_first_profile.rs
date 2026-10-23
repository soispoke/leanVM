use format_recursion::{native_hash::Builder,closed_recursion::{Certificate,record_native_first},private_recursion::Setup,private_trace};
use primitives::field::F192;
use std::time::Instant;
#[global_allocator]
static ALLOC: bench::Jemalloc = bench::Jemalloc;
fn application() -> Builder {
    let mut b=Builder::default();
    let message:Vec<_>=(0..8).map(|i|b.constant(u64::from_le_bytes(std::array::from_fn(|j|((i*8+j)%251) as u8)))).collect();
    let h=b.hash_words(&message);
    let length=b.constant(64);
    let mut statement=vec![length]; statement.extend(h);
    let output=b.hash_words(&statement);
    for w in output { b.expose(w); }
    b
}
fn main(){
    parallel::init(); assert_eq!(parallel::num_threads(),12);
    let base=application();let bridge=base.setup().unwrap();let public=base.public_values();
    let ctx=primitives::hash::hash(b"hometurf-native-hash-application-v1");
    let bytes:Vec<_>=public[public.len()-4..].iter().flat_map(|w|w.c0.to_le_bytes()).collect();
    let statement=bytes.try_into().unwrap();
    let proof=bridge.prove(&base.values,&base.compressions,&ctx).unwrap();
    assert!(bridge.verify(&public,&ctx,&proof));
    let cert=Certificate{height:0,statement,proof};
    let prefix=&public[..public.len()-4];
    let trace=record_native_first(&bridge,prefix,&ctx,[&cert,&cert]);
    assert!(trace.satisfied());
    let lower=private_trace::lower(&trace,&trace).unwrap();
    let rows=lower.circuit.rows.len();let compressions=lower.compressions.len();drop(lower);
    let setup=Setup::new(trace).unwrap();
    let expected=fiat_shamir::merkle::hash_to_scalars(&format_recursion::recursion_fast::node_statement(&statement,&statement));
    for label in ["A1","A2"] {
        let start=Instant::now();
        assert!(bridge.verify(&public,&ctx,&cert.proof));assert!(bridge.verify(&public,&ctx,&cert.proof));
        let trace=record_native_first(&bridge,prefix,&ctx,[&cert,&cert]);
        let proof=setup.prove(&trace,&expected).unwrap();let seconds=start.elapsed().as_secs_f64();
        assert!(setup.verify(&expected,&proof));
        let shape=setup.bridge.verifier_shape();
        println!("{}",serde_json::json!({"label":label,"seconds":seconds,"rows":rows,"compressions":compressions,"shape":format!("{shape:?}"),"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"bytes":bincode::serialize(&proof).unwrap().len()}));
    }
    let mut bad=cert.clone();bad.statement[0]^=1;
    let invalid=record_native_first(&bridge,prefix,&ctx,[&bad,&cert]);assert!(!invalid.satisfied());
    let out=fiat_shamir::merkle::hash_to_scalars(&format_recursion::recursion_fast::node_statement(&bad.statement,&statement));
    if let Some(p)=setup.prove(&invalid,&out){assert!(!setup.verify(&out,&p));}
    let _=F192::ZERO;
}
