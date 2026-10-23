#[path = "../../format_recursion/examples/application_support/mod.rs"]
#[allow(dead_code)]
mod application_support;
#[path = "../../format_recursion/examples/native_application_support/mod.rs"]
#[allow(dead_code)]
mod native_application_support;
use format_recursion::closed_recursion::{Certificate, FirstMergeSetup};
use std::time::Instant;
#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;
fn main() {
    parallel::init();
    let application = native_application_support::Application::<circuit_suite::blake2s::Blake2s64>::new();
    let setup = FirstMergeSetup::new(application.create(20261023).trace).unwrap();
    let path = std::env::args().nth(1).unwrap();
    let read = |name: &str| Certificate::decode(&std::fs::read(format!("{path}/{name}")).unwrap()).unwrap();
    let left = read("app-0-0.cert");
    let right = read("app-0-1.cert");
    let start = Instant::now();
    let cert = setup.prove(&left, &right).unwrap();
    let seconds = start.elapsed().as_secs_f64();
    assert!(setup.verify(&cert));
    assert!(setup.prove(&cert, &right).is_none());
    assert!(!setup.verify(&left));
    let mut tampered = cert.clone();
    tampered.statement[0] ^= 1;
    assert!(!setup.verify(&tampered));
    let mut wrong = left.clone();
    wrong.statement[0] ^= 1;
    assert!(setup.prove(&wrong, &right).is_none());
    println!(
        "{}",
        serde_json::json!({"seconds":seconds,"rows":setup.arithmetic_rows,"compressions":setup.compressions,"products":setup.products,"shape":format!("{:?}",setup.shape()),"bytes":cert.encode().unwrap().len(),"rejections":"passed"})
    );
}
