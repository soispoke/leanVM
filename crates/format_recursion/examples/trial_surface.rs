//! Read-only frozen setup census; never a proving or verification boundary.
use bincode::Options;
use format_recursion::row_format::{generator::Generator, spartan::Setup};
use serde::de::DeserializeOwned;
fn load<T: DeserializeOwned>(path: &str) -> T {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&std::fs::read(path).unwrap())
        .unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let s: Setup = if args[1] == "aggregate" {
        load(&args[2])
    } else {
        let (s, _): (Setup, Generator) = load(&args[2]);
        s
    };
    let config = pcs::whir::config_for_rate(s.stack_log, 2).unwrap();
    println!(
        "{}",
        serde_json::json!({"joint_whir":{"target_bits":pcs::whir::SECURITY_BITS,"log_inverse_rates":config.log_inv_rates,"queries":config.queries,"query_grinding_bits":config.grinding_bits,"ood_samples":config.ood_samples,"level_ks":config.level_ks},"census":s.r1cs.census(),"row_log":s.row_log,"col_log":s.z_log,"stack_log":s.stack_log,"q_offset":s.q_offset,"committed_words":s.committed_words,"key":s.key})
    );
}
