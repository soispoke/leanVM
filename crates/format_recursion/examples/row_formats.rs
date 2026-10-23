use format_recursion::row_format::{self, R1cs};
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let source = row_format::source(case);
    for max_terms in [0, 8, 16, 32, 64, 128] {
        let r = R1cs::lower_bounded(
            &source.circuit,
            &source.connectors,
            &source.values,
            source.fixed_len,
            max_terms,
        );
        assert!(r.satisfied(&r.witness(&source.values)));
        println!(
            "{}",
            serde_json::json!({"circuit":case,"max_terms":max_terms,"census":r.census()})
        );
    }
}
