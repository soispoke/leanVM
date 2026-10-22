fn main() {
    parallel::init();
    let chain = std::env::args().nth(1).map_or(2, |s| s.parse().unwrap());
    assert!(format_recursion::closed_recursion::shape_iterations(chain, 24).is_some());
}
