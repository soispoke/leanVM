fn main() {
    parallel::init();
    println!("{:?}", format_recursion::closed_recursion::tree_only_census().unwrap());
}
