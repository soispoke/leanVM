//! Standalone opening regression harness.
#[allow(dead_code)]
#[path = "comparison_support/standalone_opening.rs"]
mod adapter;
fn main() {
    adapter::run();
}
