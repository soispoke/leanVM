use circuit_suite::{Ckt, PUBLIC_ROWS, falcon};
use format_recursion::{boolean_application, native_hash::Builder};
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn main() {
    parallel::init();
    let mut c = Ckt::new();
    c.enable_native_keccak();
    let (public, handles) = falcon::build_falcon(&mut c, &falcon::Params::falcon512());
    let used = c.rows();
    let mut boundaries = vec![("start", PUBLIC_ROWS)];
    let mut cursor = PUBLIC_ROWS;
    for &(name, count) in &handles.rows {
        if name.starts_with("s1 =") {
            continue;
        }
        cursor += count;
        boundaries.push((name, cursor));
    }
    assert_eq!(cursor, used);
    let (circuit, sources, calls) = c.finish_native_keccak(&public);
    boundaries.push(("public output and padding", circuit.rows().len()));
    let mut b = Builder::default();
    // Values do not influence dependency trimming or emitted row counts.
    let inputs: Vec<_> = (0..circuit.n_inputs() - 1600 * calls.len())
        .map(|_| b.input(0))
        .collect();
    let mut next = 0;
    let mut previous = 0;
    boolean_application::lower_with_keccak_observe(&mut b, &circuit, &sources, &inputs, &calls, |row, native| {
        while next < boundaries.len() && boundaries[next].1 == row {
            println!(
                "{}",
                serde_json::json!({"part":boundaries[next].0,"boolean_boundary":row,"native_rows":native-previous,"native_boundary":native})
            );
            previous = native;
            next += 1;
        }
    });
    assert_eq!(next, boundaries.len());
    println!(
        "{}",
        serde_json::json!({"total_native_lowering_rows":b.rows(),"permutations":calls.len(),"inputs":inputs.len()})
    );
}
