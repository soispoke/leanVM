//! Component census only: this is not a Falcon verification proof.
use format_recursion::word_lowering::Lowering;
fn main() {
    parallel::init();
    let fixture = &circuit_suite::falcon::fixtures()[0];
    let roots = circuit_suite::falcon::zetas(12289, 9);
    let mut c = Lowering::default();
    let input: Vec<_> = fixture
        .h
        .iter()
        .map(|&v| {
            let w = c.b.input(v);
            c.unpack(w, 2)
        })
        .collect();
    let before = c.b.rows();
    let queries_before = c.query_count();
    let output = c.ntt(input, &roots, 12289);
    let rows = c.b.rows() - before;
    let queries = c.query_count() - queries_before;
    let psi = roots[256];
    for (i, bytes) in output.iter().enumerate() {
        let br = i.reverse_bits() >> (usize::BITS - 9);
        let point = circuit_suite::falcon::powmod(psi, (2 * br + 1) as u64, 12289);
        let expected = fixture.h.iter().rev().fold(0, |acc, &v| (acc * point + v) % 12289);
        let word = c.pack(bytes);
        assert_eq!(c.b.value(word).c0, expected);
    }
    assert!(c.b.satisfied());
    println!(
        "{}",
        serde_json::json!({"component":"NTT(h)","n":512,"native_rows":rows,"queries":queries,"total_rows_with_inputs_and_output_packing":c.b.rows(),"witness_values":c.b.values.len(),"all_512_outputs_match_direct_evaluation":true,"full_application":false})
    );
}
