//! Integer component census, not a complete Falcon application proof.
use format_recursion::{
    falcon_word::{self, Signed},
    word_lowering::Lowering,
};
fn main() {
    parallel::init();
    let fixture = &circuit_suite::falcon::fixtures()[0];
    let p = circuit_suite::falcon::Params::falcon512();
    let s1 = circuit_suite::falcon::native::s1(&p, &fixture.h, &fixture.msg, &fixture.nonce, &fixture.s2);
    let (challenge, _) = circuit_suite::falcon::native::hash_to_point(&fixture.nonce, &fixture.msg, 512, 12289);
    let mut c = Lowering::default();
    let h: Vec<_> = fixture
        .h
        .iter()
        .map(|&v| {
            let w = c.b.input(v);
            c.unpack(w, 2)
        })
        .collect();
    let challenge: Vec<_> = challenge
        .iter()
        .map(|&v| {
            let w = c.b.input(v);
            c.unpack(w, 2)
        })
        .collect();
    let mut signed = |values: &[i64]| {
        values
            .iter()
            .map(|&v| {
                let w = c.b.input(v.unsigned_abs());
                let magnitude = c.unpack(w, 2);
                let sign = c.b.input(u64::from(v < 0));
                Signed { magnitude, sign }
            })
            .collect::<Vec<_>>()
    };
    let s1 = signed(&s1);
    let s2 = signed(&fixture.s2);
    for stage in falcon_word::relation(&mut c, &h, &s1, &s2, &challenge) {
        println!(
            "{}",
            serde_json::json!({"part":stage.name,"rows":stage.rows,"queries":stage.queries})
        );
    }
    assert!(c.b.satisfied());
    println!(
        "{}",
        serde_json::json!({"total_integer_rows":c.b.rows(),"total_queries":c.query_count(),"full_application":false,"arithmetic_witness_satisfied":true})
    );
}
