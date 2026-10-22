mod support;

use circuit_suite::read_statement;
use format_recursion::{Child, record};
use std::time::Instant;
use support::child;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    parallel::init();
    let args: Vec<String> = std::env::args().collect();
    let row_limit = args
        .iter()
        .position(|s| s == "--row-limit")
        .map_or(1 << 23, |i| args[i + 1].parse().unwrap());
    let t = Instant::now();
    let mut child = child(20261022);
    let reference = record(&child);
    assert!(reference.satisfied(), "complete verifier trace rejects honest proof");
    let other = record(&self::child(20261023));
    assert!(other.satisfied());
    assert!(reference.same_program(&other), "proof contents changed the circuit");
    let mut negatives = 0;
    let mut check = |child: &Child| {
        let bad = record(child);
        assert!(reference.same_program(&bad), "proof-dependent circuit shape");
        assert!(!bad.satisfied(), "accepted tampered child");
        negatives += 1;
    };
    child.statement.y[0] ^= 1;
    check(&child);
    child.statement.y[0] ^= 1;
    for i in 0..2 {
        child.piop.stream[i].c2 ^= 1;
        check(&child);
        child.piop.stream[i].c2 ^= 1;
    }
    for i in [0usize, 4, 8] {
        child.piop.stream[i].c0 ^= 1;
        check(&child);
        child.piop.stream[i].c0 ^= 1;
    }
    for opening in 0..3 {
        let last = child.openings[opening].stream.len() - 1;
        for at in [0, last] {
            child.openings[opening].stream[at].c0 ^= 1;
            check(&child);
            child.openings[opening].stream[at].c0 ^= 1;
        }
        child.openings[opening].merkle[0].leaf_data[0].0 ^= 1;
        check(&child);
        child.openings[opening].merkle[0].leaf_data[0].0 ^= 1;
        child.openings[opening].merkle[0].path[0][0] ^= 1;
        check(&child);
        child.openings[opening].merkle[0].path[0][0] ^= 1;
    }
    println!(
        "{}",
        serde_json::json!({"kind":"trace","child_log_rows":child.log_rows,"nodes":reference.nodes.len(),"checks":reference.checks.len(),"hash_compressions":reference.hash_compressions(),"negative_cases":negatives,"fresh_proof_same_circuit":true,"operations":reference.operation_counts(),"sections":reference.sections,"elapsed_ms":t.elapsed().as_millis()})
    );
    if args.iter().any(|x| x == "--trace-only") {
        return;
    }
    let t = Instant::now();
    match reference.lower(row_limit) {
        Err((node, rows)) => {
            let section = reference
                .sections
                .iter()
                .rev()
                .find(|(_, start)| *start <= node)
                .map(|(name, _)| name.as_str());
            println!(
                "{}",
                serde_json::json!({"kind":"capacity","status":"row_limit_exceeded","outer_proof_produced":false,"row_limit":row_limit,"rows_so_far":rows,"nodes_lowered":node,"total_nodes":reference.nodes.len(),"section":section,"elapsed_ms":t.elapsed().as_millis()})
            );
        }
        Ok(lowered) => {
            lowered.circuit.check_wired().unwrap();
            let values = lowered.circuit.values(&lowered.inputs);
            let statement = read_statement(&values, &lowered.sources);
            assert_eq!(statement[32], 1, "Boolean verifier rejected an honest child");
            assert_eq!(&statement[33..], &[0u8; 31]);
            println!(
                "{}",
                serde_json::json!({"kind":"circuit","rows_used":lowered.rows,"log_rows":lowered.circuit.log_rows,"inputs":lowered.inputs.len(),"statement":statement.to_vec(),"elapsed_ms":t.elapsed().as_millis()})
            );
        }
    }
}
