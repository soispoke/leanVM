//! ONE-TIME setup metadata for quotient paths and whole-row liveness opportunities.
use circuit_suite::{Src, Workload};
use std::collections::BTreeMap;

fn run<W: Workload>() {
    let (circuit, sources, used) = circuit_suite::build::<W>();
    circuit.check_wired().expect("quotient wiring");
    let before = primitives::hash::hash(&circuit_suite::describe::encode(&circuit));
    let mut required = vec![[false; 2]; circuit.rows().len()];
    for source in sources {
        if let Src::Row(r) = source {
            required[r as usize][0] = true;
        }
    }
    for (r, row) in circuit.rows().iter().enumerate().skip(circuit_suite::PUBLIC_ROWS).rev() {
        if required[r].iter().any(|&needed| needed) {
            for (src, component) in [(row.x, 0), (row.y, 0), (row.c, 1)] {
                if let Src::Row(from) = src {
                    required[from as usize][component] = true;
                }
            }
        }
    }
    let mut kinds = BTreeMap::<&str, usize>::new();
    for (r, row) in circuit
        .rows()
        .iter()
        .enumerate()
        .take(used)
        .skip(circuit_suite::PUBLIC_ROWS)
    {
        let input = [row.x, row.y, row.c] == [Src::Row(r as u32), Src::Zero, Src::Zero];
        let kind = if input {
            "input_kept"
        } else {
            match required[r] {
                [false, false] => "whole_row_dead",
                [true, false] => "sum_only",
                [false, true] => "carry_only",
                [true, true] => "both_outputs",
            }
        };
        *kinds.entry(kind).or_default() += 1;
    }
    let dead = *kinds.get("whole_row_dead").unwrap_or(&0);
    let live = used - dead;
    let hypothetical_log = live
        .next_power_of_two()
        .trailing_zeros()
        .max(circuit_suite::MIN_LOG_ROWS as u32);
    assert_eq!(
        before,
        primitives::hash::hash(&circuit_suite::describe::encode(&circuit))
    );
    println!(
        "{}",
        serde_json::json!({"role":"ONE-TIME setup","workload":W::NAME,
        "quotient_used_rows":used,"quotient_log_rows_before":circuit.log_rows,
        "quotient_log_rows_after_native_trimming":circuit.log_rows,
        "quotient_padded_rows_before":1usize<<circuit.log_rows,
        "quotient_padded_rows_after_native_trimming":1usize<<circuit.log_rows,
        "quotient_rows_to_next_boundary":used.saturating_sub(1usize<<(circuit.log_rows-1)),
        "output_liveness_in_used_rows":kinds,"description_hash":before,
        "whole_row_dce_hypothetical_used_rows":live,"whole_row_dce_hypothetical_log_rows":hypothetical_log,
        "scope":"native output trimming changes no quotient row or wiring; whole-row DCE is analysis only",
        "cpus":"24-35","threads":12})
    );
}
fn main() {
    parallel::init();
    match std::env::args().nth(1).as_deref() {
        Some("blake64") => run::<circuit_suite::blake2s::Blake2s64>(),
        Some("blake1k") => run::<circuit_suite::blake2s::Blake2sOneKiB>(),
        Some("sha1k") => run::<circuit_suite::sha256::Sha256OneKiB>(),
        Some("keccak1k") => run::<circuit_suite::keccak::Keccak256OneKiB>(),
        Some("shielded") => run::<circuit_suite::shielded::ShieldedTransfer>(),
        Some("falcon") => run::<circuit_suite::falcon::Falcon512>(),
        Some("mpt") => run::<circuit_suite::mpt::MptStorageProof>(),
        _ => panic!("unknown workload"),
    }
}
