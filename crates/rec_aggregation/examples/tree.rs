//! A two-level tree of matched aggregates: `--leaves` leaf aggregates of `--per-leaf`
//! applications each, and one root that verifies them in-circuit (`aggregation::tree`).
#[allow(dead_code)]
#[path = "comparison_support/mod.rs"]
mod shared;
use flock::membership::DEPTH;
use leanvm_core::cpu;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rec_aggregation::aggregation::tree;
use shared::{apps::*, *};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = interface(&args);
    let leaves: usize = arg(&args, "--leaves").parse().unwrap();
    let per_leaf: usize = arg(&args, "--per-leaf").parse().unwrap();
    let mut rng = StdRng::seed_from_u64(
        args.iter()
            .position(|a| a == "--seed")
            .map_or(4242, |i| args[i + 1].parse().unwrap()),
    );
    let s = setup();
    let layouts = layouts();
    let clients: Vec<Client> = (0..leaves * per_leaf)
        .map(|_| {
            let mut bytes = || {
                let mut b = [0; 32];
                rng.fill_bytes(&mut b);
                b
            };
            let w = Witness {
                x: bytes(),
                siblings: (0..DEPTH).map(|_| bytes()).collect(),
                directions: rng.next_u32(),
            };
            prove_client(&s, mode.1, &w, &mut rng).0
        })
        .collect();
    let admitted: Vec<_> = clients
        .iter()
        .map(|c| admit(&s, &layouts, mode.1, c).expect("admissible client proof"))
        .collect();

    // Every leaf has the same shape, so one compiled program serves them all.
    let leaf = program(&s, mode, &admitted[..per_leaf]);
    let mut leaf_proofs = Vec::new();
    let mut leaf_runs = Vec::new();
    for (cs, ads) in clients.chunks(per_leaf).zip(admitted.chunks(per_leaf)) {
        let mut p = leaf.clone();
        for (c, (opened, raws)) in cs.iter().zip(ads) {
            let mut q = leaf.clone();
            install_witness(&mut q, opened, raws, &statement(c), &c.piop);
            p.append_witness_from(&q);
        }
        let pi = public(&s, mode.0, cs, ads);
        let t = Instant::now();
        let (proof, stats) = cpu::prove(&p, pi, LOG_INV_RATE).expect("leaf aggregate");
        leaf_runs.push(serde_json::json!({"prove_us": elapsed(t), "base_cycles": stats.base_counts.iter().sum::<usize>(), "committed": stats.committed}));
        leaf_proofs.push((pi, proof));
    }

    let t = Instant::now();
    let root_program = tree::root_guest(&leaf, leaves);
    let compile_us = elapsed(t);
    let t = Instant::now();
    let (root, stats) = tree::prove_root(&leaf, &root_program, &leaf_proofs, LOG_INV_RATE).expect("root aggregate");
    let root_prove_us = elapsed(t);
    let publics: Vec<_> = leaf_proofs.iter().map(|(pi, _)| *pi).collect();
    let t = Instant::now();
    tree::verify_root(&leaf, &root_program, &publics, &root).expect("root verification");
    let verify_us = elapsed(t);

    // The root must speak about exactly these leaves, in this order, of this program.
    let mut rejected = 0;
    let mut reject = |ok: bool, what: &str| {
        assert!(!ok, "accepted {what}");
        rejected += 1;
    };
    if leaves > 1 {
        let mut swapped = publics.clone();
        swapped.swap(0, 1);
        reject(
            tree::verify_root(&leaf, &root_program, &swapped, &root).is_ok(),
            "reordered leaves",
        );
    }
    let mut changed = publics.clone();
    changed[0][0] += primitives::field::F192::ONE;
    reject(
        tree::verify_root(&leaf, &root_program, &changed, &root).is_ok(),
        "a changed leaf",
    );
    reject(
        tree::verify_root(&leaf, &root_program, &publics[1..], &root).is_ok(),
        "a dropped leaf",
    );
    reject(
        tree::verify_root(&leaf, &root_program, &publics, &root.with_moved_claim()).is_ok(),
        "a moved deferred claim",
    );
    let other_mode = (!mode.0, flock::quotient::Oracle::Keccak);
    let other = program(&s, other_mode, &admitted[..per_leaf]);
    reject(
        tree::verify_root(&other, &tree::root_guest(&other, leaves), &publics, &root).is_ok(),
        "another leaf program",
    );
    let mut forged = leaf_proofs.clone();
    forged[0].0[1] += primitives::field::F192::ONE;
    reject(
        tree::prove_root(&leaf, &root_program, &forged, LOG_INV_RATE).is_ok(),
        "a leaf proof for another statement",
    );

    println!(
        "{}",
        serde_json::json!({"kind": "tree", "interface": arg(&args, "--interface"), "leaves": leaves, "per_leaf": per_leaf,
            "leaf_code_len": leaf.code_len(), "leaf_runs": leaf_runs, "root_code_len": root_program.code_len(), "root_compile_us": compile_us,
            "root_prove_us": root_prove_us, "root_base_cycles": stats.base_counts.iter().sum::<usize>(), "root_committed": stats.committed,
            "root_stats": stats.details(), "root_proof_bytes": bincode::serialize(&root.proof).unwrap().len(), "verify_us": verify_us,
            "negative_cases": rejected})
    );
}
