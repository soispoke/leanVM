mod support;

use fiat_shamir::merkle::hash_to_scalars;
use format_recursion::{record, replay, trace::Op};
use primitives::field::F192;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn public(child: &format_recursion::Child) -> [F192; 2] {
    let bytes: Vec<u8> = child
        .statement
        .halves()
        .iter()
        .flat_map(|x| [x.c0.to_le_bytes(), x.c1.to_le_bytes()].concat())
        .collect();
    hash_to_scalars(&primitives::protocol_hash::hash(&bytes))
}

fn main() {
    parallel::init();
    let args: Vec<String> = std::env::args().collect();
    let repeat = args
        .iter()
        .position(|x| x == "--repeat")
        .map_or(1usize, |i| args[i + 1].parse().unwrap());
    assert!((1..=9).contains(&repeat));
    let row_limit = args
        .iter()
        .position(|x| x == "--row-limit")
        .map_or(1usize << 23, |i| args[i + 1].parse().unwrap());
    let child = support::child(20261022);
    let reference = record(&child);
    assert!(reference.satisfied());
    for sample in 0..repeat {
        let fresh = support::child(20261023 + sample as u64);
        let actual = record(&fresh);
        assert!(reference.same_program(&actual));
        let expected = public(&fresh);
        let values: Vec<_> = actual.nodes.iter().map(|n| n.value).collect();
        let requests = replay::requests(&reference, &values, &expected).unwrap();
        assert_eq!(requests.len(), reference.operation_counts()["blake2s_call"]);
        let start = Instant::now();
        let proof = replay::prove(&reference, values, &expected).unwrap();
        let prove_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        assert!(replay::verify(&reference, &expected, &proof));
        let verify_ms = start.elapsed().as_secs_f64() * 1000.;
        let mut negative_cases = 0;
        let mut reject = |bad: &replay::Certificate, public: &[F192]| {
            assert!(!replay::verify(&reference, public, bad));
            negative_cases += 1;
        };
        let mut public = expected;
        public[0].c0 ^= 1;
        reject(&proof, &public);
        let mut bad = proof.clone();
        bad.values[0].c0 ^= 1;
        reject(&bad, &expected);
        for name in [
            "field_multiply",
            "field_add",
            "bit_slice",
            "bit_pack",
            "select",
            "frobenius",
            "constant",
        ] {
            let at = reference
                .nodes
                .iter()
                .position(|n| match (name, &n.op) {
                    ("field_multiply", Op::Mul(a, b)) => a != b,
                    ("field_add", Op::Add(..))
                    | ("bit_slice", Op::Slice(..))
                    | ("bit_pack", Op::Pack(..))
                    | ("select", Op::Select(..))
                    | ("frobenius", Op::Frobenius(..))
                    | ("constant", Op::Constant) => true,
                    _ => false,
                })
                .unwrap();
            bad = proof.clone();
            bad.values[at].c0 ^= 1;
            reject(&bad, &expected);
        }
        let at = reference
            .nodes
            .iter()
            .position(|n| matches!(n.op, Op::Hash(_)))
            .unwrap();
        bad = proof.clone();
        bad.values[at].c2 = 1;
        reject(&bad, &expected);
        bad = proof.clone();
        bad.values.pop();
        reject(&bad, &expected);
        bad = proof.clone();
        bad.hashes.intermediates[0][0] ^= 1;
        reject(&bad, &expected);
        bad = proof.clone();
        bad.hashes.proof.stream[0].c0 ^= 1;
        reject(&bad, &expected);
        bad = proof.clone();
        bad.hashes.proof.stream.push(F192::ONE);
        reject(&bad, &expected);
        // Change an unmasked raw input to a hash. Arithmetic replay still accepts
        // this mutation; the coupled hash proof must reject it.
        let mut nonhash_use = vec![false; reference.nodes.len()];
        for node in &reference.nodes {
            let deps: Vec<_> = match &node.op {
                Op::Add(a, b) | Op::Mul(a, b) => vec![*a, *b],
                Op::Frobenius(a) | Op::Slice(a, ..) | Op::HashHigh(a) => vec![*a],
                Op::Select(bit, a, b) => vec![*bit, *a, *b],
                Op::Pack(parts) => parts.iter().map(|(s, _)| *s).collect(),
                _ => Vec::new(),
            };
            for dependency in deps {
                nonhash_use[dependency.0] = true;
            }
        }
        for &(a, b) in &reference.checks {
            nonhash_use[a.0] = true;
            nonhash_use[b.0] = true;
        }
        for s in &reference.public {
            nonhash_use[s.0] = true;
        }
        let at = reference
            .nodes
            .iter()
            .find_map(|node| match &node.op {
                Op::Hash(parts) => parts.iter().find_map(|&(s, len)| {
                    (len > 0 && !nonhash_use[s.0] && matches!(reference.nodes[s.0].op, Op::Input)).then_some(s.0)
                }),
                _ => None,
            })
            .expect("need a raw input whose only consumer is a hash");
        bad = proof.clone();
        bad.values[at].c0 ^= 1;
        assert!(replay::requests(&reference, &bad.values, &expected).is_some());
        reject(&bad, &expected);
        let forged_hash_test = true;
        let encoded_hash_proof_bytes =
            bincode::serialized_size(&proof.hashes.proof).unwrap() + (proof.hashes.intermediates.len() * 32) as u64;
        println!(
            "{}",
            serde_json::json!({
                "kind":"batched_hash_replay", "sample":sample, "status":"verified",
                "child_log_rows":fresh.log_rows, "hash_calls":requests.len(),
                "compressions":actual.hash_compressions(), "trace_values":proof.values.len(),
                "transparent_values_bytes":proof.values.len()*24, "hash_certificate_bytes":encoded_hash_proof_bytes,
                "prove_ms":prove_ms,"verify_ms":verify_ms,"negative_cases":negative_cases,
                "forged_hash_rejected_by_batch":forged_hash_test,"fresh_proof_same_program":true,
                "arithmetic_mode":"transparent_native_replay", "outer_recursive_snark_produced":false
            })
        );
    }
    // Even this optimistic diagnostic omits the circuit-to-coprocessor binding cost.
    let start = Instant::now();
    match reference.lower_hash_advice_diagnostic(row_limit) {
        Err((node, rows)) => {
            let section = reference
                .sections
                .iter()
                .rev()
                .find(|(_, s)| *s <= node)
                .map(|(name, _)| name);
            println!(
                "{}",
                serde_json::json!({"kind":"arithmetic_capacity", "status":"row_limit_exceeded",
                "hash_constraints_omitted":true,"binding_constraints_omitted":true,"row_limit":row_limit,
                "nodes_lowered":node,"rows_so_far":rows,"section":section,
                "outer_recursive_snark_produced":false,"elapsed_ms":start.elapsed().as_millis()})
            );
        }
        Ok((rows, log_rows)) => println!(
            "{}",
            serde_json::json!({"kind":"arithmetic_capacity",
            "status":"optimistic_circuit_fits","hash_constraints_omitted":true,"binding_constraints_omitted":true,
            "rows":rows,"log_rows":log_rows,"outer_recursive_snark_produced":false})
        ),
    }
}
