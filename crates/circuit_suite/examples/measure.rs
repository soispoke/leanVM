//! Build, check, describe, commit and (with `--prove`) prove and verify the suite's statements in the one
//! circuit format. One JSON line a statement.
//!
//! `measure [--prove] [--seed S] [--out DIR] NAME...`; the names are the workloads' `NAME`s, or `membership`.
use circuit_suite::{Circuit, Ckt, Instance, Src, Workload, blake2s, describe, read_statement};
use flock::membership::Statement;
use flock::quotient::{self, Index, Oracle, Table, opening};
use primitives::field::F64;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::time::Instant;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn us(t: Instant) -> u64 {
    t.elapsed().as_micros() as u64
}

fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Built {
    name: &'static str,
    circuit: Circuit,
    srcs: Vec<Src>,
    used: usize,
    conversions: [usize; 3],
    build_us: u64,
    valid: Option<Instance>,
    invalid: Option<Instance>,
}

fn build<W: Workload>(seed: u64) -> Built {
    let t = Instant::now();
    let mut c = Ckt::new();
    let public = W::build(&mut c);
    let (used, conversions) = (c.rows(), c.conversions);
    let (circuit, srcs) = c.finish(&public);
    Built {
        name: W::NAME,
        circuit,
        srcs,
        used,
        conversions,
        build_us: us(t),
        valid: Some(W::instance(seed)),
        invalid: W::invalid_instance(seed),
    }
}

fn membership(seed: u64) -> Built {
    use flock::membership::{DEPTH, Secret};
    let t = Instant::now();
    let circuit = quotient::circuit::membership();
    let build_us = us(t);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = || {
        let mut b = [0; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let secret = Secret {
        x: bytes(),
        siblings: std::array::from_fn(|_| bytes()),
        directions: (seed as u32).wrapping_mul(0x9E37_79B9) & (u32::MAX >> (32 - DEPTH)),
    };
    let st = secret.statement();
    let mut statement = [0u8; 64];
    statement[..32].copy_from_slice(&st.y);
    statement[32..].copy_from_slice(&st.root);
    let srcs = describe::public_sources(&circuit);
    let used = circuit.rows().len();
    Built {
        name: "membership",
        circuit,
        srcs,
        used,
        conversions: [0; 3],
        build_us,
        valid: Some(Instance {
            inputs: quotient::circuit::membership_inputs(&secret),
            statement,
        }),
        invalid: None,
    }
}

fn get(name: &str, seed: u64) -> Built {
    match name {
        "membership" => membership(seed),
        n if n == blake2s::Blake2sOneKiB::NAME => build::<blake2s::Blake2sOneKiB>(seed),
        n if n == circuit_suite::sha256::Sha256OneKiB::NAME => build::<circuit_suite::sha256::Sha256OneKiB>(seed),
        n if n == circuit_suite::shielded::ShieldedTransfer::NAME => build::<circuit_suite::shielded::ShieldedTransfer>(seed),
        n if n == blake2s::Blake2s64::NAME => build::<blake2s::Blake2s64>(seed),
        n if n == blake2s::Blake2s256::NAME => build::<blake2s::Blake2s256>(seed),
        n if n == blake2s::Blake2s4KiB::NAME => build::<blake2s::Blake2s4KiB>(seed),
        n if n == blake2s::Blake2s16KiB::NAME => build::<blake2s::Blake2s16KiB>(seed),
        other => panic!("unknown statement {other}"),
    }
}

fn statement_of(bytes: &[u8; 64]) -> Statement {
    Statement {
        y: bytes[..32].try_into().unwrap(),
        root: bytes[32..].try_into().unwrap(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let prove = args.iter().any(|a| a == "--prove");
    let flag = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    let seed: u64 = flag("--seed").map_or(1, |s| s.parse().unwrap());
    let out = flag("--out");
    let names: Vec<&String> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| {
            !a.starts_with("--") && (*i == 0 || !matches!(args[i - 1].as_str(), "--seed" | "--out" | "--dump"))
        })
        .map(|(_, a)| a)
        .collect();
    for name in names {
        let b = get(name, seed);
        let mut report = serde_json::json!({"statement": b.name, "rows_used": b.used, "log_rows": b.circuit.log_rows,
            "inputs": b.circuit.n_inputs(), "conversion_rows": b.conversions, "build_us": b.build_us});

        let t = Instant::now();
        b.circuit
            .check_wired()
            .expect("the circuit meets the Lean theorem's hypotheses");
        report["check_wired_us"] = us(t).into();

        // The statement the circuit computes is the reference's; an invalid instance's differs.
        let valid = b.valid.as_ref().unwrap();
        let t = Instant::now();
        let values = b.circuit.values(&valid.inputs);
        report["eval_us"] = us(t).into();
        assert_eq!(
            read_statement(&values, &b.srcs),
            valid.statement,
            "the reference statement"
        );
        if let Some(bad) = &b.invalid {
            let got = read_statement(&b.circuit.values(&bad.inputs), &b.srcs);
            assert_eq!(got, bad.statement, "the reference's invalid statement");
            assert_ne!(got, valid.statement);
            report["invalid_checked"] = true.into();
        }
        report["statement_hex"] = hex(&valid.statement).into();

        // The description, and the circuit, wiring table and root rebuilt from it alone.
        let t = Instant::now();
        let data = describe::encode(&b.circuit);
        report["describe_us"] = us(t).into();
        report["description_bytes"] = data.len().into();
        if let Some(dir) = &out {
            std::fs::write(format!("{dir}/{}.qcd", b.name), &data).unwrap();
            // An instance for the independent evaluator: the input bits packed low first, and the statement.
            let mut packed = vec![0u8; valid.inputs.len().div_ceil(8)];
            for (i, &bit) in valid.inputs.iter().enumerate() {
                packed[i / 8] |= (bit as u8) << (i % 8);
            }
            std::fs::write(format!("{dir}/{}.inputs", b.name), packed).unwrap();
            std::fs::write(format!("{dir}/{}.statement", b.name), valid.statement).unwrap();
        }
        let t = Instant::now();
        let index = Index::new(&b.circuit);
        let wiring = opening::commit(index.table());
        report["index_us"] = us(t).into();
        report["index_root"] = hex(&wiring.root).into();
        report["wiring_table_entries"] = (index.table().lanes.len()).into();
        let t = Instant::now();
        let (decoded, decoded_srcs) = describe::decode(&data).unwrap();
        let rebuilt = opening::commit(Index::new(&decoded).table()).root;
        report["rebuild_us"] = us(t).into();
        assert_eq!(rebuilt, wiring.root, "a description reproduces the root");
        assert_eq!(decoded_srcs, b.srcs);
        drop(decoded);

        if prove {
            let log_rows = b.circuit.log_rows;
            let st = statement_of(&valid.statement);
            let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
            let t = Instant::now();
            let cells = b.circuit.cells(&valid.inputs);
            let witness_us = us(t);
            let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
            let mut committed = Vec::new();
            let mut commit = |table: &Table| {
                let c = opening::commit(table);
                let root = c.root;
                committed.push(c);
                root
            };
            let t = Instant::now();
            let p = quotient::prove_with(
                Oracle::Keccak,
                &b.circuit,
                &index,
                &wiring.root,
                &st,
                &cells,
                &masks,
                &mut commit,
            );
            let piop_us = us(t);
            drop(cells);
            let t = Instant::now();
            let openings = [
                opening::open(&p.witness, &committed[0], std::slice::from_ref(&p.claims.witness)),
                opening::open(index.table(), &wiring, std::slice::from_ref(&p.claims.wiring)),
                opening::open(&p.quotient, &committed[1], &[p.claims.quotient, p.claims.sum]),
            ];
            let opening_us = us(t);
            let proof_bytes = bincode::serialize(&p.proof).unwrap().len()
                + openings
                    .iter()
                    .map(|o| bincode::serialize(o).unwrap().len())
                    .sum::<usize>();
            let committed_entries: usize = p.witness.lanes.len() + p.quotient.lanes.len();
            drop(p.witness);
            drop(p.quotient);

            let verify = |st: &Statement| -> bool {
                let Ok((roots, claims)) = quotient::verify_with(Oracle::Keccak, &wiring.root, st, &p.proof, log_rows)
                else {
                    return false;
                };
                let layouts = [quotient::witness_layout(log_rows), quotient::quotient_layout(log_rows)];
                opening::verify(
                    &layouts[0],
                    &roots[0],
                    std::slice::from_ref(&claims.witness),
                    &openings[0],
                ) && opening::verify(
                    &index.table().layout,
                    &wiring.root,
                    std::slice::from_ref(&claims.wiring),
                    &openings[1],
                ) && opening::verify(&layouts[1], &roots[1], &[claims.quotient, claims.sum], &openings[2])
            };
            let t = Instant::now();
            let ok = verify(&st);
            let verify_us = us(t);
            assert!(ok, "the honest proof verifies");
            // Every statement bit is bound: flip one in each half.
            let mut rejected = 0;
            for bit in [0usize, 300, 511] {
                let mut other = valid.statement;
                other[bit / 8] ^= 1 << (bit % 8);
                assert!(!verify(&statement_of(&other)), "accepted a flipped statement bit {bit}");
                rejected += 1;
            }
            // The same proof checked by the format's verifier as an EVM contract for this circuit: the claims it
            // returns are the Rust verifier's, and its gas is one application's execution under the PCS interface.
            let contract = evm::quotient::contract(&wiring.root, log_rows);
            let outcome = evm::machine::call(&contract.code, &evm::quotient::calldata(&st, &p.proof));
            let (evm_roots, evm_claims) =
                evm::quotient::decode(&outcome.output.expect("the contract accepts"), log_rows).expect("its claims");
            let (roots, claims) = quotient::verify_with(Oracle::Keccak, &wiring.root, &st, &p.proof, log_rows).unwrap();
            assert_eq!(
                (evm_roots, &evm_claims),
                (roots, &claims),
                "the contract's claims are the verifier's"
            );
            let mut other = st;
            other.y[0] ^= 1;
            let rejected_by_evm = evm::machine::call(&contract.code, &evm::quotient::calldata(&other, &p.proof))
                .output
                .is_none_or(|o| evm::quotient::decode(&o, log_rows) != Some((roots, claims.clone())));
            assert!(rejected_by_evm);
            report["evm"] = serde_json::json!({"code_bytes": contract.code.len(), "execution_gas": outcome.execution,
                "field_muls": contract.field_muls, "hashes": contract.hashes});
            report["prove"] = serde_json::json!({"witness_us": witness_us, "piop_us": piop_us, "opening_us": opening_us,
                "prove_us": witness_us + piop_us + opening_us, "verify_us": verify_us, "proof_bytes": proof_bytes,
                "committed_entries_f64": committed_entries, "negative_cases": rejected, "threads": parallel::num_threads()});
        }
        if let Some(dir) = flag("--dump") {
            // The PIOP alone with the VM's BLAKE2s oracle, for the independent verifier
            // (`experiments/pcs-r1cs/format/spec`): its proof stream, statement, root and the claims Rust derives.
            let st = statement_of(&valid.statement);
            let cells = b.circuit.cells(&valid.inputs);
            let mut rng = StdRng::seed_from_u64(seed ^ 0xd0);
            let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
            let p = quotient::prove_with(
                Oracle::Blake2s,
                &b.circuit,
                &index,
                &wiring.root,
                &st,
                &cells,
                &masks,
                &mut |t: &Table| opening::commit(t).root,
            );
            assert!(p.proof.merkle.is_empty());
            let bytes: Vec<u8> = p
                .proof
                .stream
                .iter()
                .flat_map(|x| [x.c0, x.c1, x.c2].into_iter().flat_map(u64::to_le_bytes))
                .collect();
            std::fs::write(format!("{dir}/{}.stream", b.name), bytes).unwrap();
            let (roots, claims) =
                quotient::verify_with(Oracle::Blake2s, &wiring.root, &st, &p.proof, b.circuit.log_rows).unwrap();
            let e = |x: &primitives::field::F192| [x.c0, x.c1, x.c2];
            let claim = |c: &flock::standalone::Claim| serde_json::json!({"point": c.point.iter().map(e).collect::<Vec<_>>(), "value": e(&c.value)});
            let dump = serde_json::json!({"statement": hex(&valid.statement), "index_root": hex(&wiring.root),
                "log_rows": b.circuit.log_rows, "roots": roots.iter().map(|r| hex(r)).collect::<Vec<_>>(),
                "witness": claim(&claims.witness), "wiring": claim(&claims.wiring), "quotient": claim(&claims.quotient),
                "sum": claim(&claims.sum)});
            std::fs::write(format!("{dir}/{}.json", b.name), dump.to_string()).unwrap();
        }
        report["peak_rss_kib"] = peak_rss_kib().into();
        println!("{report}");
    }
}
