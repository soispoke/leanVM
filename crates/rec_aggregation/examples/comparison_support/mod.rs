//! Matched standalone-opening aggregation and circuit claims.
#[path = "keccak.rs"]
mod keccak;
#[allow(dead_code)]
#[path = "standalone_opening.rs"]
pub(crate) mod opening_adapter;
#[path = "piop_guest.rs"]
mod piop_guest;
#[path = "r1cs.rs"]
pub(crate) mod r1cs;
use fiat_shamir::{merkle::hash_to_scalars, transcript::Proof};
use flock::{
    membership::{Secret, Statement},
    quotient::{self, Index, Table, circuit, opening},
    standalone::Claim,
};
use leanvm_core::cpu::{self, Program};
use primitives::{
    field::{F64, F192},
    hash::hash,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::{collections::BTreeSet, fmt::Write, time::Instant};

pub(crate) struct Opened<'a> {
    pub layout: &'a opening::Layout,
    pub root: [u8; 32],
    pub claims: Vec<Claim>,
    pub proof: Proof,
}
fn literal(x: F192) -> String {
    if x.c2 == 0 {
        format!("{}", x.c0 as u128 | ((x.c1 as u128) << 64))
    } else {
        format!(
            "({} + {} * Y_TOWER * Y_TOWER)",
            x.c0 as u128 | ((x.c1 as u128) << 64),
            x.c2
        )
    }
}
fn namespace(s: &str, suffix: &str) -> String {
    let mut names = BTreeSet::new();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("def ") {
            names.insert(rest.split('(').next().unwrap().to_string());
        } else if !line.starts_with([' ', '#']) && line.contains(" = ") {
            names.insert(line.split(" = ").next().unwrap().to_string());
        }
    }
    for name in [
        "claim",
        "opening_stream",
        "merkle_caps",
        "merkle_cap_active",
        "merkle_leaf_rows",
        "merkle_children",
    ] {
        names.insert(name.into());
    }
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        out.push_str(word);
        if names.contains(word.as_str()) {
            out.push_str(suffix);
        }
        word.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}
pub(crate) fn build(
    opened: &[Opened],
    raws: &[fiat_shamir::transcript::RawProof],
    index_root: &[u8; 32],
    app_id: &[u8; 32],
    full: bool,
    batch: usize,
) -> Program {
    assert_eq!(opened.len(), 3, "three opening profiles are required");
    assert_eq!(raws.len(), opened.len());
    assert!(batch > 0, "a batch cannot be empty");
    assert_eq!(opened.iter().map(|o| o.claims.len()).collect::<Vec<_>>(), [1, 1, 2]);
    let mut headers = String::new();
    let mut functions = String::new();
    for (i, o) in opened.iter().enumerate() {
        let raw = &raws[i];
        let code = opening_adapter::guest_source(o.layout, o.claims.len(), raw.stream.len());
        let last = code
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("digest_")
                    .and_then(|r| r.split(" =").next())
                    .filter(|r| r.chars().all(|c| c.is_ascii_digit()))
                    .and_then(|r| r.parse::<usize>().ok())
            })
            .max()
            .unwrap();
        let code = code
            .lines()
            .filter(|l| !l.contains("pub_ptr"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut code = replace_once(&code, "def main():", "def verify_opening(expected):");
        let n = 2 + o.claims.iter().map(|c| c.point.len() + 1).sum::<usize>();
        code = replace_once(
            &code,
            "    hint_witness(data, \"claim\")",
            &format!(
                "    hint_witness(data, \"claim\")\n    for k in unroll(0, {n}):\n        assert data[k] == expected[GEN ** k]"
            ),
        );
        let at = code.rfind("    return").unwrap();
        code.replace_range(at.., &format!("    return digest_{last}[0], digest_{last}[1]\n"));
        let code = namespace(&code, &format!("_p{i}"));
        let at = code.find("@inline").unwrap();
        headers.push_str(&code[..at]);
        functions.push_str(&code[at..]);
    }
    let mut main = String::from("\ndef main():\n");
    if full {
        let (h, f, m) = piop_guest::generate(index_root, app_id, 20);
        headers.push_str(&h);
        functions.push_str(&f);
        main.push_str(&m);
    } else {
        for (i, o) in opened.iter().enumerate() {
            let n = 2 + o.claims.iter().map(|c| c.point.len() + 1).sum::<usize>();
            writeln!(
                main,
                "    claim_{i} = StackBuf({n})\n    hint_witness(claim_{i}, \"app_claim_{i}\")"
            )
            .unwrap();
        }
    }
    for i in 0..opened.len() {
        writeln!(main, "    d{i}_0, d{i}_1 = verify_opening_p{i}(addr(claim_{i}))").unwrap();
    }
    if !full {
        let domain = hash_to_scalars(&hash(b"pcs-aggregate-claims-v1"));
        writeln!(main,"    a = StackBuf(2)\n    b = StackBuf(2)\n    blake2s([{}, {}], [d0_0,d0_1], a, counter=64, final=0)\n    blake2s([d1_0,d1_1], [d2_0,d2_1], b, cv=a, counter=128, final=1)\n    pub_ptr = GEN ** 0\n    assert pub_ptr[1] == b[0]\n    assert pub_ptr[GEN] == b[1]",literal(domain[0]),literal(domain[1])).unwrap();
    }
    main.push_str("    return\n");
    if batch > 1 {
        main = main
            .replace("def main():", "def verify_application():")
            .lines()
            .filter(|l| !l.contains("pub_ptr"))
            .collect::<Vec<_>>()
            .join("\n");
        let end = main.rfind("    return").unwrap();
        main.truncate(end);
        main.push_str(if full {
            "    return claim_hash1[0], claim_hash1[1]\n"
        } else {
            "    return b[0], b[1]\n"
        });
        main.push_str("\ndef main():\n");
        let domain = hash_to_scalars(&hash(b"matched-application-batch-v1"));
        writeln!(
            main,
            "    batch_hash0 = StackBuf(2)\n    blake2s([{},{}], [{batch},0], batch_hash0, counter=64, final=0)",
            literal(domain[0]),
            literal(domain[1])
        )
        .unwrap();
        for i in 0..batch {
            writeln!(main, "    app{i}_0, app{i}_1 = verify_application()").unwrap();
        }
        for pair in 0..batch.div_ceil(2) {
            let i = pair * 2;
            let right = if i + 1 < batch {
                format!("[app{}_0,app{}_1]", i + 1, i + 1)
            } else {
                "[0,0]".into()
            };
            let next = pair + 1;
            let last = i + 2 >= batch;
            let counter = 64 + 32 * (i + 2).min(batch);
            writeln!(main,"    batch_hash{next} = StackBuf(2)\n    blake2s([app{i}_0,app{i}_1], {right}, batch_hash{next}, cv=batch_hash{pair}, counter={counter}, final={})",usize::from(last)).unwrap();
        }
        let last = batch.div_ceil(2);
        writeln!(main,"    pub_ptr = GEN ** 0\n    assert pub_ptr[1] == batch_hash{last}[0]\n    assert pub_ptr[GEN] == batch_hash{last}[1]\n    return").unwrap();
    }
    let source = headers + &functions + &main;
    lean_compiler::compile(&lean_compiler::parse(&source).expect("combined guest parses"))
}
pub(crate) fn pcs_public(opened: &[Opened]) -> [F192; 2] {
    let mut bytes = hash(b"pcs-aggregate-claims-v1").to_vec();
    for o in opened {
        let (_, d) = opening_adapter::bind(&o.root, &o.claims);
        for x in d {
            bytes.extend(x.c0.to_le_bytes());
            bytes.extend(x.c1.to_le_bytes());
        }
    }
    hash_to_scalars(&hash(&bytes))
}
pub(crate) fn elapsed(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e6
}
pub(crate) fn claim_contract(id: &[u8; 32]) -> Vec<u8> {
    // Require exactly two public 32-byte words, return circuit ID || statement.
    // The host dependency-frame adapter authenticates this claim against the aggregate.
    let mut code = vec![0x36, 0x60, 64, 0x14, 0x60, 11, 0x57, 0x5f, 0x5f, 0xfd, 0x00, 0x5b, 0x7f];
    code.extend(id);
    code.extend([0x5f, 0x52, 0x60, 64, 0x5f, 0x60, 32, 0x37, 0x60, 96, 0x5f, 0xf3]);
    code
}
fn pcs_claim_public(roots: &[[u8; 32]; 2], index: &[u8; 32], c: &quotient::Claims) -> [F192; 2] {
    let mut bytes = hash(b"pcs-aggregate-claims-v1").to_vec();
    for (root, claims) in [
        (roots[0], vec![c.witness.clone()]),
        (*index, vec![c.wiring.clone()]),
        (roots[1], vec![c.quotient.clone(), c.sum.clone()]),
    ] {
        let (_, d) = opening_adapter::bind(&root, &claims);
        for x in d {
            bytes.extend(x.c0.to_le_bytes());
            bytes.extend(x.c1.to_le_bytes());
        }
    }
    hash_to_scalars(&hash(&bytes))
}
pub(crate) fn execution(
    full: bool,
    code: &[u8],
    data: &[u8],
    id: &[u8; 32],
    index: &[u8; 32],
    public: [F192; 2],
) -> (f64, f64, u64) {
    let t = Instant::now();
    let outcome = evm::machine::call(code, data);
    let evm_us = elapsed(t);
    let t = Instant::now();
    let output = outcome.output.expect("application execution succeeds");
    let expected = if full {
        assert_eq!(output.len(), 96);
        assert_eq!(&output[..32], id);
        let s = Statement {
            y: output[32..64].try_into().unwrap(),
            root: output[64..96].try_into().unwrap(),
        };
        r1cs::public_claim(id, &s)
    } else {
        let (roots, claims) = evm::quotient::decode(&output, 20).expect("canonical PCS claims");
        pcs_claim_public(&roots, index, &claims)
    };
    assert_eq!(
        expected, public,
        "every emitted dependency must be covered by the aggregate"
    );
    (evm_us, elapsed(t), outcome.execution)
}
pub(crate) fn install_witness(
    program: &mut Program,
    opened: &[Opened],
    raws: &[fiat_shamir::transcript::RawProof],
    statement: &Statement,
    piop: &Proof,
) {
    for (i, (o, raw)) in opened.iter().zip(raws).enumerate() {
        let (data, _) = opening_adapter::bind(&o.root, &o.claims);
        program.set_witness(format!("app_claim_{i}"), vec![data.clone()]);
        program.set_witness(format!("claim_p{i}"), vec![data]);
        opening_adapter::hints_named(program, raw, o.layout, &format!("_p{i}"));
    }
    program.set_witness("app_statement", vec![statement.halves().to_vec()]);
    program.set_witness("app_proof", vec![piop.stream.clone()]);
}
fn adversarial(
    program: &Program,
    opened: &[Opened],
    raws: &[fiat_shamir::transcript::RawProof],
    statement: &Statement,
    piop: &Proof,
    public: [F192; 2],
    full: bool,
    id: &[u8; 32],
) -> usize {
    let mut count = 0;
    let mut reject = |p: &Program, pi: [F192; 2]| {
        assert!(p.execute(pi).is_err(), "tampered aggregate witness accepted");
        count += 1;
    };
    for k in 0..2 {
        let mut pi = public;
        pi[k] += F192::ONE;
        reject(program, pi);
    }
    for (i, o) in opened.iter().enumerate() {
        let (data, _) = opening_adapter::bind(&o.root, &o.claims);
        // Both the opening's advertised claim and its caller's claim are changed.
        // The existing outer digest / application PIOP must still prevent substitution.
        let mut positions = vec![0, 2];
        let mut offset = 2;
        for c in &o.claims {
            positions.push(offset + c.point.len());
            offset += c.point.len() + 1;
        }
        for k in positions {
            let mut d = data.clone();
            d[k] += F192::ONE;
            let mut p = program.clone();
            p.set_witness(format!("claim_p{i}"), vec![d.clone()]);
            p.set_witness(format!("app_claim_{i}"), vec![d]);
            reject(&p, public);
        }
        let mut raw = raws[i].clone();
        raw.stream[0] += F192::ONE;
        let mut p = program.clone();
        opening_adapter::hints_named(&mut p, &raw, o.layout, &format!("_p{i}"));
        reject(&p, public);
    }
    if full {
        for k in 0..piop.stream.len() {
            let mut proof = piop.stream.clone();
            proof[k] += F192::ONE;
            let mut p = program.clone();
            p.set_witness("app_proof", vec![proof]);
            reject(&p, public);
        }
        for k in 0..4 {
            let mut s = *statement;
            if k < 2 {
                s.y[16 * k] ^= 1;
            } else {
                s.root[16 * (k - 2)] ^= 1;
            }
            let mut p = program.clone();
            p.set_witness("app_statement", vec![s.halves().to_vec()]);
            reject(&p, r1cs::public_claim(id, &s));
        }
        for statement_word in [false, true] {
            let mut p = program.clone();
            let mut data = if statement_word {
                statement.halves().to_vec()
            } else {
                piop.stream.clone()
            };
            data[0] += F192::new(0, 0, 1);
            p.set_witness(if statement_word { "app_statement" } else { "app_proof" }, vec![data]);
            reject(&p, public);
        }
    }
    count
}
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args
        .windows(2)
        .find(|p| p[0] == "--samples")
        .map(|p| p[1].parse::<usize>().unwrap())
        .unwrap_or(3);
    let skip_negative = args.iter().any(|a| a == "--skip-negative");
    let seed = args
        .windows(2)
        .find(|p| p[0] == "--seed")
        .map(|p| p[1].parse::<u64>().unwrap())
        .unwrap_or(902);
    let mut rng = StdRng::seed_from_u64(seed);
    let t = Instant::now();
    let circuit = circuit::membership();
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let app_id = r1cs::identity(&circuit);
    let pcs_code = evm::quotient::contract(&wiring.root, circuit.log_rows).code;
    let r1cs_code = claim_contract(&app_id);
    let shared_setup_us = elapsed(t);
    for data in [vec![], vec![0; 63], vec![0; 65]] {
        assert!(evm::machine::call(&r1cs_code, &data).output.is_none());
    }
    println!(
        "{}",
        serde_json::json!({"kind":"setup","shared_setup_us":shared_setup_us,"upstream":"651453c6839de98566c18e94d058507c9ff8920b","app_id":app_id,"rows":1usize<<circuit.log_rows,"r1cs_gate_constraints":6usize<<circuit.log_rows,"copy_constraints":circuit.sigma.len(),"public_constraints":1024,"samples":samples,"warmup_samples":1})
    );
    for sample in 0..=samples {
        let mut bytes = || {
            let mut b = [0; 32];
            rng.fill_bytes(&mut b);
            b
        };
        let secret = Secret {
            x: bytes(),
            siblings: std::array::from_fn(|_| bytes()),
            directions: 0x13287965,
        };
        let statement = secret.statement();
        let t = Instant::now();
        let cells = circuit.cells(&circuit::membership_inputs(&secret));
        let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
        let witness_us = elapsed(t);
        let t = Instant::now();
        r1cs::check(&circuit, &cells, &statement).expect("application R1CS witness");
        let reference_check_us = elapsed(t);
        if sample == 0 && !skip_negative {
            let mut bad = statement;
            bad.y[0] ^= 1;
            assert!(r1cs::check(&circuit, &cells, &bad).is_err());
            let mut bad_cells = cells.clone();
            bad_cells[3] += F64::ONE;
            assert!(r1cs::check(&circuit, &bad_cells, &statement).is_err());
        }
        let t = Instant::now();
        let mut committed = Vec::new();
        let mut commit = |table: &Table| {
            let c = opening::commit(table);
            let root = c.root;
            committed.push(c);
            root
        };
        let proved = quotient::prove(&circuit, &index, &wiring.root, &statement, &cells, &masks, &mut commit);
        let piop_prove_us = elapsed(t);
        let t = Instant::now();
        let mut opened = Vec::new();
        for (table, c, claims) in [
            (&proved.witness, &committed[0], vec![proved.claims.witness.clone()]),
            (index.table(), &wiring, vec![proved.claims.wiring.clone()]),
            (
                &proved.quotient,
                &committed[1],
                vec![proved.claims.quotient.clone(), proved.claims.sum.clone()],
            ),
        ] {
            let proof = opening::open(table, c, &claims);
            opened.push(Opened {
                layout: &table.layout,
                root: c.root,
                claims,
                proof,
            });
        }
        let opening_prove_us = elapsed(t);
        let client_us = witness_us + piop_prove_us + opening_prove_us;
        // Both interfaces admit exactly the same native proof, retaining authenticated
        // Merkle expansions for aggregation rather than doing that work a second time.
        let t = Instant::now();
        let (roots, claims) = quotient::verify(&wiring.root, &statement, &proved.proof, circuit.log_rows).unwrap();
        assert_eq!(claims, proved.claims);
        assert_eq!(roots, [committed[0].root, committed[1].root]);
        let admission_piop_us = elapsed(t);
        let t = Instant::now();
        let raws: Vec<_> = opened
            .iter()
            .map(|o| opening::verification_trace(o.layout, &o.root, &o.claims, &o.proof).expect("native admission"))
            .collect();
        let admission_openings_us = elapsed(t);
        let mode_order = if sample % 2 == 0 { [false, true] } else { [true, false] };
        for full in mode_order {
            if args.iter().any(|a| a == "--full") && !full || args.iter().any(|a| a == "--pcs") && full {
                continue;
            }
            let t = Instant::now();
            let mut program = build(&opened, &raws, &wiring.root, &app_id, full, 1);
            let compile_us = elapsed(t);
            let t = Instant::now();
            install_witness(&mut program, &opened, &raws, &statement, &proved.proof);
            let hint_prep_us = elapsed(t);
            let public = if full {
                r1cs::public_claim(&app_id, &statement)
            } else {
                pcs_public(&opened)
            };
            let t = Instant::now();
            program.execute(public).expect("valid aggregate guest");
            let guest_execute_us = elapsed(t);
            let negatives = if sample == 0 && !skip_negative {
                adversarial(
                    &program,
                    &opened,
                    &raws,
                    &statement,
                    &proved.proof,
                    public,
                    full,
                    &app_id,
                )
            } else {
                0
            };
            let code = if full { &r1cs_code } else { &pcs_code };
            let calldata = if full {
                [statement.y, statement.root].concat()
            } else {
                evm::quotient::calldata(&statement, &proved.proof)
            };
            let (evm_with_context_us, coverage_us, execution_gas) =
                execution(full, code, &calldata, &app_id, &wiring.root, public);
            eprintln!(
                "sample={sample} full={full} code={} negatives={negatives}",
                program.code_len()
            );
            let t = Instant::now();
            let (proof, stats) = cpu::prove(&program, public, 2).expect("aggregate proof");
            let aggregate_prove_us = elapsed(t);
            let t = Instant::now();
            cpu::verify(&program, &public, &proof).expect("aggregate verification");
            let aggregate_verify_us = elapsed(t);
            if sample == 0 && !skip_negative {
                let mut wrong = public;
                wrong[0] += F192::ONE;
                assert!(cpu::verify(&program, &wrong, &proof).is_err());
            }
            let serialized = bincode::serialize(&proof).unwrap();
            let serial_warm_us = client_us
                + admission_piop_us
                + admission_openings_us
                + hint_prep_us
                + aggregate_prove_us
                + aggregate_verify_us
                + evm_with_context_us
                + coverage_us;
            println!(
                "{}",
                serde_json::json!({"kind":"sample","sample":sample,"warmup":sample==0,"interface":if full{"r1cs"}else{"pcs"},"statement":statement.halves().iter().map(|x|[x.c0,x.c1]).collect::<Vec<_>>(),"witness_us":witness_us,"piop_prove_us":piop_prove_us,"opening_prove_us":opening_prove_us,"client_us":client_us,"reference_r1cs_check_us":reference_check_us,"admission_piop_us":admission_piop_us,"admission_openings_us":admission_openings_us,"compile_us":compile_us,"hint_prep_us":hint_prep_us,"guest_execute_diagnostic_us":guest_execute_us,"aggregate_prove_us":aggregate_prove_us,"aggregate_verify_us":aggregate_verify_us,"evm_with_context_us":evm_with_context_us,"coverage_us":coverage_us,"execution_gas":execution_gas,"calldata_bytes":calldata.len(),"eip7623_transaction_gas":evm::machine::transaction_gas(&calldata,execution_gas,40),"serial_warm_us":serial_warm_us,"serial_cold_us":serial_warm_us+shared_setup_us+compile_us,"negative_guest_cases":negatives,"aggregate_transport_bytes":serialized.len(),"code_len":program.code_len(),"base_cycles":stats.base_counts.iter().sum::<usize>(),"base_counts":stats.base_counts,"padded_cycles":stats.cycles,"memory_cells":stats.mem_used,"stats":stats.details()})
            );
        }
    }
}

#[allow(dead_code)] // Used by the batch example.
pub(crate) fn batch_public(claims: &[[F192; 2]]) -> [F192; 2] {
    let mut bytes = hash(b"matched-application-batch-v1").to_vec();
    bytes.extend((claims.len() as u128).to_le_bytes());
    bytes.extend([0u8; 16]);
    for pair in claims {
        for x in pair {
            assert_eq!(x.c2, 0);
            bytes.extend(x.c0.to_le_bytes());
            bytes.extend(x.c1.to_le_bytes());
        }
    }
    hash_to_scalars(&hash(&bytes))
}

/// Refuse to generate a weaker guest if an upstream source marker changes.
fn replace_once(source: &str, marker: &str, replacement: &str) -> String {
    assert_eq!(
        source.matches(marker).count(),
        1,
        "guest marker must occur exactly once: {marker}"
    );
    source.replacen(marker, replacement, 1)
}
#[cfg(test)]
mod generator_tests {
    use super::*;
    #[test]
    fn source_edits_fail_closed() {
        assert!(std::panic::catch_unwind(|| replace_once("missing", "binding", "new")).is_err());
        assert!(std::panic::catch_unwind(|| replace_once("binding binding", "binding", "new")).is_err());
        assert_eq!(
            replace_once("before binding after", "binding", "checked"),
            "before checked after"
        );
    }
}
