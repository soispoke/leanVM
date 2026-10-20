//! Generate the exact upstream PIOP graph, including constrained Keccak-f1600.
//! Generate the exact upstream PIOP graph, with its transcript on either random oracle: Keccak-256 as a GF(2)
//! circuit, or the VM's native BLAKE2s chain.
use super::keccak;
use evm::{
    contract::Recorder,
    record::{Node, Sym, record},
};
use flock::{
    membership::Statement,
    quotient::{self, Oracle},
};
use primitives::field::F192;
use std::{collections::HashMap, fmt::Write};
fn lit(x: F192) -> String {
    if x.c2 == 0 {
        format!("{}", x.c0 as u128 | ((x.c1 as u128) << 64))
    } else {
        format!(
            "({} + {} * Y_TOWER_p0 * Y_TOWER_p0)",
            x.c0 as u128 | ((x.c1 as u128) << 64),
            x.c2
        )
    }
}
fn v(s: Sym) -> String {
    format!("v{}", s.0)
}
/// `Σ bit(i)·e_i` over `limbs` 64-bit tower limbs, by Horner in `x` within each limb:
/// two instructions a bit and no constant loads.
fn recompose(m: &mut String, name: &str, limbs: usize, bit: impl Fn(usize) -> String) -> String {
    for l in 0..limbs {
        writeln!(m, "    {name}_l{l} = {}", bit(64 * l + 63)).unwrap();
        for j in (0..63).rev() {
            writeln!(m, "    {name}_l{l} = {name}_l{l} * GEN + {}", bit(64 * l + j)).unwrap();
        }
    }
    (1..limbs).rev().fold(format!("{name}_l{}", limbs - 1), |acc, l| {
        format!("{name}_l{} + Y_TOWER_p0 * ({acc})", l - 1)
    })
}
/// Hint the coordinate bits of `value`, pin each to `{0, 1}` and bind them to it.
/// `limbs < 3` also proves the top limbs zero: the canonical 128-bit encoding.
fn scalar_bits(m: &mut String, name: &str, value: &str, limbs: usize) {
    let n = 64 * limbs;
    writeln!(
        m,
        "    {name} = StackBuf({n})\n    hint_decompose_bits({name}, {value}, {n})"
    )
    .unwrap();
    for i in 0..n {
        writeln!(m, "    {name}[{i}] = {name}[{i}] * {name}[{i}]").unwrap();
    }
    let sum = recompose(m, &format!("{name}_acc"), limbs, |i| format!("{name}[{i}]"));
    writeln!(m, "    assert {sum} == {value}").unwrap();
}
/// The bits of a 32-byte big-endian word holding coordinate bits `bit(i)`, `i < 8·width`.
fn word_bits(width: usize, bit: impl Fn(usize) -> String) -> Vec<String> {
    (0..256)
        .map(|p| {
            let (byte, k) = (p / 8, p % 8);
            let i = 8 * (31 - byte) + k;
            if i < 8 * width { bit(i) } else { "0".into() }
        })
        .collect()
}
pub fn generate(oracle: Oracle, index_root: &[u8; 32], app_id: &[u8; 32], log_rows: usize) -> (String, String, String) {
    let (r, g) = record(|| quotient::reduce(&mut Recorder::new(), log_rows).unwrap());
    let mut m = String::from(
        "    statement = StackBuf(4)\n    hint_witness(statement, \"app_statement\")\n    proof = StackBuf(9)\n    hint_witness(proof, \"app_proof\")\n",
    );
    // Statement words and commitment roots are canonical 128-bit values; their bits
    // are reused wherever the transcript absorbs them.
    for k in 0..4 {
        if oracle == Oracle::Keccak {
            scalar_bits(&mut m, &format!("sbits{k}"), &format!("statement[{k}]"), 2);
            scalar_bits(&mut m, &format!("rootbits{k}"), &format!("proof[{k}]"), 2);
        } else {
            // BLAKE2s message chunks pin the statement's top limbs; a root's are pinned here.
            writeln!(m, "    root_lo{k}, root_hi{k} = canonical_limbs_p0(proof[{k}])").unwrap();
        }
    }
    let mut bits: HashMap<u32, (String, usize)> = HashMap::new();
    for (i, node) in g.nodes.iter().enumerate() {
        match *node {
            Node::Statement(k) => bits.insert(i as u32, (format!("sbits{k}"), 2)),
            Node::Root(k) => bits.insert(i as u32, (format!("rootbits{k}"), 2)),
            _ => None,
        };
    }
    // The aggregate's public claim is H(application ID || canonical public inputs).
    let ids = fiat_shamir::merkle::hash_to_scalars(app_id);
    writeln!(m,"    claim_hash0 = StackBuf(2)\n    claim_hash1 = StackBuf(2)\n    blake2s([{},{}], [statement[0],statement[1]], claim_hash0, counter=64, final=0)\n    blake2s([statement[2],statement[3]], [0,0], claim_hash1, cv=claim_hash0, counter=96, final=1)\n    pub_ptr = GEN ** 0\n    assert pub_ptr[1] == claim_hash1[0]\n    assert pub_ptr[GEN] == claim_hash1[1]",lit(ids[0]),lit(ids[1])).unwrap();
    for (i, node) in g.nodes.iter().enumerate() {
        match *node {
            Node::Const(c) => {
                writeln!(m, "    v{i} = {}", lit(F192::new(c[0], c[1], c[2]))).unwrap();
            }
            Node::Statement(k) => {
                writeln!(m, "    v{i} = statement[{k}]").unwrap();
            }
            Node::Root(k) => {
                writeln!(m, "    v{i} = proof[{k}]").unwrap();
            }
            Node::Input(k) => {
                writeln!(m, "    v{i} = proof[{}]", k + 4).unwrap();
            }
            Node::Add(a, b) => {
                writeln!(m, "    v{i} = v{a} + v{b}").unwrap();
            }
            Node::Mul(a, b) => {
                writeln!(m, "    v{i} = v{a} * v{b}").unwrap();
            }
            Node::Frobenius(a) => {
                writeln!(
                    m,
                    "    v{i} = v{a}\n    for j in unroll(0, 64):\n        v{i} = v{i} * v{i}"
                )
                .unwrap();
            }
            Node::Seed if oracle == Oracle::Blake2s => {
                let [circuit, _] = quotient::vm_seed(
                    index_root,
                    &Statement {
                        y: [0; 32],
                        root: [0; 32],
                    },
                );
                let iv: Vec<u8> = circuit.iter().flat_map(|w| w.0.to_le_bytes()).collect();
                let iv = fiat_shamir::merkle::hash_to_scalars(&iv.try_into().unwrap());
                writeln!(m, "    seed_pi = StackBuf(2)\n    blake2s([statement[0], statement[1]], [statement[2], statement[3]], seed_pi)\n    f{i} = StackBuf(2)\n    blake2s([{}, {}], seed_pi, f{i})", lit(iv[0]), lit(iv[1])).unwrap();
            }
            Node::Hash(prev, fields, n) if oracle == Oracle::Blake2s => {
                let mut state = format!("f{prev}");
                for (k, &a) in fields[..n as usize].iter().enumerate() {
                    writeln!(m, "    f{i}_{k} = obs_p0({state}, v{a})").unwrap();
                    state = format!("f{i}_{k}");
                }
                writeln!(m, "    f{i} = squeeze_state_p0({state})").unwrap();
            }
            Node::Low(a) if oracle == Oracle::Blake2s => {
                writeln!(m, "    v{i} = challenge_from_state_p0(f{a})").unwrap();
            }
            Node::Seed => {
                // The label is a constant prefix followed by the four 16-byte statement words.
                let label = quotient::label(
                    index_root,
                    &Statement {
                        y: [0; 32],
                        root: [0; 32],
                    },
                );
                let prefix = &label[..label.len() - 64];
                let mut input: Vec<String> = prefix
                    .iter()
                    .flat_map(|b| (0..8).map(move |k| ((b >> k) & 1).to_string()))
                    .collect();
                for k in 0..4 {
                    for byte in 0..16 {
                        for bit in 0..8 {
                            input.push(format!("sbits{k}[{}]", 8 * (15 - byte) + bit));
                        }
                    }
                }
                assert_eq!(input.len(), 8 * label.len());
                keccak::hash(&mut m, &format!("h{i}"), &input);
            }
            Node::Hash(prev, fields, n) => {
                let mut input: Vec<String> = (0..256).map(|k| format!("h{prev}[{k}]")).collect();
                for &a in &fields[..n as usize] {
                    let (name, limbs) = bits.entry(a).or_insert_with(|| {
                        let name = format!("hb{a}");
                        scalar_bits(&mut m, &name, &format!("v{a}"), 3);
                        (name, 3)
                    });
                    input.extend(word_bits(8 * *limbs, |i| format!("{name}[{i}]")));
                }
                keccak::hash(&mut m, &format!("h{i}"), &input);
            }
            Node::Low(a) => {
                // The challenge is the low 192 bits of the big-endian digest.
                let sum = recompose(&mut m, &format!("low{i}"), 3, |c| {
                    format!("h{a}[{}]", 8 * (31 - c / 8) + c % 8)
                });
                writeln!(m, "    v{i} = {sum}").unwrap();
            }
        }
    }
    for a in g.nonzero {
        writeln!(m, "    assert v{a} * (1 / v{a}) == 1").unwrap();
    }
    let index = fiat_shamir::merkle::hash_to_scalars(index_root);
    let mut claims = [
        vec![v(r.roots[0][0]), v(r.roots[0][1])],
        vec![lit(index[0]), lit(index[1])],
        vec![v(r.roots[1][0]), v(r.roots[1][1])],
    ];
    for (dst, (point, value)) in claims.iter_mut().zip([r.witness, r.wiring, r.quotient]) {
        dst.extend(point.into_iter().map(v));
        dst.push(v(value));
    }
    claims[2].extend(quotient::sum_point(log_rows).into_iter().map(lit));
    claims[2].push(v(r.sum));
    for (i, values) in claims.iter().enumerate() {
        writeln!(m, "    claim_{i} = StackBuf({})", values.len()).unwrap();
        for (k, value) in values.iter().enumerate() {
            writeln!(m, "    claim_{i}[{k}] = {value}").unwrap();
        }
    }
    let functions = match oracle {
        Oracle::Keccak => keccak::permutation_function(),
        Oracle::Blake2s => String::new(),
    };
    (String::new(), functions, m)
}
