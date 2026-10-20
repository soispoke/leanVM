//! Generate the exact upstream PIOP graph, including constrained Keccak-f1600.
use evm::{
    contract::Recorder,
    record::{Node, Sym, record},
};
use flock::{membership::Statement, quotient};
use primitives::field::F192;
use std::fmt::Write;
const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];
const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
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
/// Shared, non-inline round. Booleanity follows from the constrained input bits.
fn keccak() -> String {
    let mut f = String::from(
        "\ndef keccak_round(s, rc):\n    rb = StackBuf(64)\n    hint_decompose_bits(rb, rc, 64)\n    bind_bits_p0(addr(rb), rc, 64)\n",
    );
    for x in 0..5 {
        for z in 0..64 {
            let terms = (0..5)
                .map(|y| format!("s[GEN ** {}]", 64 * (x + 5 * y) + z))
                .collect::<Vec<_>>()
                .join(" + ");
            writeln!(f, "    c{x}_{z} = {terms}").unwrap();
        }
    }
    for x in 0..5 {
        for z in 0..64 {
            writeln!(
                f,
                "    d{x}_{z} = c{}_{} + c{}_{}",
                (x + 4) % 5,
                z,
                (x + 1) % 5,
                (z + 63) % 64
            )
            .unwrap();
        }
    }
    for (x, rot) in ROT.iter().enumerate() {
        for (y, r) in rot.iter().enumerate() {
            for z in 0..64 {
                writeln!(
                    f,
                    "    b{}_{}_{} = s[GEN ** {}] + d{x}_{z}",
                    y,
                    (2 * x + 3 * y) % 5,
                    (z + r) % 64,
                    64 * (x + 5 * y) + z
                )
                .unwrap();
            }
        }
    }
    f.push_str("    out = HeapBuf(1600)\n");
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..64 {
                let iota = if x == 0 && y == 0 {
                    format!(" + rb[{z}]")
                } else {
                    String::new()
                };
                writeln!(
                    f,
                    "    out[GEN ** {}] = b{x}_{y}_{z} + (1 + b{}_{y}_{z}) * b{}_{y}_{z}{iota}",
                    64 * (x + 5 * y) + z,
                    (x + 1) % 5,
                    (x + 2) % 5
                )
                .unwrap();
            }
        }
    }
    f.push_str("    return out\n");
    f
}
fn hash_function(n: usize) -> String {
    let mut f = format!(
        "\ndef keccak_hash_{n}(bits):\n    state = HeapBuf(1600)\n    for i in unroll(0, 1600):\n        state[GEN ** i] = 0\n"
    );
    for block in 0..=n / 136 {
        f.push_str("    absorbed = HeapBuf(1600)\n");
        for i in 0..1600 {
            let position = block * 1088 + i;
            let extra = if i < 1088 && position < n * 8 {
                format!(" + bits[GEN ** {position}]")
            } else if i < 1088 && (position == n * 8 || (block == n / 136 && i == 1087)) {
                " + 1".into()
            } else {
                String::new()
            };
            writeln!(f, "    absorbed[GEN ** {i}] = state[GEN ** {i}]{extra}").unwrap();
        }
        f.push_str("    state = absorbed\n");
        for rc in RC {
            writeln!(f, "    state = keccak_round(state, {rc})").unwrap();
        }
    }
    f.push_str("    return state\n");
    f
}

fn scalar_bits(m: &mut String, name: &str, value: &str, n: usize) {
    writeln!(m,"    {name} = StackBuf({n})\n    hint_decompose_bits({name}, {value}, {n})\n    bind_bits_p0(addr({name}), {value}, {n})").unwrap();
}
fn constants_bits(m: &mut String, dest: &str, offset: usize, data: &[u8]) {
    for (i, b) in data.iter().enumerate() {
        for k in 0..8 {
            writeln!(m, "    {dest}[{}] = {}", offset + i * 8 + k, (b >> k) & 1).unwrap();
        }
    }
}
pub fn generate(index_root: &[u8; 32], app_id: &[u8; 32], log_rows: usize) -> (String, String, String) {
    let (r, g) = record(|| quotient::reduce(&mut Recorder::new(), log_rows).unwrap());
    let mut sizes = std::collections::BTreeSet::new();
    let mut m = String::from(
        "    statement = StackBuf(4)\n    hint_witness(statement, \"app_statement\")\n    proof = StackBuf(9)\n    hint_witness(proof, \"app_proof\")\n",
    );
    for k in 0..4 {
        scalar_bits(&mut m, &format!("sbits{k}"), &format!("statement[{k}]"), 128);
        scalar_bits(&mut m, &format!("rootbits{k}"), &format!("proof[{k}]"), 128);
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
            Node::Seed => {
                let label = quotient::label(
                    index_root,
                    &Statement {
                        y: [0; 32],
                        root: [0; 32],
                    },
                );
                let prefix = &label[..label.len() - 64];
                writeln!(m, "    hashbits{i} = StackBuf({})", label.len() * 8).unwrap();
                constants_bits(&mut m, &format!("hashbits{i}"), 0, prefix);
                for k in 0..4 {
                    for byte in 0..16 {
                        for bit in 0..8 {
                            writeln!(
                                m,
                                "    hashbits{i}[{}] = sbits{k}[{}]",
                                8 * (prefix.len() + 16 * k + byte) + bit,
                                8 * (15 - byte) + bit
                            )
                            .unwrap();
                        }
                    }
                }
                sizes.insert(label.len());
                writeln!(m, "    h{i} = keccak_hash_{}(addr(hashbits{i}))", label.len()).unwrap();
            }
            Node::Hash(prev, fields, n) => {
                writeln!(m,"    hashbits{i} = StackBuf({})\n    for k in unroll(0, 256):\n        hashbits{i}[k] = h{prev}[GEN ** k]",(1+n as usize)*256).unwrap();
                for (k, &a) in fields[..n as usize].iter().enumerate() {
                    scalar_bits(&mut m, &format!("hb{i}_{k}"), &format!("v{a}"), 192);
                    for byte in 0..32 {
                        for bit in 0..8 {
                            let value = if byte < 8 {
                                "0".into()
                            } else {
                                format!("hb{i}_{k}[{}]", 8 * (31 - byte) + bit)
                            };
                            writeln!(m, "    hashbits{i}[{}] = {value}", (k + 1) * 256 + byte * 8 + bit).unwrap();
                        }
                    }
                }
                sizes.insert((1 + n as usize) * 32);
                writeln!(m, "    h{i} = keccak_hash_{}(addr(hashbits{i}))", (1 + n as usize) * 32).unwrap();
            }
            Node::Low(a) => {
                writeln!(m, "    v{i} = 0").unwrap();
                for byte in 8..32 {
                    for bit in 0..8 {
                        writeln!(
                            m,
                            "    v{i} += h{a}[GEN ** {}] * COORD_BASIS_p0[{}]",
                            byte * 8 + bit,
                            8 * (31 - byte) + bit
                        )
                        .unwrap();
                    }
                }
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
    let mut functions = keccak();
    for n in sizes {
        functions.push_str(&hash_function(n));
    }
    (String::new(), functions, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};
    #[test]
    fn keccak_matches_independent_implementation() {
        // Include all PIOP lengths and both sides of the sponge's block boundary.
        for n in [0usize, 1, 32, 96, 112, 135, 136, 137, 192, 272] {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 31 + 17) as u8).collect();
            let digest = Keccak256::digest(&bytes);
            let basis = (0..64).map(|i| format!("{}", 1u64 << i)).collect::<Vec<_>>().join(",");
            let mut src = format!(
                "from snark_lib import *\nCOORD_BASIS_p0 = [{basis}]\n@inline\ndef bind_bits_p0(bits,value,n: Const):\n    acc = 0\n    for i in unroll(0,n):\n        b = bits[GEN ** i]\n        assert b * b == b\n        acc += b * COORD_BASIS_p0[i]\n    assert acc == value\n    return\n"
            );
            src.push_str(&keccak());
            src.push_str(&hash_function(n));
            writeln!(src, "\ndef main():\n    bits = StackBuf({})", (8 * n).max(1)).unwrap();
            constants_bits(&mut src, "bits", 0, &bytes);
            writeln!(src, "    result = keccak_hash_{n}(addr(bits))").unwrap();
            for (i, b) in digest.iter().enumerate() {
                for bit in 0..8 {
                    writeln!(src, "    assert result[GEN ** {}] == {}", 8 * i + bit, (b >> bit) & 1).unwrap();
                }
            }
            src.push_str("    return\n");
            let p = lean_compiler::compile(&lean_compiler::parse(&src).unwrap());
            p.execute([F192::ZERO; 2])
                .unwrap_or_else(|e| panic!("Keccak length {n}: {e:?}"));
        }
    }
}
