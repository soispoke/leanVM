//! Keccak-f[1600] as a straight-line GF(2) circuit, emitted as one zkDSL function.
//!
//! Every state bit is one machine word, `+` is XOR and `*` is AND on bits. The
//! circuit folds constants (iota and padding cost nothing: a constant only flips a
//! wire's polarity) and shares repeated subterms, so a round is the theta parity
//! network (two XORs a bit) plus chi (one AND and about two XORs a bit). The state
//! lives in frame cells, so no round reads or writes the heap.
use std::collections::HashMap;
use std::fmt::Write;

pub(crate) const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
/// `ROT[x][y]`, the rho offset of lane `(x, y)`.
pub(crate) const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub(crate) const STATE: usize = 1600;
/// Bytes absorbed per permutation by Keccak-256.
pub(crate) const RATE: usize = 136;
pub(crate) const fn at(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}

/// A wire: `node ⊕ flip`, where `node` is an input or a gate and `None` is zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Bit {
    node: Option<u32>,
    flip: bool,
}
impl Bit {
    pub(crate) const ZERO: Self = Self {
        node: None,
        flip: false,
    };
    pub(crate) const ONE: Self = Self { node: None, flip: true };
    fn of(node: u32) -> Self {
        Self {
            node: Some(node),
            flip: false,
        }
    }
    fn not(self) -> Self {
        Self {
            flip: !self.flip,
            ..self
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Gate {
    Xor(u32, u32),
    And(u32, u32),
}
/// Nodes `0..inputs` are inputs; node `inputs + i` is `gates[i]`.
pub(crate) struct Circuit {
    pub inputs: u32,
    pub gates: Vec<Gate>,
    memo: HashMap<Gate, u32>,
}
impl Circuit {
    pub(crate) fn new(inputs: usize) -> Self {
        Self {
            inputs: inputs as u32,
            gates: Vec::new(),
            memo: HashMap::new(),
        }
    }
    pub(crate) fn input(&self, i: usize) -> Bit {
        assert!(i < self.inputs as usize);
        Bit::of(i as u32)
    }
    fn gate(&mut self, gate: Gate) -> u32 {
        let next = self.inputs + self.gates.len() as u32;
        *self.memo.entry(gate).or_insert_with(|| {
            self.gates.push(gate);
            next
        })
    }
    pub(crate) fn xor(&mut self, a: Bit, b: Bit) -> Bit {
        let node = match (a.node, b.node) {
            (None, n) | (n, None) => n,
            (Some(x), Some(y)) if x == y => None,
            (Some(x), Some(y)) => Some(self.gate(Gate::Xor(x.min(y), x.max(y)))),
        };
        Bit {
            node,
            flip: a.flip ^ b.flip,
        }
    }
    /// `(x ⊕ fa)(y ⊕ fb) = xy ⊕ fb·x ⊕ fa·y ⊕ fa·fb`. Inputs are bits, so `x·x = x`.
    pub(crate) fn and(&mut self, a: Bit, b: Bit) -> Bit {
        let (Some(x), Some(y)) = (a.node, b.node) else {
            let (constant, other) = if a.node.is_none() { (a, b) } else { (b, a) };
            return if constant.flip { other } else { Bit::ZERO };
        };
        let product = if x == y {
            x
        } else {
            self.gate(Gate::And(x.min(y), x.max(y)))
        };
        let mut r = Bit {
            node: Some(product),
            flip: a.flip & b.flip,
        };
        if b.flip {
            r = self.xor(r, Bit::of(x));
        }
        if a.flip {
            r = self.xor(r, Bit::of(y));
        }
        r
    }
    pub(crate) fn round(&mut self, a: &[Bit], rc: u64) -> Vec<Bit> {
        let mut c = [[Bit::ZERO; 64]; 5];
        for x in 0..5 {
            for z in 0..64 {
                c[x][z] = (0..5).fold(Bit::ZERO, |acc, y| self.xor(acc, a[at(x, y, z)]));
            }
        }
        let mut b = vec![Bit::ZERO; STATE];
        for x in 0..5 {
            for z in 0..64 {
                let d = self.xor(c[(x + 4) % 5][z], c[(x + 1) % 5][(z + 63) % 64]);
                for y in 0..5 {
                    b[at(y, (2 * x + 3 * y) % 5, (z + ROT[x][y]) % 64)] = self.xor(a[at(x, y, z)], d);
                }
            }
        }
        let mut out = vec![Bit::ZERO; STATE];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let t = self.and(b[at((x + 1) % 5, y, z)].not(), b[at((x + 2) % 5, y, z)]);
                    out[at(x, y, z)] = self.xor(b[at(x, y, z)], t);
                }
            }
        }
        for (z, bit) in out[..64].iter_mut().enumerate() {
            if rc >> z & 1 == 1 {
                *bit = bit.not();
            }
        }
        out
    }
    pub(crate) fn permutation(&mut self, state: &[Bit]) -> Vec<Bit> {
        RC.iter().fold(state.to_vec(), |s, &rc| self.round(&s, rc))
    }
}

fn operand(node: u32, inputs: u32) -> String {
    if node < inputs {
        format!("s{node}")
    } else {
        format!("t{node}")
    }
}
/// `def keccak_f(s0, .., s1599)`, returning the permuted state as a `StackBuf(1600)`.
/// A gate whose only use is one unflipped output is computed straight into it.
pub(crate) fn permutation_function() -> String {
    let mut circuit = Circuit::new(STATE);
    let state: Vec<_> = (0..STATE).map(|i| circuit.input(i)).collect();
    let out = circuit.permutation(&state);
    let n = circuit.inputs;
    let mut uses = vec![0usize; (n as usize) + circuit.gates.len()];
    for gate in &circuit.gates {
        let (Gate::Xor(a, b) | Gate::And(a, b)) = *gate;
        uses[a as usize] += 1;
        uses[b as usize] += 1;
    }
    for bit in &out {
        if let Some(node) = bit.node {
            uses[node as usize] += 1;
        }
    }
    let direct: HashMap<u32, usize> = out
        .iter()
        .enumerate()
        .filter_map(|(i, bit)| {
            bit.node
                .filter(|&k| k >= n && !bit.flip && uses[k as usize] == 1)
                .map(|k| (k, i))
        })
        .collect();
    let params = (0..STATE).map(|i| format!("s{i}")).collect::<Vec<_>>().join(", ");
    let mut f = format!("\ndef keccak_f({params}):\n    out = StackBuf({STATE})\n");
    for (i, gate) in circuit.gates.iter().enumerate() {
        let node = n + i as u32;
        let (a, op, b) = match *gate {
            Gate::Xor(a, b) => (a, '+', b),
            Gate::And(a, b) => (a, '*', b),
        };
        let target = direct
            .get(&node)
            .map_or_else(|| format!("t{node}"), |o| format!("out[{o}]"));
        writeln!(f, "    {target} = {} {op} {}", operand(a, n), operand(b, n)).unwrap();
    }
    for (i, bit) in out.iter().enumerate() {
        match (bit.node, bit.flip) {
            (Some(k), false) if direct.contains_key(&k) => {}
            (Some(k), flip) => {
                writeln!(f, "    out[{i}] = {}{}", operand(k, n), if flip { " + 1" } else { "" }).unwrap()
            }
            (None, flip) => writeln!(f, "    out[{i}] = {}", u8::from(flip)).unwrap(),
        }
    }
    f.push_str("    return out\n");
    f
}

/// Keccak-256 of the bit expressions `bits` (LSB first within each byte), bound to the
/// `StackBuf(1600)` named `name`; its first 256 cells are the digest. Each block is
/// one call of [`permutation_function`]; padding constants are passed as literals.
pub(crate) fn hash(m: &mut String, name: &str, bits: &[String]) {
    assert_eq!(bits.len() % 8, 0, "Keccak-256 hashes whole bytes");
    let blocks = bits.len() / (8 * RATE) + 1;
    let rate_bits = 8 * RATE;
    let mut previous: Option<String> = None;
    for block in 0..blocks {
        let args: Vec<String> = (0..STATE)
            .map(|i| {
                let p = block * rate_bits + i;
                let message = if i >= rate_bits {
                    None
                } else if p < bits.len() {
                    Some(bits[p].clone())
                } else {
                    let pad = p == bits.len() || (block + 1 == blocks && i + 1 == rate_bits);
                    pad.then(|| "1".to_string())
                };
                match (&previous, message) {
                    (None, m) => m.unwrap_or_else(|| "0".into()),
                    (Some(s), None) => format!("{s}[{i}]"),
                    (Some(s), Some(m)) => format!("{s}[{i}] + {m}"),
                }
            })
            .collect();
        let target = if block + 1 == blocks {
            name.to_string()
        } else {
            format!("{name}_block{block}")
        };
        writeln!(m, "    {target} = keccak_f({})", args.join(", ")).unwrap();
        previous = Some(target);
    }
}

#[cfg(test)]
mod tests {
    //! The circuit is checked against an independent FIPS 202 reference written here
    //! from the specification, which is itself checked against `sha3`.
    use super::*;
    use sha3::{Digest, Keccak256};

    /// Reference round on 64 bitsliced instances: `a[i]` holds bit `i` of each.
    fn reference_round(a: &[u64], rc: u64) -> Vec<u64> {
        let lane = |x: usize, y: usize| 5 * y + x;
        let mut lanes = [[0u64; 64]; 25];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    lanes[lane(x, y)][z] = a[at(x, y, z)];
                }
            }
        }
        // theta
        let parity: Vec<[u64; 64]> = (0..5)
            .map(|x| std::array::from_fn(|z| (0..5).fold(0, |p, y| p ^ lanes[lane(x, y)][z])))
            .collect();
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    lanes[lane(x, y)][z] ^= parity[(x + 4) % 5][z] ^ parity[(x + 1) % 5][(z + 63) % 64];
                }
            }
        }
        // rho then pi: B[y][2x+3y] = rot(A[x][y], r[x][y]), rot moving bit z to z + r.
        let mut b = [[0u64; 64]; 25];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    b[lane(y, (2 * x + 3 * y) % 5)][(z + ROT[x][y]) % 64] = lanes[lane(x, y)][z];
                }
            }
        }
        // chi, iota
        let mut out = vec![0u64; STATE];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    out[at(x, y, z)] = b[lane(x, y)][z] ^ (!b[lane((x + 1) % 5, y)][z] & b[lane((x + 2) % 5, y)][z]);
                }
            }
        }
        for z in 0..64 {
            if rc >> z & 1 == 1 {
                out[z] = !out[z];
            }
        }
        out
    }
    /// Round constants from the FIPS 202 LFSR, not from the table above.
    fn lfsr_constants() -> Vec<u64> {
        let mut r: u8 = 1;
        let mut bit = || {
            let out = r & 1;
            r = if r & 0x80 != 0 { (r << 1) ^ 0x71 } else { r << 1 };
            out
        };
        (0..24)
            .map(|_| (0..7).fold(0u64, |rc, j| rc | (u64::from(bit()) << ((1 << j) - 1))))
            .collect()
    }
    fn reference_keccak256(bytes: &[u8]) -> Vec<u8> {
        let mut padded = bytes.to_vec();
        padded.push(1);
        padded.resize(padded.len().div_ceil(RATE) * RATE, 0);
        *padded.last_mut().unwrap() |= 0x80;
        let mut state = vec![0u64; STATE];
        for block in padded.chunks(RATE) {
            for (i, byte) in block.iter().enumerate() {
                for k in 0..8 {
                    state[8 * i + k] ^= if byte >> k & 1 == 1 { u64::MAX } else { 0 };
                }
            }
            for &rc in &lfsr_constants() {
                state = reference_round(&state, rc);
            }
        }
        (0..32)
            .map(|i| (0..8).fold(0u8, |b, k| b | ((state[8 * i + k] & 1) as u8) << k))
            .collect()
    }
    /// Evaluate the emitted `keccak_f` text itself, bitsliced, so the check covers
    /// the exact source the guest compiles rather than the builder that produced it.
    fn interpret(source: &str, inputs: &[u64]) -> Vec<u64> {
        let mut cells: HashMap<&str, u64> = HashMap::new();
        let mut out = vec![None; STATE];
        let value = |cells: &HashMap<&str, u64>, t: &str| -> u64 {
            match t {
                "0" => 0,
                "1" => u64::MAX,
                _ if t.starts_with('s') => inputs[t[1..].parse::<usize>().unwrap()],
                _ => cells[t],
            }
        };
        for line in source.lines().map(str::trim) {
            if line.is_empty() || line.starts_with("def ") || line.starts_with("out = ") || line.starts_with("return") {
                continue;
            }
            let (target, expr) = line.split_once(" = ").unwrap();
            let tokens: Vec<&str> = expr.split(' ').collect();
            let v = match tokens.as_slice() {
                [a] => value(&cells, a),
                [a, "+", b] => value(&cells, a) ^ value(&cells, b),
                [a, "*", b] => value(&cells, a) & value(&cells, b),
                _ => panic!("unexpected line {line}"),
            };
            if let Some(i) = target.strip_prefix("out[").and_then(|t| t.strip_suffix(']')) {
                let i: usize = i.parse().unwrap();
                assert!(out[i].replace(v).is_none(), "output {i} written twice");
            } else {
                assert!(
                    target.starts_with('t') && cells.insert(target, v).is_none(),
                    "bad target {target}"
                );
            }
        }
        out.into_iter().map(|v| v.expect("every output written")).collect()
    }

    #[test]
    fn constants_match_the_specification() {
        assert_eq!(lfsr_constants(), RC);
        // rho offsets: (t+1)(t+2)/2 along the orbit (x, y) -> (y, 2x + 3y) from (1, 0).
        let (mut x, mut y) = (1, 0);
        let mut rot = [[0usize; 5]; 5];
        for t in 0..24 {
            rot[x][y] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        assert_eq!(rot, ROT);
    }

    #[test]
    fn reference_matches_sha3() {
        for n in [0usize, 1, 31, 32, 96, 112, 135, 136, 137, 192, 271, 272, 273] {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 73 + 5) as u8).collect();
            assert_eq!(
                reference_keccak256(&bytes),
                Keccak256::digest(&bytes).to_vec(),
                "length {n}"
            );
        }
    }

    /// Exhaustive equivalence of one generated round with the reference round.
    ///
    /// Without iota both are polynomials of degree at most two over GF(2) in the 1600
    /// input bits (theta, rho and pi are linear; chi multiplies two linear forms).
    /// A polynomial of degree at most two is determined by its values on the inputs of
    /// Hamming weight at most two (Möbius inversion: the coefficient of `x_S` is the
    /// sum of the values on the subsets of `S`). So agreement on all 1,280,801 such
    /// inputs proves the two rounds equal on every input. Iota is a constant per round,
    /// compared separately against the LFSR.
    #[test]
    fn round_is_exactly_the_reference_round() {
        let mut circuit = Circuit::new(STATE);
        let state: Vec<_> = (0..STATE).map(|i| circuit.input(i)).collect();
        let out = circuit.round(&state, 0);
        let mut points: Vec<Vec<usize>> = vec![vec![]];
        points.extend((0..STATE).map(|i| vec![i]));
        points.extend((0..STATE).flat_map(|i| (i + 1..STATE).map(move |j| vec![i, j])));
        assert_eq!(points.len(), 1 + 1600 + 1600 * 1599 / 2);
        for chunk in points.chunks(64) {
            let mut inputs = vec![0u64; STATE];
            for (lane, point) in chunk.iter().enumerate() {
                for &i in point {
                    inputs[i] |= 1 << lane;
                }
            }
            let mut values = inputs.clone();
            for gate in &circuit.gates {
                values.push(match *gate {
                    Gate::Xor(a, b) => values[a as usize] ^ values[b as usize],
                    Gate::And(a, b) => values[a as usize] & values[b as usize],
                });
            }
            let mask = if chunk.len() == 64 {
                u64::MAX
            } else {
                (1 << chunk.len()) - 1
            };
            let expected = reference_round(&inputs, 0);
            for (bit, want) in out.iter().zip(&expected) {
                let got = bit.node.map_or(0, |k| values[k as usize]) ^ if bit.flip { u64::MAX } else { 0 };
                assert_eq!(got & mask, want & mask);
            }
        }
    }

    /// The emitted 24-round function, read back from its text, against the reference
    /// permutation on random states.
    #[test]
    fn emitted_permutation_matches_reference() {
        let source = permutation_function();
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..4 {
            let inputs: Vec<u64> = (0..STATE).map(|_| next()).collect();
            let expected = lfsr_constants()
                .iter()
                .fold(inputs.clone(), |s, &rc| reference_round(&s, rc));
            assert_eq!(interpret(&source, &inputs), expected);
        }
    }

    /// The guest itself: the compiled VM program hashes like `sha3` at every PIOP length
    /// and on both sides of the block boundary.
    #[test]
    fn compiled_hash_matches_sha3() {
        for n in [0usize, 1, 32, 96, 112, 135, 136, 137, 192, 272] {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 31 + 17) as u8).collect();
            let bits: Vec<String> = bytes
                .iter()
                .flat_map(|b| (0..8).map(move |k| ((b >> k) & 1).to_string()))
                .collect();
            let mut src = String::from("from snark_lib import *\n");
            src.push_str(&permutation_function());
            src.push_str("\ndef main():\n");
            hash(&mut src, "h", &bits);
            for (i, b) in Keccak256::digest(&bytes).iter().enumerate() {
                for k in 0..8 {
                    writeln!(src, "    assert h[{}] == {}", 8 * i + k, (b >> k) & 1).unwrap();
                }
            }
            src.push_str("    return\n");
            let p = lean_compiler::compile(&lean_compiler::parse(&src).unwrap());
            p.execute([primitives::field::F192::ZERO; 2])
                .unwrap_or_else(|e| panic!("Keccak length {n}: {e:?}"));
        }
    }
}
