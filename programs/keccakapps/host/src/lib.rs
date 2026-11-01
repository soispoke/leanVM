//! Exact L6 shielded fixture generator, copied from shielded_keccak.rs.
use keccakapps::{DEPTH, INPUT_BYTES};
use std::collections::BTreeMap;
pub fn leanvm_input(i: usize) -> Vec<u8> {
    let mut draw = Draw::new(i);

    // Two notes, each owned by its own key: values below 2^64, so every sum fits.
    let keys: [[u8; 32]; 2] = [draw.bytes(), draw.bytes()];
    let rhos: [[u8; 32]; 2] = [draw.bytes(), draw.bytes()];
    let mut values = [u128::from(draw.u64() >> 1), u128::from(draw.u64() >> 1)];
    // Two distinct leaves of the 2^20.
    let index_0 = draw.u64() as u32 % (1 << DEPTH);
    let index_1 = (index_0 + 1 + draw.u64() as u32 % ((1 << DEPTH) - 1)) % (1 << DEPTH);

    // The shape decides what leaves the pool, and which notes are empty.
    let shape = i % 3;
    if shape == 2 {
        values[1] = 0;
    }
    let total = values[0] + values[1];
    let fee = total / 1000;
    let public_amount = if shape == 1 { total / 2 } else { 0 };
    let out_0 = total - fee - public_amount;
    let outputs: [(u128, [u8; 32]); 2] = match shape {
        // The withdrawal's second output is empty: its inner part is its sink, 2.
        1 => [(out_0, draw.bytes()), (0, sink(1))],
        _ => [(out_0 - out_0 / 3, draw.bytes()), (out_0 / 3, draw.bytes())],
    };
    let recipient: [u8; 20] = if public_amount == 0 { [0; 20] } else { draw.bytes() };
    let authorizer: [u8; 20] = draw.bytes();
    let domain: [u8; 32] = draw.bytes();

    // Both inputs in one tree, whatever their values.
    let commitments = [0, 1].map(|k| note_commitment(&keys[k], &rhos[k], values[k]));
    let (root, paths) = tree([(index_0, commitments[0]), (index_1, commitments[1])]);

    // Laid out at the specification's offsets.
    let mut input = [0; INPUT_BYTES];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        input[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&root);
    put(&domain);
    put(&public_amount.to_be_bytes());
    put(&fee.to_be_bytes());
    put(&recipient);
    put(&authorizer);
    for (k, index) in [index_0, index_1].into_iter().enumerate() {
        put(&keys[k]);
        put(&rhos[k]);
        put(&values[k].to_be_bytes());
        put(&index.to_be_bytes());
        paths[k].iter().for_each(|sibling| put(sibling));
    }
    for (value, inner) in outputs {
        put(&inner);
        put(&value.to_be_bytes());
    }
    assert_eq!(at, INPUT_BYTES);
    input.to_vec()
}

/// Keccak-256-256 of a tag byte, then the parts: every hash of the specification.
fn tagged(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut message = vec![tag];
    for part in parts {
        message.extend_from_slice(part);
    }
    {
        use sha3::Digest;
        sha3::Keccak256::digest(&message).into()
    }
}

/// A note's commitment, from its spend key, randomness and value.
fn note_commitment(spend_key: &[u8; 32], rho: &[u8; 32], value: u128) -> [u8; 32] {
    let owner = tagged(1, &[spend_key]);
    let inner = tagged(5, &[&owner, rho]);
    tagged(2, &[&inner, &value.to_be_bytes()])
}

/// The root of a depth-20 tree holding `leaves` and nothing else, and each leaf's siblings, the leaf's first.
///
/// An empty leaf is 32 zero bytes, and an empty subtree the hash of two empty ones.
fn tree(leaves: [(u32, [u8; 32]); 2]) -> ([u8; 32], [[[u8; 32]; DEPTH]; 2]) {
    let mut empty = [0; 32];
    // The nodes present at the current level, by position.
    let mut level: BTreeMap<u32, [u8; 32]> = leaves.into_iter().collect();
    // Each level's siblings of the two leaves' paths, the leaf level first.
    let mut siblings = Vec::with_capacity(DEPTH);
    for depth in 0..DEPTH {
        // A sibling is present, or an empty subtree.
        siblings.push(leaves.map(|(index, _)| *level.get(&((index >> depth) ^ 1)).unwrap_or(&empty)));
        // One level up: each parent from its two children.
        let parents: BTreeMap<u32, [u8; 32]> = (level.keys())
            .map(|&position| {
                let child = |p: u32| *level.get(&p).unwrap_or(&empty);
                let left = position & !1;
                (position >> 1, tagged(4, &[&child(left), &child(left | 1)]))
            })
            .collect();
        level = parents;
        empty = tagged(4, &[&empty, &empty]);
    }
    let paths = [0, 1].map(|k| std::array::from_fn(|depth| siblings[depth][k]));
    (level[&0], paths)
}

/// The inner part an empty output in position `k` must have: `k + 1` as a 32-byte big-endian word.
const fn sink(k: usize) -> [u8; 32] {
    let mut inner = [0; 32];
    inner[31] = k as u8 + 1;
    inner
}

/// A deterministic stream of bytes: Keccak-256 of a label, the spend's index and a counter.
struct Draw {
    /// The spend's index.
    spend: u64,
    /// Draws made so far.
    count: u64,
}

impl Draw {
    const fn new(spend: usize) -> Self {
        Self {
            spend: spend as u64,
            count: 0,
        }
    }

    /// The next `N` bytes, at most 32.
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        self.count += 1;
        let block = tagged(
            0xFF,
            &[b"shielded", &self.spend.to_le_bytes(), &self.count.to_le_bytes()],
        );
        block[..N].try_into().unwrap()
    }

    /// The next 64 bits.
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }
}

pub fn merkle_input(seed: u64) -> [u64; 84] {
    let mut input = [0; 84];
    for (i, word) in input[..4].iter_mut().enumerate() {
        *word = seed.wrapping_mul(0x10001).wrapping_add(i as u64 + 17);
    }
    for level in 0..16 {
        for i in 0..4 {
            input[4 + 5 * level + i] = (seed + 3) * 0x1000001 + 4 * level as u64 + i as u64;
        }
        input[8 + 5 * level] = (seed + level as u64) & 1;
    }
    input
}

pub fn seeded_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..n)
        .map(|_| {
            s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(words: &[u64]) -> String {
        words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    #[test]
    fn l6_vectors_and_wrong_paths() {
        let payload: [u8; 1680] = leanvm_input(20261024).try_into().unwrap();
        let statement = keccakapps::shielded_statement(&payload);
        assert_eq!(
            hex(&statement[..4]),
            "599943d4ea06d97bbd20b602add63200e167a17a72d9775d91d33fa3eb72e4d3"
        );
        assert_eq!(statement[4], 1);
        let mut bad = payload;
        bad[136 + 84] ^= 1;
        assert_eq!(keccakapps::shielded_statement(&bad)[4], 0);
        let input = merkle_input(1);
        let root = keccakapps::merkle_root(&input).unwrap();
        use sha3::{Digest, Keccak256};
        let leaf: Vec<u8> = input[..4].iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut independent: [u8; 32] = Keccak256::digest(&leaf).into();
        for level in 0..16 {
            let at = 4 + 5 * level;
            let sibling: Vec<u8> = input[at..at + 4].iter().flat_map(|w| w.to_le_bytes()).collect();
            let pair = if input[at + 4] == 1 {
                [independent.as_slice(), sibling.as_slice()].concat()
            } else {
                [sibling.as_slice(), independent.as_slice()].concat()
            };
            independent = Keccak256::digest(pair).into();
        }
        let got: Vec<u8> = root.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(got, independent);
        println!("corrected L6 Merkle seed 1 root {}", hex(&root));
        let mut bad = input;
        bad[4] ^= 1;
        assert_ne!(keccakapps::merkle_root(&bad).unwrap(), root);
        bad[8] = 2;
        assert!(keccakapps::merkle_root(&bad).is_none());
    }
}
