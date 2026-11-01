//! Native-row verifier for the target-sum leanXMSS instance.
use crate::native_hash::{Builder, Word};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Fixture {
    pub claim: [u64; 9],
    pub chain_tips: Vec<[u64; 2]>,
    pub randomness: [u64; 3],
    pub path: Vec<[u64; 2]>,
}

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert_eq!(bytes.len(), N * 8);
    std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

/// Match leanVM host::batch(1). Fixture generation is outside wallet timing.
pub fn fixture() -> Fixture {
    let (sk, pk) = xmss::key_gen_from_seed([0; 32], 1234, 1234).unwrap();
    let signature = xmss::sign(&sk, &[0x42; 32], 1234).unwrap();
    let mut claim = [0; 9];
    claim[..2].copy_from_slice(&words::<2>(&pk.merkle_root));
    claim[2..4].copy_from_slice(&words::<2>(&pk.public_param));
    claim[4] = 1234;
    claim[5..].fill(0x4242_4242_4242_4242);
    Fixture {
        claim,
        chain_tips: signature.wots_signature.chain_tips.iter().map(|d| words(d)).collect(),
        randomness: words(&signature.wots_signature.randomness),
        path: signature.merkle_proof.iter().map(|d| words(d)).collect(),
    }
}

fn xor(b: &mut Builder, a: Word, c: Word) -> Word {
    b.gate(a, b.one(), c)
}
fn and(b: &mut Builder, a: Word, c: Word) -> Word {
    b.gate(a, c, b.zero())
}
fn not(b: &mut Builder, a: Word) -> Word {
    xor(b, a, b.one())
}

fn add_bits(b: &mut Builder, a: &[Word], c: &[Word]) -> Vec<Word> {
    let mut carry = b.zero();
    (0..a.len())
        .map(|i| {
            let right = c.get(i).copied().unwrap_or(b.zero());
            let axb = xor(b, a[i], right);
            let result = xor(b, axb, carry);
            let ab = and(b, a[i], right);
            let carried = and(b, axb, carry);
            carry = xor(b, ab, carried);
            result
        })
        .collect()
}

fn tweak_hash(b: &mut Builder, pp: [Word; 2], ty: u64, position: u64, index: Word, payload: &[Word]) -> [Word; 2] {
    let first = b.constant((ty << 8) | (position << 32));
    let weight = b.constant(1u64 << 32);
    let second = b.gate(index, weight, b.zero());
    let mut message = vec![first, second, pp[0], pp[1]];
    message.extend_from_slice(payload);
    let digest = b.hash_words(&message);
    [digest[0], digest[1]]
}

pub struct Application {
    pub builder: Builder,
    pub output: [u64; 4],
}

/// The schedule is independent of signature digits: compute each candidate
/// chain edge and select only edges at or above the constrained encoding digit.
pub fn create(f: &Fixture) -> Application {
    assert_eq!(f.chain_tips.len(), 42);
    assert_eq!(f.path.len(), 32);
    let mut b = Builder::default();
    let claim = f.claim.map(|v| b.input(v));
    let pp = [claim[2], claim[3]];
    let index_bits = b.bits(claim[4], 32);
    let randomness = f.randomness.map(|v| b.input(v));
    let mut payload = claim[5..].to_vec();
    payload.extend(randomness);
    payload.push(b.zero());
    let encoded = tweak_hash(&mut b, pp, 4, 0, claim[4], &payload);
    let halves = encoded.map(|w| b.bits(w, 64));
    b.assert_eq(halves[0][63], b.zero());
    b.assert_eq(halves[1][63], b.zero());
    let digits: Vec<_> = (0..42)
        .map(|i| halves[i / 21][3 * (i % 21)..3 * (i % 21) + 3].to_vec())
        .collect();
    let mut sum = vec![b.zero(); 9];
    for digit in &digits {
        sum = add_bits(&mut b, &sum, digit);
    }
    let expected = b.constant(195);
    let packed = b.pack(&sum);
    b.assert_eq(packed, expected);
    let mut ends = Vec::new();
    for (i, digit) in digits.iter().enumerate() {
        let mut current = f.chain_tips[i].map(|v| b.input(v));
        let mut enabled = b.zero();
        for step in 0..7 {
            let mut equal = b.one();
            for (bit, &d) in digit.iter().enumerate() {
                let factor = if step & (1 << bit) == 0 { not(&mut b, d) } else { d };
                equal = and(&mut b, equal, factor);
            }
            enabled = xor(&mut b, enabled, equal);
            let candidate = tweak_hash(&mut b, pp, 1, (8 * i + step) as u64, claim[4], &current);
            current = std::array::from_fn(|j| b.select(enabled, current[j], candidate[j]));
        }
        ends.extend(current);
    }
    let mut node = tweak_hash(&mut b, pp, 2, 0, claim[4], &ends);
    for level in 0..32 {
        let sibling = f.path[level].map(|v| b.input(v));
        let parent_index = b.pack(&index_bits[level + 1..]);
        let left = std::array::from_fn::<_, 2, _>(|i| b.select(index_bits[level], node[i], sibling[i]));
        let right = std::array::from_fn::<_, 2, _>(|i| b.select(index_bits[level], sibling[i], node[i]));
        node = tweak_hash(
            &mut b,
            pp,
            3,
            (level + 1) as u64,
            parent_index,
            &[left[0], left[1], right[0], right[1]],
        );
    }
    for i in 0..2 {
        b.assert_eq(node[i], claim[i]);
    }
    let output_words = b.hash_words(&claim);
    for w in output_words {
        b.expose(w);
    }
    let output = output_words.map(|w| b.value(w).c0);
    Application { builder: b, output }
}

// These fixtures exercise the legacy BLAKE2s application/bridge backend.
#[cfg(all(test, not(feature = "keccak-protocol")))]
mod tests {
    use super::*;
    #[test]
    fn exact_leanvm_signature_and_malformed_claims() {
        parallel::init();
        let f = fixture();
        let a = create(&f);
        assert!(a.builder.satisfied());
        assert_eq!(
            a.output,
            [
                16814765567871573320,
                5643609832429911137,
                18313627300063359640,
                15515260675635821613
            ]
        );
        let setup = a.builder.setup().unwrap();
        let public = a.builder.public_values();
        let proof = setup
            .prove(&a.builder.values, &a.builder.compressions, &[42; 32])
            .unwrap();
        assert!(setup.verify(&public, &[42; 32], &proof));
        for mutation in 0..4 {
            let mut bad = f.clone();
            match mutation {
                0 => bad.path[31][0] ^= 1,
                1 => bad.chain_tips[41][1] ^= 1 << 63,
                2 => bad.randomness[0] ^= 1,
                _ => bad.claim[4] |= 1 << 32,
            }
            let other = create(&bad);
            assert!(!other.builder.satisfied());
            let forged = setup
                .prove(&other.builder.values, &other.builder.compressions, &[42; 32])
                .unwrap();
            assert!(!setup.verify(&public, &[42; 32], &forged));
        }
    }
}
