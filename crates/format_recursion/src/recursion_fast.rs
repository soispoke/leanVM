//! Statement adapter for recursion.fast's pinned byte relation.
//!
//! These circuits calculate leaf statements and the node digest. A node digest
//! circuit alone does not check child proofs and is not a recursive verifier.
//! This adapter adds no Lean certificate or security claim for the proof backend.

use circuit_suite::{Circuit, Ckt, Src, Wire, Word, blake2s, bytes_to_bits, read_statement};

pub type Digest = [u8; 32];
pub const CONTRACT_REVISION: &str = "15e4ae5eaba6a65211668c6e0f55f9fea1d9050d";
pub const CHAIN_CAP: u64 = 1 << 20;
pub const PROOF_CAP: usize = 1 << 20;
pub const TAG_CHAIN: u8 = 0x43;
pub const TAG_LEAF: u8 = 0x4c;
pub const TAG_NODE: u8 = 0x4e;
pub const TAG_RO: u8 = 0x52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ChainTooLong,
    RowLimit,
}

fn tagged_bytes(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![tag];
    for part in parts {
        bytes.extend_from_slice(part);
    }
    bytes
}

pub fn enc64(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

pub fn chain_step(digest: &Digest) -> Digest {
    primitives::hash::hash(&tagged_bytes(TAG_CHAIN, &[digest]))
}

pub fn chain_end(start: &Digest, n: u64) -> Result<Digest, Error> {
    if n > CHAIN_CAP {
        return Err(Error::ChainTooLong);
    }
    Ok((0..n).fold(*start, |digest, _| chain_step(&digest)))
}

/// Hash an already computed chain end, with the same length bound as the relation.
pub fn leaf_statement(end: &Digest, n: u64) -> Result<Digest, Error> {
    if n > CHAIN_CAP {
        return Err(Error::ChainTooLong);
    }
    Ok(primitives::hash::hash(&tagged_bytes(TAG_LEAF, &[end, &enc64(n)])))
}

/// Independent native path: no circuit evaluation or prover advice is used.
pub fn expected_leaf(start: &Digest, n: u64) -> Result<Digest, Error> {
    leaf_statement(&chain_end(start, n)?, n)
}

pub fn node_statement(left: &Digest, right: &Digest) -> Digest {
    primitives::hash::hash(&tagged_bytes(TAG_NODE, &[left, right]))
}

pub fn oracle(query: &[u8]) -> Digest {
    primitives::hash::hash(&tagged_bytes(TAG_RO, &[query]))
}

/// Check the node relation using the caller's instantiated child verifier.
/// Both child proofs must fit the contract's Vb wrapper before verification.
pub fn node_relation(
    expected: &Digest,
    left: &Digest,
    left_proof: &[u8],
    right: &Digest,
    right_proof: &[u8],
    mut verify_child: impl FnMut(&Digest, &[u8]) -> bool,
) -> bool {
    left_proof.len() <= PROOF_CAP
        && right_proof.len() <= PROOF_CAP
        && node_statement(left, right) == *expected
        && verify_child(left, left_proof)
        && verify_child(right, right_proof)
}

fn constant_bytes(bytes: &[u8]) -> Word {
    bytes_to_bits(bytes).into_iter().map(Wire::constant).collect()
}

fn tagged_circuit(c: &mut Ckt, tag: u8, parts: &[&[Wire]]) -> Word {
    let mut message = constant_bytes(&[tag]);
    for part in parts {
        message.extend_from_slice(part);
    }
    blake2s::blake2s(c, &message)
}

fn check_rows(c: &Ckt, row_limit: usize) -> Result<(), Error> {
    if c.rows() > row_limit {
        Err(Error::RowLimit)
    } else {
        Ok(())
    }
}

/// Digest gadget for composition with two actual child-verifier circuits.
pub fn node_digest(c: &mut Ckt, left: &[Wire; 256], right: &[Wire; 256]) -> Word {
    tagged_circuit(c, TAG_NODE, &[left, right])
}

/// Fixed-length leaf circuit: only the start is private. The first 32 public
/// bytes hold the contract digest, and the remaining 32 bytes are fixed zeros.
pub struct LeafCircuit {
    pub circuit: Circuit,
    pub public_sources: Vec<Src>,
    pub chain_length: u64,
}

impl LeafCircuit {
    /// Bound construction by rows, checking after each hash rather than building
    /// an entire oversized chain. The final padded circuit must fit too.
    pub fn build(n: u64, row_limit: usize) -> Result<Self, Error> {
        if n > CHAIN_CAP {
            return Err(Error::ChainTooLong);
        }
        // Circuit cell and permutation addresses use u32. This is an adapter
        // construction limit, not a new limit on the challenge relation.
        if !(1 << circuit_suite::MIN_LOG_ROWS..=1 << 29).contains(&row_limit) {
            return Err(Error::RowLimit);
        }
        let mut c = Ckt::new();
        let mut digest = c.inputs(256);
        for _ in 0..n {
            digest = tagged_circuit(&mut c, TAG_CHAIN, &[&digest]);
            check_rows(&c, row_limit)?;
        }
        digest = tagged_circuit(&mut c, TAG_LEAF, &[&digest, &constant_bytes(&enc64(n))]);
        check_rows(&c, row_limit)?;
        digest.resize(circuit_suite::PUBLIC_BITS, Wire::ZERO);
        if (1usize << c.log_rows_for(&digest)) > row_limit {
            return Err(Error::RowLimit);
        }
        let (circuit, public_sources) = c.finish(&digest);
        Ok(Self {
            circuit,
            public_sources,
            chain_length: n,
        })
    }

    /// Reference evaluation only. Proof acceptance must separately verify the
    /// backend argument against this exact public statement and fixed index.
    pub fn evaluate(&self, start: &Digest) -> [u8; 64] {
        read_statement(&self.circuit.values(&bytes_to_bits(start)), &self.public_sources)
    }

    pub fn public_statement(expected: &Digest) -> [u8; 64] {
        let mut public = [0; 64];
        public[..32].copy_from_slice(expected);
        public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(hex: &str) -> Digest {
        assert_eq!(hex.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn independent_hashlib_tag_vectors() {
        // Generated independently with Python hashlib.blake2s, not these helpers.
        let start = std::array::from_fn(|i| i as u8);
        for (n, end, expected) in [
            (
                0,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "c45a9178d03d11311448aa3ae70050f48038607a324ec127ff095a236163a664",
            ),
            (
                1,
                "7b3746567b4e4fabc189813de4005675433183b47660560825d4741774350544",
                "775d71de608565541a72a851c52f6d22a18187f1a9e587ad144611df29d3d5cd",
            ),
            (
                2,
                "84de040b23986f9880cc37aec1852359e17c164ac488dc81edf784cee0ae1945",
                "c594018cbf51defe61cfcb8b455786e24e528adafa81be2a314195c5c711bb48",
            ),
            (
                16,
                "a71f6bd7ac08ab5936654a7904bd8feb7636e1f0eb556ae2619ba7c1be41e58d",
                "c81156bc71500494780f6635d8533cb9e7b738f5c408ebadb58ceef477cd2b4b",
            ),
        ] {
            assert_eq!(chain_end(&start, n), Ok(digest(end)));
            assert_eq!(expected_leaf(&start, n), Ok(digest(expected)));
        }
        let right = std::array::from_fn(|i| (32 + i) as u8);
        assert_eq!(
            node_statement(&start, &right),
            digest("866619172f453a537ead1581419d995c6d48c496ece42801663c57a44234422c")
        );
        assert_eq!(
            oracle(&[1, 2, 3]),
            digest("5d32eaa721251d8e473bc410cf953591949de810e935f6e06caa3f8d5ae9cf84")
        );
        assert_eq!(enc64(0x0102_0304_0506_0708), [8, 7, 6, 5, 4, 3, 2, 1]);
        assert!(leaf_statement(&start, CHAIN_CAP).is_ok());
    }

    #[test]
    fn leaf_circuit_binds_start_length_digest_and_padding() {
        let start = std::array::from_fn(|i| i as u8);
        for n in [0, 1, 2, 16] {
            let leaf = LeafCircuit::build(n, 1 << 20).unwrap();
            leaf.circuit.check_wired().unwrap();
            assert_eq!(leaf.circuit.n_inputs(), 256);
            let public = LeafCircuit::public_statement(&expected_leaf(&start, n).unwrap());
            assert_eq!(leaf.evaluate(&start), public);
            let mut changed = start;
            changed[0] ^= 1;
            assert_ne!(leaf.evaluate(&changed), public);
            assert_ne!(
                LeafCircuit::public_statement(&expected_leaf(&start, n + 1).unwrap()),
                public
            );
            let mut bad_digest = public;
            bad_digest[0] ^= 1;
            assert_ne!(leaf.evaluate(&start), bad_digest);
            let mut bad_padding = public;
            bad_padding[63] = 1;
            assert_ne!(leaf.evaluate(&start), bad_padding);
        }
    }

    #[test]
    fn reject_chain_and_construction_caps_before_large_work() {
        assert_eq!(chain_end(&[0; 32], CHAIN_CAP + 1), Err(Error::ChainTooLong));
        assert_eq!(leaf_statement(&[0; 32], CHAIN_CAP + 1), Err(Error::ChainTooLong));
        assert!(matches!(
            LeafCircuit::build(CHAIN_CAP + 1, 1 << 20),
            Err(Error::ChainTooLong)
        ));
        for limit in [0, 1, (1 << 12) - 1, (1 << 29) + 1] {
            assert!(matches!(LeafCircuit::build(0, limit), Err(Error::RowLimit)));
        }
        assert!(matches!(LeafCircuit::build(CHAIN_CAP, 1 << 12), Err(Error::RowLimit)));
    }

    #[test]
    fn node_gadget_binds_order_and_both_children() {
        let left = std::array::from_fn(|i| i as u8);
        let right = std::array::from_fn(|i| (32 + i) as u8);
        let mut c = Ckt::new();
        let left_bits = c.inputs(256).try_into().unwrap();
        let right_bits = c.inputs(256).try_into().unwrap();
        let mut output = node_digest(&mut c, &left_bits, &right_bits);
        output.resize(circuit_suite::PUBLIC_BITS, Wire::ZERO);
        let (circuit, sources) = c.finish(&output);
        circuit.check_wired().unwrap();
        let mut bytes = left.to_vec();
        bytes.extend_from_slice(&right);
        let got = read_statement(&circuit.values(&bytes_to_bits(&bytes)), &sources);
        assert_eq!(got, LeafCircuit::public_statement(&node_statement(&left, &right)));
        assert_ne!(got, LeafCircuit::public_statement(&node_statement(&right, &left)));
        for at in [0, 31, 32, 63] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert_ne!(read_statement(&circuit.values(&bytes_to_bits(&changed)), &sources), got);
        }
    }

    #[test]
    fn native_node_relation_requires_actual_child_acceptance_and_caps() {
        let left = [1; 32];
        let right = [2; 32];
        let expected = node_statement(&left, &right);
        let accept = |d: &Digest, proof: &[u8]| proof == d;
        assert!(node_relation(&expected, &left, &left, &right, &right, accept));
        assert!(!node_relation(&expected, &left, &left, &right, &left, accept));
        assert!(!node_relation(&expected, &right, &right, &left, &left, accept));
        let mut bad = expected;
        bad[0] ^= 1;
        assert!(!node_relation(&bad, &left, &left, &right, &right, accept));
        let oversized = vec![0; PROOF_CAP + 1];
        let never = |_: &Digest, _: &[u8]| panic!("must reject oversized proof first");
        assert!(!node_relation(&expected, &left, &oversized, &right, &right, never));
        assert!(!node_relation(&expected, &left, &left, &right, &oversized, never));
    }
}
