//! Application compression circuits using the private native hash bridge.

use crate::{native_arithmetic::Circuit, private_bridge::PrivateBridge};
use flock::hash::{Compression, blake2s_compress};
use primitives::field::F192;

/// A packed pair of little-endian u32 words in a native circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word(usize);
impl Word {
    pub const ZERO: Self = Self(0);
}

/// Circuit and witness builder. Constants are public anchors, private inputs
/// remain witness variables, and compression outputs can feed later rows.
pub struct Builder {
    circuit: Circuit,
    constants: std::collections::HashMap<u64, Word>,
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    connectors: Vec<[usize; 18]>,
    pub permutations: Vec<flock::keccak::reduction::Permutation>,
    keccak_connectors: Vec<[usize; 50]>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            circuit: Circuit {
                variables: 2,
                rows: Vec::new(),
                public: vec![0, 1],
            },
            constants: [(0, Word(0)), (1, Word(1))].into_iter().collect(),
            values: vec![F192::ZERO, F192::ONE],
            compressions: Vec::new(),
            connectors: Vec::new(),
            permutations: Vec::new(),
            keccak_connectors: Vec::new(),
        }
    }
}

impl Builder {
    pub fn scalar(&mut self, value: F192) -> Word {
        let word = Word(self.values.len());
        self.values.push(value);
        self.circuit.variables += 1;
        word
    }
    pub fn value(&self, word: Word) -> F192 {
        self.values[word.0]
    }
    pub fn zero(&self) -> Word {
        Word(0)
    }
    pub fn one(&self) -> Word {
        Word(1)
    }
    pub fn gate(&mut self, a: Word, b: Word, c: Word) -> Word {
        let result = self.scalar(self.value(a) * self.value(b) + self.value(c));
        self.circuit.rows.push([a.0, b.0, c.0, result.0]);
        result
    }
    pub fn satisfied(&self) -> bool {
        self.circuit
            .rows
            .iter()
            .all(|&[a, b, c, d]| self.values[a] * self.values[b] + self.values[c] == self.values[d])
    }
    pub fn rows(&self) -> usize {
        self.circuit.rows.len()
    }
    pub fn boolean(&mut self, a: Word) {
        self.circuit.rows.push([a.0, a.0, 0, a.0]);
    }
    pub fn bits(&mut self, word: Word, n: usize) -> Vec<Word> {
        assert!(n <= 64);
        let v = self.value(word).c0;
        let bits: Vec<_> = (0..n)
            .map(|i| {
                let w = self.input((v >> i) & 1);
                self.boolean(w);
                w
            })
            .collect();
        let packed = self.pack(&bits);
        self.assert_eq(word, packed);
        bits
    }
    pub fn pack(&mut self, bits: &[Word]) -> Word {
        assert!(bits.len() <= 64);
        let mut acc = self.zero();
        for (i, &bit) in bits.iter().enumerate() {
            let weight = self.constant(1u64 << i);
            acc = self.gate(bit, weight, acc);
        }
        acc
    }
    /// Materialize a lookup query coordinate in the arithmetic witness itself.
    /// Copy/permutation wiring binds this row to the original variable.
    pub(crate) fn copy_lookup_word(&mut self, word: Word) {
        self.circuit.rows.push([word.0, 1, 0, word.0]);
    }

    /// Align an upcoming table of query coordinates in the final bridge index.
    pub(crate) fn align_lookup_rows(&mut self, log_queries: usize) -> usize {
        let public_rows = (self.circuit.public.len() + 18).next_power_of_two();
        let start = (public_rows + self.circuit.rows.len()).next_multiple_of(1usize << log_queries);
        self.circuit.rows.resize(start - public_rows, [0, 0, 0, 0]);
        start
    }

    pub fn input(&mut self, value: u64) -> Word {
        let word = Word(self.values.len());
        self.values.push(F192::new(value, 0, 0));
        self.circuit.variables += 1;
        word
    }

    pub fn constant(&mut self, value: u64) -> Word {
        if let Some(&word) = self.constants.get(&value) {
            return word;
        }
        let word = self.input(value);
        self.expose(word);
        self.constants.insert(value, word);
        word
    }

    /// The verifier must supply the expected value for every exposed word,
    /// including constants, in insertion order after the zero and one anchors.
    pub fn expose(&mut self, word: Word) {
        self.circuit.public.push(word.0);
    }

    pub fn assert_eq(&mut self, left: Word, right: Word) {
        self.circuit.rows.push([left.0, 1, 0, right.0]);
    }

    /// Counter is the byte counter; flags packs f0 in the low half and f1 in
    /// the high half. A final block uses f0 = u32::MAX and f1 = 0.
    pub fn compress(&mut self, h: [Word; 4], m: [Word; 8], counter: Word, flags: Word) -> [Word; 4] {
        let unpack = |word: Word, half: usize| (self.values[word.0].c0 >> (32 * half)) as u32;
        let initial = std::array::from_fn(|i| unpack(h[i / 2], i % 2));
        let message = std::array::from_fn(|i| unpack(m[i / 2], i % 2));
        let counter_value = self.values[counter.0].c0;
        let flag_value = self.values[flags.0].c0;
        let output = blake2s_compress(
            &initial,
            &message,
            counter_value,
            flag_value as u32,
            (flag_value >> 32) as u32,
        );
        let result =
            std::array::from_fn(|i| self.input(u64::from(output[2 * i]) | (u64::from(output[2 * i + 1]) << 32)));
        let mut io = [0; 18];
        for i in 0..4 {
            io[i] = h[i].0;
            io[4 + i] = result[i].0;
        }
        for i in 0..8 {
            io[8 + i] = m[i].0;
        }
        io[16] = counter.0;
        io[17] = flags.0;
        self.connectors.push(io);
        self.compressions.push((
            initial,
            message,
            counter_value,
            flag_value as u32,
            (flag_value >> 32) as u32,
        ));
        result
    }

    /// One native Keccak-f[1600] row. All 25 input and output lanes are
    /// bound to the permutation witness by the Keccak bridge opening.
    pub fn keccak_f(&mut self, input: [Word; 25]) -> [Word; 25] {
        let lanes = input.map(|w| self.value(w).c0);
        let output = flock::keccak::reduction::permute(&lanes);
        let result = output.map(|w| self.input(w));
        let io = std::array::from_fn(|i| if i < 25 { input[i].0 } else { result[i - 25].0 });
        self.keccak_connectors.push(io);
        self.permutations.push(lanes);
        result
    }

    /// Keccak-only application bridge. Mixed BLAKE2s/Keccak circuits require a
    /// shared commitment adapter and must not silently use either single bridge.
    pub fn setup_keccak(&self) -> Option<crate::keccak_bridge::KeccakBridge> {
        if !self.compressions.is_empty() {
            return None;
        }
        crate::keccak_bridge::KeccakBridge::new(self.circuit.clone(), self.keccak_connectors.clone())
    }

    pub fn setup_mixed(&self) -> Option<crate::keccak_bridge::KeccakBridge> {
        if cfg!(feature = "keccak-protocol") && !self.compressions.is_empty() {
            return None;
        }
        PrivateBridge::new_mixed(
            self.circuit.clone(),
            self.connectors.clone(),
            self.keccak_connectors.clone(),
        )
    }

    /// Hash an aligned byte string, with zero padding of its last block.
    /// Every supplied word is part of the message; lengths are circuit metadata.
    #[cfg(feature = "keccak-protocol")]
    pub fn hash_words(&mut self, words: &[Word]) -> [Word; 4] {
        self.keccak256_words(words)
    }

    #[cfg(not(feature = "keccak-protocol"))]
    pub fn hash_words(&mut self, words: &[Word]) -> [Word; 4] {
        let iv = flock::hash::param_iv();
        let mut h = std::array::from_fn(|i| self.constant(u64::from(iv[2 * i]) | (u64::from(iv[2 * i + 1]) << 32)));
        let blocks = words.len().div_ceil(8).max(1);
        for block in 0..blocks {
            let m = std::array::from_fn(|i| words.get(block * 8 + i).copied().unwrap_or(Word::ZERO));
            let counter = self.constant(((block + 1) * 64).min(words.len() * 8) as u64);
            let flags = self.constant(if block + 1 == blocks { u64::from(u32::MAX) } else { 0 });
            h = self.compress(h, m, counter, flags);
        }
        h
    }

    /// Keccak-256 of an aligned byte string, each word serialized little-endian.
    /// Ethereum suffix 0x01 and final 0x80; all 17 rate lanes are used.
    pub fn keccak256_words(&mut self, words: &[Word]) -> [Word; 4] {
        let mut state = [Word::ZERO; 25];
        let blocks = words.len() / 17 + 1;
        for block in 0..blocks {
            for (i, lane) in state.iter_mut().enumerate().take(17) {
                let at = block * 17 + i;
                let input = if at < words.len() {
                    words[at]
                } else if at == words.len() {
                    self.constant(1)
                } else {
                    Word::ZERO
                };
                *lane = self.gate(*lane, self.one(), input);
            }
            if block + 1 == blocks {
                let last = self.constant(1u64 << 63);
                state[16] = self.gate(state[16], self.one(), last);
            }
            state = self.keccak_f(state);
        }
        state[..4].try_into().unwrap()
    }

    /// Select b when bit is one, a otherwise. The selector is constrained Boolean.
    pub fn select(&mut self, bit: Word, a: Word, b: Word) -> Word {
        self.boolean(bit);
        let difference = self.gate(a, self.one(), b);
        self.gate(bit, difference, a)
    }

    /// Variable indices exposed by this fixed application statement.
    pub fn public_variables(&self) -> &[usize] {
        &self.circuit.public
    }

    pub fn public_values(&self) -> Vec<F192> {
        self.circuit.public.iter().map(|&i| self.values[i]).collect()
    }

    pub fn setup(&self) -> Option<PrivateBridge> {
        if !self.permutations.is_empty() {
            return None;
        }
        PrivateBridge::new(self.circuit.clone(), self.connectors.clone())
    }

    /// Export every native Keccak I/O obligation with the arithmetic graph.
    pub fn export_keccak_circuit(&self) -> (Circuit, Vec<[usize; 50]>) {
        assert!(self.compressions.is_empty(), "Keccak source export cannot discard BLAKE obligations");
        (self.circuit.clone(), self.keccak_connectors.clone())
    }

    /// Export the identical arithmetic graph and hash-port identities for format experiments.
    pub fn export_circuit(&self) -> (Circuit, Vec<[usize; 18]>) {
        assert!(self.permutations.is_empty(), "BLAKE source export cannot discard Keccak obligations");
        (self.circuit.clone(), self.connectors.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_chain_rejects_wrong_digest_and_witness_and_proof() {
        parallel::init();
        let mut b = Builder::default();
        let h = std::array::from_fn(|i| b.constant(i as u64));
        let m = std::array::from_fn(|i| b.input((i + 17) as u64));
        let counter = b.constant(64);
        let flags = b.constant(u64::from(u32::MAX));
        let first = b.compress(h, m, counter, flags);
        let second = b.compress(first, m, counter, flags);
        for word in second {
            b.expose(word);
        }
        let setup = b.setup().unwrap();
        let public = b.public_values();
        let proof = setup.prove(&b.values, &b.compressions, &[23; 32]).unwrap();
        assert!(setup.verify(&public, &[23; 32], &proof));
        let mut wrong = public.clone();
        *wrong.last_mut().unwrap() += F192::ONE;
        assert!(!setup.verify(&wrong, &[23; 32], &proof));
        let mut tampered = proof;
        tampered.stream[0] += F192::ONE;
        assert!(!setup.verify(&public, &[23; 32], &tampered));
        b.values[first[0].0] += F192::ONE;
        assert!(setup.prove(&b.values, &b.compressions, &[23; 32]).is_none());
    }
}

#[cfg(test)]
mod keccak_sponge_tests {
    use super::*;

    #[test]
    fn full_rate_and_padding_boundaries_match_reference() {
        for len in [0, 1, 4, 8, 16, 17, 18, 33, 34, 128] {
            let mut b = Builder::default();
            let words: Vec<_> = (0..len).map(|i| b.input(i as u64 * 0x10001 + 17)).collect();
            let bytes: Vec<_> = words.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
            let digest = b.keccak256_words(&words);
            let actual: Vec<_> = digest.iter().flat_map(|&w| b.value(w).c0.to_le_bytes()).collect();
            assert_eq!(actual, circuit_suite::keccak::keccak256_native(&bytes), "words={len}");
            assert_eq!(b.permutations.len(), len / 17 + 1);
            assert!(b.compressions.is_empty());
        }
    }
}
