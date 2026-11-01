//! Standard Keccak-256 and domain-separated transcript steps over full permutation rows.
use super::Builder;
use crate::rec::circuit::{Compression, Dw, Ew, Kw, Limbs};
use crate::rec::table::Table;
use primitives::field::F192;

impl Builder {
    fn xor_word(&mut self, a: Kw, b: Kw) -> Kw {
        let zero = self.k_zero();
        if a == zero { return b; }
        if b == zero { return a; }
        if a == b { return zero; }
        let (a, b) = (self.k_to_e1(a), self.k_to_e1(b));
        let c = self.add(a, b);
        self.e_to_k(c)[0]
    }
    fn permutation(&mut self, input: [Kw; 25]) -> [Kw; 25] {
        let permutation = Compression(input.map(|w| self.k(w)));
        let output = permutation.output().map(|v| self.free_k(v));
        let mut slots = [0; 50];
        for i in 0..25 {
            slots[i] = input[i].0;
            slots[25 + i] = output[i].0;
        }
        self.row(Table::Hash, &slots);
        self.hash.push(permutation);
        output
    }
    /// Ethereum Keccak-256 of little-endian whole words, with pad10*1 suffix 0x01.
    pub fn chain(&mut self, words: &[Kw]) -> Dw {
        let zero = self.k_zero();
        let mut state = [zero; 25];
        let (blocks, rest) = words.as_chunks::<17>();
        for block in blocks {
            for i in 0..17 {
                state[i] = self.xor_word(state[i], block[i]);
            }
            state = self.permutation(state);
        }
        for (i, &word) in rest.iter().enumerate() {
            state[i] = self.xor_word(state[i], word);
        }
        let suffix = self.k_const(1);
        state[rest.len()] = self.xor_word(state[rest.len()], suffix);
        let end = self.k_const(1 << 63);
        state[16] = self.xor_word(state[16], end);
        state = self.permutation(state);
        self.k_to_d(state[..4].try_into().unwrap())
    }
    /// Transcript seed / grinding hash Keccak-256(acc32 || x24 || ds8).
    pub fn compress(&mut self, acc: Dw, x: Ew, ds: Kw) -> (Dw, Ew) {
        let mut words = vec![self.k_const(fiat_shamir::DS_HASH)];
        words.extend(self.d_to_k(acc));
        words.extend(self.e_to_k(x));
        words.push(ds);
        let out = self.chain(&words);
        let (challenge, _) = self.d_to_e_and_k(out);
        (out, challenge)
    }
    /// Ratchet Keccak-256(state32 || step_block64). Tags and scalar count stay bound.
    pub fn step(&mut self, h: Dw, scalars: &[Ew], tag: u64) -> (Dw, Ew) {
        assert!(scalars.len() <= 2);
        let zero = self.k_zero();
        let mut words = vec![self.k_const(fiat_shamir::DS_STEP)];
        words.extend(self.d_to_k(h));
        let (first, last) = match scalars {
            [a, b] => (Some(*a), Some(*b)),
            [b] => (None, Some(*b)),
            _ => (None, None),
        };
        words.extend(first.map_or([zero; 3], |v| self.e_to_k(v)));
        words.push(self.k_const(scalars.len() as u64));
        words.extend(last.map_or([zero; 3], |v| self.e_to_k(v)));
        words.push(self.k_const(tag));
        let out = self.chain(&words);
        let (challenge, _) = self.d_to_e_and_k(out);
        (out, challenge)
    }
    /// Merkle parent, enforcing a Boolean orientation bit even for direct callers.
    pub fn node(&mut self, acc: Dw, bit: Kw, sibling: Limbs) -> Dw {
        let bit_e = self.k_to_e1(bit);
        let check = self.mul_add(bit_e, bit_e, bit_e);
        self.eq_e_const(check, F192::ZERO);
        let a = self.d_to_k(acc);
        let s = sibling.map(|v| self.free_k(v));
        let mut words = Vec::with_capacity(8);
        for right in [false, true] {
            for i in 0..4 {
                let (base, other) = if right { (s[i], a[i]) } else { (a[i], s[i]) };
                let (base, other) = (self.k_to_e1(base), self.k_to_e1(other));
                let delta = self.add(base, other);
                let selected = self.mul_k_add(delta, bit, base);
                words.push(self.e_to_k(selected)[0]);
            }
        }
        self.chain(&words)
    }
    pub fn parent(&mut self, left: Dw, right: Dw) -> Dw {
        let mut words = self.d_to_k(left).to_vec();
        words.extend(self.d_to_k(right));
        self.chain(&words)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rec::circuit::chain;
    #[test]
    fn the_chain_in_rows_is_the_native_chain() {
        for n in [0, 3, 8, 13, 16, 17, 18, 34] {
            let words: Vec<u64> = (0..n).map(|i| 0x9e3779b97f4a7c15u64.wrapping_mul(i + 1)).collect();
            let mut b = Builder::new();
            let wires: Vec<_> = words.iter().map(|&w| b.free_k(w)).collect();
            let h = b.chain(&wires);
            assert_eq!(b.d(h), chain(&words));
        }
    }
}
