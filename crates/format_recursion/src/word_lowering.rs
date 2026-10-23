//! Application-independent byte arithmetic over the three frozen word tables.
use crate::{
    keccak_bridge::{KeccakBridge, WordCoordinate},
    native_hash::{Builder, Word},
};
use primitives::field::F192;

#[derive(Default)]
pub struct Lowering {
    pub b: Builder,
    queries: Vec<[WordCoordinate; 6]>,
}
impl Lowering {
    fn value(&self, a: Word) -> u64 {
        self.b.value(a).c0
    }
    fn query(&mut self, tag: u64, words: [Word; 5]) {
        let mut query = [WordCoordinate::Constant(F192::ZERO); 6];
        query[0] = WordCoordinate::Constant(F192::new(tag, 0, 0));
        for (coordinate, word) in query[1..].iter_mut().zip(words) {
            *coordinate = WordCoordinate::Variable(word.variable());
        }
        self.queries.push(query);
    }
    /// Field-linear byte serialization, not integer addition.
    pub fn pack(&mut self, bytes: &[Word]) -> Word {
        assert!(bytes.len() <= 8);
        let mut packed = Word::ZERO;
        for (i, &byte) in bytes.iter().enumerate() {
            let coefficient = self.b.constant(1 << (8 * i));
            packed = self.b.gate(byte, coefficient, packed);
        }
        packed
    }
    pub fn byte(&mut self, value: u8) -> Word {
        let byte = self.b.input(value as u64);
        self.query(1, [byte, Word::ZERO, byte, Word::ZERO, Word::ZERO]);
        byte
    }
    pub fn unpack(&mut self, word: Word, width: usize) -> Vec<Word> {
        assert!((1..=8).contains(&width));
        let value = self.value(word);
        let bytes: Vec<_> = (0..width).map(|i| self.byte((value >> (8 * i)) as u8)).collect();
        let packed = self.pack(&bytes);
        self.b.assert_eq(word, packed);
        bytes
    }
    pub fn logic8(&mut self, a: Word, b: Word) -> (Word, Word) {
        let xor = self.b.input(self.value(a) ^ self.value(b));
        let and = self.b.input(self.value(a) & self.value(b));
        self.query(1, [a, b, xor, and, Word::ZERO]);
        // Serialize both outputs so the existing arithmetic commitment owns
        // them even if a caller consumes only one result.
        self.pack(&[xor, and]);
        (xor, and)
    }
    pub fn add8(&mut self, a: Word, b: Word, carry: Word) -> (Word, Word) {
        let value = self.value(a) + self.value(b) + self.value(carry);
        let sum = self.b.input(value & 255);
        let carry_out = self.b.input(value >> 8);
        self.query(2, [a, b, carry, sum, carry_out]);
        self.pack(&[sum, carry_out]);
        (sum, carry_out)
    }
    pub fn mul8(&mut self, a: Word, b: Word) -> (Word, Word) {
        let value = self.value(a) * self.value(b);
        let low = self.b.input(value & 255);
        let high = self.b.input(value >> 8);
        self.query(3, [a, b, low, high, Word::ZERO]);
        self.pack(&[low, high]);
        (low, high)
    }
    /// Fixed-width little-endian unsigned sum, returning its overflow bit.
    pub fn add(&mut self, a: &[Word], b: &[Word]) -> (Vec<Word>, Word) {
        assert_eq!(a.len(), b.len());
        let mut carry = Word::ZERO;
        let mut out = Vec::with_capacity(a.len());
        for (&a, &b) in a.iter().zip(b) {
            let (sum, next) = self.add8(a, b, carry);
            out.push(sum);
            carry = next;
        }
        (out, carry)
    }
    /// Full-width unsigned product using byte products and carry propagation.
    pub fn mul(&mut self, a: &[Word], b: &[Word]) -> Vec<Word> {
        let width = a.len() + b.len();
        let mut out = vec![Word::ZERO; width];
        for (i, &a) in a.iter().enumerate() {
            for (j, &b) in b.iter().enumerate() {
                let (low, high) = self.mul8(a, b);
                let mut term = vec![Word::ZERO; width];
                term[i + j] = low;
                term[i + j + 1] = high;
                let (sum, carry) = self.add(&out, &term);
                self.b.assert_eq(carry, Word::ZERO);
                out = sum;
            }
        }
        out
    }
    /// Enforce an unsigned bound through the same byte carry relation.
    pub fn assert_less_than(&mut self, value: &[Word], bound: u64) {
        assert!(!value.is_empty() && value.len() < 8);
        let base = 1u64 << (8 * value.len());
        assert!(bound > 0 && bound < base);
        let complement = base - bound;
        let constant: Vec<_> = (0..value.len())
            .map(|i| self.b.constant((complement >> (8 * i)) & 255))
            .collect();
        let (_, carry) = self.add(value, &constant);
        self.b.assert_eq(carry, Word::ZERO);
    }
    /// Modular addition of little-endian byte limbs.
    pub fn add_mod(&mut self, a: &[Word], b: &[Word], modulus: u64) -> Vec<Word> {
        let (mut sum, carry) = self.add(a, b);
        sum.push(carry);
        self.remainder(&sum, modulus)
    }
    /// Unsigned subtraction modulo the fixed limb width. Carry is one iff a >= b.
    pub fn subtract(&mut self, a: &[Word], b: &[Word]) -> (Vec<Word>, Word) {
        assert_eq!(a.len(), b.len());
        let one = self.b.one();
        let mask = self.b.constant(255);
        let mut carry = one;
        let mut out = Vec::with_capacity(a.len());
        for (&a, &b) in a.iter().zip(b) {
            let complement = self.b.gate(b, one, mask);
            let (sum, next) = self.add8(a, complement, carry);
            out.push(sum);
            carry = next;
        }
        (out, carry)
    }
    pub fn sub_mod(&mut self, a: &[Word], b: &[Word], modulus: u64) -> Vec<Word> {
        assert_eq!(a.len(), b.len());
        let constant: Vec<_> = (0..a.len())
            .map(|i| self.b.constant((modulus >> (8 * i)) & 255))
            .collect();
        let (mut sum, carry) = self.add(a, &constant);
        sum.push(carry);
        let mut right = b.to_vec();
        right.push(Word::ZERO);
        let (diff, no_borrow) = self.subtract(&sum, &right);
        self.b.assert_eq(no_borrow, self.b.one());
        self.remainder(&diff, modulus)
    }
    /// Modular multiplication of little-endian byte limbs.
    pub fn mul_mod(&mut self, a: &[Word], b: &[Word], modulus: u64) -> Vec<Word> {
        let product = self.mul(a, b);
        self.remainder(&product, modulus)
    }
    /// A byte-table NTT butterfly network with ordinary constant roots.
    pub fn ntt(&mut self, mut values: Vec<Vec<Word>>, roots: &[u64], modulus: u64) -> Vec<Vec<Word>> {
        let n = values.len();
        assert!(n.is_power_of_two() && roots.len() >= n);
        let mut len = n / 2;
        let mut k = 1;
        while len > 0 {
            for start in (0..n).step_by(2 * len) {
                let constant = self.b.constant(roots[k]);
                let twiddle = self.unpack(constant, 2);
                for j in start..start + len {
                    let product = self.mul_mod(&values[j + len], &twiddle, modulus);
                    let sum = self.add_mod(&values[j], &product, modulus);
                    let diff = self.sub_mod(&values[j], &product, modulus);
                    values[j] = sum;
                    values[j + len] = diff;
                }
                k += 1;
            }
            len /= 2;
        }
        values
    }

    /// Euclidean remainder, checked with byte multiplication and addition.
    /// The modulus is a circuit constant, never a lookup-table parameter.
    pub fn remainder(&mut self, value: &[Word], modulus: u64) -> Vec<Word> {
        assert!(!value.is_empty() && value.len() <= 4 && modulus > 1 && modulus < 1u64 << 24);
        let integer = value
            .iter()
            .enumerate()
            .fold(0u64, |n, (i, &w)| n | (self.value(w) << (8 * i)));
        let width = ((64 - modulus.leading_zeros() as usize) + 7) / 8;
        let quotient = integer / modulus;
        let rem = integer % modulus;
        let q: Vec<_> = (0..value.len())
            .map(|i| self.byte((quotient >> (8 * i)) as u8))
            .collect();
        self.pack(&q);
        let r: Vec<_> = (0..width).map(|i| self.byte((rem >> (8 * i)) as u8)).collect();
        self.pack(&r);
        self.assert_less_than(&r, modulus);
        let modulus_bytes: Vec<_> = (0..width)
            .map(|i| self.b.constant((modulus >> (8 * i)) & 255))
            .collect();
        let product = self.mul(&q, &modulus_bytes);
        let mut padded_r = r.clone();
        padded_r.resize(product.len(), Word::ZERO);
        let (sum, carry) = self.add(&product, &padded_r);
        self.b.assert_eq(carry, Word::ZERO);
        let mut padded_value = value.to_vec();
        padded_value.resize(sum.len(), Word::ZERO);
        let lhs = self.pack(&sum);
        let rhs = self.pack(&padded_value);
        self.b.assert_eq(lhs, rhs);
        r
    }
    pub fn query_count(&self) -> usize {
        self.queries.len()
    }
    pub fn setup(&self) -> Option<KeccakBridge> {
        let mut queries = self.queries.clone();
        if queries.is_empty() {
            return self.b.setup_mixed();
        }
        let padding = [
            WordCoordinate::Constant(F192::new(1, 0, 0)),
            WordCoordinate::Constant(F192::ZERO),
            WordCoordinate::Constant(F192::ZERO),
            WordCoordinate::Constant(F192::ZERO),
            WordCoordinate::Constant(F192::ZERO),
            WordCoordinate::Constant(F192::ZERO),
        ];
        queries.resize(queries.len().max(2).next_power_of_two(), padding);
        self.b.setup_mixed()?.with_word_queries(&queries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ntt_matches_direct_negacyclic_evaluations_and_opens() {
        let modulus = 12289;
        let n = 8usize;
        let roots = circuit_suite::falcon::zetas(modulus, 3);
        let input: Vec<_> = (0..n).map(|i| (i as u64 * 6151 + 12288) % modulus).collect();
        let mut c = Lowering::default();
        let words: Vec<_> = input
            .iter()
            .map(|&v| {
                let w = c.b.input(v);
                c.unpack(w, 2)
            })
            .collect();
        let output = c.ntt(words, &roots, modulus);
        let psi = roots[n / 2];
        for (i, bytes) in output.iter().enumerate() {
            let br = i.reverse_bits() >> (usize::BITS - 3);
            let point = circuit_suite::falcon::powmod(psi, (2 * br + 1) as u64, modulus);
            let expected = input.iter().rev().fold(0, |acc, &v| (acc * point + v) % modulus);
            let packed = c.pack(bytes);
            assert_eq!(c.value(packed), expected, "output {i}");
            c.b.expose(packed);
        }
        assert!(c.b.satisfied());
        c.b.keccak_f([Word::ZERO; 25]);
        let setup = c.setup().expect("NTT queries all have committed witness cells");
        let context = primitives::hash::hash(b"word-ntt");
        let proof = setup
            .prove_mixed(&c.b.values, &c.b.permutations, &[], &context)
            .unwrap();
        assert!(setup.verify(&c.b.public_values(), &context, &proof));
    }

    #[test]
    fn byte_arithmetic_uses_same_tables_and_joint_opening() {
        let mut c = Lowering::default();
        let a = c.b.input(12288);
        let b = c.b.input(12289);
        let aa = c.unpack(a, 2);
        let bb = c.unpack(b, 2);
        let product = c.mul(&aa, &bb);
        let packed = c.pack(&product);
        assert_eq!(c.value(packed), 12288 * 12289);
        c.b.expose(packed);
        let rem = c.remainder(&product, 12289);
        let rem_packed = c.pack(&rem);
        assert_eq!(c.value(rem_packed), 0);
        c.b.expose(rem_packed);
        c.b.keccak_f([Word::ZERO; 25]);
        let context = primitives::hash::hash(b"word-lowering-fixed-rules");
        let setup = c.setup().expect("all query coordinates in arithmetic witness");
        let proof = setup
            .prove_mixed(&c.b.values, &c.b.permutations, &c.b.compressions, &context)
            .unwrap();
        assert!(setup.verify(&c.b.public_values(), &context, &proof));
    }
}
