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
