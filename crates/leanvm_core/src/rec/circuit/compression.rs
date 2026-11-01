//! Full Keccak-f[1600] permutation instances for recursive hashing.
use super::Limbs;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compression(pub [u64; 25]);
impl Compression {
    pub(crate) const PADDING: Self = Self([0; 25]);
    pub const fn inputs(&self) -> &[u64; 25] {
        &self.0
    }
    pub fn output(&self) -> [u64; 25] {
        let mut state = self.0;
        primitives::keccak::keccak_f(&mut state);
        state
    }
}
pub fn chain(words: &[u64]) -> Limbs {
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    digest_limbs(&primitives::hash::hash(&bytes))
}
pub(crate) fn digest_limbs(d: &[u8; 32]) -> Limbs {
    primitives::hash::digest_words(d)
}
