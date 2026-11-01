//! Protocol hashing is standard Keccak-256 (Ethereum suffix 0x01).
pub use crate::keccak::{Hasher, OUT_LEN, RATE as BLOCK_LEN, zero_prefix_state};
pub const LANES: usize = crate::keccak::LANES;
pub const BATCH: usize = crate::keccak::LANES;
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    crate::keccak::hash(data)
}
pub fn digest_words(digest: &[u8; OUT_LEN]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap()))
}
pub fn hash_many<const LEN: usize>(data: &[u8], out: &mut [u8]) {
    crate::keccak::hash_many(data, LEN, out);
}
pub fn hash_many_dyn_from_state(data: &[u8], len: usize, state: &[u64; 25], t_offset: u64, out: &mut [u8]) {
    assert!(t_offset.is_multiple_of(BLOCK_LEN as u64));
    crate::keccak::hash_many_from_state(data, len, state, out);
}
