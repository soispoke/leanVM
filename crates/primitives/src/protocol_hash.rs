//! Protocol hash selection. The Keccak configuration keeps the transcript's
//! domain-separated grinding chain and replaces its byte hash, not its layout.
#[cfg(not(feature = "keccak-protocol"))]
pub use crate::hash::{
    BATCH, BLOCK_LEN, Hasher, LANES, OUT_LEN, hash, hash_from_state, hash_many, hash_many_dyn_from_state,
    zero_prefix_state,
};
#[cfg(not(feature = "keccak-protocol"))]
pub type PrefixState = [u32; 8];

#[cfg(feature = "keccak-protocol")]
pub use keccak_protocol::*;

#[cfg(feature = "keccak-protocol")]
mod keccak_protocol {
    pub const BLOCK_LEN: usize = 136;
    pub const OUT_LEN: usize = 32;
    pub const LANES: usize = 8;
    pub const BATCH: usize = 8;
    pub type PrefixState = [u64; 25];

    #[derive(Clone)]
    pub struct Hasher {
        state: PrefixState,
        buffer: [u8; BLOCK_LEN],
        used: usize,
    }
    impl Default for Hasher {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Hasher {
        pub fn new() -> Self {
            Self {
                state: [0; 25],
                buffer: [0; BLOCK_LEN],
                used: 0,
            }
        }
        fn absorb(&mut self) {
            for (lane, bytes) in self.state.iter_mut().zip(self.buffer.as_chunks::<8>().0) {
                *lane ^= u64::from_le_bytes(*bytes);
            }
            keccak::Keccak::new().with_f1600(|f| f(&mut self.state));
            self.buffer.fill(0);
            self.used = 0;
        }
        pub fn update(&mut self, mut bytes: &[u8]) -> &mut Self {
            while !bytes.is_empty() {
                let take = bytes.len().min(BLOCK_LEN - self.used);
                self.buffer[self.used..self.used + take].copy_from_slice(&bytes[..take]);
                self.used += take;
                bytes = &bytes[take..];
                if self.used == BLOCK_LEN {
                    self.absorb();
                }
            }
            self
        }
        pub fn finalize(&self) -> [u8; OUT_LEN] {
            let mut h = self.clone();
            h.buffer[h.used] ^= 1;
            h.buffer[BLOCK_LEN - 1] ^= 0x80;
            h.absorb();
            let mut digest = [0; OUT_LEN];
            for (bytes, lane) in digest.as_chunks_mut::<8>().0.iter_mut().zip(h.state) {
                *bytes = lane.to_le_bytes();
            }
            digest
        }
    }
    pub fn hash(bytes: &[u8]) -> [u8; OUT_LEN] {
        Hasher::new().update(bytes).finalize()
    }
    pub fn zero_prefix_state(blocks: usize) -> PrefixState {
        let mut state = [0; 25];
        for _ in 0..blocks {
            keccak::Keccak::new().with_f1600(|f| f(&mut state));
        }
        state
    }
    pub fn hash_from_state(bytes: &[u8], state: &PrefixState, offset: u64) -> [u8; OUT_LEN] {
        assert!(offset.is_multiple_of(BLOCK_LEN as u64));
        let mut h = Hasher {
            state: *state,
            buffer: [0; BLOCK_LEN],
            used: 0,
        };
        h.update(bytes).finalize()
    }
    pub fn hash_many_dyn_from_state(bytes: &[u8], len: usize, state: &PrefixState, offset: u64, out: &mut [u8]) {
        assert!(len > 0);
        assert!(out.len().is_multiple_of(OUT_LEN));
        assert_eq!(bytes.len(), out.len() / OUT_LEN * len);
        for (input, digest) in bytes.chunks_exact(len).zip(out.as_chunks_mut::<OUT_LEN>().0.iter_mut()) {
            digest.copy_from_slice(&hash_from_state(input, state, offset));
        }
    }
    pub fn hash_many<const LEN: usize>(bytes: &[u8], out: &mut [u8]) {
        hash_many_dyn_from_state(bytes, LEN, &[0; 25], 0, out);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use sha3::Digest;
        #[test]
        fn ethereum_padding_streaming_batch_and_prefix() {
            for len in [0, 1, 32, 64, 135, 136, 137, 271, 272, 1024] {
                let bytes: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
                let expected: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
                assert_eq!(hash(&bytes), expected, "length={len}");
                let mut stream = Hasher::new();
                for chunk in bytes.chunks(7) {
                    stream.update(chunk);
                }
                assert_eq!(stream.finalize(), expected);
                if len > 0 {
                    let mut out = [0; 64];
                    hash_many_dyn_from_state(
                        &[bytes.as_slice(), bytes.as_slice()].concat(),
                        len,
                        &[0; 25],
                        0,
                        &mut out,
                    );
                    assert_eq!(&out[..32], &expected);
                    assert_eq!(&out[32..], &expected);
                }
                for blocks in [0, 1, 3] {
                    let full = [vec![0; blocks * BLOCK_LEN], bytes.clone()].concat();
                    assert_eq!(
                        hash_from_state(&bytes, &zero_prefix_state(blocks), (blocks * BLOCK_LEN) as u64),
                        hash(&full)
                    );
                }
            }
        }
    }
}
