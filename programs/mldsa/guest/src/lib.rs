#![no_std]
use ml_dsa::{EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};

pub const PK_BYTES: usize = 1312;
pub const SIG_BYTES: usize = 2420;
pub type PublicKey = [u64; PK_BYTES / 8];
pub type Message = [u64; 4];
pub type SignatureWords = [u64; SIG_BYTES.div_ceil(8)];

pub fn bytes<const N: usize>(words: &[u64]) -> [u8; N] {
    core::array::from_fn(|i| (words[i / 8] >> (8 * (i % 8))) as u8)
}

pub fn verify(pk: &PublicKey, message: &Message, signature: &SignatureWords) -> bool {
    if signature[SIG_BYTES / 8] >> 32 != 0 {
        return false;
    }
    let pk: EncodedVerifyingKey<MlDsa44> = bytes::<PK_BYTES>(pk).into();
    let signature = bytes::<SIG_BYTES>(signature);
    let Ok(signature) = Signature::<MlDsa44>::try_from(signature.as_slice()) else {
        return false;
    };
    let key = VerifyingKey::<MlDsa44>::decode(&pk);
    key.verify_with_context(&bytes::<32>(message), &[], &signature)
}
