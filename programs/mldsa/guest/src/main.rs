#![no_std]
#![no_main]
use leanvm_guest::{commit, read};
use mldsa::{Message, PublicKey, SignatureWords};
leanvm_guest::advice_words!(1 << 14);
#[unsafe(no_mangle)]
extern "C" fn main() {
    let n = *read::<u64>();
    for _ in 0..n {
        let pk = read::<PublicKey>();
        let message = read::<Message>();
        let signature = read::<SignatureWords>();
        commit(&(mldsa::verify(pk, message, signature) as u64));
        commit(pk);
        commit(message);
    }
}
