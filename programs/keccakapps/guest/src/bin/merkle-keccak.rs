#![no_std]
#![no_main]
use leanvm_guest::{commit, read};
#[unsafe(no_mangle)]
extern "C" fn main() {
    commit(&keccakapps::merkle_root(read::<[u64; 84]>()).expect("Boolean path bits"));
}
