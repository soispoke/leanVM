#![no_std]
#![no_main]
use leanvm_guest::{commit, keccak::keccak256, read};
#[unsafe(no_mangle)]
extern "C" fn main() {
    commit(&keccak256(read::<[u64; 128]>(), 1024));
}
