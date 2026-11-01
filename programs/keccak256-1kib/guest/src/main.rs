#![no_std]
#![no_main]
use leanvm_guest::{commit,read,keccak};
#[unsafe(no_mangle)]
extern "C" fn main() {
 let words=read::<[u64;128]>();
 commit(&keccak::keccak256(words,1024));
}
