#![no_std]
#![no_main]
use leanvm_guest::{commit, read};
#[unsafe(no_mangle)]
extern "C" fn main() {
    let words = read::<[u64; 210]>();
    // SAFETY: every u64 array is a contiguous byte string; the RISC-V target is little endian.
    let input: &[u8; 1680] = unsafe { &*(words as *const [u64; 210]).cast::<[u8; 1680]>() };
    commit(&keccakapps::shielded_statement(input));
}
