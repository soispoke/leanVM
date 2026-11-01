#![no_std]
#![no_main]
use leanvm_guest::{commit,read};
use sha2::{Digest,Sha256};
#[unsafe(no_mangle)]
extern "C" fn main() {
 let words=read::<[u64;128]>(); let mut h=Sha256::new();
 for word in words {h.update(word.to_le_bytes());}
 let digest=h.finalize();
 let result:[u64;4]=core::array::from_fn(|i|u64::from_le_bytes(digest[i*8..i*8+8].try_into().unwrap()));
 commit(&result);
}
