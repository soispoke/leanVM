#![no_std]
#![no_main]
use leanvm_guest::{precompile::blake2s_compress, commit, read};
#[unsafe(no_mangle)]
extern "C" fn main() {
 let mode=*read::<u64>(); let n=*read::<u64>();
 let mut value=*read::<[u64;4]>(); let index=*read::<u64>(); commit(&value);
 for level in 0..n {
  let sibling=if mode==0 {[0u64;4]} else {*read::<[u64;4]>()};

  let (a,b)=if mode==1 && ((index>>level)&1)==1 {(sibling,value)} else {(value,sibling)};
  let m=[a[0],a[1],a[2],a[3],b[0],b[1],b[2],b[3]];
  let iv=[0xBB67_AE85_6A09_E667u64 ^ 0x0101_0020,0xA54F_F53A_3C6E_F372,0x9B05_688C_510E_527F,0x5BE0_CD19_1F83_D9AB];
  value=blake2s_compress(&iv,&m,64,true);
 }
 commit(&mode); commit(&n); commit(&index); commit(&value);
}
