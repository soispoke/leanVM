use sha3::{Digest,Keccak256};
fn hash(b:&[u8])->[u8;32] {Keccak256::digest(b).into()}
use circuit_suite::{Workload, falcon::{self, Params, native}};
use tide_fn_dsa::{CryptoRng, FALCON_KEYGEN_SEED_SIZE, FN_DSA_LOGN_512, FalconProfile, KeyPairGenerator512, RngCore, RngError, SHAKE256, SIGN_KEY_SIZE_512, SIGNATURE_SIZE_512, SigningKey, SigningKeyStandard, VRFY_KEY_SIZE_512};
struct Stream(SHAKE256);
impl Stream { fn new(label: &[u8], seed: u64) -> Self { let mut s=SHAKE256::new(); s.inject(b"leanr1cs-referee-v2").unwrap(); s.inject(label).unwrap(); s.inject(&seed.to_le_bytes()).unwrap(); s.flip().unwrap(); Self(s) } }
impl RngCore for Stream {
 fn next_u32(&mut self)->u32 {let mut b=[0;4];self.fill_bytes(&mut b);u32::from_le_bytes(b)}
 fn next_u64(&mut self)->u64 {let mut b=[0;8];self.fill_bytes(&mut b);u64::from_le_bytes(b)}
 fn fill_bytes(&mut self,d:&mut[u8]) {self.0.extract(d).unwrap();}
 fn try_fill_bytes(&mut self,d:&mut[u8])->Result<(),RngError>{self.fill_bytes(d);Ok(())}
}
impl CryptoRng for Stream {}
fn main(){
 let a:Vec<_>=std::env::args().collect();let app=&a[1];let seed:u64=a[2].parse().unwrap();let out=&a[3];std::fs::create_dir_all(out).unwrap();
 let mut extra=serde_json::json!({});
 let instance=match app.as_str(){
 "A"=>{let bytes=circuit_suite::shielded_keccak::leanvm_input(seed as usize);std::fs::write(format!("{out}/payload.bin"),&bytes).unwrap();circuit_suite::shielded_keccak::instance_of(&bytes)},
 "B"=>{
 let mut ks=[0;FALCON_KEYGEN_SEED_SIZE];Stream::new(b"key",seed).fill_bytes(&mut ks);
 let(mut sk,mut pk)=([0;SIGN_KEY_SIZE_512],[0;VRFY_KEY_SIZE_512]);KeyPairGenerator512::default().keygen_from_seed_pqclean(FN_DSA_LOGN_512,&ks,&mut sk,&mut pk).unwrap();
 let mut msg=[0;32];Stream::new(b"message",seed).fill_bytes(&mut msg);let mut sig=[0;SIGNATURE_SIZE_512];let len=SigningKeyStandard::decode(&sk).unwrap().sign_falcon(&mut Stream::new(b"signature",seed),FalconProfile::PqClean,&msg,&mut sig).unwrap();
 let p=Params::falcon512();let h=native::decode_pk(&p,&pk).unwrap();let s2=native::comp_decode(&sig[41..len],512).unwrap();let nonce=&sig[1..41];assert!(native::verify(&p,&h,&msg,nonce,&s2));
 let s1=native::s1(&p,&h,&msg,nonce,&s2);extra=serde_json::json!({"h":h,"msg":msg.to_vec(),"nonce":nonce,"s2":s2,"s1":s1,"pk_encoded":pk.to_vec(),"signature_encoded":sig[..len].to_vec(),"relation":"decoded inputs; parsing done outside circuit"});
 std::fs::write(format!("{out}/public-key.bin"),pk).unwrap();std::fs::write(format!("{out}/signature.bin"),&sig[..len]).unwrap();std::fs::write(format!("{out}/message.bin"),msg).unwrap();
 falcon::instance_for(&p,&h,&msg,nonce,&s2,Some(&s1))},
 "keccak1k"=>circuit_suite::keccak::Keccak256OneKiB::instance(seed),
 "mpt"=>{
 use circuit_suite::mpt::{self,Keccak,Params};let p=Params::MAINNET;let(root,addr,slot,value,bits)=mpt::synth_instance::<Keccak>(&p,seed);let mut paths=Vec::new();let mut off=8*(32+20+32);
 for(inner,leaf_max) in [(p.acct_inner,p.acct_leaf_max),(p.stor_inner,p.stor_leaf_max)] {let mut nodes=Vec::new();for i in 0..=inner {let n=if i==inner{leaf_max}else{p.inner_max};let bytes:Vec<u8>=(0..n).map(|k|(0..8).fold(0,|v,j|v|((bits[off+8*k+j] as u8)<<j))).collect();let active=i==inner||bits[off+8*n];if active{let(_,_,_,len)=mpt::native::item(&bytes,0);nodes.push(bytes[..len].to_vec());}off+=8*n+if i==inner{3}else{20};}paths.push(nodes);}
 extra=serde_json::json!({"root":root,"address":addr,"slot":slot,"value":value,"account_nodes":paths[0],"storage_nodes":paths[1],"relation":"bounded exact circuit predicate; serialized active nodes"});circuit_suite::mpt::MptStorageProof::instance(seed)
 },
 "merkle-keccak"=>{
 let mut words=Vec::new();for i in 0..4u64 {words.push(seed.wrapping_mul(0x10001).wrapping_add(i+17));}
 let mut root=hash(&words.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>());
 for l in 0..16u64 {let sib:Vec<u64>=(0..4).map(|i|seed.wrapping_add(3).wrapping_mul(0x1000001).wrapping_add(4*l+i)).collect();let bytes:Vec<u8>=sib.iter().flat_map(|w|w.to_le_bytes()).collect();let bit=seed.wrapping_add(l)&1;let pair=if bit==1 {[root.to_vec(),bytes].concat()}else{[bytes,root.to_vec()].concat()};root=hash(&pair);words.extend(sib);words.push(bit);}
 extra=serde_json::json!({"words":words,"root":root.to_vec(),"depth":16,"path_bit_one":"current left"});
 { let mut statement=[0;64];statement[..32].copy_from_slice(&root);let inputs=words.iter().flat_map(|w|(0..64).map(move|i|w>>i&1==1)).collect();circuit_suite::Instance { inputs,statement } }},
 _=>panic!("unknown app")};
 let record=serde_json::json!({"app":app,"seed":seed,"inputs":instance.inputs,"statement":instance.statement.to_vec(),"extra":extra,"fresh":true});std::fs::write(format!("{out}/instance.json"),serde_json::to_vec(&record).unwrap()).unwrap();println!("{}",serde_json::json!({"app":app,"seed":seed,"output":out}));
}
