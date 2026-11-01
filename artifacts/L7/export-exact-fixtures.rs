use circuit_suite::mpt::{self,Keccak,Params};
fn main(){
 let p=Params::MAINNET; let (root,addr,slot,value,bits)=mpt::synth_instance::<Keccak>(&p,20261024);
 let mut paths=Vec::new();let mut off=8*(32+20+32);
 for (inner,leaf_max) in [(p.acct_inner,p.acct_leaf_max),(p.stor_inner,p.stor_leaf_max)] {
  let mut nodes=Vec::new();
  for i in 0..=inner {
   let n=if i==inner{leaf_max}else{p.inner_max};
   let bytes:Vec<u8>=(0..n).map(|k|(0..8).fold(0,|v,j|v|((bits[off+8*k+j] as u8)<<j))).collect();
   let active=i==inner||bits[off+8*n];
   if active {let (_,_,_,len)=mpt::native::item(&bytes,0);nodes.push(bytes[..len].to_vec());}
   off+=8*n+if i==inner{3}else{20};
  } paths.push(nodes);
 }
 let v=&circuit_suite::falcon::fixtures()[20261024usize%circuit_suite::falcon::fixtures().len()];
 println!("{}",serde_json::json!({"seed":20261024,"mpt":{"root":root,"address":addr,"slot":slot,"value":value,"account_nodes":paths[0],"storage_nodes":paths[1],"statement":mpt::statement::<Keccak>(&root,&addr,&slot,&value,true)},"falcon":{"h":v.h,"message":v.msg,"nonce":v.nonce,"signature":v.sig}}));
}
