use blake2::{Blake2s256, Digest};
use ml_dsa::{Keypair, MlDsa44, SigningKey};
fn main() {
    let mut seed = [0x51; 32];
    seed[..8].copy_from_slice(&0u64.to_le_bytes());
    let message = [0x42; 32];
    let key = SigningKey::<MlDsa44>::from_seed(&seed.into());
    let signature = key.expanded_key().sign_deterministic(&message, &[]).unwrap();
    let pk = key.verifying_key().encode();
    assert!(key.verifying_key().verify_with_context(&message, &[], &signature));
    let mut digest = Blake2s256::new();
    digest.update(1u64.to_le_bytes());
    digest.update(pk.as_slice());
    digest.update(message);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("{}", serde_json::json!({"source":"L5 programs/mldsa/host sign(0), ml-dsa=0.1.1","seed":hex(&seed),"pk":hex(pk.as_slice()),"message":hex(&message),"signature":hex(signature.encode().as_slice()),"public_digest":hex(&digest.finalize())}));
}
