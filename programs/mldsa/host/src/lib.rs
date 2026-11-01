use leanvm_guest::{PublicValues, Run};
use ml_dsa::{Keypair, MlDsa44, SigningKey};
use mldsa::{Message, PublicKey, SignatureWords};
pub const ELF: &[u8] = include_bytes!("../../mldsa.elf");
pub const MESSAGE: Message = [0x4242_4242_4242_4242; 4];

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut out = [0; N];
    for (i, b) in bytes.iter().enumerate() {
        out[i / 8] |= u64::from(*b) << (8 * (i % 8));
    }
    out
}
pub fn sign(i: usize) -> (PublicKey, SignatureWords) {
    let mut seed = [0x51; 32];
    seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
    let key = SigningKey::<MlDsa44>::from_seed(&seed.into());
    let signature = key
        .expanded_key()
        .sign_deterministic(&mldsa::bytes::<32>(&MESSAGE), &[])
        .unwrap();
    (
        words(key.verifying_key().encode().as_slice()),
        words(signature.encode().as_slice()),
    )
}
pub fn batch(n: usize) -> Run {
    let mut advice = vec![n as u64];
    let mut public = PublicValues::new();
    for i in 0..n {
        let (pk, sig) = sign(i);
        assert!(mldsa::verify(&pk, &MESSAGE, &sig));
        advice.extend(pk);
        advice.extend(MESSAGE);
        advice.extend(sig);
        public.commit(&1u64).commit(&pk).commit(&MESSAGE);
    }
    Run {
        advice,
        expected: public.digest(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_and_mutated_encodings() {
        let (pk, sig) = sign(0);
        assert!(mldsa::verify(&pk, &MESSAGE, &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!mldsa::verify(&pk, &MESSAGE, &bad));
        let mut msg = MESSAGE;
        msg[0] ^= 1;
        assert!(!mldsa::verify(&pk, &msg, &sig));
        let (other, _) = sign(1);
        assert!(!mldsa::verify(&other, &MESSAGE, &sig));
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn nist_acvp_internal_vectors() {
        use ml_dsa::{EncodedVerifyingKey, Signature, VerifyingKey};
        for line in include_str!("../kat/acvp-internal.txt").lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            let key: EncodedVerifyingKey<MlDsa44> = hex(f[2]).as_slice().try_into().unwrap();
            let key = VerifyingKey::<MlDsa44>::decode(&key);
            let valid = Signature::<MlDsa44>::try_from(hex(f[4]).as_slice())
                .is_ok_and(|sig| key.verify_internal(&hex(f[3]), &sig));
            assert_eq!(valid, f[1] == "1", "ACVP tcId {}", f[0]);
        }
    }
    #[test]
    fn guest_accepts_and_rejects_mutations() {
        use leanvm::Program;
        let override_elf = std::env::var("L5_TEST_ELF").ok().map(|p| std::fs::read(p).unwrap());
        let program = Program::from_elf(override_elf.as_deref().unwrap_or(ELF)).unwrap();
        let run = batch(1);
        assert_eq!(program.execute(&run.advice).unwrap().output, run.expected);
        for offset in [1, 1 + 164, 1 + 164 + 4] {
            let mut advice = run.advice.clone();
            advice[offset] ^= 1;
            let pk: PublicKey = advice[1..165].try_into().unwrap();
            let msg: Message = advice[165..169].try_into().unwrap();
            let mut public = PublicValues::new();
            public.commit(&0u64).commit(&pk).commit(&msg);
            assert_eq!(program.execute(&advice).unwrap().output, public.digest());
        }
    }
}
