//! Fixed-size counterparts of the RISC-V hometurf hash-chain and Merkle guest.
use crate::native_hash::{Builder, Word};

pub struct Application {
    pub builder: Builder,
    pub output: [u64; 4],
}

/// Match programs/hometurf: commit seed, mode, count, index, then final digest.
/// Siblings are private. Count is specialized into the circuit key.
pub fn create(merkle: bool, count: usize, tamper_path: bool) -> Application {
    assert!(count > 0);
    assert!(!merkle || count <= 32);
    let mut b = Builder::default();
    let seed: [Word; 4] = std::array::from_fn(|_| b.input(0));
    let mode = b.constant(u64::from(merkle));
    let n = b.constant(count as u64);
    let index = b.input(if merkle { 0x5555_5555 & ((1u64 << count) - 1) } else { 0 });
    let directions = if merkle { b.bits(index, count) } else { Vec::new() };
    let mut value = seed;
    for level in 0..count {
        let sibling = if merkle {
            std::array::from_fn(|i| b.input((level + 1) as u64 ^ u64::from(tamper_path && level == 0 && i == 0)))
        } else {
            [Word::ZERO; 4]
        };
        let mut message = [Word::ZERO; 8];
        for i in 0..4 {
            if merkle {
                message[i] = b.select(directions[level], value[i], sibling[i]);
                message[4 + i] = b.select(directions[level], sibling[i], value[i]);
            } else {
                message[i] = value[i];
                message[4 + i] = sibling[i];
            }
        }
        value = b.hash_words(&message);
    }
    let mut statement = seed.to_vec();
    statement.extend([mode, n, index]);
    statement.extend(value);
    let result = b.hash_words(&statement);
    for word in result {
        b.expose(word);
    }
    let output = result.map(|w| b.value(w).c0);
    Application { builder: b, output }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::field::F192;

    #[test]
    fn merkle_path_and_proof_tampering_are_rejected() {
        parallel::init();
        let valid = create(true, 20, false);
        let invalid = create(true, 20, true);
        assert_ne!(valid.output, invalid.output);
        let setup = valid.builder.setup().unwrap();
        let public = valid.builder.public_values();
        let context = [38; 32];
        let proof = setup
            .prove(&valid.builder.values, &valid.builder.compressions, &context)
            .unwrap();
        assert!(setup.verify(&public, &context, &proof));
        let forged = setup
            .prove(&invalid.builder.values, &invalid.builder.compressions, &context)
            .unwrap();
        assert!(!setup.verify(&public, &context, &forged));
        let mut wrong = public.clone();
        *wrong.last_mut().unwrap() += F192::ONE;
        assert!(!setup.verify(&wrong, &context, &proof));
        let mut tampered = proof;
        tampered.stream[0] += F192::ONE;
        assert!(!setup.verify(&public, &context, &tampered));
    }
}
