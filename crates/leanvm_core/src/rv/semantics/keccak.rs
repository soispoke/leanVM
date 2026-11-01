//! Keccak-f[1600] over a block with separate input and output banks.
//!
//! Words 0..25 hold the input; words 25..50 receive the permutation. Word k is
//! at base XOR 8*k, as with the existing hash block. The SDK aligns to 512 bytes.

use super::InstructionClass;
use crate::rv::circuits::{ClassCircuit};
use flock::circuit::Circuit;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keccak {
    pub block: [u64; Self::WORDS],
}

impl Keccak {
    pub const LANES: usize = 25;
    pub const WORDS: usize = 50;
    pub const OUT: usize = 25;
}

impl InstructionClass for Keccak {
    const LEGAL: &'static [u64] = &[0];
    type Output = [u64; Self::LANES];

    fn eval(&self) -> Self::Output {
        let mut state = self.block[..Self::LANES].try_into().expect("25 input lanes");
        primitives::keccak::keccak_f(&mut state);
        state
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationAccess {
    pub block: [u64; Keccak::WORDS],
    pub out: [u64; Keccak::LANES],
}

impl From<Keccak> for PermutationAccess {
    fn from(keccak: Keccak) -> Self {
        Self {
            block: keccak.block,
            out: keccak.eval(),
        }
    }
}

impl ClassCircuit for Keccak {
    fn circuit() -> Circuit {
        Circuit::keccak()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rv::{
        Class,
        semantics::tests::{Ports, circuit_matches_reference, edge_word},
    };
    use proptest::prelude::*;

    impl Arbitrary for Keccak {
        type Parameters = ();
        type Strategy = proptest::strategy::BoxedStrategy<Self>;
        fn arbitrary_with((): ()) -> Self::Strategy {
            proptest::collection::vec(edge_word(), Self::WORDS)
                .prop_map(|block| Self {
                    block: block.try_into().unwrap(),
                })
                .boxed()
        }
    }
    impl Ports for Keccak {
        const CLASS: Class = Class::Keccak;
        fn input_words(&self) -> Vec<u64> {
            self.block[..25].to_vec()
        }
        fn output_words(&self, out: &[u64; 25]) -> Vec<u64> {
            out.to_vec()
        }
    }
    #[test]
    fn permutation_circuit_matches_native() {
        circuit_matches_reference::<Keccak>(8);
    }
}
