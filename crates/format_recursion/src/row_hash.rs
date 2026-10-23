//! One selected native hash relation for the sparse carried-claims backend.
#[cfg(not(feature = "keccak-protocol"))]
pub use flock::hash::{Blake2sSetup as Setup, Compression as Block, K_LOG, R1CS_DIGEST, generate_witness_with_ab_packed_and_lincheck as generate, ring_switch_open as ring_open, ring_switch_verify as ring_verify};
#[cfg(not(feature = "keccak-protocol"))]
pub const PORTS: usize = 18;
#[cfg(not(feature = "keccak-protocol"))]
pub const SLOTS: [usize; PORTS] = [0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17,18,19];
#[cfg(not(feature = "keccak-protocol"))]
pub fn padding() -> [u64; PORTS] {
    let b = flock::hash::padding_block();
    crate::private_bridge::io_words(&b, &flock::hash::blake2s_compress(&b.0,&b.1,b.2,b.3,b.4))
}
#[cfg(feature = "keccak-protocol")]
pub use keccak::*;
#[cfg(feature = "keccak-protocol")]
mod keccak {
    use fiat_shamir::transcript::{ProverState, VerifierState};
    use flock::{hash::SliceClaim, keccak::{INPUT, OUTPUT, reduction}};
    pub use flock::keccak::{K_LOG, reduction::{Permutation as Block, generate}};
    pub const PORTS: usize = 50;
    pub const SLOTS: [usize; PORTS] = {
        let mut out = [0; PORTS];
        let mut i = 0;
        while i < 25 { out[i] = INPUT / 64 + i; out[25+i] = OUTPUT / 64 + i; i+=1; }
        out
    };
    pub const R1CS_DIGEST: [u8;32] = *b"Keccak-f1600-chi24-k16-io64-v1__";
    pub fn padding() -> [u64; PORTS] {
        crate::keccak_bridge::io_words(&[0;25], &reduction::permute(&[0;25]))
    }
    pub struct Setup { block_log: usize }
    pub struct Reduced { pub claim: SliceClaim }
    impl Setup {
        pub fn new(blocks: usize) -> Self { Self { block_log: blocks.next_power_of_two().ilog2() as usize } }
        pub fn prove_reduction_precomputed(&self, z: &[u64], a: &[u64], b: &[u64], stripes: &[u8], ps: &mut ProverState) -> SliceClaim {
            reduction::KeccakSetup { block_log:self.block_log }.prove(z,a,b,stripes,ps)
        }
        pub fn verify_reduction(&self, vs: &mut VerifierState<'_>) -> Result<Reduced, flock::verifier::VerifyError> {
            Ok(Reduced { claim: reduction::KeccakSetup { block_log:self.block_log }.verify(vs)? })
        }
    }
    pub fn ring_open(_blocks: usize, offset: usize, claim: &SliceClaim) -> pcs::stack_open::RingSwitchOpen {
        reduction::ring_open(offset, claim)
    }
    pub fn ring_verify(_blocks: usize, offset: usize, claim: &SliceClaim) -> pcs::stack_open::RingSwitchVerify<'_> {
        reduction::ring_verify(offset, claim)
    }
}
pub type Connectors = [usize; PORTS];
