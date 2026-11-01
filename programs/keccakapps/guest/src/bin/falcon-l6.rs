#![no_std]
#![no_main]
use falcon::{Message, PublicKey, Signature};
use leanvm_guest::{commit, keccak::f1600, read, read_unchecked};
#[unsafe(no_mangle)]
extern "C" fn main() {
    let pk = unsafe { read_unchecked::<PublicKey>() };
    let msg = read::<Message>();
    let sig = unsafe { read_unchecked::<Signature>() };
    falcon::verify(pk, msg, sig).expect("valid Falcon512 signature");
    // SHAKE256(pk encoding || message), exactly the L6 statement digest.
    let mut bytes = [0u8; 929];
    bytes[0] = 9;
    for (i, w) in pk.h.iter().enumerate() {
        bytes[1 + 8 * i..9 + 8 * i].copy_from_slice(&w.to_be_bytes());
    }
    for (i, w) in msg.iter().enumerate() {
        bytes[897 + 8 * i..905 + 8 * i].copy_from_slice(&w.to_le_bytes());
    }
    let mut state = [0u64; 25];
    let mut at = 0;
    for b in bytes {
        state[at / 8] ^= (b as u64) << (8 * (at % 8));
        at += 1;
        if at == 136 {
            f1600(&mut state);
            at = 0;
        }
    }
    state[at / 8] ^= 0x1f << (8 * (at % 8));
    state[16] ^= 0x80 << 56;
    f1600(&mut state);
    commit(&[state[0], state[1], state[2], state[3], 1, 0, 0, 0]);
}
