//! BLAKE2s-256 (RFC 7693) of a message whose length is fixed when the circuit is built, and the workload
//! hashing a private 1 KiB message: bytes 0..32 of the statement are the digest, the rest zeros.
//!
//! A `G` half is two additions and two XORs of 32-bit words, one row a bit each, rotations free: 160 rows, so
//! 25,600 for the ten rounds and 256 more for the output, `h ^ v[i] ^ v[i + 8]` being one row a bit. The first
//! round's constants add rows to make negated bits positive before an adder, and fold others away.

use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload, bytes_to_bits};

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn word(value: u32) -> Word {
    Ckt::constant_word(value as u128, 32)
}

/// `x` rotated right by `by`.
fn rotr(x: &[Wire], by: usize) -> Word {
    (0..32).map(|i| x[(i + by) % 32]).collect()
}

/// One compression of `block` (sixteen words) into `h`, `t` bytes counted so far and `last` the final flag.
pub fn compress(c: &mut Ckt, h: &[Word], block: &[Word], t: u64, last: bool) -> Vec<Word> {
    let mut v: Vec<Word> = h.iter().cloned().chain(IV.iter().map(|&w| word(w))).collect();
    v[12] = word(IV[4] ^ t as u32);
    v[13] = word(IV[5] ^ (t >> 32) as u32);
    if last {
        v[14] = word(!IV[6]);
    }
    for s in &SIGMA {
        for (g, [a, b, cc, d]) in [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ]
        .into_iter()
        .enumerate()
        {
            for (half, [r1, r2]) in [[16, 12], [8, 7]].into_iter().enumerate() {
                let m = &block[s[2 * g + half]];
                let sum = c.add(&v[a], &v[b]);
                v[a] = c.add(&sum, m);
                let x = c.xor_word(&v[d], &v[a]);
                v[d] = rotr(&x, r1);
                v[cc] = c.add(&v[cc], &v[d]);
                let x = c.xor_word(&v[b], &v[cc]);
                v[b] = rotr(&x, r2);
            }
        }
    }
    (0..8)
        .map(|i| (0..32).map(|j| c.xor3(h[i][j], v[i][j], v[i + 8][j])).collect())
        .collect()
}

/// BLAKE2s-256 of `message`, its bytes' bits low first; the digest likewise.
pub fn blake2s(c: &mut Ckt, message: &[Wire]) -> Word {
    assert_eq!(message.len() % 8, 0);
    let len = message.len() / 8;
    let mut h: Vec<Word> = IV.iter().map(|&w| word(w)).collect();
    h[0] = word(IV[0] ^ 0x0101_0020);
    let blocks = len.div_ceil(64).max(1);
    for k in 0..blocks {
        let mut bits: Word = message[(512 * k).min(message.len())..(512 * (k + 1)).min(message.len())].to_vec();
        bits.resize(512, Wire::ZERO);
        let block: Vec<Word> = bits.chunks(32).map(|w| w.to_vec()).collect();
        let last = k + 1 == blocks;
        let t = if last { len as u64 } else { 64 * (k as u64 + 1) };
        h = compress(c, &h, &block, t, last);
    }
    h.concat()
}

pub fn blake2s_native(message: &[u8]) -> [u8; 32] {
    primitives::hash::hash(message)
}

/// BLAKE2s of a private message of `$bytes` bytes, the digest in bytes 0..32 of the statement.
macro_rules! blake2s_workload {
    ($ty:ident, $name:literal, $bytes:expr) => {
        pub struct $ty;

        impl Workload for $ty {
            const NAME: &'static str = $name;

            fn build(c: &mut Ckt) -> Vec<Wire> {
                let message = c.inputs(8 * $bytes);
                let mut public = blake2s(c, &message);
                public.resize(PUBLIC_BITS, Wire::ZERO);
                public
            }

            fn instance(seed: u64) -> Instance {
                let message: Vec<u8> = (0..$bytes)
                    .map(|i: usize| {
                        (seed
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                            .wrapping_add(i as u64 * 0xD1B5_4A32_D192_ED03)
                            >> 56) as u8
                    })
                    .collect();
                let mut statement = [0u8; 64];
                statement[..32].copy_from_slice(&blake2s_native(&message));
                Instance {
                    inputs: bytes_to_bits(&message),
                    statement,
                }
            }

            fn invalid_instance(_: u64) -> Option<Instance> {
                None
            }
        }
    };
}

pub const MESSAGE_BYTES: usize = 1024;
blake2s_workload!(Blake2sOneKiB, "blake2s-1kib", MESSAGE_BYTES);
// The same statement at other lengths, for how proving scales with rows.
blake2s_workload!(Blake2s64, "blake2s-64b", 64);
blake2s_workload!(Blake2s256, "blake2s-256b", 256);
blake2s_workload!(Blake2s4KiB, "blake2s-4kib", 4096);
blake2s_workload!(Blake2s16KiB, "blake2s-16kib", 16384);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build, read_statement};

    #[test]
    fn reference_is_rfc_7693() {
        // RFC 7693 appendix B: BLAKE2s-256("abc").
        assert_eq!(
            blake2s_native(b"abc"),
            [
                0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F, 0x37,
                0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82
            ]
        );
    }

    #[test]
    fn digests_match_the_reference_at_every_block_boundary() {
        for len in [0usize, 1, 3, 63, 64, 65, 127, 128, 200] {
            let message: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            let mut c = Ckt::new();
            let ins = c.inputs(8 * len);
            let mut public = blake2s(&mut c, &ins);
            public.resize(PUBLIC_BITS, Wire::ZERO);
            let (circuit, srcs) = c.finish(&public);
            circuit.check_wired().unwrap();
            let st = read_statement(&circuit.values(&bytes_to_bits(&message)), &srcs);
            assert_eq!(st[..32], blake2s_native(&message), "length {len}");
        }
    }

    #[test]
    fn one_kib_workload() {
        let (circuit, srcs, used) = build::<Blake2sOneKiB>();
        circuit.check_wired().unwrap();
        for seed in 0..3 {
            let inst = Blake2sOneKiB::instance(seed);
            assert_eq!(read_statement(&circuit.values(&inst.inputs), &srcs), inst.statement);
        }
        let mut c = Ckt::new();
        let h: Vec<Word> = (0..8).map(|_| c.inputs(32)).collect();
        let m: Vec<Word> = (0..16).map(|_| c.inputs(32)).collect();
        let before = c.rows();
        compress(&mut c, &h, &m, 64, false);
        let per = c.rows() - before;

        println!(
            "blake2s-1kib: {used} rows used of 2^{}, {} inputs, {per} rows a compression, {:?} conversion rows",
            circuit.log_rows,
            circuit.n_inputs(),
            c.conversions
        );
        // 25,856 rows of adders and XORs, and the first round's negations: its words of constants XORed in
        // come out negated where the constant has a one, and an adder's carry needs them positive.
        assert_eq!((per, c.conversions), (28_516, [0, 0, 2_793]));
    }
}
