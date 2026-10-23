use super::keccak_protocol::{BLOCK_LEN, OUT_LEN, PrefixState};
use core::arch::x86_64::*;

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[inline]
unsafe fn permute(s: &mut [__m512i; 25]) {
    const ROT: [[i64; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];
    // SAFETY: this module is compiled only when AVX-512F is enabled.
    unsafe {
        for &rc in &RC {
            let c: [__m512i; 5] = core::array::from_fn(|x| {
                _mm512_xor_si512(
                    _mm512_xor_si512(s[x], s[x + 5]),
                    _mm512_xor_si512(s[x + 10], _mm512_xor_si512(s[x + 15], s[x + 20])),
                )
            });
            let mut b = [_mm512_setzero_si512(); 25];
            for x in 0..5 {
                let d = _mm512_xor_si512(c[(x + 4) % 5], _mm512_rol_epi64::<1>(c[(x + 1) % 5]));
                for y in 0..5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] =
                        _mm512_rolv_epi64(_mm512_xor_si512(s[x + 5 * y], d), _mm512_set1_epi64(ROT[x][y]));
                }
            }
            for y in 0..5 {
                for x in 0..5 {
                    s[x + 5 * y] = _mm512_xor_si512(
                        b[x + 5 * y],
                        _mm512_andnot_si512(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]),
                    );
                }
            }
            s[0] = _mm512_xor_si512(s[0], _mm512_set1_epi64(rc as i64));
        }
    }
}

pub(super) fn hash_eight(bytes: &[u8], len: usize, prefix: &PrefixState, out: &mut [u8]) {
    assert_eq!(bytes.len(), 8 * len);
    assert_eq!(out.len(), 8 * OUT_LEN);
    // SAFETY: AVX-512F is enabled for this module; all vector transfers use
    // exactly eight u64s, and the input/output lengths are checked above.
    unsafe {
        let mut s: [__m512i; 25] = core::array::from_fn(|i| _mm512_set1_epi64(prefix[i] as i64));
        for block in 0..len / BLOCK_LEN {
            for j in 0..BLOCK_LEN / 8 {
                let lanes: [u64; 8] = core::array::from_fn(|i| {
                    let at = i * len + block * BLOCK_LEN + 8 * j;
                    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
                });
                s[j] = _mm512_xor_si512(s[j], _mm512_loadu_si512(lanes.as_ptr().cast()));
            }
            permute(&mut s);
        }
        let used = len % BLOCK_LEN;
        let mut tail = [[0u8; BLOCK_LEN]; 8];
        for i in 0..8 {
            tail[i][..used].copy_from_slice(&bytes[i * len + len - used..(i + 1) * len]);
            tail[i][used] = 1;
            tail[i][BLOCK_LEN - 1] ^= 0x80;
        }
        for j in 0..BLOCK_LEN / 8 {
            let lanes: [u64; 8] =
                core::array::from_fn(|i| u64::from_le_bytes(tail[i][8 * j..8 * j + 8].try_into().unwrap()));
            s[j] = _mm512_xor_si512(s[j], _mm512_loadu_si512(lanes.as_ptr().cast()));
        }
        permute(&mut s);
        for j in 0..OUT_LEN / 8 {
            let mut lanes = [0u64; 8];
            _mm512_storeu_si512(lanes.as_mut_ptr().cast(), s[j]);
            for i in 0..8 {
                out[i * OUT_LEN + 8 * j..i * OUT_LEN + 8 * j + 8].copy_from_slice(&lanes[i].to_le_bytes());
            }
        }
    }
}
