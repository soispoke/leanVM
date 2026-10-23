//! SHA-256 composed from the unchanged shared-byte lowering primitives.
use crate::{native_hash::Word, word_lowering::Lowering};
type W = Vec<Word>;
fn constant(c: &mut Lowering, value: u32) -> W {
    value.to_le_bytes().iter().map(|&v| c.b.constant(v as u64)).collect()
}
fn logic(c: &mut Lowering, a: &W, b: &W, and: bool) -> W {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| {
            let (x, y) = c.logic8(a, b);
            if and { y } else { x }
        })
        .collect()
}
fn shift(c: &mut Lowering, a: &W, n: usize, rotate: bool) -> W {
    let packed = c.pack(a);
    let bits = c.b.bits(packed, 32);
    let shifted: Vec<_> = (0..32)
        .map(|i| {
            if rotate || i + n < 32 {
                bits[(i + n) % 32]
            } else {
                Word::ZERO
            }
        })
        .collect();
    shifted.as_chunks::<8>().0.iter().map(|bits| c.b.pack(bits)).collect()
}
fn sigma(c: &mut Lowering, a: &W, rot: [usize; 3], last_shift: bool) -> W {
    let x = shift(c, a, rot[0], true);
    let y = shift(c, a, rot[1], true);
    let z = shift(c, a, rot[2], !last_shift);
    let xy = logic(c, &x, &y, false);
    logic(c, &xy, &z, false)
}
fn add(c: &mut Lowering, a: &W, b: &W) -> W {
    c.add(a, b).0
}
pub fn application(message: &[u8], identity: [u8; 32]) -> Lowering {
    let mut c = Lowering::default();
    let mut padded: Vec<_> = message.iter().map(|&v| c.byte(v)).collect();
    for bytes in padded.chunks(8) {
        c.pack(bytes);
    }
    padded.push(c.b.constant(128));
    while padded.len() % 64 != 56 {
        padded.push(Word::ZERO);
    }
    padded.extend(
        ((message.len() as u64) * 8)
            .to_be_bytes()
            .iter()
            .map(|&v| c.b.constant(v as u64)),
    );
    let mut state: Vec<_> = circuit_suite::sha256::IV.iter().map(|&v| constant(&mut c, v)).collect();
    for block in padded.as_chunks::<64>().0.iter() {
        let mut schedule: Vec<W> = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| b.iter().copied().rev().collect())
            .collect();
        for i in 16..64 {
            let s0 = sigma(&mut c, &schedule[i - 15], [7, 18, 3], true);
            let s1 = sigma(&mut c, &schedule[i - 2], [17, 19, 10], true);
            let a = add(&mut c, &schedule[i - 16], &s0);
            let b = add(&mut c, &schedule[i - 7], &s1);
            schedule.push(add(&mut c, &a, &b));
        }
        let mut working = state.clone();
        for i in 0..64 {
            let big1 = sigma(&mut c, &working[4], [6, 11, 25], false);
            let ef = logic(&mut c, &working[4], &working[5], true);
            let mask = constant(&mut c, u32::MAX);
            let ne = logic(&mut c, &working[4], &mask, false);
            let ng = logic(&mut c, &ne, &working[6], true);
            let ch = logic(&mut c, &ef, &ng, false);
            let k = constant(&mut c, circuit_suite::sha256::K[i]);
            let t1 = add(&mut c, &working[7], &big1);
            let t1 = add(&mut c, &t1, &ch);
            let t1 = add(&mut c, &t1, &k);
            let t1 = add(&mut c, &t1, &schedule[i]);
            let big0 = sigma(&mut c, &working[0], [2, 13, 22], false);
            let ab = logic(&mut c, &working[0], &working[1], true);
            let ac = logic(&mut c, &working[0], &working[2], true);
            let bc = logic(&mut c, &working[1], &working[2], true);
            let maj = logic(&mut c, &ab, &ac, false);
            let maj = logic(&mut c, &maj, &bc, false);
            let t2 = add(&mut c, &big0, &maj);
            let a = add(&mut c, &t1, &t2);
            let e = add(&mut c, &working[3], &t1);
            working = vec![
                a,
                working[0].clone(),
                working[1].clone(),
                working[2].clone(),
                e,
                working[4].clone(),
                working[5].clone(),
                working[6].clone(),
            ];
        }
        state = state.iter().zip(working).map(|(a, b)| add(&mut c, a, &b)).collect();
    }
    let mut statement: Vec<_> = state.iter().flat_map(|w| w.iter().copied().rev()).collect();
    statement.resize(64, Word::ZERO);
    let mut claim_input: Vec<_> = identity
        .as_chunks::<8>()
        .0
        .iter()
        .map(|v| c.b.constant(u64::from_le_bytes(*v)))
        .collect();
    for half in statement.as_chunks::<16>().0.iter() {
        let rev: Vec<_> = half.iter().copied().rev().collect();
        for word in rev.as_chunks::<8>().0.iter() {
            claim_input.push(c.pack(word));
        }
    }
    let claim = c.b.hash_words(&claim_input);
    for w in claim {
        c.b.expose(w);
    }
    c.b.keccak_f([Word::ZERO; 25]);
    c
}
