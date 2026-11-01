#![no_std]
#![no_main]
use leanvm_guest::{commit, keccak::keccak256, read, read_slice};
use stateproof::{Address, Hash, Node};
leanvm_guest::advice_words!(1 << 14);
// Validate the bounded L6 node grammar; the existing trie walker binds paths and hashes.
fn item(b: &[u8], at: usize) -> (usize, usize, bool, usize) {
    let x = b[at];
    let (off, len, list) = match x {
        0..=0x7f => (at, 1, false),
        0x80..=0xb7 => (at + 1, (x - 0x80) as usize, false),
        0xc0..=0xf7 => (at + 1, (x - 0xc0) as usize, true),
        _ => {
            let base = if x >= 0xf8 { 0xf7 } else { 0xb7 };
            let n = (x - base) as usize;
            assert!(n <= 2);
            assert_ne!(b[at + 1], 0);
            let mut len = 0;
            for v in &b[at + 1..at + 1 + n] {
                len = 256 * len + *v as usize;
            }
            assert!(len >= 56);
            (at + 1 + n, len, x >= 0xf8)
        }
    };
    assert!(off + len <= b.len());
    if x == 0x81 {
        assert!(b[off] >= 0x80);
    }
    (off, len, list, off + len)
}
fn grammar(b: &[u8], leaf: bool, account: bool) {
    let (o, l, list, end) = item(b, 0);
    assert!(list && end == b.len());
    let mut spans = [(0, 0); 17];
    let mut at = o;
    let mut n = 0;
    while at < o + l {
        assert!(n < 17);
        let (p, k, islist, e) = item(b, at);
        assert!(!islist);
        spans[n] = (p, k);
        n += 1;
        at = e;
    }
    if !leaf && n == 17 {
        let mut occupied = 0;
        for &(p, k) in &spans[..16] {
            assert!(k == 0 || k == 32);
            if k == 32 {
                occupied += 1;
            }
            let _ = p;
        }
        assert!(occupied >= 2 && spans[16].1 == 0);
        return;
    }
    assert_eq!(n, 2);
    let (p, k) = spans[0];
    assert!(k > 0);
    let flag = b[p] >> 4;
    assert_eq!(flag & 2, if leaf { 2 } else { 0 });
    assert!(flag <= 3);
    if flag & 1 == 0 {
        assert_eq!(b[p] & 15, 0);
    }
    if !leaf {
        assert!(2 * k - 2 + (flag & 1) as usize > 0);
        assert_eq!(spans[1].1, 32);
        return;
    }
    let (p, k) = spans[1];
    let value = &b[p..p + k];
    if account {
        let (o, l, list, end) = item(value, 0);
        assert!(list && end == value.len());
        let mut at = o;
        for bound in [8, 32, 32, 32] {
            let (p, k, list, e) = item(value, at);
            assert!(!list && k <= bound);
            if bound == 32 && at >= o + l - 66 {
                assert_eq!(k, 32);
            } else if k > 0 {
                assert_ne!(value[p], 0);
            }
            at = e;
        }
        assert_eq!(at, o + l);
    } else {
        let (p, k, list, end) = item(value, 0);
        assert!(!list && end == value.len() && k <= 32 && k > 0);
        assert_ne!(value[p], 0);
    }
}
fn proof(max: usize, leafmax: usize, account: bool) -> impl Iterator<Item = Node<'static>> {
    let n = *read::<u64>() as usize;
    assert!(n > 0 && n <= max);
    (0..n).map(move |i| {
        let len = *read::<u64>() as usize;
        assert!(len >= 32 && len <= if i + 1 == n { leafmax } else { 532 });
        let words = read_slice::<u64>(len.div_ceil(8));
        let mut b = [0u8; 532];
        for (i, w) in words.iter().enumerate() {
            let k = (len - 8 * i).min(8);
            b[8 * i..8 * i + k].copy_from_slice(&w.to_le_bytes()[..k]);
        }
        grammar(&b[..len], i + 1 == n, account);
        Node::new(words, len).unwrap()
    })
}
#[unsafe(no_mangle)]
extern "C" fn main() {
    let root = read::<Hash>();
    let addr = read::<Address>();
    let slot = read::<Hash>();
    let account = stateproof::account(root, addr, proof(9, 148, true)).expect("account inclusion");
    let value = stateproof::storage(&account.storage_root, slot, proof(7, 70, false)).expect("storage inclusion");
    assert_ne!(value, [0; 4]);
    let mut msg = [0u8; 120];
    for (i, w) in root.iter().enumerate() {
        msg[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
    }
    for (i, w) in addr.iter().enumerate() {
        let k = (20 - 8 * i).min(8);
        msg[32 + 8 * i..32 + 8 * i + k].copy_from_slice(&w.to_le_bytes()[..k]);
    }
    for (i, w) in slot.iter().enumerate() {
        msg[52 + 8 * i..60 + 8 * i].copy_from_slice(&w.to_le_bytes());
    }
    for (i, w) in value.iter().rev().enumerate() {
        msg[84 + 8 * i..92 + 8 * i].copy_from_slice(&w.to_be_bytes());
    }
    let words = core::array::from_fn::<_, 15, _>(|i| u64::from_le_bytes(msg[8 * i..8 * i + 8].try_into().unwrap()));
    let d = keccak256(&words, 116);
    commit(&[d[0], d[1], d[2], d[3], 1, 0, 0, 0]);
}
