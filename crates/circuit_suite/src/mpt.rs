//! A private L1 state proof: slot `S` of account `A` holds value `V` under state root `R`, by an Ethereum
//! Merkle-Patricia-Trie account proof and storage proof (`eth_getProof`'s `accountProof` and `storageProof`).
//!
//! # Statement `MptStorageProof`
//!
//! Free inputs, in order: `R` (32 bytes), `A` (20 bytes), `S` (32 bytes, the slot as a big-endian word), then
//! the account path's slots and the storage path's slots (below). Statement bytes `0..32` are
//! `keccak256(R || A || S || V)` with `V` the 32-byte big-endian value the circuit reads from the storage leaf;
//! bytes `32..64` are `[valid, 0, ..]`. Keccak-256 rather than SHA-256 because the trie's own hash is Keccak
//! (the circuit has it anyway); the digest binds all four public values.
//!
//! `valid = 1` means: `keccak256(A)` is a key in the trie under `R`, its account's storage root is `T`,
//! `keccak256(S)` is a key in the trie under `T`, and its value is `V` (the leaf's value is `rlp(V)`).
//! Only inclusion is proved: an absent slot (value zero) or account is not provable (`valid = 0`).
//!
//! # Bounds (`Params::MAINNET`)
//!
//! * Account path: at most 9 nodes (8 inner slots, branch or extension, and a leaf slot); storage path: at most
//!   7 nodes (6 inner slots and a leaf). A path shorter than its bound leaves leading inner slots inactive;
//!   the active inner slots are the last ones (`active` is monotone), so the leaf always sits in the leaf slot.
//! * An inner node is at most 532 bytes (a full branch: `0xf9 0x02 0x11`, 16 hashes, the empty value), hashed
//!   as up to 4 Keccak blocks; an account leaf at most 148 bytes (2 blocks; 64 path nibbles, nonce up to 8
//!   bytes, balance up to 32); a storage leaf at most 70 bytes (1 block).
//! * Every child reference is a 32-byte hash. A node shorter than 32 bytes is embedded in its parent by
//!   Ethereum's rules; embedded nodes are rejected. With hashed 64-nibble keys a node within these depths is
//!   always at least 32 bytes unless keys share prefixes of about 40 nibbles, so this costs completeness only
//!   for keys ground to collide in that many nibbles, never soundness.
//!
//! # Per slot, and why `valid = 1` is sound
//!
//! Every slot's node is given padded to its bound, with hints: an inner slot has `active`, `is_branch`, the
//! branch's 16 occupancy bits `occ`, and for a two-item node `hl2` (long list header) and `single` (a one-byte
//! path item); a leaf slot has `hl2`, `single` and the value item's form (`vlong` for an account, a long
//! string header; `vsingle` for a storage value, a single byte below `0x80`). From the bytes and hints the
//! slot derives the node's length `L` and checks its RLP structure; the circuit then checks
//! `keccak256(node[..L]) == h`, the reference the walk expects (the state root for the first active slot).
//!
//! Keccak's padding is built for the derived `L`: byte `j` of the hashed message is `node[j]` masked by
//! `[j < L]`, `0x01` at `j = L`, `0x80` at the end of block `L / 136`, and the digest compared is the one after
//! block `L / 136 + 1` of the four absorbed; bytes past `L` cannot reach the hash. By collision resistance,
//! `node[..L]` is then the true node with hash `h` (and `L` its length), so it suffices that, *on the true
//! node*, every hint the checks accept gives the true parse:
//!
//! * a branch: from `occ`, the payload length `P = 17 + 32 popcount(occ)` and the header length; the header
//!   bytes must be exactly that list header, and item `j` must start, at `hl + j + 32 popcount(occ[..j])`,
//!   with `0xa0` (32-byte string) if `occ[j]`, else `0x80` (empty), and item 16 with `0x80` at `L - 1`. Each
//!   check reads an item's header where the previous items' headers put it, so the true node is a list of
//!   exactly these 17 items. The child is item `k` for the key's next nibble `k`, `occ[k]` must be set.
//!   A branch of fewer than two children, never a trie node, has no accepted header at mainnet sizes;
//! * a two-item node: the list header from `hl2`, the path item's header from `single` (or `0x81..=0xb7`),
//!   the second item's header where the first ends, and the second item must end exactly at `L`. The path's
//!   hex-prefix flag nibble must say extension (`0`, `1`) or leaf (`2`, `3`) as the slot requires, and its
//!   nibbles must equal the key's from the position the walk has consumed (all of the rest for a leaf);
//! * an extension's second item is a 32-byte hash, the child; an account leaf's value ends at `L`, so its
//!   storage root is the 32 bytes at `L - 65` (an account is `[nonce, balance, storageRoot, codeHash]`, its
//!   last 66 bytes the two hashes); a storage leaf's value item is `rlp(V)`, so `V` is the last `len(V)` bytes.
//!
//! The walk is the trie's own lookup: so `valid = 1` implies the lookup of `keccak256(A)` under `R` finds the
//! account, and of `keccak256(S)` under its storage root finds `rlp(V)`.
//!
//! # Rows
//!
//! 8,379,278 rows with the 62,286 input rows and the 512 public rows: it closes on 2^23 (`report`, the test
//! `report_counts`). Hashing is 91.6%: 62 Keccak-f permutations, 14 inner slots of 4 blocks, the leaves' 2
//! and 1, and three single blocks (the two keys and the statement):
//!
//! | component | rows | share |
//! |---|---:|---:|
//! | Keccak-f, node hashes (59 permutations) | 7,318,688 | 87.3% |
//! | Keccak-f, keys and statement (3) | 357,412 | 4.3% |
//! | reference and value selection (barrel shifters) | 284,275 | 3.4% |
//! | hash padding: mask past `L`, `0x01 .. 0x80`, block choice, digest compare | 138,287 | 1.7% |
//! | RLP headers and items (branch item checks, two-item parse) | 76,187 | 0.9% |
//! | key nibble alignment (shift by the nibbles consumed) | 74,768 | 0.9% |
//! | path nibbles (hex-prefix decode and compare) | 54,608 | 0.7% |
//! | slot muxes (walk state, validity) | 12,252 | 0.1% |
//!
//! Selection and parsing, padding included, is 640,380 rows (7.6%): the part a lookup argument or RAM would
//! cut. Most of it is reading 33 bytes at a variable offset of up to 498 in a 532-byte node (19,000 rows a
//! slot); the RLP structure checks themselves are under 1%. The cost is set by the bounds, not the proof:
//! every slot always hashes its 4 blocks. A storage bound of 9 nodes (WETH's) is 9,468,124 rows (2^24).
//!
//! Everything is generic over [`Params`] and the node hash ([`TrieHash`]), so the bounded tests run the same
//! generator with tiny nodes and a 16-bit stand-in hash ([`Toy`], used only by the tests).
//!
//! # Tests
//!
//! * native: the reference trie (test only) gives the empty root and the roots of ethereum/tests'
//!   `hex_encoded_securetrie_test` and `trieanyorder_secureTrie`; its proofs, the synthetic paths and two
//!   mainnet `eth_getProof` responses (fetched for this module, embedded below) verify with an independent
//!   alloy-rlp walk;
//! * the full circuit: `check_wired`, four synthetic instances and their invalid ones, the mainnet Curve
//!   tricrypto2 proof (9 account nodes, 4 storage nodes), proofs from a 2,001-account trie with idle slots,
//!   every hint bit of every slot flipped, bytes past a node's end set, address, slot and root flipped; WETH's
//!   9-node storage proof at a storage bound of 9 (`--ignored`);
//! * bounded and exhaustive, `Toy` hash, 4-nibble keys, 2-byte references (`Params::toy`): every slot kind on
//!   40 true nodes, all hint values (all 2^16 occupancies under the branch parse) by every key and position,
//!   asserting that an accepted slot of the true length gives the lookup step's output, and that honest
//!   hints are accepted; the whole circuit with two-level paths, all 2^26 hint assignments jointly; three-level
//!   paths, all non-occupancy hints jointly by 19 occupancy patterns a slot.

use crate::keccak::{self, Stats};
use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload};

/// A byte as wires, low bit first.
pub type Byte = [Wire; 8];
/// A nibble as wires, low bit first.
pub type Nib = [Wire; 4];

pub fn byte_const(v: u8) -> Byte {
    std::array::from_fn(|i| Wire::constant((v >> i) & 1 == 1))
}

fn input_bytes(c: &mut Ckt, n: usize) -> Vec<Byte> {
    (0..n).map(|_| std::array::from_fn(|_| c.input())).collect()
}

fn byte_bits(b: &[Byte]) -> Vec<Wire> {
    b.iter().flat_map(|x| x.iter().copied()).collect()
}

/// The rows each component of a circuit took.
#[derive(Default, Debug, Clone)]
pub struct Tally {
    pub parts: Vec<(&'static str, usize)>,
}

impl Tally {
    pub fn add(&mut self, name: &'static str, rows: usize) {
        match self.parts.iter_mut().find(|(n, _)| *n == name) {
            Some(p) => p.1 += rows,
            None => self.parts.push((name, rows)),
        }
    }

    pub fn get(&self, name: &str) -> usize {
        self.parts.iter().find(|(n, _)| *n == name).map_or(0, |p| p.1)
    }
}

/// Run `f`, counting its rows under `name`.
fn tally<R>(c: &mut Ckt, t: &mut Tally, name: &'static str, f: impl FnOnce(&mut Ckt, &mut Tally) -> R) -> R {
    let r0 = c.rows();
    let r = f(c, t);
    t.add(name, c.rows() - r0);
    r
}

// ---------------------------------------------------------------------------------------------------------
// Words.

fn zext(w: &[Wire], n: usize) -> Word {
    (0..n).map(|i| w.get(i).copied().unwrap_or(Wire::ZERO)).collect()
}

fn kword(k: u64, n: usize) -> Word {
    Ckt::constant_word(k as u128, n)
}

fn addw(c: &mut Ckt, a: &[Wire], b: &[Wire], n: usize) -> Word {
    c.add(&zext(a, n), &zext(b, n))
}

fn addk(c: &mut Ckt, a: &[Wire], k: u64, n: usize) -> Word {
    c.add(&zext(a, n), &kword(k, n))
}

/// `a * k` on `n` bits.
fn mulk(c: &mut Ckt, a: &[Wire], k: u64, n: usize) -> Word {
    let mut acc = kword(0, n);
    for i in 0..64 {
        if (k >> i) & 1 == 1 {
            let mut s = vec![Wire::ZERO; i.min(n)];
            s.extend(a.iter().copied());
            acc = addw(c, &acc, &s, n);
        }
    }
    acc
}

/// `a == k`.
fn eqk(c: &mut Ckt, a: &[Wire], k: u64) -> Wire {
    if a.len() < 64 && k >> a.len() != 0 {
        return Wire::ZERO;
    }
    let lits: Vec<Wire> = a
        .iter()
        .enumerate()
        .map(|(i, &w)| if (k >> i) & 1 == 1 { w } else { w.not() })
        .collect();
    c.all(&lits)
}

fn eqw(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Wire {
    let n = a.len().max(b.len());
    c.eq(&zext(a, n), &zext(b, n))
}

/// `a <= b`.
fn lew(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Wire {
    let n = a.len().max(b.len());
    c.sub(&zext(b, n), &zext(a, n)).1
}

fn lek(c: &mut Ckt, a: &[Wire], k: u64) -> Wire {
    let n = a.len().max(64 - k.leading_zeros() as usize);
    lew(c, a, &kword(k, n))
}

fn muxw(c: &mut Ckt, s: Wire, a: &[Wire], b: &[Wire]) -> Word {
    let n = a.len().max(b.len());
    let (a, b) = (zext(a, n), zext(b, n));
    c.mux_word(s, &a, &b)
}

fn mux_bytes(c: &mut Ckt, s: Wire, a: &[Byte], b: &[Byte]) -> Vec<Byte> {
    a.iter()
        .zip(b)
        .map(|(x, y)| std::array::from_fn(|i| c.mux(s, x[i], y[i])))
        .collect()
}

fn and_all(c: &mut Ckt, w: &[Wire]) -> Wire {
    c.all(w)
}

fn popcount(c: &mut Ckt, bits: &[Wire]) -> Word {
    match bits.len() {
        0 => vec![],
        1 => vec![bits[0]],
        n => {
            let (a, b) = bits.split_at(n / 2);
            let (pa, pb) = (popcount(c, a), popcount(c, b));
            let w = pa.len().max(pb.len()) + 1;
            addw(c, &pa, &pb, w)
        }
    }
}

/// `t[j] = [j < v]` for `j < n`, about two rows an output.
pub fn therm(c: &mut Ckt, v: &[Wire], n: usize) -> Vec<Wire> {
    if n == 0 {
        return vec![];
    }
    let k = v.len();
    if k == 0 {
        return vec![Wire::ZERO; n];
    }
    let half = 1usize << (k - 1);
    let top = v[k - 1];
    if n <= half {
        let low = therm(c, &v[..k - 1], n);
        low.into_iter().map(|t| c.or(top, t)).collect()
    } else {
        let low = therm(c, &v[..k - 1], half);
        (0..n)
            .map(|j| {
                if j < half {
                    c.or(top, low[j])
                } else if j - half < half {
                    c.and(top, low[j - half])
                } else {
                    Wire::ZERO
                }
            })
            .collect()
    }
}

/// `out[i] = data[off + i]` for `i < width` (zero past the data), for `off <= max_off`: a barrel shifter whose
/// levels narrow to what lower bits can still reach.
pub fn shift_elems(c: &mut Ckt, data: &[Vec<Wire>], off: &[Wire], max_off: usize, width: usize) -> Vec<Vec<Wire>> {
    let ew = data.first().map_or(0, |e| e.len());
    let zero = vec![Wire::ZERO; ew];
    let nbits = (usize::BITS - max_off.leading_zeros()) as usize;
    let mut cur: Vec<Vec<Wire>> = data[..data.len().min(max_off + width)].to_vec();
    for b in (0..nbits).rev() {
        let sh = 1usize << b;
        let rem = max_off.min(sh - 1);
        let len = width + rem;
        let s = off.get(b).copied().unwrap_or(Wire::ZERO);
        let mut next = Vec::with_capacity(len);
        for i in 0..len {
            let a = cur.get(i + sh).unwrap_or(&zero).clone();
            let d = cur.get(i).unwrap_or(&zero).clone();
            next.push(a.iter().zip(&d).map(|(&x, &y)| c.mux(s, x, y)).collect());
        }
        cur = next;
    }
    cur.resize(width, zero);
    cur.truncate(width);
    cur
}

pub fn shift_bytes(c: &mut Ckt, data: &[Byte], off: &[Wire], max_off: usize, width: usize) -> Vec<Byte> {
    let d: Vec<Vec<Wire>> = data.iter().map(|b| b.to_vec()).collect();
    shift_elems(c, &d, off, max_off, width)
        .into_iter()
        .map(|v| v.try_into().unwrap())
        .collect()
}

fn nibbles_of(bytes: &[Byte]) -> Vec<Nib> {
    bytes
        .iter()
        .flat_map(|b| {
            let hi: Nib = std::array::from_fn(|i| b[4 + i]);
            let lo: Nib = std::array::from_fn(|i| b[i]);
            [hi, lo]
        })
        .collect()
}

fn bits_needed(max: usize) -> usize {
    (usize::BITS - max.leading_zeros()) as usize
}

/// Bits for lengths and offsets within a node of at most `n` bytes: enough that no sum the slots form (at
/// most `n + 3 + 255 + 58`) wraps.
fn len_bits(n: usize) -> usize {
    bits_needed(n + 320)
}

// ---------------------------------------------------------------------------------------------------------
// The node hash.

/// The trie's hash, its key derivation, and their native versions.
pub trait TrieHash {
    /// Bytes of a hash (a child reference).
    const H: usize;
    /// The fewest bytes a hashed node has (its `check` enforces it).
    const MIN_NODE: usize;
    /// `[hash(bytes[..len]) == expect]`, for `len <= bytes.len()`.
    fn check(c: &mut Ckt, bytes: &[Byte], len: &[Wire], expect: &[Byte], t: &mut Tally) -> Wire;
    /// The hash of `bytes`, all of them.
    fn fixed(c: &mut Ckt, bytes: &[Byte], t: &mut Tally) -> Vec<Byte>;
    /// The trie key of an address or slot.
    fn key(c: &mut Ckt, bytes: &[Byte], t: &mut Tally) -> Vec<Byte>;
    fn native(msg: &[u8]) -> Vec<u8>;
    fn native_key(msg: &[u8]) -> Vec<u8>;
}

/// Keccak-256, Ethereum's.
pub struct Keccak;

fn to_bytes(bits: &[Wire]) -> Vec<Byte> {
    bits.chunks(8).map(|b| b.try_into().unwrap()).collect()
}

impl TrieHash for Keccak {
    const H: usize = 32;
    const MIN_NODE: usize = 32;

    fn check(c: &mut Ckt, bytes: &[Byte], len: &[Wire], expect: &[Byte], t: &mut Tally) -> Wire {
        let n = bytes.len();
        let nb = n / keccak::RATE + 1;
        let total = keccak::RATE * nb;
        // A hashed node has at least 32 bytes (a shorter one is embedded in its parent), so the first 32 bytes
        // are never padding.
        const MIN: usize = Keccak::MIN_NODE;
        let (blocks, sel, long_enough) = tally(c, t, "hash padding (mask, pad, length)", |c, _| {
            let lw = bits_needed(total);
            let len = &len[..len.len().min(lw)];
            let th = therm(c, len, total);
            let mut msg = Vec::with_capacity(8 * total);
            for j in 0..total {
                for b in 0..8 {
                    let d = if j < n { bytes[j][b] } else { Wire::ZERO };
                    msg.push(if j < MIN { d } else { c.and(d, th[j]) });
                }
                if j >= MIN {
                    let eq = c.xor(th[j - 1], th[j]);
                    msg[8 * j] = c.xor(msg[8 * j], eq);
                }
            }
            // The last block is `L / 136 + 1`: `[136 (b - 1) <= L < 136 b]`.
            let mut sel = Vec::with_capacity(nb);
            for b in 1..=nb {
                let lower = if b == 1 {
                    Wire::ONE
                } else {
                    th[keccak::RATE * (b - 1) - 1]
                };
                let s = c.xor(lower, th[keccak::RATE * b - 1]);
                let at = 8 * (keccak::RATE * b - 1) + 7;
                msg[at] = c.xor(msg[at], s);
                sel.push(s);
            }
            let blocks: Vec<Vec<Wire>> = msg.chunks(8 * keccak::RATE).map(|b| b.to_vec()).collect();
            (blocks, sel, th[MIN - 1])
        });
        let diffs = tally(c, t, "keccak-f (node hashes)", |c, _| {
            let mut stats = Stats::default();
            let all: Vec<usize> = (1..=nb).collect();
            keccak::sponge_diff(c, &blocks, &all, &byte_bits(expect), &mut stats)
        });
        tally(c, t, "hash padding (mask, pad, length)", |c, _| {
            let oks: Vec<Wire> = diffs
                .iter()
                .zip(&sel)
                .map(|(d, &s)| {
                    let differ = c.any(d);
                    c.and(s, differ.not())
                })
                .collect();
            let ok = c.any(&oks);
            c.and(ok, long_enough)
        })
    }

    fn fixed(c: &mut Ckt, bytes: &[Byte], t: &mut Tally) -> Vec<Byte> {
        tally(c, t, "keccak-f (keys, statement)", |c, _| {
            to_bytes(&keccak::keccak256(c, &byte_bits(bytes)))
        })
    }

    fn key(c: &mut Ckt, bytes: &[Byte], t: &mut Tally) -> Vec<Byte> {
        Self::fixed(c, bytes, t)
    }

    fn native(msg: &[u8]) -> Vec<u8> {
        use sha3::Digest;
        sha3::Keccak256::digest(msg).to_vec()
    }

    fn native_key(msg: &[u8]) -> Vec<u8> {
        Self::native(msg)
    }
}

/// A 16-bit stand-in for the node hash, for the bounded exhaustive tests only: not collision resistant, so
/// those tests treat an accepted proof whose hashed bytes differ from the true node as a collision, not a
/// soundness failure. Keys are the address or slot bytes themselves.
pub struct Toy;

fn toy_step(c: &mut Ckt, h: &[Wire], x: &Byte, j: usize) -> Word {
    let k = (j as u64).wrapping_mul(0x9e37).wrapping_add(0x79b9) & 0xffff;
    let rot: Word = (0..16).map(|i| h[(i + 16 - 5) % 16]).collect();
    let xx: Word = (0..16)
        .map(|i| {
            let w = x[i % 8];
            if (k >> i) & 1 == 1 { w.not() } else { w }
        })
        .collect();
    let s = c.add(&rot, &xx);
    (0..16)
        .map(|i| if i + 3 < 16 { c.xor(s[i], h[i + 3]) } else { s[i] })
        .collect()
}

fn toy_native_step(h: u16, x: u8, j: usize) -> u16 {
    let k = ((j as u64).wrapping_mul(0x9e37).wrapping_add(0x79b9) & 0xffff) as u16;
    let xx = ((x as u16) | ((x as u16) << 8)) ^ k;
    h.rotate_left(5).wrapping_add(xx) ^ (h >> 3)
}

impl TrieHash for Toy {
    const H: usize = 2;
    const MIN_NODE: usize = 0;

    fn check(c: &mut Ckt, bytes: &[Byte], len: &[Wire], expect: &[Byte], t: &mut Tally) -> Wire {
        tally(c, t, "toy hash", |c, _| {
            let len = &len[..len.len().min(bits_needed(bytes.len()))];
            let th = therm(c, len, bytes.len());
            let mut h = kword(0x6a09, 16);
            for (j, b) in bytes.iter().enumerate() {
                let next = toy_step(c, &h, b, j);
                h = c.mux_word(th[j], &next, &h);
            }
            let h = addw(c, &h, len, 16);
            eqw(c, &h, &byte_bits(expect))
        })
    }

    fn fixed(c: &mut Ckt, bytes: &[Byte], t: &mut Tally) -> Vec<Byte> {
        tally(c, t, "toy hash", |c, _| {
            let mut h = kword(0x6a09, 16);
            for (j, b) in bytes.iter().enumerate() {
                h = toy_step(c, &h, b, j);
            }
            let h = addk(c, &h, bytes.len() as u64, 16);
            to_bytes(&h)
        })
    }

    fn key(_c: &mut Ckt, bytes: &[Byte], _t: &mut Tally) -> Vec<Byte> {
        bytes.to_vec()
    }

    fn native(msg: &[u8]) -> Vec<u8> {
        let mut h = 0x6a09u16;
        for (j, &x) in msg.iter().enumerate() {
            h = toy_native_step(h, x, j);
        }
        h = h.wrapping_add(msg.len() as u16);
        h.to_le_bytes().to_vec()
    }

    fn native_key(msg: &[u8]) -> Vec<u8> {
        msg.to_vec()
    }
}

// ---------------------------------------------------------------------------------------------------------
// Parameters.

#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Bytes of a trie key (64 nibbles for Ethereum).
    pub key_bytes: usize,
    pub addr_bytes: usize,
    pub slot_bytes: usize,
    /// Bytes of the value `V` as the statement has it (big-endian).
    pub value_bytes: usize,
    /// Inner slots (branch or extension) of the account path and of the storage path.
    pub acct_inner: usize,
    pub stor_inner: usize,
    /// Bytes an inner node, an account leaf and a storage leaf may have.
    pub inner_max: usize,
    pub acct_leaf_max: usize,
    pub stor_leaf_max: usize,
}

impl Params {
    pub const MAINNET: Params = Params {
        key_bytes: 32,
        addr_bytes: 20,
        slot_bytes: 32,
        value_bytes: 32,
        acct_inner: 8,
        stor_inner: 6,
        inner_max: 532,
        acct_leaf_max: 148,
        stor_leaf_max: 70,
    };

    /// Tiny parameters for the bounded tests with [`Toy`]: 4-nibble keys, 2-byte references.
    pub fn toy(acct_inner: usize, stor_inner: usize) -> Params {
        Params {
            key_bytes: 2,
            addr_bytes: 2,
            slot_bytes: 2,
            value_bytes: 2,
            acct_inner,
            stor_inner,
            // A full branch: header, 16 references of 3 bytes, the empty value.
            inner_max: 50,
            acct_leaf_max: 20,
            stor_leaf_max: 10,
        }
    }

    fn k(&self) -> usize {
        2 * self.key_bytes
    }
}

// ---------------------------------------------------------------------------------------------------------
// Slots.

/// An inner slot's inputs.
pub struct InnerIn {
    pub node: Vec<Byte>,
    pub active: Wire,
    pub is_branch: Wire,
    pub occ: Vec<Wire>,
    pub hl2: Wire,
    pub single: Wire,
}

impl InnerIn {
    pub fn inputs(c: &mut Ckt, max: usize) -> InnerIn {
        let node = input_bytes(c, max);
        let active = c.input();
        let is_branch = c.input();
        let occ = c.inputs(16);
        let hl2 = c.input();
        let single = c.input();
        InnerIn {
            node,
            active,
            is_branch,
            occ,
            hl2,
            single,
        }
    }
}

/// A leaf slot's inputs; `vform` is `vlong` for an account leaf, `vsingle` for a storage leaf.
pub struct LeafIn {
    pub node: Vec<Byte>,
    pub hl2: Wire,
    pub single: Wire,
    pub vform: Wire,
}

impl LeafIn {
    pub fn inputs(c: &mut Ckt, max: usize) -> LeafIn {
        let node = input_bytes(c, max);
        let hl2 = c.input();
        let single = c.input();
        let vform = c.input();
        LeafIn {
            node,
            hl2,
            single,
            vform,
        }
    }
}

/// What a slot derives from its node: whether its checks pass, the node's length, and (inner) the child
/// reference and the nibbles consumed, or (leaf) the value read.
pub struct SlotOut {
    pub ok: Wire,
    pub len: Word,
    pub out: Vec<Byte>,
    pub consumed: Word,
}

/// A two-item node's header and path item.
struct TwoItem {
    ok: Wire,
    len: Word,
    /// Whether the path's flag nibble says leaf.
    leaf: Wire,
    nn: Word,
    path_ok: Wire,
    /// Where the second item starts.
    q: Word,
}

fn two_item(c: &mut Ckt, p: &Params, node: &[Byte], hl2: Wire, single: Wire, key_sh: &[Nib], t: &mut Tally) -> TwoItem {
    let k = p.k();
    let lw = len_bits(node.len());
    let (ok, len, leaf, nn, q, s_off, plen_ok) = tally(c, t, "rlp headers and items", |c, _| {
        // The list header: `0xc0 + P` (P <= 55), or `0xf8 P`.
        let b0 = node[0];
        let big = c.and(b0[5], b0[4]);
        let big = c.and(big, b0[3]);
        let short_ok = c.and(b0[7], b0[6]);
        let short_ok = c.and(short_ok, big.not());
        let long_ok = eqk(c, &b0, 0xf8);
        let hdr_ok = c.mux(hl2, long_ok, short_ok);
        let p_short: Word = b0[..6].to_vec();
        let pay = muxw(c, hl2, &node[1], &p_short);
        let hl: Word = vec![hl2.not(), hl2];
        let len = addw(c, &hl, &pay, lw);
        // The path item at `hl`: a single byte below 0x80, or `0x80 + plen` with `1 <= plen <= 55`.
        let pb: Byte = std::array::from_fn(|i| c.mux(hl2, node[2][i], node[1][i]));
        let s_ok = pb[7].not();
        let plen: Word = pb[..6].to_vec();
        let nz = c.any(&plen);
        let pbig = c.and(pb[5], pb[4]);
        let pbig = c.and(pbig, pb[3]);
        let ns_ok = c.and(pb[7], pb[6].not());
        let ns_ok = c.and(ns_ok, nz);
        let ns_ok = c.and(ns_ok, pbig.not());
        let item_ok = c.mux(single, s_ok, ns_ok);
        let ok = c.and(hdr_ok, item_ok);
        let plen_eff = muxw(c, single, &kword(1, 6), &plen);
        // The flag byte, at `cs = hl + (1 - single)`.
        let f: Byte = std::array::from_fn(|i| {
            let a = c.mux(single, node[2][i], node[3][i]);
            let b = c.mux(single, node[1][i], node[2][i]);
            c.mux(hl2, a, b)
        });
        let leaf = f[5];
        let flag_hi_ok = c.or(f[7], f[6]).not();
        let ok = c.and(ok, flag_hi_ok);
        let odd = f[4];
        // nn = 2 (plen - 1) + odd.
        let pm1 = c.sub(&plen_eff, &kword(1, 6)).0;
        let mut nn: Word = vec![odd];
        nn.extend(pm1);
        // q = hl + 1 + (single ? 0 : plen).
        let pl: Word = plen.iter().map(|&w| c.and(w, single.not())).collect();
        let hl1 = addk(c, &hl, 1, 3);
        let q = addw(c, &hl1, &pl, lw);
        // The path's first nibble is nibble `2 cs + 2 - odd` of the node; minus 3: `2 (cs - 1) + 1 - odd`.
        let ns = single.not();
        let s_off: Word = vec![odd.not(), c.xor(hl2, ns), c.and(hl2, ns)];
        (ok, len, leaf, nn, q, s_off, item_ok)
    });
    let _ = plen_ok;
    let path_ok = tally(c, t, "path nibbles", |c, _| {
        let nibs = nibbles_of(node);
        let stream: Vec<Vec<Wire>> = nibs.iter().skip(3).map(|n| n.to_vec()).collect();
        let stream = &stream[..stream.len().min(k + 5)];
        let path = shift_elems(c, stream, &s_off, 5, k);
        let mask = therm(c, &nn, k);
        let mism: Vec<Wire> = (0..k)
            .map(|i| {
                let d: Vec<Wire> = (0..4).map(|b| c.xor(path[i][b], key_sh[i][b])).collect();
                let d = c.any(&d);
                c.and(d, mask[i])
            })
            .collect();
        c.any(&mism).not()
    });
    TwoItem {
        ok,
        len,
        leaf,
        nn,
        path_ok,
        q,
    }
}

/// An inner slot: a branch or an extension, read against the key nibbles from position `n` on (`key_sh`).
pub fn inner_slot<T: TrieHash>(
    c: &mut Ckt,
    p: &Params,
    s: &InnerIn,
    key_sh: &[Nib],
    n: &[Wire],
    t: &mut Tally,
) -> SlotOut {
    let h = T::H;
    let k = p.k();
    let node = &s.node;
    let big_n = node.len();
    let lw = len_bits(big_n);
    // The branch.
    let (b_ok, b_len, pk) = tally(c, t, "rlp headers and items", |c, _| {
        let pc = popcount(c, &s.occ);
        let pay = {
            let m = mulk(c, &pc, h as u64, lw);
            addk(c, &m, 17, lw)
        };
        let hl1 = lek(c, &pay, 55);
        let hl3 = c.any(&pay[8.min(lw)..]);
        let hl2 = c.or(hl1, hl3).not();
        let hlsel = [hl1, hl2, hl3];
        // hl = 1 + [P > 55] + [P > 255].
        let hl = {
            let a: Word = vec![hl1.not()];
            let b: Word = vec![hl3];
            let ab = addw(c, &a, &b, 2);
            addk(c, &ab, 1, 2)
        };
        let len = addw(c, &hl, &pay, lw);
        // The header bytes.
        let e1 = {
            let mut exp: Word = pay[..6].to_vec();
            exp.push(Wire::ONE);
            exp.push(Wire::ONE);
            eqw(c, &node[0], &exp)
        };
        let e2 = {
            let a = eqk(c, &node[0], 0xf8);
            let b = eqw(c, &node[1], &zext(&pay, 8));
            c.and(a, b)
        };
        let e3 = if big_n > 2 {
            let a = eqk(c, &node[0], 0xf9);
            let b = eqw(c, &node[1], &zext(&pay[8.min(lw)..], 8));
            let d = eqw(c, &node[2], &zext(&pay, 8));
            let ab = c.and(a, b);
            c.and(ab, d)
        } else {
            Wire::ZERO
        };
        let h1 = c.and(hl1, e1);
        let h2 = c.and(hl2, e2);
        let h3 = c.and(hl3, e3);
        let hdr = c.any(&[h1, h2, h3]);
        // Item j starts at hl + j + h m_j, m_j = popcount(occ[..j]); `e[m]` is `[m_j == m]`.
        let max_pc = |hlv: usize| -> usize {
            let cap = match hlv {
                1 => 55,
                2 => 255,
                _ => usize::MAX,
            };
            if cap < 17 { 0 } else { ((cap - 17) / h).min(16) }
        };
        let mut e: Vec<Wire> = vec![Wire::ONE];
        let mut items = Vec::with_capacity(17);
        for j in 0..=16 {
            let mut acc = Vec::new();
            for hlv in 1..=3usize {
                // A header length no occupancy reaches (P = 17 + h pc, pc <= 16) has no candidates.
                // Nor does one only a branch of fewer than two children (never a trie node) would have.
                let (p_min, p_max) = (17 + 2 * h, 17 + 16 * h);
                if (hlv >= 2 && p_max <= 55) || (hlv == 3 && p_max <= 255) || (hlv == 1 && p_min > 55) {
                    continue;
                }
                for (m, &em) in e.iter().enumerate().take(max_pc(hlv).min(j) + 1) {
                    let at = hlv + j + h * m;
                    if at >= big_n {
                        continue;
                    }
                    let b = node[at];
                    // 0x80, or 0x80 + h when the child is present.
                    let lits: Vec<Wire> = (0..8)
                        .map(|i| {
                            if (0x80 >> i) & 1 == 1 {
                                b[i]
                            } else if j < 16 && (h >> i) & 1 == 1 {
                                c.xor(b[i], s.occ[j]).not()
                            } else {
                                b[i].not()
                            }
                        })
                        .collect();
                    let eqb = c.all(&lits);
                    let sel = c.and(hlsel[hlv - 1], em);
                    acc.push(c.and(sel, eqb));
                }
            }
            items.push(c.any(&acc));
            if j < 16 {
                let o = s.occ[j];
                let mut next = Vec::with_capacity(e.len() + 1);
                for m in 0..=e.len() {
                    let stay = e.get(m).copied().unwrap_or(Wire::ZERO);
                    let up = if m > 0 { e[m - 1] } else { Wire::ZERO };
                    next.push(c.mux(o, up, stay));
                }
                e = next;
            }
        }
        let items_ok = and_all(c, &items);
        // The child: item `kk`, the key's next nibble.
        let kk: Word = key_sh[0].to_vec();
        let occ_words: Vec<Vec<Wire>> = s.occ.iter().map(|&w| vec![w]).collect();
        let occ_k = shift_elems(c, &occ_words, &kk, 15, 1)[0][0];
        let below = therm(c, &kk, 16);
        let masked: Vec<Wire> = (0..16).map(|i| c.and(s.occ[i], below[i])).collect();
        let mk = popcount(c, &masked);
        let hm = mulk(c, &mk, h as u64, lw);
        let pk = addw(c, &hl, &kk, lw);
        let pk = addw(c, &pk, &hm, lw);
        let n_ok = c.sub(n, &kword(k as u64, n.len())).1.not();
        let ok = c.all(&[hdr, items_ok, occ_k, n_ok]);
        (ok, len, pk)
    });
    // The extension.
    let two = two_item(c, p, node, s.hl2, s.single, key_sh, t);
    // The reference: at `pk` for a branch, `q` for an extension, after a one-byte header.
    let max_o = (3 + 15 + 15 * h).max(2 + 1 + 55);
    let (o, len, consumed) = tally(c, t, "slot muxes", |c, _| {
        let o = muxw(c, s.is_branch, &pk, &two.q);
        let len = muxw(c, s.is_branch, &b_len, &two.len);
        let consumed = muxw(c, s.is_branch, &kword(1, n.len()), &zext(&two.nn, n.len()));
        (o, len, consumed)
    });
    let win = tally(c, t, "reference and value selection", |c, _| {
        shift_bytes(c, node, &o, max_o, 1 + h)
    });
    let ok = tally(c, t, "rlp headers and items", |c, _| {
        let hdr = eqk(c, &win[0], 0x80 + h as u64);
        let q_end = addk(c, &two.q, 1 + h as u64, lw);
        let fills = eqw(c, &q_end, &two.len);
        let nsum = addw(c, n, &two.nn, n.len().max(7) + 1);
        let fits = lek(c, &nsum, k as u64);
        let e_ok = c.all(&[two.ok, two.leaf.not(), two.path_ok, hdr, fills, fits]);
        let ok = c.mux(s.is_branch, b_ok, e_ok);
        let in_bounds = lek(c, &len, big_n as u64);
        c.and(ok, in_bounds)
    });
    SlotOut {
        ok,
        len,
        out: win[1..].to_vec(),
        consumed,
    }
}

/// A leaf slot: the rest of the key must be its path. For an account leaf the output is the storage root; for
/// a storage leaf, the value as `value_bytes` big-endian bytes.
pub fn leaf_slot<T: TrieHash>(
    c: &mut Ckt,
    p: &Params,
    s: &LeafIn,
    account: bool,
    key_sh: &[Nib],
    n: &[Wire],
    t: &mut Tally,
) -> SlotOut {
    let h = T::H;
    let k = p.k();
    let node = &s.node;
    let big_n = node.len();
    let lw = len_bits(big_n);
    let two = two_item(c, p, node, s.hl2, s.single, key_sh, t);
    let w2 = tally(c, t, "reference and value selection", |c, _| {
        shift_bytes(c, node, &two.q, 2 + 1 + 55, 2)
    });
    let (ok, vlen) = tally(c, t, "rlp headers and items", |c, _| {
        let nsum = addw(c, n, &two.nn, n.len().max(7) + 1);
        let ends = eqk(c, &nsum, k as u64);
        let (item_ok, end, vlen) = if account {
            // `0xb8 vlen`, or `0x80 + vlen` with vlen <= 55.
            let long_ok = eqk(c, &w2[0], 0xb8);
            let big = c.and(w2[0][5], w2[0][4]);
            let big = c.and(big, w2[0][3]);
            let short_ok = c.and(w2[0][7], w2[0][6].not());
            let short_ok = c.and(short_ok, big.not());
            let ok = c.mux(s.vform, long_ok, short_ok);
            let e_long = {
                let a = addk(c, &two.q, 2, lw);
                addw(c, &a, &w2[1], lw)
            };
            let e_short = {
                let a = addk(c, &two.q, 1, lw);
                addw(c, &a, &w2[0][..6], lw)
            };
            let end = muxw(c, s.vform, &e_long, &e_short);
            (ok, end, vec![])
        } else {
            // A single byte below 0x80; or `0x81 + vlen, 0x80 + vlen` with 1 <= vlen <= value_bytes.
            let single_ok = w2[0][7].not();
            let vl: Word = w2[1][..6].to_vec();
            let nz = c.any(&vl);
            let le = lek(c, &vl, p.value_bytes as u64);
            let one_more = addk(c, &w2[1], 1, 8);
            let nested = eqw(c, &w2[0], &one_more);
            let multi_ok = c.all(&[w2[1][7], w2[1][6].not(), nz, le, nested]);
            let ok = c.mux(s.vform, single_ok, multi_ok);
            let e_single = addk(c, &two.q, 1, lw);
            let e_multi = {
                let a = addk(c, &two.q, 2, lw);
                addw(c, &a, &vl, lw)
            };
            let end = muxw(c, s.vform, &e_single, &e_multi);
            let vlen = muxw(c, s.vform, &kword(1, 6), &vl);
            (ok, end, vlen)
        };
        let fills = eqw(c, &end, &two.len);
        let in_bounds = lek(c, &two.len, big_n as u64);
        let ok = c.all(&[two.ok, two.leaf, two.path_ok, ends, item_ok, fills, in_bounds]);
        (ok, vlen)
    });
    let out = tally(c, t, "reference and value selection", |c, _| {
        // Windows ending at `L`, read from the node behind zeros, from the shortest node's end on.
        let min = T::MIN_NODE;
        let from_min = c.sub(&two.len, &kword(min as u64, two.len.len())).0;
        if account {
            // The storage root: the `h` bytes at `L - 2h - 1`.
            let mut padded = vec![byte_const(0); 2 * h + 1];
            padded.extend_from_slice(node);
            shift_bytes(c, &padded[min..], &from_min, big_n - min, h)
        } else {
            // The value: the last `vlen` bytes before `L`, right-aligned in `value_bytes`.
            let vb = p.value_bytes;
            let mut padded = vec![byte_const(0); vb];
            padded.extend_from_slice(node);
            let win = shift_bytes(c, &padded[min..], &from_min, big_n - min, vb);
            let keep = therm(c, &vlen, vb);
            (0..vb)
                .map(|i| {
                    let kp = keep[vb - 1 - i];
                    std::array::from_fn(|b| c.and(win[i][b], kp))
                })
                .collect()
        }
    });
    SlotOut {
        ok,
        len: two.len,
        out,
        consumed: vec![],
    }
}

/// What a whole circuit exposes besides its public bits, for tests.
pub struct Built {
    pub public: Vec<Wire>,
    pub valid: Wire,
    pub value: Vec<Byte>,
    pub tally: Tally,
    /// Per slot, account path first then storage (inner slots, then the leaf): `(active, len)`.
    pub slots: Vec<(Wire, Word)>,
}

/// One path: inner slots then the leaf, from `root`, along `key`. Returns validity, the leaf's output.
#[allow(clippy::too_many_arguments)]
fn walk<T: TrieHash>(
    c: &mut Ckt,
    p: &Params,
    root: &[Byte],
    key: &[Byte],
    inner: &[InnerIn],
    leaf: &LeafIn,
    account: bool,
    t: &mut Tally,
    slots: &mut Vec<(Wire, Word)>,
) -> (Wire, Vec<Byte>) {
    let k = p.k();
    let nw = bits_needed(k) + 1;
    let key_nibs: Vec<Vec<Wire>> = nibbles_of(key).iter().map(|n| n.to_vec()).collect();
    let mut h: Vec<Byte> = root.to_vec();
    let mut n: Word = kword(0, nw);
    let mut valid = Wire::ONE;
    let mut prev = Wire::ZERO;
    let shift_key = |c: &mut Ckt, n: &Word, t: &mut Tally| -> Vec<Nib> {
        tally(c, t, "key nibble alignment", |c, _| {
            shift_elems(c, &key_nibs, n, k, k)
                .into_iter()
                .map(|v| v.try_into().unwrap())
                .collect()
        })
    };
    for s in inner {
        let key_sh = shift_key(c, &n, t);
        let o = inner_slot::<T>(c, p, s, &key_sh, &n, t);
        let hash_ok = T::check(c, &s.node, &o.len, &h, t);
        slots.push((s.active, o.len.clone()));
        tally(c, t, "slot muxes", |c, _| {
            let good = c.and(o.ok, hash_ok);
            let v1 = c.or(s.active.not(), good);
            let v2 = c.or(prev.not(), s.active);
            valid = c.all(&[valid, v1, v2]);
            prev = s.active;
            h = mux_bytes(c, s.active, &o.out, &h);
            let next = addw(c, &n, &o.consumed, nw);
            n = muxw(c, s.active, &next, &n);
        });
    }
    let key_sh = shift_key(c, &n, t);
    let o = leaf_slot::<T>(c, p, leaf, account, &key_sh, &n, t);
    let hash_ok = T::check(c, &leaf.node, &o.len, &h, t);
    slots.push((Wire::ONE, o.len.clone()));
    let valid = tally(c, t, "slot muxes", |c, _| c.all(&[valid, o.ok, hash_ok]));
    (valid, o.out)
}

/// The whole statement: inputs as the module documents, public bits `hash(R || A || S || V)` and `valid`.
pub fn build_mpt<T: TrieHash>(c: &mut Ckt, p: &Params) -> Built {
    let mut t = Tally::default();
    let r_in = c.rows();
    let root = input_bytes(c, T::H);
    let addr = input_bytes(c, p.addr_bytes);
    let slot = input_bytes(c, p.slot_bytes);
    let acct_inner: Vec<InnerIn> = (0..p.acct_inner).map(|_| InnerIn::inputs(c, p.inner_max)).collect();
    let acct_leaf = LeafIn::inputs(c, p.acct_leaf_max);
    let stor_inner: Vec<InnerIn> = (0..p.stor_inner).map(|_| InnerIn::inputs(c, p.inner_max)).collect();
    let stor_leaf = LeafIn::inputs(c, p.stor_leaf_max);
    t.add("input rows", c.rows() - r_in);
    let akey = T::key(c, &addr, &mut t);
    let skey = T::key(c, &slot, &mut t);
    let mut slots = Vec::new();
    let (va, sroot) = walk::<T>(c, p, &root, &akey, &acct_inner, &acct_leaf, true, &mut t, &mut slots);
    let (vs, value) = walk::<T>(c, p, &sroot, &skey, &stor_inner, &stor_leaf, false, &mut t, &mut slots);
    let valid = c.and(va, vs);
    let mut msg = root.clone();
    msg.extend_from_slice(&addr);
    msg.extend_from_slice(&slot);
    msg.extend_from_slice(&value);
    let digest = T::fixed(c, &msg, &mut t);
    let mut public = byte_bits(&digest);
    public.resize(256, Wire::ZERO);
    public.push(valid);
    public.resize(PUBLIC_BITS, Wire::ZERO);
    Built {
        public,
        valid,
        value,
        tally: t,
        slots,
    }
}

// ---------------------------------------------------------------------------------------------------------
// The native side: RLP, hex-prefix paths, synthetic proofs, and the witness.

pub mod native {
    use super::{Params, TrieHash};

    pub fn rlp_str(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        let mut out = header(0x80, b.len());
        out.extend_from_slice(b);
        out
    }

    /// A list of already encoded items.
    pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = header(0xc0, payload.len());
        out.extend(payload);
        out
    }

    fn header(base: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            vec![base + len as u8]
        } else {
            let be: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
            let mut out = vec![base + 55 + be.len() as u8];
            out.extend(be);
            out
        }
    }

    /// The minimal big-endian bytes of a number given as big-endian bytes.
    pub fn minimal(be: &[u8]) -> Vec<u8> {
        be.iter().copied().skip_while(|&b| b == 0).collect()
    }

    /// Hex-prefix encoding of `nibbles`.
    pub fn hp(nibbles: &[u8], leaf: bool) -> Vec<u8> {
        let flag = if leaf { 2 } else { 0 } + (nibbles.len() % 2) as u8;
        let mut out = Vec::new();
        let rest = if nibbles.len() % 2 == 1 {
            out.push((flag << 4) | nibbles[0]);
            &nibbles[1..]
        } else {
            out.push(flag << 4);
            nibbles
        };
        for pair in rest.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
        out
    }

    pub fn nibbles(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().flat_map(|&b| [b >> 4, b & 15]).collect()
    }

    /// One level of a synthetic path, root first.
    #[derive(Clone, Copy, Debug)]
    pub enum Level {
        /// A branch with this many children (the path's among them).
        Branch(usize),
        /// An extension of this many nibbles.
        Ext(usize),
    }

    /// A proof for `key` holding `value` (the leaf's value bytes) along `levels`, siblings random
    /// references: the root hash and the nodes, root first.
    pub fn synth_path<T: TrieHash>(
        key: &[u8],
        value: &[u8],
        levels: &[Level],
        rng: &mut impl FnMut() -> u64,
    ) -> (Vec<u8>, Vec<Vec<u8>>) {
        let nib = nibbles(key);
        let depth: usize = levels
            .iter()
            .map(|l| match l {
                Level::Branch(_) => 1,
                Level::Ext(e) => *e,
            })
            .sum();
        let mut child = rlp_list(&[rlp_str(&hp(&nib[depth..], true)), rlp_str(value)]);
        let mut nodes = vec![child.clone()];
        let mut at = depth;
        for l in levels.iter().rev() {
            let r = T::native(&child);
            assert!(child.len() >= T::H, "an embedded node");
            child = match *l {
                Level::Branch(children) => {
                    at -= 1;
                    let me = nib[at] as usize;
                    let mut slots: Vec<Option<Vec<u8>>> = vec![None; 16];
                    slots[me] = Some(r);
                    let mut placed = 1;
                    while placed < children.min(16) {
                        let j = (rng() % 16) as usize;
                        if slots[j].is_none() {
                            slots[j] = Some((0..T::H).map(|_| rng() as u8).collect());
                            placed += 1;
                        }
                    }
                    let mut items: Vec<Vec<u8>> = slots.iter().map(|s| rlp_str(s.as_deref().unwrap_or(&[]))).collect();
                    items.push(rlp_str(&[]));
                    rlp_list(&items)
                }
                Level::Ext(e) => {
                    at -= e;
                    rlp_list(&[rlp_str(&hp(&nib[at..at + e], false)), rlp_str(&r)])
                }
            };
            nodes.push(child.clone());
        }
        nodes.reverse();
        (T::native(&child), nodes)
    }

    /// An account's RLP.
    pub fn account(nonce: u64, balance: &[u8], storage_root: &[u8], code_hash: &[u8]) -> Vec<u8> {
        rlp_list(&[
            rlp_str(&minimal(&nonce.to_be_bytes())),
            rlp_str(&minimal(balance)),
            rlp_str(storage_root),
            rlp_str(code_hash),
        ])
    }

    /// A minimal RLP reader: `(offset of payload, payload length, is list, total length)` of the item at `at`.
    pub fn item(b: &[u8], at: usize) -> (usize, usize, bool, usize) {
        let x = b[at];
        match x {
            0..=0x7f => (at, 1, false, 1),
            0x80..=0xb7 => (at + 1, (x - 0x80) as usize, false, 1 + (x - 0x80) as usize),
            0xb8..=0xbf | 0xf8..=0xff => {
                let ll = (x - if x >= 0xf8 { 0xf7 } else { 0xb7 }) as usize;
                let len = b[at + 1..at + 1 + ll]
                    .iter()
                    .fold(0usize, |a, &y| (a << 8) | y as usize);
                (at + 1 + ll, len, x >= 0xf8, 1 + ll + len)
            }
            0xc0..=0xf7 => (at + 1, (x - 0xc0) as usize, true, 1 + (x - 0xc0) as usize),
        }
    }

    /// The items of a list node: `(start, total length)` each.
    pub fn items(node: &[u8]) -> Vec<(usize, usize)> {
        let (off, len, list, _) = item(node, 0);
        assert!(list);
        let mut out = Vec::new();
        let mut at = off;
        while at < off + len {
            let (_, _, _, tot) = item(node, at);
            out.push((at, tot));
            at += tot;
        }
        out
    }

    /// An inner slot's hint bits: `[is_branch, occ[16], hl2, single]`.
    pub fn inner_hints(node: &[u8]) -> Vec<bool> {
        let it = items(node);
        let mut out = Vec::new();
        if it.len() == 17 {
            out.push(true);
            out.extend((0..16).map(|j| it[j].1 > 1));
            out.extend([false, false]);
        } else {
            out.push(false);
            out.extend([false; 16]);
            out.push(node[0] == 0xf8);
            out.push(node[it[0].0] < 0x80);
        }
        out
    }

    /// A leaf slot's hint bits: `[hl2, single, vform]`.
    pub fn leaf_hints(node: &[u8], account: bool) -> Vec<bool> {
        let it = items(node);
        let v = node[it[1].0];
        vec![
            node[0] == 0xf8,
            node[it[0].0] < 0x80,
            if account { v >= 0xb8 } else { v < 0x80 },
        ]
    }

    fn bits(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
        bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
    }

    /// The free inputs for a proof, or `None` if it does not fit `p`.
    pub fn witness(
        p: &Params,
        root: &[u8],
        addr: &[u8],
        slot: &[u8],
        acct_proof: &[Vec<u8>],
        stor_proof: &[Vec<u8>],
    ) -> Option<Vec<bool>> {
        let mut out: Vec<bool> = Vec::new();
        out.extend(bits(root));
        out.extend(bits(addr));
        out.extend(bits(slot));
        for (proof, inner, leaf_max, account) in [
            (acct_proof, p.acct_inner, p.acct_leaf_max, true),
            (stor_proof, p.stor_inner, p.stor_leaf_max, false),
        ] {
            let (leaf, nodes) = proof.split_last()?;
            if nodes.len() > inner || leaf.len() > leaf_max {
                return None;
            }
            let idle = inner - nodes.len();
            for i in 0..inner {
                let mut b = vec![0u8; p.inner_max];
                let mut hints = vec![false; 20];
                if i >= idle {
                    let node = &nodes[i - idle];
                    if node.len() > p.inner_max {
                        return None;
                    }
                    b[..node.len()].copy_from_slice(node);
                    hints[0] = true;
                    hints[1..].copy_from_slice(&inner_hints(node));
                }
                out.extend(bits(&b));
                out.extend(hints);
            }
            let mut b = vec![0u8; leaf_max];
            b[..leaf.len()].copy_from_slice(leaf);
            out.extend(bits(&b));
            out.extend(leaf_hints(leaf, account));
        }
        Some(out)
    }

    /// The input index of each slot's first hint bit (`active` for inner slots, `hl2` for leaves), and of its
    /// node's first bit, account path first.
    pub fn slot_offsets(p: &Params, h: usize) -> Vec<(usize, usize)> {
        let mut at = 8 * (h + p.addr_bytes + p.slot_bytes);
        let mut out = Vec::new();
        for (inner, leaf_max) in [(p.acct_inner, p.acct_leaf_max), (p.stor_inner, p.stor_leaf_max)] {
            for _ in 0..inner {
                out.push((at + 8 * p.inner_max, at));
                at += 8 * p.inner_max + 20;
            }
            out.push((at + 8 * leaf_max, at));
            at += 8 * leaf_max + 3;
        }
        out
    }
}

/// A realistic instance: account path of 8 or 9 nodes (six full branch levels, an 11-child level, sometimes a
/// sparse one, the leaf), storage path of 5 to 7 nodes, sometimes through an extension.
/// A synthetic instance: root, address, slot, value (32 bytes) and the free inputs.
pub type Synth = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<bool>);

pub fn synth_instance<T: TrieHash>(p: &Params, seed: u64) -> Synth {
    use native::Level::{Branch, Ext};
    let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x1234_5678;
    let mut rng = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let addr: Vec<u8> = (0..p.addr_bytes).map(|_| rng() as u8).collect();
    let mut slot = vec![0u8; p.slot_bytes];
    slot[p.slot_bytes - 1] = (seed % 7) as u8;
    // A value of 1 to value_bytes bytes, sometimes a single small byte.
    let vlen = if seed % 3 == 1 {
        1
    } else {
        1 + (rng() as usize) % p.value_bytes
    };
    let mut value = vec![0u8; p.value_bytes];
    for v in &mut value[p.value_bytes - vlen..] {
        *v = rng() as u8;
    }
    let lead = p.value_bytes - vlen;
    if value[lead] == 0 {
        value[lead] = 1;
    }
    if seed % 3 == 1 {
        value[lead] &= 0x7f;
        value[lead] |= 1;
    }
    let mut stor_levels = vec![Branch(16), Branch(16), Branch(16), Branch(16), Branch(6)];
    if seed % 2 == 1 {
        stor_levels = vec![Branch(16), Branch(16), Branch(16), Branch(16), Ext(2), Branch(2)];
    }
    stor_levels.truncate(p.stor_inner);
    let skey = T::native_key(&slot);
    let (sroot, sproof) = native::synth_path::<T>(
        &skey,
        &native::rlp_str(&native::minimal(&value)),
        &stor_levels,
        &mut rng,
    );
    let code: Vec<u8> = (0..T::H).map(|_| rng() as u8).collect();
    let balance: Vec<u8> = (0..12).map(|_| rng() as u8).collect();
    let acct = native::account(rng() % 100_000, &balance, &sroot, &code);
    let mut acct_levels = vec![Branch(16); 6];
    acct_levels.push(Branch(11));
    if seed % 3 != 2 {
        acct_levels.push(Branch(2));
    }
    acct_levels.truncate(p.acct_inner);
    let akey = T::native_key(&addr);
    let (root, aproof) = native::synth_path::<T>(&akey, &acct, &acct_levels, &mut rng);
    let inputs = native::witness(p, &root, &addr, &slot, &aproof, &sproof).expect("fits");
    (root, addr, slot, value, inputs)
}

/// The statement's 64 bytes, computed natively.
pub fn statement<T: TrieHash>(root: &[u8], addr: &[u8], slot: &[u8], value: &[u8], valid: bool) -> Vec<u8> {
    let msg = [root, addr, slot, value].concat();
    let mut st = T::native(&msg);
    st.resize(64, 0);
    st[32.max(T::H)] = valid as u8;
    st
}

/// `MptStorageProof`: the module's statement at [`Params::MAINNET`].
pub struct MptStorageProof;

impl Workload for MptStorageProof {
    const NAME: &'static str = "mpt-storage-proof";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        build_mpt::<Keccak>(c, &Params::MAINNET).public
    }

    fn instance(seed: u64) -> Instance {
        let p = Params::MAINNET;
        let (root, addr, slot, value, inputs) = synth_instance::<Keccak>(&p, seed);
        Instance {
            inputs,
            statement: statement::<Keccak>(&root, &addr, &slot, &value, true)
                .try_into()
                .unwrap(),
        }
    }

    /// A sibling reference in the account path's root node tampered with: the root's hash fails.
    fn invalid_instance(seed: u64) -> Option<Instance> {
        let p = Params::MAINNET;
        let (root, addr, slot, value, mut inputs) = synth_instance::<Keccak>(&p, seed);
        let offs = native::slot_offsets(&p, Keccak::H);
        let first_active = (0..p.acct_inner).find(|&i| inputs[offs[i].0]).unwrap();
        // A byte well inside the root node (its first child's hash or the empty marker after it).
        let at = offs[first_active].1 + 8 * 40 + 3;
        inputs[at] ^= true;
        Some(Instance {
            inputs,
            statement: statement::<Keccak>(&root, &addr, &slot, &value, false)
                .try_into()
                .unwrap(),
        })
    }
}

/// Rows and inputs of [`MptStorageProof`], with the breakdown.
pub fn report() -> (usize, usize, Tally) {
    let mut c = Ckt::new();
    let b = build_mpt::<Keccak>(&mut c, &Params::MAINNET);
    (c.rows(), c.n_inputs(), b.tally)
}

#[cfg(test)]
mod tests {
    use super::native::{self, Level};
    use super::*;
    use crate::keccak::tests::{eval64, wire64};
    use crate::{Circuit, Src, read_statement};
    use std::collections::HashMap;
    use std::sync::OnceLock;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn keccak(m: &[u8]) -> Vec<u8> {
        Keccak::native(m)
    }

    // Mainnet block 26240091 (0x57e489730d37450dec4d412b701fa3d8154911a78c0601e072af95df9382202f), from https://ethereum-rpc.publicnode.com: eth_getProof of Curve tricrypto2 (0xD51a44d3FaE010294C616388b506AcdA1bfAAE46), slot 1.
    const TRI_ROOT: &str = "d90c457c3fa6d7c4bb540b798544d20932918f4046aabba1662acca1b43fb8ec";
    const TRI_ADDR: &str = "d51a44d3fae010294c616388b506acda1bfaae46";
    const TRI_SLOT: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const TRI_VALUE: &str = "856fcabfe67b44faf700000000000011a2806f1e7fce45e0a7";
    const TRI_STORAGE_HASH: &str = "50c68a44a4e53bdd18bf23fd59a5cebc3e4200ff97c84806ae29d6a9db04b81b";
    const TRI_ACCOUNT_PROOF: &[&str] = &[
        "f90211a072fc4e08ee563e1c98656fea043a1cda1f29456e85df6d4dd43b6f169051dbc7a086b392f6aed897fcbfb497f6a3fc538f7af272d60d72b99908f09d694b8a1efca0f7edf1112d2aef6a48f10cb521949c681dbccb6b546f9a9655b020100c7f8a1da090c54147e6959c1e66fd57270318c2bafeaa2804eb6485948b9f103b08c75a74a01d0fc0b4aad5f1acd0cdab7ccec3d7e0b2fec97bf19ef03d7e94bec7e70e0492a09c7cf07989441157ccb0b77254c734a671a5cfe315485ed79a362125f6628049a03f352b59e5b1af0b1578f687b7a659533ee59afdf76da5908341baf12f916936a051a465afd8361af03a1455bfa1a84c10b5155f45e5985c183f0c8bdc258efec7a0e0b269d787def5703cea49481efc902bab047eb0ca5a6135e4201ee416458477a08114eb8578aea0a7561f904a92375937d41c86a9d495262ccc9dc523fc7c54d6a0694b32021a27a67040b0121953fb480e0685a0b289fcf7a3df859344a251e6c3a03ad9826e5e46e4b486e06088e4938d8e0749aafc20b8b36de6da0e92d88c5ce0a0a01f2601a6fadbfd061aa3becdb9db30014224ce07d1a333a8167905cffe2b9fa034052a0db8f6092ebff5c99157dad5ef5c8f8a84e9b6ac733dc1f82a89a137d1a06fc055134386381e3730193bcc7efa6d01e2457c6a86ed9f1184a8b7ef1892d3a07a22d110a50931e82cee0aa578406e6fe5aeb430ccd47d0b652ce380fa969f4580",
        "f90211a023912a53013bca47fa296e3b9414c258240537f15fd0945ac3c422a9feac1ccaa048690ed9254cc1f1c9a7400bd829c8b142a0770e61000e3269522d1a3219a0e3a09aece05f60f1e4adf297daa53af46e9bdf9e9b3f91b44effbd8522052525fe94a048ed3931033757117b11480febac3f3f8f756566936be4c008ba3ff90b250d5ea0a77b228d5a1698ac0b9aeb5fa9c2ce2b872797bdb086d733522e214817d21736a06d3b6ffd2ef80906ea9e742269d9208b317fc46ccaa980cb931371e42e4a2819a0d3da21a52c148633498bdd038765ae6ec7de1cb13364e37d86152933c93b9ebda0aa05b0fa36e6ad5e4d7640a5e3ac6d5b964ee7faf58f13e329824331d5178907a007d00a81d1168b32ccb2ca747fdbe4ec2356799db3538a0523069b0077ac4439a02351100d2aae5d70f660a2a36078aff7bc1e1b057cfa8031cdcecce563d2ad03a0a1148ce3eac5e291a714f9c62b9a22567a0ffaa0685b829da85d0384ef12ff19a04a4d679fa208181d549b6d9f9317b089a0c30888e77dda15617c76a6f6ef7cf2a09ccafb2bf6b85a15d1d935bbcafc38219b6a522b5c6cb778ab28caefca6f7d6ea00b094d1b93ac5a62409e6dc330187818ad50b54c334ea4413e6b21a90a45daa0a023e314e8be1e0f628275060a5f96bb295d0afa9c4ed58e00c8814978b89571fba045ea35cc76b87e6ddebdcb1eaf77c6f3588dd8d0552eecd34b61605a91d4196e80",
        "f90211a05a89ecbe15cd34ead2cdf8a496f5bf8f2646898c440916256b5ebdd94c840b45a07009a347d3d4e28ff9cb557db721a9f95e0ac63d454727b830632bbb1788352da0fe62ed945a71af1e2b5755d80b7bf5a6513e3eaed7660a60b6765c73063a5403a084fa0b1515c173b2a0b575380492bb62025e1d478677789ef158c7318d5848d1a0b847449757fdc0cee0697aae370df082912e5baf395898aa409be63b288f17bea0c5be61a48ae124adc70141422c7142768169ffb58886c9285733fa6e4ead2d8ca04dbd280adb371c8f03fdc0fb16adfe964e3bfa80463c10fe282e7d23d8756bb9a01ec66bf348b150b7194f86deac31b8f5e1d6a73176bcd85062153716d0eda438a01623e1b4487f77b2aa497e05ed5503c82d5a85884d6dc82677c6a76697d4902ca0a356a999e5dacae2b8e2b12de549e1081d0d4d84474b3d47898b581a06b64c65a0b0e71e1125ce1c68c3d0dbe850ecd417e5fe44e1d9cb652493c170bc52c12505a01f4004c591b122c02dd4b066e07b9e38ec1fd623be1aaf0c9470d2df66bd216fa0cfac1e1723198e8409b870de92de639220bb7e2070c1ba948c6f970fde139a2ca0f8ac52010f70c79a0f5f1f80aa89aba5dac0e1837c35a1799c77f63e217bfe0ea04f9b41fcaa456b9b1dbc3658e1ca582fa11d9b112f85fed083e2d4d9aa96416da0315ea361c00462d8fc98a227d09140296bcd6ecf21bff276672cbed64398f1e780",
        "f90211a0f9e6b8ce9e6a2748b8f2184e12747d2ce885cb0d87f83437b8aa082ca6cfbde8a04e0470a1d2d855e83e04ce883b7afc15b6a9e340d0d14c8d4b1bfc2f1b0e15dda018d51491f35fae1d8c81267aea8daa41890e00d5fd019369045fa1ab2e7c56dea01edc0e9574aa04fbd82b937871f4b3c9267f46a04dddc98907d6d1af482037fca057d1852ba81301eac362ac2d96d9d8b74bedcdf4d61015426422452cec6c31cca020e77ed727bed4bf72eba87737b1744cf3971c6ba06888c846a8cbb10f9c519ea0fcab573bd40c9d92e0cede6898363b31dc231bf98973bd8d0e8a0c4ef0acd571a0d7ba1828059ba0b667d676e9caa61474693ef497a4ef0494270586912990d3e7a0af71916c0d1ba9dacb9fb49ccb01f81bfb443f2595c82b5ce502e3e905f95d90a077f1496e8590e846a450d1ac226b058622c9245d37ab87d39fb24ed3bd0b4e2ea01b8d33c2a99901991153cf652acdcb5ef560a660f1b121f73e24f669cf769bd9a0e2726651d8a1de6afc07a8560f4441fda42bf74f579b5a8fb62a27108afb8480a0f8453068698b6304644c99c496c7f61739af1e59ef8aacf94f38fff87275a9b3a00cab5ea7f2f70f85e0daa456eadf7c42f78b418c48a191b79bafb1f97be66e9da032d608766fb51e95338882e2bd7fec24a8c3c119baa50e6bea48db8274867a10a058570a16f2ff90860a929921637e8bad9dbd61e4d8b9c1e9f0a5e6756285359580",
        "f90211a0a0fd522a4446be18479e03364fcd6afd7c2149c6f255d7e4094dfba47e4f3f8da03df7f166c6f9b8d3cf93a51ebf41e8b4777957ec317d57eb7a926227d7d9f996a07576b7c249c4d1990c3caab685eb9f0d4e6abe9df23190441476a3243d8a4a52a0456df9517dc7521742795f52388101f5bd7f75519fdefd1db5762025fd08e83da084091fffd60017b29255ebaef7e7e459df0d4b74b65a21f661658eda58b9bbe0a04ed93ca9218c6d42bbcf0a86f81d55e9864185cf7fe3be9375c79166ba46b39fa022b0c12c4db78b0e60f4c46791daf92b514439afe0d1656724d3dad2fe6e1435a0e634a88946d797693775a1736eed5fbc61ed98e2fec585c3f5ac71710a409129a0e1484cbe84cd302b8ec98f1019b0acffe12cbdfe1c6625adae3928f8c54e1f2ca09a704a787b35138ccc36df4ff338428776df1647164b4abe678fa25c47a7894aa000125d973db646fa6172eaed4b363dbf20cbf69f0a594b4278d831cf34c53798a0a864e877d9e5ff12da603f1d90bf7b8aa357bc780d13e3109e6764fc4656fff6a0ca4ff473a6d90463620bc495d8d0084126e91ed41231e7a04c0d32efb930efdda04c264999960b60e90793d79bf9c1b18185e903d178d04b648b1aad13fcb87bf5a07fbef23fac002c35f0ff390664ecf210612a113deeadf1a7bfc93294863ec9eaa0ee8d8b86f086c5c05777900b54f3d07af7ff025f20996aed811826570de2e65380",
        "f90211a0aaf4ef3c2b0047759fa2a967b30b52981d36b3c5f00513c8b22f68b2939afea9a095b16021adb7253bdefbbf513f9bd93280c8fb01dc09ae147951579cf8720808a065a890e1234ca9b15b5121498b81327e918ecfb13a001a16c8d8777d575211f8a0eb7c3d604ae7e7d4f0070cce7b1bb2558330183ff1d0558d68785919d0f46f7da0610aac06d70eca544cbbd6a344c5c6a7784f9c7b783b7728c8514cee82bd8d3da009b89951b329d73c72e4414061e610e984d0137f95472dd4a495bb7b4d60ac3aa0622e26065cfd18d20788442ca413baa8412ae41c897343df07a7c781340ab23ba016c647251a3b2b136674881467581b7366533820f8fa6b3d49d9ace102ac410fa0514a7a8f4902476be01fc285a4980b10accd26fb7eeffc83362df757ac20cb41a05c72123f4ea43f5d1371da6e0e81c8598475f182f9c7cb639150d3499a2db65ea0d817b94c3b1ed9795dcec464dfa6b5f020510b9f66df3cc35ccc7c939656f492a0902fe9fe209e09fe3763a41a93e94c0888fc40ee372cf03c250995ffc2e2c885a0383d083426fde39be412ce9301ca3e81aa9b12bac531aa6affd52dfaa2e9047ca05aa75845fe3190acd9c18e010a93d7134d20a2f58905cc8201f7ef52161e116ea0fb4f99a1f705902975eeaa163cc61ac1e6813d453325a40b9d4c7abf5b0cd788a07f5517adbbf2c4fc4b6324953893b25502ca86d72ba7c7a29b81fe8e874f660b80",
        "f901b1a02908b54ee91bc00f50f85087df58c7e0133e5f0b823b93f2a779370b5e371183a0aeb1b386b8f1be97f0ae7e1bd94c6ae851f5e948081cead07ae98c1247738ad9a03ad7e2b67aa72f271151c066aeeb6e7ef8ecffab4112efec0d439a5f57a364dba086301be976ae43ba2a5032aae17090801ec4dbda17f77bf15300aff6c1da1c40a06e38cec1ea982ca6293f9ca3b6d93b3f2160cd8faebdd84a47d4d9b2fba1399080a04d9e1f04fde6c9b23e0e80b4946c9ef6859fcabb36b25cb90aa8f9592e8c99e180a0fd5c773124a2620da2714ca566d61a47413e646becbc817625a22f958617d34fa0d74f1a8caf3375eec12d0f504a356c86ab50a68c943ee9c649b54252b8864b1480a0ae35575205bb98bfa74f1dd63921dfe5c75befbf040f873d875c9cd59c938095a0d5458539b70efebdbc652074097b607ca55b30690551eb9c76ed0b562b0538a4a0b6d846edcf38b3fd0e28784b8cbef2a1b461d15b757769b98515426498792aa1a00a9ee79599374eb60d58576aa29fd7e99f796d7d12a43234d937e6744f127866a0c6f780e340997909b63fa79cba66f80ec28b6755223a9a00304a798630f5ec5d80",
        "f87180808080808080a03071e36cf171d24e892a74aa8f33e247232d30813c74b0db51b58169737bef858080a0d8bdc2bbfc66ecd2c61de8afd426c06f900ded909dda2df2ce4438448500d1d98080a094fec57d9d148f1343645f98762c3cc2075e998072171172414393c66e3cde3f808080",
        "f86e9d2078953cc51d08f48f03e3f90919a82fd58b842f26fc3059f3d9386b9db84ef84c0188012bc0b6729f1a31a050c68a44a4e53bdd18bf23fd59a5cebc3e4200ff97c84806ae29d6a9db04b81ba09cb858c1d8e8ab8ba7dc273f146d428965b0ca686d05fb02cb4ffc62149ec928",
    ];

    const TRI_STORAGE_PROOF: &[&str] = &[
        "f901f1a0e484b28aed994a0e6050b7651ee4701ab627bddb033daf9608c80458e210575ea00415a1d7c03a5718b5adc0e28735dc56d285dca753218f23b0109b3389783c44a0dd9aaffbac143fd59bde4611057ca4be6406b27b33a91ce7024e3fde0997239ba05c2398eeb41ab9420452f758909aa761d489ff7f4b16648efc71d1142c858dcea08b40ab8ef382a988aca6620052693a12e37d19328e27669887196474c9dada08a0cdf9c152c559809e540d99c1e4f502b35eb68bbc26c51a91aaa17a57fc4c0c2ca0afc449b656404588dd6ffdb6d26cc6fd65ce1c9c94d02c2232ba46b59e4306b980a0aa20421cde8660090e2c8e508ac19816712ac496384be425f7941aae6f4b2ea4a00a70d6e4a8a5938cfb1ca5221742e0895e4835ab9538a682939049ffa4e61af9a018c6c2354461d7f60aafd2f5ffaded67ef799ad8e4defc0dcb589905e9ee0ab1a08cfd7d627827a987dbad3f8601491e34a8870144faf66ed713e6c9fe85528094a0ca1da9f7b8b9508604ce980de5392c0ddc0a5d8c1c443921fd49db336a49a57ca03896bc1f9485a8600c02276f94d7f000790b4d2dba994ad9d006370f53b262c3a063dcc8721a14b15ff2282d221d682950099ff88feea344634d2583adabbe622aa0f7f1df9646de61b3777cc85b45fd728c6ac74bab1f205bd875421659259df5a780",
        "f85180a00ce6236033126a802ae0c937a2c77512f990afed13214f02c58565c6340d53dd808080808080808080a0de4794c6574ea15f09acb9fb2d20702b9b1f735c9f3a463ba8a112673bd612378080808080",
        "f851a0f8d237da0a6c3856c919908ed677067673820fa6d328cbcd1ab66ba92b0424e28080a032354f0231538b6df9443e8f23cf404c8b26741635ff4803c431d080da818a5a80808080808080808080808080",
        "f83b9f3e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf69a99856fcabfe67b44faf700000000000011a2806f1e7fce45e0a7",
    ];

    // Mainnet block 26240090 (0x5c14f4125acc959415476e513bc49432e71c670c7b4cc4c069e8c85ce3e7da1d), from https://ethereum-rpc.publicnode.com: eth_getProof of WETH (0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2), balanceOf(tricrypto2) (mapping slot 3).
    const WETH_ROOT: &str = "13f8f6e769f07ffa8ec035cadaf556a705c5047006f72894e19bb8df47a512ea";
    const WETH_ADDR: &str = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    const WETH_SLOT: &str = "9b354f30d74ca151470e4c01c97d425c838beac0ab30a0bd396660e4405f8bee";
    const WETH_VALUE: &str = "5277ccfb39d7f1831b";
    const WETH_ACCOUNT_PROOF: &[&str] = &[
        "f90211a0c55d85302e31edc63c43d5cc381b2d4607da342dbb75f0e8024adf469b8355b7a061fdd4902f88ff18da342f75ded672b46f5a0e185ac53fe7128aae7405c03806a02a6743df8c5ae744dff3075e4b9a58a0700892df20c6bce617c8bd2f1ee4ef50a0f7399b13338e2f0bc564edfd85106f1c553e087fcd2fe867ad2da88e97c035cda01eacd36d72ff118ab248181e37f79ab301a953f54787094c0bd2c59aa7b81a02a02763a54eb8ee3a3ddfcd0269cb68b9f41160bf4e2308d61931b82a40a7d352dca0760b958116d75d9d16f7ce7d47ed4bce090957e88fe9b13eccbaf09953f768d9a0c2a3a05974327d0cdc6c353990ce879322d5b49fdf8a13e96bede0ada26e6390a0ed9a2307d3c107c8a658cf3bd2a261f846906fb558338c8630158d07acbf566aa004b77c3ce0ca514a5b41d9fee3c220f3794f178deca8932d08e3d3d792369847a0abf8bd65e54ea16e696f6ce0072b9fda28a86183f8a3fa4a6c8a5288d3b3a8d0a026a13864993f01c5c776b0ee569cab98801ae085bd9c58deeacb66d2d72714dea06e14bdc76a394490796e55e5989f4662a09cdb0af907788af5f4ea8358eada8ca0fabbce15c0942becc80fdc6dbed9db11ccfef9d0272de956451e4f099166c908a02c7bceca26748a7ff1c503abc3a78519385f840111eed4532e08bf7df7549a3aa011d9e6f20a3c803cd22d017a131e48a6c0827d7eebfa2251d0a40eb776c2ae4f80",
        "f90211a0b6031b2bf8b5ced56eec41a141cbfbd591c64efd1afc1dfaa5cc7aa4312cc72aa0e24b072d7e6816f41c40b8edacc21ba31cf9d426509283c142a03377dea0a0bea0f225fcf17bfea774a89efa6ed00f36b03646ee3eadbd85863d8c90b58c1acc42a0af447fdb9f8c5caaaed8bdd38f4559d64774d5414bae913c729eebbfa901917ba025b9335400394782153e5de544177f9b9a4fa2e1ac0c8cf6db1d716bca272c05a0041ddfcc211940e632ecfec4cd62cd0985ecc0959151e63d6c3f41a945d902baa0cb78c958289f869f9b0353c7be2497e9283a9f9340d876e4ee34a53113e19fa4a07f2f7e918616dd731de165c1a3b97302dda43182303fa7c10a19e47b37b3c4eea073c4ca0cc1b8cfda67f099d3f25242cdc20646cd0680bc3d5d1fd41a78b9a2d6a07ace683ff69b995cf501f8f5a1f712f2c72feaf80533a66ef95c2b3564e36c27a0e71315e53514fb2d0bc64329efb1e6e48235e1ad02ba58166860c7c22e2c19fda0c201194f1e0d758298d0867eced5033c0b6e6bb565189829b2549c20431bf07fa0758695a1c7da27c21b6a8442ff903bc963767a380e2e81e7ab807f5fdc57abeaa02cb7cbfce5da881a43d126da303b9ea846036a485623753fedeaf259e5d8a752a0d0898680cf6bc8c109d21ceb1d0fcaf59add231102e4fcc23b6738281499823aa0f494d8656980363056d5ed01f518ef590aa724f76e3bec7ac7fccd084ef00daf80",
        "f90211a0bd12b74065a1de5b9bf3107dedb60d01e8f858a98905796325ebb3ff5e86cbeda00e78a2f10ca7bfe2ebdeef8a97f610edc189c2e7a70114869d9b929956ce6c0ca0df78ef1da77c7eb35d21978ffb52059af8b52b430d878a045eedd691c125e083a08d377ec567fa35f2f6f676591edb52b97ee9a11c9f7eafb247061ae71cfc347fa0ced9dd9260de26e765aeaa5a31a2a50d5af35e28e5da2e0c8fd4edcbdefda33da0ee13c256b4135514b54be0b5d61b5f197b5974b95b9cc5e1d73fd2f673a8a913a0ff53a1d18e1876421f7e702b4b5eacd0ea72e5697f9e1348eedacd532402cfc8a012f12b398476d23aec9e5f5c4ce6f9fa81e5300521c473ab51cd02f20b7a4019a0f39a2f4ee9e1a9a6170093410934b53a1e563ea87b7fde03aa2c91c64f01432ca03029d5015994a6d198e1cb12d72429edb86e59ee35d7f9815a57364e99ca2e9ea045ac197b892c8984bb17e405d10e58e30a0ddb30525ea630ef34715c2e6b76e8a08f00a7c6e95104f177d3aacd55f2592f10245bb54e7f909629e6a5bb5ac81edea0eba7a10002349cef3f44d1a1f0d9b0a8fe4e0ebccb007dc1ffa66f268423e263a0f8759457b1ced26eee9464cb1d39ab3e7be9db6a979edb9b190f7340489ececaa0e5e5beb109dfe5a806bd09e4a39e64ffd6e6fb9f134c69e7c88d7ebe5930ac02a08120ae7839538617e1c35fd04486d2a95ee978f75690d1a84d3e62f5dc89001380",
        "f90211a02190162703164f9d31bb31b851b91d2f10290b2dd3bed1a57107c2ccea68f7c8a0977e959f14b13e358c5a89d133c6d6d44a502e217f30cff0f53de2c6aa5fb1b3a07af6353174e77d3ae0c893d72015560c93e45796fcefc6a2eb55110baa470118a0cac9eeb24b973dc041fa389a34d56e6d0692d52dfd59fcb0f0b546be4c529988a034924c6bfeba20d72d6795b5a87ca836cb3f7c04be12b7e255a1089aec24a61ca0593f4cc30d35e3235014aa79f54117304fdbb73f71b42af5855b2e4eec5ac611a0185b33411b80ca8c2622550c31540b8bfb72977fc3a202e05dbea9353e1673eaa0102562ee596123778c39cb57ae9a195f8805ac22b3d4bbf197cb988ad89eb4f7a074bc5295e74ce3c677e021227913a8e6a64d7f2d2b9b2284b69baefb66f7d052a02b70ecf9bc60cad0cb5afd0b076ab27d8e1d110c45bb7c62ea098ad071ddfe2ca0f76c010f3f31b8ac7599f05e2eeee9fac8ea56b54ccb127f1f91b33bfc3c43efa095d5227a5204f2abc9c0559b0f391d852f5c4df1476da0dfdc609a08caeefd34a05cd5aed71d99db15995644fa406b33b747ddbcbff28f80ef64a1d89a22e5e94ca0e93a4f411c204d54d1dd463d61f6326388a7d3855cfeef1ad69c1de77b257d9fa0a21fb3327f8dc15dc0bb473ef8a4740b74840989a46cd36d5a4656bf1b0f6a28a0e683968888c1630ecdbf89561c594f8a556b366c2bfa2dc06be4941baa1698aa80",
        "f90211a0390ae9155f5779aadece35bd5a62da20a39806770cd2c98c8896cd28afffa496a05938368eec253556cc681c807a88892493e9e2c8c0826b247ae704aa3a3a9c75a0fadb72b90e8933602d1e5740a44a0c9936cc27cade7e5ec510662fae7bac328ea04b5f6cd58dfed0bf366f49ef36aa2113ab2ab7b1a4d54fa8da2378a434ce6c26a0ee4286c63e8d42e23915f1d1c5e320321b0b6481b0586d8a8e8844f2c99175e8a0a2f9d347407776e97cd02124395292c344a051aef570c61cfdf483b1834686c1a0c775d90074a88cbb1f45201f66c455197b72da36a30a57f7aa0f335e449e3f50a0b99276c413f32f6cb6bf88a186bd48b449c725ee2dd40eeda1775c88f82f98dba09415d6a31fc3c3fb39c24222ff51b52e4fdedd318addbec5d15f13b88ec88c9ea071b96f161e590b3fabdbfdc3a66c4537a4e345f5d47ab8284846a417dd0686c3a025eb43181b5e9a53a917e4b145b714e20f66e4e7d148355156b6ce7188a1675fa0199803d770ebd03afefb7f9646bbce210487fb21352528afa77aaedbb15d2bfba0b2758adf5d4bde796fb445dbe729380a6b8eba971a04a7a3b3d35deb3fda8afca0101f7167ea67524d5071f688cc84e5b1f1b9265e038705fb5b9344cb47eeda46a01a05eb2daa01cd11f3685ddc6f3a1c5033fcf0881be2e1779c9539d85fe8c189a0369aaf221bf97f1906e7e84491671b128e840ea914e5f5696859be3508cb8dc880",
        "f90211a0a9b1e8cd2c5d4767ed821478555142652dbd2db2254674349635354a52400788a0b22c12062b8f48d8f92be9784e41c88365d91b7732de1d9bf3138830bedaac99a01e07b5313054ef98dd398bc380631800b299d611df893742ad867f09f09f78bca0c64412b092311980d93c35c0c5a25ebc3c5cc81685d56367625c69569edcfcd7a083989caa85f131fe98ee39e943c91f71d4355278fdfcbc985324319068703516a0687cc05ab946fded745a8043e6011947d0a53bb690c3c76eb4d6792b8f6d107fa0ebfa7ea99a892196df02c97e5d02513ff1dcb884ce2464310d7f9058a9d26bcda092785b9f1f414d3df467823a100a19be8f098e13885bba867c4e0c70cd45450aa0e5da26fec6c58551d93dd5d5894c92c3b3787571e06b9dc53a653ee57ac4f3b4a05ef32bb7de2b05ead3e1db1587898448540f61c20cc1934b88a8158ee987cf04a01ef0899444ff317d347323f2a13f681f9e79ff0de5c3785cb6df6a7de63aa841a09eecb6806592ae4b171eb39b46e13e604ec3ede3762989e21aa010a6cb1121c6a0d2ff8d8e77579304ad3eb68dca29445ab14596dee08708a4660ed947c7027e22a05d55dc34363a354b9ccc4ff9d27ba7ef86cb7f31cb36e4b48501652c85548429a04acea4f4a80ba524790c61ee3833c8676b204b51896175b2278187ed833e88bca094901be9e608d9b3317d1aa990f28369ea5b2f10b5cb8bb9aac450c0a70eba4880",
        "f90171a0ca06c2b4c97d9941e56c3c752abe4c2b0b2cd162e22a5d25f61774dc453deedfa03d3eb3e6727b6887fa8f2de5f824572621ca7ed08c845a54b26158f1f383fafe80a010f8b91c7ae81978fb4a930ed0f4765d46dfaee99d7dfc8403b4893110cfaad1a0ed90dbfde0982512d27b81cecfe7a045350ea4cd9ac030b84adc57ad780d1126a0525e7dd1bf391cf7df9ffaaa07093363a2c7a1c7d467d01403e368bd8c1f4e56a0dbeb1de9649b481c377b0d381eea3f98b507a1c74cddbdefd2c6f4212482c9f6a00c63d33c99fe830146043f68586cb5989865e64b556668f56af13ab0c975b308a046ea849b301050a23b2eb62a8f34477efc4e6311290e0ddac19c015ab0dcf3a5808080a045cb60da8d809907e41951641c061a82fc7beaf2d8c075ae0d5db21073c935cda0bdf39c6275dc5cbda30f3e8c8b47e99c8ddc7dc7fce69f4fc6646efa7cea3b95a02c52c95ea3758d9e8e8f1aaad27a22728d7a564b2005bda8682b95f144f3050e8080",
        "f87180a063696b31bf58b4455c3732254e2a52bfe8b9428dd073b7cfa4ff23f865ed059880a03aca9d88035d7cf997118973b7fcf681f57aa04183c945f0e2ace487f3592f5d808080808080808080a0de8dd9a1c76ac13a950634a96a2c13e3e7284578318767c800e9fab7b01468f1808080",
        "f8719d20a65bd257638cf8cf09b8238888947cc3c0bea2aa2cc3f1c4ac7a3002b851f84f018b01d2cc00e3de2b6541f821a0317fe0d5e546b8510ca89ac2a44fa3fbfe1882931fb5685eb7cb233db7b68471a0d0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23",
    ];

    const WETH_STORAGE_PROOF: &[&str] = &[
        "f90211a041e92ce961e3fc5c45c4a75eec94a5a0362ccab17ea2c41a76a82eb265ef2206a0988c49eebf2b354e58123a7b908c6a1568e37ddeb8db9f910d1de4000dd0ab04a02e884c4ba6a97cfc72658fe1b20221c17bf78c1fbfb59e5d1c36fdd9e2ac7c6ca0ab411d76ecd0d3f041da6f4261056a344d420fd6827fbb2a811983fa43f4d6aca0539affa55f18c9b80eec8a0f70821d625ad2e6511103f4c318774f43baba346fa05e7fc8d8e1b35a4ef328ecc3c3ec33ca0f985ac9f54dabc81b704110cb6c2eada0ff51e49cfc2ebe1f8be8c6ea54f8db5f250f9f7f700b09a6439d83f67f7b85b1a0ba08f55b916b0743f403c5f50d4b96a5ef09eb276a8a82ace455a923ef20a7e7a04d12ba1e6af145ca4ea85bb5c93a8173c47ec90570bd043ef5675605067e86b1a04f317dd99618ea272db44d9132f417f0d60b667857452d275f9317c85e55c506a01463cfd039833788069bd2f5f5b795afed169e8110ee7dbbed78e9b701107558a0f6416877b619ff7c5eae284053878f2c55b19b3448d94e3a40ce1dcb0b66ef9ca098c5ecb08dc545bab8752a7edf7452010f76c6b6d1a918eac449cba65f24fde1a081cb94498e70cc57d6f76e46507ac056656aa43846f942e9f182ce0c285b3297a014960b013319a9879e79b63acd5a6f2a0c865a4ecf4f0cc026f0731edda12206a0fa45cbeb96f3221823365bfbfe68aa4d7774a466abd4f0c53ffdbf5087a1471980",
        "f90211a06f93c3c64e5f1deb4f179a8b6c5917890aa7112c0206a70a56e08fe6168b4a37a0ef9d0863b15caf64397cf0c7b1ffd7218bff02a61141ef5a611b77a424963c8fa0e0ccb722bac0cf83526c720e4904f7c18e4750bf5ba49bd5b4b85c4ac57a8e61a0fa7f51791dee72779dfed89f87d4680fba37457ac7d7ee68140d9375fc707f1fa072424702129beced9b62d4e4ae9bdeb9590cd2f0a6dbcd89da58777232e6a0b7a0086b62694ac644383a0f8522b02e9224d09c7bee3ab4d076a271c29dc0d80d5aa02d90baff51342460321b321d6015eb7d467b57048ec4d210287155d83adb9f75a0d441a7cb3026ffb3f12b5e416a2cbd6d88020c52d51182e8e8e5d015c2f7c4eda0df07ce323a1ae61ecba146e2ec2cc28046878ef5a346b486d5f0a370ebffe36fa010aa39b4cbee11336a0ba0da3353345df922ad73ecce140cfa825716fc292e5ca0d42990b8c41edb659a639e1686ca71d2cb170ea5f1d19d5e2212277c35e64f12a0b74b5648b42cfc889305c359df439fc05fe93ed731fcf9bd51ba5294b8f352a1a0b7d5e87cd12b37f50a801dd7f040a81d72c869f5c0526a87b25d03ce77b84735a09f35028a799cee876b5b10b4f25d86228716d0c8c456e5c71b0696786133f89da091958c4471275767089c1bb4e6596c79ce33d9a5ac409bfb2342025dc5725d1ba022ba8c18ea18434baf294033c784b377b21a092b07f1a44f4cab1f899bed3dd680",
        "f90211a0d0c6a3071f0150511549b7a37d6e11503a19cffc3ddcab6609b84683c30d0a86a0313fa0bbafd45576e6715dad73af8031cd02cb4e001f9550c76f91d122206fc2a0552ad94db58918c97d991651f031b837333a3b4366cc308de4586921c3fe2910a091fe72981e92d997e5f1da16742f164d6565da4f148b8d8f3f8f2a8f9538a177a0120dba16af90a39cf4a4e400abfb105b7016e3afac95d6039b26fe137dd6f5a9a0c25de5374f39d4ad04c616047870c74edff0e8052000b918b9031424e4cbd73aa0389559eb82984ce0452846cfc426b615bbff92e3cf62fb8e705018da48400983a0a8156054c0e1664cc99bd168e8eb02a53cee7d8f55b9b263233b0a17eb236777a0c28ab1a5bc3faa3de8f0a3eed8e4f787ea4b7795e053286036b2533190a3d946a0051ba59c7cfda2029f9c040995f24adc6374da37c98d8305ff00ed1c42dce93aa028a14c37dccbe0c59cdccd1ed8b9027f3147524b6751dea82957addc8ba1c1aaa0d2ec4530b32cec0f5322f4336bbb97c6641faabd0228cb142be856c7acfbf908a000a4b2c59be46826eb2aea3a962d4e481528970dcaef5ca65b3329b449ef7a91a0ac97f52d3743ebab1a1299a9b099a7f67b612f3f1575ebfbc9c520ce0317c3d5a076e8fbbc96ed92b182b4b51aa1ea9874452096f26a31282962bc4c50148cb1e5a0addcabe6be725714a72fab083c9322702a6323eb4794db08f62bec73b00e45d880",
        "f90211a0fe4da4183927845d1fc63cd458d63edef13e1eb5029b75c77864e175e4e4eb98a09cf94f663dc45d7e12fb138703aac334b12dfe8b65e9a4dd9e47ebaa293283eaa0b942d0c850459e57a69aafc839a8e7e7098c90f70c791902329d136f5427f78aa09cd45f9a1badf30f2ec7b9f51a16341920a48c8772b674bfdcc01924f8ac3cfea0508969911a33dc70de0ae0c87775e529d96ac654bd50caa7232c0887863fbcf6a0a454b80f2d7138ba3ef00d1b15ba341c62f1be3caf8ff9cf2a7e87fd742e5a16a0c13b084aae069c81e8a95315a488cd3b1ef0e606cc5c6d4dfdac8a8d271ab204a0d3cdbc84e13e7397c320453c5fa16decfe6a29165df968e7bad484adf8641274a0bc190a27e0b14294fb114b39edede1c9b29e78ecd1298e8332bece892d834d5ba00e7c257a49aff25a6b36c21eeba4c5e2373b784e1006968c9af299795b6c2f03a01d4ad0e313ba1cbcf2103c9aa224f0afa8fd587b6afe1258cea9e5fdfbb74bbba0da764104921b0166804cba5110fd085e2f42dcaaa22621342775c79d3e36dd12a0013d47dfe2cb9da1f767291dddb9180995dc1771c1d97c42144b0c09fc9e867ea0919b92fb0624f49e521220c7c6e95811a1ab0e9be595e7c54875e98aa70c863ea03b41bca99b900b3f7fedd50fa6be543b0fdd654fa9605943ad9e3960f1c04e40a02785c78ae7f89ed9c6434541e8c37db8a4c1ede63cce79ee79197861cc737bdf80",
        "f90211a0ea188e679daf8bddf73f54d1e68c3e34d067608cc5f3f85a733c8e0a60dcdae0a09a7318f905ce206a6b7225baf9d6755df1e3ae74e64b4f8788d3e1733675f498a078e2514723e3809563551be5bca1fa0b57a7dbd0cb3d0534fa7f60a5d63ca9eea04e2dc6629735aa6de1ab0ade93a7b4adf6e7bc7f8ece190e32e459fc1010d9f3a0852d2c603729b4d09a654757934cf88d74a78165293a64f51bf1218de2c82ed2a0d52917c01a71f636b0c1259ccf8ccfd96cfbf7910b2ce05cda68d5b395b1d0dda0f1ff01b2063b8ad19c43d60c6a2f821ecba8244e0830d7354bb32850da637c5ba09a8fe894aa168d8144c62de05f9b494d6a8919602c63662f7e44003965dcbcbda06ee918a20fdb6062f892593b6af78e659ed072b4fbb5771ba141194ac4f84ba9a0abd432eb12e35a4aa35617ad7bd91d7e712184f723fb5ee8d8e3dabe573574a4a0a2b92696780492a2196fe6b2bd1144f36cafc3b4b577f1806b066798358483aea03b7a65dfcd0bb59f24f7e0c55593d9ef2915bb21e6f3b0a1d4d7ee007493c689a067eaf2fa18e24baa2648c8036b0cdb38021c428ac135dd1b6637a2baa1a4581ea0d4509d93267dcfe0350be9ebc38f1b7b92ada0e8bcabb055d97156d948fe2fe3a0b8e48f72e97162aba92d2f88affcdbcad51ce307178e75c8fecd8abd194e110fa0680980e3b70958f0d9f7fab564db9b0e91f7c13745cbf2721bbc75b7f7fc683480",
        "f90111a0225d95eb1cb32f688900fc0a49587417a5ddee5db0df3169831ce76b1452849680a08e87f4be8523783e60d3ded830ee5df1e83261022a400bdb77ef12466213f0078080a0c59158f678c8e494bfb2efe3b75b30b8f0d838ccc2945e09e5c0fd794a586f6e80a07aad3d134d06441bf935e73096e20a5c2dd74ff4990d9485d0a91fb9e0bc7c1da001db1da67551440c14c8929b676bd8ee9e36c4220332f659ac8ea2f86bc5de74a0abcb3b62c9701c700a278f97a8c2ee02b6d2a3ed2779771538436f23135b9c2880808080a0151f0c49cc03fe08d1c69f9c62fe435ce7618bf2184d4eaa13470673f1ed5d90a02fabfc7ec2fe75d85bc379153ad038f03be581b2c611126a59f46004f5d8349580",
        "e21fa0213703955a396bad3e5b9b9042c8b93202c1771519117a2f175e0ebc395ad1f2",
        "f851808080808080808080a00e2e369a4b96b8696a0c2b19fcca3826f1130b9ef442ea002443828d2bd05ad18080808080a0ca5e37e351c853faeabfddf2068c80e404a618bd6878bb8ac6d021c971a4e12380",
        "e99d20bab00af318ee741bf3d8994940d0666fbab3a4ec4f7d1d4519ac7f1d8a895277ccfb39d7f1831b",
    ];

    // ethereum/tests TrieTests (develop): (test, [(key, value)], root); keys and values hex.
    type Vector = (&'static str, &'static [(&'static str, &'static str)], &'static str);
    const SECURE_VECTORS: &[Vector] = &[
        (
            "hex_encoded_securetrie_test/test1",
            &[
                (
                    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "f848018405f446a7a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "095e7baea6a6c7c4c2dfeb977efac326af552d87",
                    "f8440101a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a004bccc5d94f4d1f99aab44369a910179931772f2a5c001c3229f57831c102769",
                ),
                (
                    "d2571607e241ecf590ed94b12d87c94babe36db6",
                    "f8440180a0ba4b47865c55a341a4a78759bb913cd15c3ee8eaf30a62fa8d1c8863113d84e8a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "62c01474f089b07dae603491675dc5b5748f7049",
                    "f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                    "f8478083019a59a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
            ],
            "730a444e08ab4b8dee147c9b232fc52d34a223d600031c1e9d25bfc985cbd797",
        ),
        (
            "hex_encoded_securetrie_test/test2",
            &[
                (
                    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "f84c01880de0b6b3a7622746a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "095e7baea6a6c7c4c2dfeb977efac326af552d87",
                    "f84780830186b7a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0501653f02840675b1aab0328c6634762af5d51764e78f9641cccd9b27b90db4f",
                ),
                (
                    "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                    "f8468082521aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
            ],
            "a7c787bf470808896308c215e22c7a580a0087bb6db6e8695fb4759537283a83",
        ),
        (
            "hex_encoded_securetrie_test/test3",
            &[
                (
                    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "f84c01880de0b6b3a7614bc3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "095e7baea6a6c7c4c2dfeb977efac326af552d87",
                    "f84880840132b3a0a065fee2fffd7a68488cf7ef79f35f7979133172ac5727b5e0cf322953d13de492a06e5d8fec8b6b9bf41c3fb9b61696d5c87b66f6daa98d5f02ba9361b0c6916467",
                ),
                (
                    "0000000000000000000000000000000000000001",
                    "f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
                (
                    "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                    "f8478083012d9da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                ),
            ],
            "40b37be88a49e2c08b8d33fcb03a0676ffd0481df54dfebd3512b8ec54f40cad",
        ),
        (
            "trieanyorder_secureTrie/singleItem",
            &[(
                "41",
                "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
            )],
            "e9e2935138352776cad724d31c9fa5266a5c593bb97726dd2a908fe6d53284df",
        ),
        (
            "trieanyorder_secureTrie/dogs",
            &[
                ("646f65", "7265696e64656572"),
                ("646f67", "7075707079"),
                ("646f67676c6573776f727468", "636174"),
            ],
            "d4cd937e4a4368d7931a9cf51686b7e10abb3dce38a39000fd7902a092b64585",
        ),
        (
            "trieanyorder_secureTrie/puppy",
            &[
                ("646f", "76657262"),
                ("686f727365", "7374616c6c696f6e"),
                ("646f6765", "636f696e"),
                ("646f67", "7075707079"),
            ],
            "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d",
        ),
        (
            "trieanyorder_secureTrie/foo",
            &[("666f6f", "626172"), ("666f6f64", "62617373")],
            "1385f23a33021025d9e87cca5c66c00de06178807b96a9acc92b7d651ccde842",
        ),
        (
            "trieanyorder_secureTrie/smallValues",
            &[("6265", "65"), ("646f67", "7075707079"), ("626564", "64")],
            "826a4f9f9054a3e980e54b20da992c24fa20467f1ca635115ef4917be66e746f",
        ),
        (
            "trieanyorder_secureTrie/testy",
            &[("74657374", "74657374"), ("7465", "7465737479")],
            "aea54fb6c80499674248a462864c420c9d9f3b3d38c879c12425bade1ad76552",
        ),
        (
            "trieanyorder_secureTrie/hex",
            &[("0045", "0123456789"), ("4500", "9876543210")],
            "bc11c02c8ab456db0c4d2728b6a2a6210d06f26a2ace4f7d8bdfc72ddf2630ab",
        ),
    ];
    // ----- A reference trie, for roots and proofs (test only).

    /// The node of `pairs` (keys as nibbles, all the same length) from nibble `d`, and each key's proof below.
    type Proofs = Vec<(Vec<u8>, Vec<Vec<u8>>)>;

    fn trie_node<T: TrieHash>(pairs: &[(Vec<u8>, Vec<u8>)], d: usize) -> (Vec<u8>, Proofs) {
        let reference = |node: &[u8]| -> Vec<u8> {
            if node.len() < T::H {
                node.to_vec()
            } else {
                native::rlp_str(&T::native(node))
            }
        };
        if pairs.len() == 1 {
            let (k, v) = &pairs[0];
            let leaf = native::rlp_list(&[native::rlp_str(&native::hp(&k[d..], true)), native::rlp_str(v)]);
            return (leaf.clone(), vec![(k.clone(), vec![leaf])]);
        }
        let first = &pairs[0].0;
        let mut cp = 0;
        while pairs.iter().all(|(k, _)| k[d + cp] == first[d + cp]) {
            cp += 1;
        }
        let with = |node: &Vec<u8>, sub: Proofs| {
            sub.into_iter()
                .map(|(k, mut pr)| {
                    pr.insert(0, node.clone());
                    (k, pr)
                })
                .collect::<Vec<_>>()
        };
        if cp > 0 {
            let (child, sub) = trie_node::<T>(pairs, d + cp);
            let ext = native::rlp_list(&[
                native::rlp_str(&native::hp(&first[d..d + cp], false)),
                reference(&child),
            ]);
            let sub = with(&ext, sub);
            return (ext, sub);
        }
        let mut items = Vec::new();
        let mut subs = Vec::new();
        for j in 0..16u8 {
            let group: Vec<(Vec<u8>, Vec<u8>)> = pairs.iter().filter(|(k, _)| k[d] == j).cloned().collect();
            if group.is_empty() {
                items.push(native::rlp_str(&[]));
            } else {
                let (child, sub) = trie_node::<T>(&group, d + 1);
                items.push(reference(&child));
                subs.extend(sub);
            }
        }
        items.push(native::rlp_str(&[]));
        let branch = native::rlp_list(&items);
        let subs = with(&branch, subs);
        (branch, subs)
    }

    /// The root of a secure trie (keys hashed) and each key's proof.
    type ProofMap = HashMap<Vec<u8>, Vec<Vec<u8>>>;

    fn trie<T: TrieHash>(pairs: &[(Vec<u8>, Vec<u8>)]) -> (Vec<u8>, ProofMap) {
        if pairs.is_empty() {
            return (T::native(&native::rlp_str(&[])), HashMap::new());
        }
        let mut hashed: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .map(|(k, v)| (native::nibbles(&T::native_key(k)), v.clone()))
            .collect();
        hashed.sort();
        let (root, proofs) = trie_node::<T>(&hashed, 0);
        (T::native(&root), proofs.into_iter().collect())
    }

    /// An independent proof check with alloy-rlp: the leaf's value bytes, if `proof` proves `key` under `root`.
    fn alloy_verify(root: &[u8], key: &[u8], proof: &[Vec<u8>]) -> Option<Vec<u8>> {
        use alloy_rlp::Header;
        let items = |node: &[u8]| -> Option<Vec<(bool, Vec<u8>)>> {
            let mut buf = node;
            let h = Header::decode(&mut buf).ok()?;
            if !h.list || buf.len() != h.payload_length {
                return None;
            }
            let mut out = Vec::new();
            while !buf.is_empty() {
                let start = buf;
                let h = Header::decode(&mut buf).ok()?;
                if start[0] < 0x80 {
                    out.push((false, vec![start[0]]));
                    buf = &start[1..];
                } else {
                    out.push((h.list, buf[..h.payload_length].to_vec()));
                    buf = &buf[h.payload_length..];
                }
            }
            Some(out)
        };
        let nib = native::nibbles(key);
        let mut expect = root.to_vec();
        let mut at = 0;
        for node in proof {
            if keccak(node) != expect {
                return None;
            }
            let it = items(node)?;
            match it.len() {
                17 => {
                    let (list, r) = &it[*nib.get(at)? as usize];
                    if *list || r.len() != 32 {
                        return None;
                    }
                    expect = r.clone();
                    at += 1;
                }
                2 => {
                    let path = &it[0].1;
                    let flag = path[0] >> 4;
                    let mut pn = native::nibbles(path);
                    pn.drain(..if flag & 1 == 1 { 1 } else { 2 });
                    if nib.get(at..at + pn.len())? != pn.as_slice() {
                        return None;
                    }
                    at += pn.len();
                    if flag & 2 == 2 {
                        return (at == nib.len()).then(|| it[1].1.clone());
                    }
                    if it[1].0 || it[1].1.len() != 32 {
                        return None;
                    }
                    expect = it[1].1.clone();
                }
                _ => return None,
            }
        }
        None
    }

    /// An account's RLP, decoded: its storage root.
    fn storage_root_of(account: &[u8]) -> Vec<u8> {
        let it = native::items(account);
        let (s, _) = it[2];
        account[s + 1..s + 33].to_vec()
    }

    /// The value in a storage leaf's value bytes (`rlp(V)`), as a 32-byte word.
    fn value_of(rlp_v: &[u8]) -> Vec<u8> {
        let (o, l, _, _) = native::item(rlp_v, 0);
        let mut w = vec![0u8; 32 - l];
        w.extend_from_slice(&rlp_v[o..o + l]);
        w
    }

    #[test]
    fn empty_trie_root() {
        assert_eq!(
            trie::<Keccak>(&[]).0,
            unhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
        );
    }

    #[test]
    fn ethereum_secure_trie_vectors() {
        for (name, pairs, root) in SECURE_VECTORS {
            let pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs.iter().map(|(k, v)| (unhex(k), unhex(v))).collect();
            let (r, proofs) = trie::<Keccak>(&pairs);
            assert_eq!(r, unhex(root), "{name}");
            for (k, v) in &pairs {
                let key = keccak(k);
                assert_eq!(
                    alloy_verify(&r, &key, &proofs[&native::nibbles(&key)]).as_ref(),
                    Some(v),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn mainnet_proofs_verify_natively() {
        let aproof: Vec<Vec<u8>> = TRI_ACCOUNT_PROOF.iter().map(|s| unhex(s)).collect();
        let sproof: Vec<Vec<u8>> = TRI_STORAGE_PROOF.iter().map(|s| unhex(s)).collect();
        let acct = alloy_verify(&unhex(TRI_ROOT), &keccak(&unhex(TRI_ADDR)), &aproof).unwrap();
        assert_eq!(storage_root_of(&acct), unhex(TRI_STORAGE_HASH));
        let v = alloy_verify(&unhex(TRI_STORAGE_HASH), &keccak(&unhex(TRI_SLOT)), &sproof).unwrap();
        let mut want = vec![0u8; 32 - TRI_VALUE.len() / 2];
        want.extend(unhex(TRI_VALUE));
        assert_eq!(value_of(&v), want);
        // And the hints the witness derives fit the bounds.
        assert!(
            native::witness(
                &Params::MAINNET,
                &unhex(TRI_ROOT),
                &unhex(TRI_ADDR),
                &unhex(TRI_SLOT),
                &aproof,
                &sproof
            )
            .is_some()
        );
    }

    #[test]
    fn synthetic_and_built_proofs_verify_natively() {
        let p = Params::MAINNET;
        for seed in 0..6 {
            let (root, addr, slot, value, inputs) = synth_instance::<Keccak>(&p, seed);
            assert_eq!(inputs.len(), count::<MptStorageProof>().1);
            let _ = (root, addr, slot, value);
        }
        // A real trie of random accounts: every proof verifies, and a wrong key does not.
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..3000u32)
            .map(|i| {
                (
                    keccak(&i.to_le_bytes())[..20].to_vec(),
                    native::account(i as u64, &[1, 2], &[7; 32], &[9; 32]),
                )
            })
            .collect();
        let (root, proofs) = trie::<Keccak>(&pairs);
        for (k, v) in pairs.iter().take(200) {
            let key = keccak(k);
            let pr = &proofs[&native::nibbles(&key)];
            assert_eq!(alloy_verify(&root, &key, pr).as_ref(), Some(v));
            let mut other = key.clone();
            other[31] ^= 1;
            assert_eq!(alloy_verify(&root, &other, pr), None);
        }
    }

    fn synth_paths_verify(seed: u64) {
        // The synthetic paths verify with alloy-rlp.
        use native::Level::Branch;
        let mut s = seed + 1;
        let mut rng = move || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s >> 11
        };
        let key = keccak(&seed.to_le_bytes());
        let (root, proof) =
            native::synth_path::<Keccak>(&key, b"value", &[Branch(16), Level::Ext(3), Branch(2)], &mut rng);
        assert_eq!(alloy_verify(&root, &key, &proof), Some(b"value".to_vec()));
    }

    #[test]
    fn synthetic_paths_verify_with_alloy() {
        for seed in 0..10 {
            synth_paths_verify(seed);
        }
    }

    use crate::count;

    // ----- The full circuit (Keccak, mainnet bounds), built once.

    struct Full {
        circuit: Circuit,
        srcs: Vec<Src>,
        valid: Wire,
    }

    fn full() -> &'static Full {
        static F: OnceLock<Full> = OnceLock::new();
        F.get_or_init(|| {
            let mut c = Ckt::new();
            let b = build_mpt::<Keccak>(&mut c, &Params::MAINNET);
            let (circuit, srcs) = c.finish(&b.public);
            Full {
                circuit,
                srcs,
                valid: b.valid,
            }
        })
    }

    fn run(inputs: &[bool]) -> ([u8; 64], bool) {
        let f = full();
        let v = f.circuit.values(inputs);
        (read_statement(&v, &f.srcs), f.valid.value(&v))
    }

    #[test]
    fn full_circuit_is_wired_and_matches_the_reference() {
        let f = full();
        f.circuit.check_wired().unwrap();
        for seed in 0..4 {
            let inst = MptStorageProof::instance(seed);
            let (st, valid) = run(&inst.inputs);
            assert!(valid, "seed {seed}");
            assert_eq!(st, inst.statement, "seed {seed}");
            let bad = MptStorageProof::invalid_instance(seed).unwrap();
            let (st, valid) = run(&bad.inputs);
            assert!(!valid);
            assert_eq!(st, bad.statement);
        }
    }

    #[test]
    fn mainnet_tricrypto2_slot_one() {
        let aproof: Vec<Vec<u8>> = TRI_ACCOUNT_PROOF.iter().map(|s| unhex(s)).collect();
        let sproof: Vec<Vec<u8>> = TRI_STORAGE_PROOF.iter().map(|s| unhex(s)).collect();
        let (root, addr, slot) = (unhex(TRI_ROOT), unhex(TRI_ADDR), unhex(TRI_SLOT));
        let v = alloy_verify(&unhex(TRI_STORAGE_HASH), &keccak(&slot), &sproof).unwrap();
        let value = value_of(&v);
        let inputs = native::witness(&Params::MAINNET, &root, &addr, &slot, &aproof, &sproof).unwrap();
        let (st, valid) = run(&inputs);
        assert!(valid);
        assert_eq!(st.to_vec(), statement::<Keccak>(&root, &addr, &slot, &value, true));
        // Another slot's claim on the same proof fails.
        let mut slot2 = slot.clone();
        slot2[31] = 2;
        let inputs = native::witness(&Params::MAINNET, &root, &addr, &slot2, &aproof, &sproof).unwrap();
        assert!(!run(&inputs).1);
    }

    #[test]
    fn real_trie_proofs_with_idle_slots() {
        // A small state: shallow paths, so most inner slots are idle.
        let mut srng = 5u64;
        let mut next = move || {
            srng = srng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            srng >> 13
        };
        let slots: Vec<(Vec<u8>, Vec<u8>)> = (0..300u64)
            .map(|i| {
                let mut s = vec![0u8; 32];
                s[24..].copy_from_slice(&i.to_be_bytes());
                let v = native::minimal(&(next() | 1).to_be_bytes());
                (s, native::rlp_str(&v))
            })
            .collect();
        let (sroot, sproofs) = trie::<Keccak>(&slots);
        let target = keccak(b"target")[..20].to_vec();
        let mut accts: Vec<(Vec<u8>, Vec<u8>)> = (0..2000u32)
            .map(|i| {
                (
                    keccak(&i.to_be_bytes())[..20].to_vec(),
                    native::account(1, &[5], &[3; 32], &[4; 32]),
                )
            })
            .collect();
        accts.push((target.clone(), native::account(7, &[1, 0, 0], &sroot, &[8; 32])));
        let (root, aproofs) = trie::<Keccak>(&accts);
        let aproof = &aproofs[&native::nibbles(&keccak(&target))];
        for (slot, rv) in slots.iter().take(3) {
            let sproof = &sproofs[&native::nibbles(&keccak(slot))];
            let inputs = native::witness(&Params::MAINNET, &root, &target, slot, aproof, sproof).unwrap();
            let (st, valid) = run(&inputs);
            assert!(valid);
            assert_eq!(
                st.to_vec(),
                statement::<Keccak>(&root, &target, slot, &value_of(rv), true)
            );
        }
    }

    /// Flip input `i` of a valid instance's inputs; the result must be invalid (or, for bytes past a node's
    /// length, still valid with the same statement).
    #[test]
    fn malicious_hints_and_bytes() {
        let p = Params::MAINNET;
        let offs = native::slot_offsets(&p, Keccak::H);
        for seed in [0u64, 1] {
            let inst = MptStorageProof::instance(seed);
            let base = inst.inputs.clone();
            let flip = |i: usize| {
                let mut x = base.clone();
                x[i] ^= true;
                run(&x).1
            };
            let first = (0..p.acct_inner).find(|&i| base[offs[i].0]).unwrap();
            // Every hint bit of every active account and storage inner slot, and of both leaves.
            let mut checked = 0;
            for (si, &(h, _)) in offs.iter().enumerate() {
                let is_leaf = si == p.acct_inner || si == p.acct_inner + 1 + p.stor_inner;
                let n_hints = if is_leaf { 3 } else { 20 };
                if !is_leaf && !base[h] {
                    // An idle slot: turning it on breaks the walk (its zero node has no such hash).
                    assert!(!flip(h), "idle slot {si} turned on");
                    continue;
                }
                for b in 0..n_hints {
                    let i = h + b;
                    // An occupancy bit of an extension is not read.
                    if !is_leaf && !base[h + 1] && (2..18).contains(&b) {
                        assert!(flip(i));
                        continue;
                    }
                    // The single-byte and long-header bits of a branch are not read.
                    if !is_leaf && base[h + 1] && b >= 18 {
                        assert!(flip(i));
                        continue;
                    }
                    assert!(!flip(i), "seed {seed} slot {si} hint {b}");
                    checked += 1;
                }
            }
            assert!(checked > 100);
            // Turning the first active slot off: the next node is not the root.
            assert!(!flip(offs[first].0));
            // Bytes past a node's end are masked out of the hash and never parsed: the account leaf's last two
            // bytes and the storage leaf's last (both nodes are shorter than their bounds here).
            let leaf_at = offs[p.acct_inner].1;
            let stor_at = offs[p.acct_inner + 1 + p.stor_inner].1;
            let mut y = base.clone();
            for b in 8 * 146..8 * 148 {
                y[leaf_at + b] = true;
            }
            for b in 8 * 69..8 * 70 {
                y[stor_at + b] = true;
            }
            let (st, valid) = run(&y);
            assert!(valid);
            assert_eq!(st, inst.statement);
            // Every byte of the storage leaf matters, and of the account leaf's first 64.
            for byte in 0..30 {
                assert!(!flip(stor_at + 8 * byte + (byte % 8)), "storage leaf byte {byte}");
            }
            for byte in 0..64 {
                assert!(!flip(leaf_at + 8 * byte + (byte % 8)), "account leaf byte {byte}");
            }
            // The address and slot.
            assert!(!flip(8 * 32 + 5));
            assert!(!flip(8 * 52 + 250));
            assert!(!flip(3));
        }
    }

    #[test]
    fn report_counts() {
        let (rows, inputs, t) = report();
        let hash = t.get("keccak-f (node hashes)") + t.get("keccak-f (keys, statement)");
        println!(
            "{}: {rows} rows (with the 512 public rows), {inputs} inputs",
            MptStorageProof::NAME
        );
        for (name, r) in &t.parts {
            println!("  {name:40} {r:>10} {:>6.2}%", 100.0 * *r as f64 / rows as f64);
        }
        let other = rows - t.parts.iter().map(|p| p.1).sum::<usize>();
        println!("  {:40} {other:>10}", "unattributed (public, valid AND)");
        let parse = rows - hash - t.get("input rows") - PUBLIC_BITS;
        println!(
            "  hashing {hash} ({:.1}%), selection and parsing incl. padding {parse} ({:.1}%)",
            100.0 * hash as f64 / rows as f64,
            100.0 * parse as f64 / rows as f64
        );
    }

    #[test]
    #[ignore = "builds a second full circuit (storage bound 9 nodes); run with --ignored"]
    fn mainnet_weth_with_a_deeper_storage_bound() {
        let p = Params {
            stor_inner: 8,
            ..Params::MAINNET
        };
        let aproof: Vec<Vec<u8>> = WETH_ACCOUNT_PROOF.iter().map(|s| unhex(s)).collect();
        let sproof: Vec<Vec<u8>> = WETH_STORAGE_PROOF.iter().map(|s| unhex(s)).collect();
        let (root, addr, slot) = (unhex(WETH_ROOT), unhex(WETH_ADDR), unhex(WETH_SLOT));
        let acct = alloy_verify(&root, &keccak(&addr), &aproof).unwrap();
        let v = alloy_verify(&storage_root_of(&acct), &keccak(&slot), &sproof).unwrap();
        let value = value_of(&v);
        let mut want = vec![0u8; 32 - WETH_VALUE.len() / 2];
        want.extend(unhex(WETH_VALUE));
        assert_eq!(value, want);
        assert!(native::witness(&Params::MAINNET, &root, &addr, &slot, &aproof, &sproof).is_none());
        let inputs = native::witness(&p, &root, &addr, &slot, &aproof, &sproof).unwrap();
        let mut c = Ckt::new();
        let b = build_mpt::<Keccak>(&mut c, &p);
        println!("storage bound 9: {} rows", c.rows());
        let (circuit, srcs) = c.finish(&b.public);
        let vals = circuit.values(&inputs);
        assert_eq!(
            read_statement(&vals, &srcs).to_vec(),
            statement::<Keccak>(&root, &addr, &slot, &value, true)
        );
    }

    // ----- Bounded exhaustive tests: the same generator, tiny parameters, the stand-in hash.

    fn word64(w: &[Wire], v: &[(u64, u64)], lane: usize) -> u64 {
        w.iter()
            .enumerate()
            .map(|(i, &x)| ((wire64(x, v) >> lane) & 1) << i)
            .sum()
    }

    fn bytes64(w: &[Byte], v: &[(u64, u64)], lane: usize) -> Vec<u8> {
        w.iter().map(|b| word64(b, v, lane) as u8).collect()
    }

    /// The circuit of one slot alone: inputs node and hints (as in the full circuit), then the key from the
    /// walk's position (`k` nibbles) and the position `n`.
    struct Gadget {
        circuit: Circuit,
        out: SlotOut,
        n_inputs: usize,
    }

    fn gadget(p: &Params, kind: u8) -> Gadget {
        let mut c = Ckt::new();
        let k = p.k();
        let nw = bits_needed(k) + 1;
        let mut t = Tally::default();
        let out = match kind {
            0 => {
                let s = InnerIn::inputs(&mut c, p.inner_max);
                let key: Vec<Nib> = (0..k).map(|_| std::array::from_fn(|_| c.input())).collect();
                let n = c.inputs(nw);
                inner_slot::<Toy>(&mut c, p, &s, &key, &n, &mut t)
            }
            _ => {
                let max = if kind == 1 { p.acct_leaf_max } else { p.stor_leaf_max };
                let s = LeafIn::inputs(&mut c, max);
                let key: Vec<Nib> = (0..k).map(|_| std::array::from_fn(|_| c.input())).collect();
                let n = c.inputs(nw);
                leaf_slot::<Toy>(&mut c, p, &s, kind == 1, &key, &n, &mut t)
            }
        };
        let n_inputs = c.n_inputs();
        let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
        Gadget { circuit, out, n_inputs }
    }

    fn bools(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
            .collect()
    }

    /// What one lookup step on a true node does for the key nibbles `key` (from position `n`): `None` if the
    /// lookup fails, else (child reference or value item, nibbles consumed).
    fn step(node: &[u8], key: &[u8], n: usize, k: usize) -> Option<(Vec<u8>, usize, bool)> {
        let it = native::items(node);
        if it.len() == 17 {
            if n >= k {
                return None;
            }
            let (at, len) = it[key[0] as usize];
            if len == 1 {
                return None;
            }
            return Some((node[at + 1..at + len].to_vec(), 1, false));
        }
        let (a0, l0) = it[0];
        let path = if l0 == 1 {
            vec![node[a0]]
        } else {
            node[a0 + 1..a0 + l0].to_vec()
        };
        let flag = path[0] >> 4;
        let mut pn = native::nibbles(&path);
        pn.drain(..if flag & 1 == 1 { 1 } else { 2 });
        if n + pn.len() > k || key[..pn.len()] != pn[..] {
            return None;
        }
        let (a1, l1) = it[1];
        if flag & 2 == 2 {
            if n + pn.len() != k {
                return None;
            }
            return Some((node[a1..a1 + l1].to_vec(), pn.len(), true));
        }
        Some((node[a1 + 1..a1 + l1].to_vec(), pn.len(), false))
    }

    /// Small true nodes: branches (various occupancies), extensions (1 to 4 nibbles, odd and even, one-byte
    /// path items), leaves (account and storage).
    fn toy_nodes(p: &Params) -> Vec<(Vec<u8>, u8)> {
        let mut out = Vec::new();
        let r = |i: u8| native::rlp_str(&[0x40 + i, 0x91 ^ i]);
        for occ in [0b11u16, 0b1000_0000_0010_0001, 0xffff, 0x7ff0, 0x8001] {
            let mut items: Vec<Vec<u8>> = (0..16)
                .map(|j| {
                    if occ >> j & 1 == 1 {
                        r(j as u8)
                    } else {
                        native::rlp_str(&[])
                    }
                })
                .collect();
            items.push(native::rlp_str(&[]));
            out.push((native::rlp_list(&items), 0));
        }
        for path in [
            vec![5u8],
            vec![3, 0xc],
            vec![0, 1, 2],
            vec![0xf, 0xe, 0xd, 0xc],
            vec![0],
        ] {
            out.push((native::rlp_list(&[native::rlp_str(&native::hp(&path, false)), r(9)]), 0));
        }
        let acct = native::account(3, &[1], &[0xaa, 0xbb], &[0xcc, 0xdd]);
        let acct2 = native::account(0, &[], &[0x12, 0x34], &[0x56, 0x78]);
        for path in [vec![1u8, 2, 3, 4], vec![7, 8, 9], vec![0xa, 0xb], vec![4], vec![]] {
            out.push((
                native::rlp_list(&[native::rlp_str(&native::hp(&path, true)), native::rlp_str(&acct)]),
                1,
            ));
            out.push((
                native::rlp_list(&[native::rlp_str(&native::hp(&path, true)), native::rlp_str(&acct2)]),
                1,
            ));
            for v in [vec![0x05u8], vec![0x85], vec![0x01, 0x02], vec![0xff, 0x00]] {
                out.push((
                    native::rlp_list(&[
                        native::rlp_str(&native::hp(&path, true)),
                        native::rlp_str(&native::rlp_str(&v)),
                    ]),
                    2,
                ));
            }
        }
        out.retain(|(n, kind)| n.len() <= [p.inner_max, p.acct_leaf_max, p.stor_leaf_max][*kind as usize]);
        out
    }

    /// For every true node and every assignment of every hint, every key from the walk's position on (all of
    /// them for two-item parses; every first nibble for branch parses, which read no other) and every position
    /// `n`: if the slot accepts and its length is the node's (what the hash check forces), its outputs are the
    /// lookup step's, and the honest hints are accepted when the step succeeds. Bytes past the node are zeros,
    /// then ones. An inner slot's occupancy bits are enumerated in full under the branch parse; under the
    /// two-item parse, which reads none of them, they take three patterns.
    #[test]
    fn bounded_exhaustive_slots() {
        type Case = (Vec<bool>, Vec<u8>);
        let p = Params::toy(1, 1);
        let k = p.k();
        let nw = bits_needed(k) + 1;
        let gadgets = [gadget(&p, 0), gadget(&p, 1), gadget(&p, 2)];
        let nodes = toy_nodes(&p);
        let total = std::sync::atomic::AtomicUsize::new(0);
        let accepted = std::sync::atomic::AtomicUsize::new(0);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let nkeys = 1usize << (4 * k);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let (gadgets, total, accepted, next, nodes) = (&gadgets, &total, &accepted, &next, &nodes);
                scope.spawn(move || {
                    loop {
                        let ni = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some((node, kind)) = nodes.get(ni) else { break };
                        let kind = *kind as usize;
                        let g = &gadgets[kind];
                        let max = [p.inner_max, p.acct_leaf_max, p.stor_leaf_max][kind];
                        let honest: Vec<bool> = if kind == 0 {
                            let mut h = vec![true];
                            h.extend(native::inner_hints(node));
                            h
                        } else {
                            native::leaf_hints(node, kind == 1)
                        };
                        let honest_occ: u32 = if kind == 0 { (0..16).map(|j| (honest[2 + j] as u32) << j).sum() } else { 0 };
                        let key_of = |x: usize| -> Vec<u8> { (0..k).map(|i| ((x >> (4 * i)) & 15) as u8).collect() };
                        // Case `i`: its hint bits and key.
                        let n_a = if kind == 0 { (1usize << 18) * 16 } else { 0 };
                        let n_b = if kind == 0 { 3 * 4 * nkeys } else { 8 * nkeys };
                        let case = |i: usize| -> (Vec<bool>, Vec<u8>) {
                            if kind != 0 {
                                let (hb, key) = (i / nkeys, i % nkeys);
                                return ((0..3).map(|b| (hb >> b) & 1 == 1).collect(), key_of(key));
                            }
                            if i < n_a {
                                let (hb, k0) = (i / 16, i % 16);
                                let mut h = vec![true, true];
                                h.extend((0..18).map(|b| (hb >> b) & 1 == 1));
                                let mut key = vec![0u8; k];
                                key[0] = k0 as u8;
                                return (h, key);
                            }
                            if i < n_a + n_b {
                                let j = i - n_a;
                                let (variant, hb, key) = (j / (4 * nkeys), (j / nkeys) % 4, j % nkeys);
                                let occ = [0u32, 0xffff, honest_occ][variant];
                                let mut h = vec![true, false];
                                h.extend((0..16).map(|b| (occ >> b) & 1 == 1));
                                h.push(hb & 1 == 1);
                                h.push(hb & 2 == 2);
                                return (h, key_of(key));
                            }
                            (honest.clone(), vec![0; k])
                        };
                        let n_cases = n_a + n_b + 1;
                        for garbage in [0u8, 0xff] {
                            let mut bytes = node.clone();
                            bytes.resize(max, garbage);
                            let node_bits = bools(&bytes);
                            for n in 0..=k {
                                let mut start = 0;
                                while start < n_cases {
                                    let chunk: Vec<(Vec<bool>, Vec<u8>)> = (start..n_cases.min(start + 64)).map(case).collect();
                                    start += 64;
                                    // Inputs as 64-lane words: the node's bits are the same in every lane.
                                    let mut words: Vec<u64> = node_bits.iter().map(|&b| if b { u64::MAX } else { 0 }).collect();
                                    let lane_word = |f: &dyn Fn(&Case) -> bool| -> u64 {
                                        chunk.iter().enumerate().map(|(l, x)| (f(x) as u64) << l).sum()
                                    };
                                    for b in 0..chunk[0].0.len() {
                                        words.push(lane_word(&|x| x.0[b]));
                                    }
                                    for i in 0..k {
                                        for b in 0..4 {
                                            words.push(lane_word(&|x| (x.1[i] >> b) & 1 == 1));
                                        }
                                    }
                                    words.extend((0..nw).map(|i| if (n >> i) & 1 == 1 { u64::MAX } else { 0 }));
                                    assert_eq!(words.len(), g.n_inputs);
                                    let v = eval64(&g.circuit, &words);
                                    let oks = wire64(g.out.ok, &v);
                                    for (lane, (h, key)) in chunk.iter().enumerate() {
                                        let ok = (oks >> lane) & 1 == 1;
                                        let is_honest = *h == honest;
                                        if !ok && !is_honest {
                                            continue;
                                        }
                                        let len = word64(&g.out.len, &v, lane) as usize;
                                        let want = step(node, key, n, k).filter(|s| (kind == 0) != s.2);
                                        if ok && len == node.len() {
                                            accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            let (out, consumed, _) = want.clone().unwrap_or_else(|| {
                                                panic!("accepted a failing step: node {node:02x?} hints {h:?} key {key:?} n {n}")
                                            });
                                            let got = bytes64(&g.out.out, &v, lane);
                                            let ctx = format!("node {node:02x?} hints {h:?} key {key:?} n {n}");
                                            match kind {
                                                0 => {
                                                    assert_eq!(got, out, "{ctx}");
                                                    assert_eq!(word64(&g.out.consumed, &v, lane) as usize, consumed, "{ctx}");
                                                }
                                                1 => assert_eq!(got, storage_root_toy(&out, Toy::H), "{ctx}"),
                                                _ => assert_eq!(got, value_toy(&out, p.value_bytes), "{ctx}"),
                                            }
                                        }
                                        // Completeness: the honest hints pass whenever the step succeeds.
                                        if is_honest && want.is_some() {
                                            assert!(ok && len == node.len(), "honest hints rejected: {node:02x?} key {key:?} n {n}");
                                        }
                                    }
                                    total.fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                });
            }
        });
        println!(
            "bounded slots: {} nodes, {} assignments checked, {} accepted with the true length",
            nodes.len(),
            total.into_inner(),
            accepted.into_inner()
        );
    }

    /// Three-level paths (two inner slots), jointly: every non-occupancy hint bit of every slot enumerated in
    /// full, each inner slot's 16 occupancy bits over 19 patterns (honest, empty, full, and each single flip of
    /// the honest one; `bounded_exhaustive_slots` enumerates all 2^16 per slot).
    #[test]
    fn bounded_whole_circuit_three_levels() {
        use native::Level::{Branch, Ext};
        for (acct_levels, stor_levels) in [
            (vec![Branch(3), Ext(1)], vec![]),
            (vec![Ext(1), Branch(2)], vec![]),
            (vec![Branch(2)], vec![Branch(4)]),
            (vec![], vec![Branch(16), Branch(2)]),
        ] {
            let p = Params::toy(acct_levels.len(), stor_levels.len());
            let mut s = 91u64;
            let mut rng = move || {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                s >> 17
            };
            let (addr, slot) = (vec![0x5a, 0x3c], vec![0x00, 0x07]);
            let value = vec![0x01, 0x80];
            let (sroot, sproof) = native::synth_path::<Toy>(
                &Toy::native_key(&slot),
                &native::rlp_str(&native::minimal(&value)),
                &stor_levels,
                &mut rng,
            );
            let acct = native::account(1, &[2], &sroot, &[0xee, 0xef]);
            let (root, aproof) = native::synth_path::<Toy>(&Toy::native_key(&addr), &acct, &acct_levels, &mut rng);
            let honest = native::witness(&p, &root, &addr, &slot, &aproof, &sproof).unwrap();
            let mut c = Ckt::new();
            let b = build_mpt::<Toy>(&mut c, &p);
            let (circuit, _) = c.finish(&b.public);
            assert!(b.valid.value(&circuit.values(&honest)));
            let offs = native::slot_offsets(&p, Toy::H);
            let mut free = Vec::new();
            let mut occs: Vec<(usize, Vec<u32>)> = Vec::new();
            for (si, &(h, _)) in offs.iter().enumerate() {
                let is_leaf = si == p.acct_inner || si == p.acct_inner + 1 + p.stor_inner;
                if is_leaf {
                    free.extend(h..h + 3);
                } else {
                    free.extend([h, h + 1, h + 18, h + 19]);
                    let hon: u32 = (0..16).map(|j| (honest[h + 2 + j] as u32) << j).sum();
                    let mut set = vec![hon, 0, 0xffff];
                    set.extend((0..16).map(|j| hon ^ (1 << j)));
                    occs.push((h + 2, set));
                }
            }
            let nf = free.len();
            let combos: usize = occs.iter().map(|o| o.1.len()).product();
            let (mut accepted, mut collisions) = (0usize, 0usize);
            let true_lens: Vec<usize> = {
                let mut v = Vec::new();
                for (proof, inner) in [(&aproof, p.acct_inner), (&sproof, p.stor_inner)] {
                    let (leaf, nodes) = proof.split_last().unwrap();
                    for i in 0..inner {
                        v.push(if i >= inner - nodes.len() {
                            nodes[i - (inner - nodes.len())].len()
                        } else {
                            0
                        });
                    }
                    v.push(leaf.len());
                }
                v
            };
            for combo in 0..combos {
                let mut base: Vec<u64> = honest.iter().map(|&b| if b { u64::MAX } else { 0 }).collect();
                let mut rest = combo;
                for (at, set) in &occs {
                    let occ = set[rest % set.len()];
                    rest /= set.len();
                    for j in 0..16 {
                        base[at + j] = if (occ >> j) & 1 == 1 { u64::MAX } else { 0 };
                    }
                }
                let mut a = 0u64;
                while a < 1 << nf {
                    let mut words = base.clone();
                    for (i, &at) in free.iter().enumerate() {
                        words[at] = if i < 6 {
                            (0..64u64).map(|l| ((l >> i) & 1) << l).sum()
                        } else if (a >> i) & 1 == 1 {
                            u64::MAX
                        } else {
                            0
                        };
                    }
                    let v = eval64(&circuit, &words);
                    let valid = wire64(b.valid, &v);
                    for lane in 0..64 {
                        if (valid >> lane) & 1 == 0 {
                            continue;
                        }
                        accepted += 1;
                        if bytes64(&b.value, &v, lane) != value {
                            let differs = b.slots.iter().zip(&true_lens).any(|((act, len), &tl)| {
                                (wire64(*act, &v) >> lane) & 1 == 1 && word64(len, &v, lane) as usize != tl
                            });
                            assert!(differs, "accepted a wrong value with every node's true length");
                            collisions += 1;
                        }
                    }
                    a += 64;
                }
            }
            println!(
                "bounded three levels {acct_levels:?}/{stor_levels:?}: 2^{nf} x {combos} assignments, {accepted} accepted, \
                 {collisions} stand-in collisions"
            );
        }
    }

    /// The storage root in a toy account's value item.
    fn storage_root_toy(item: &[u8], h: usize) -> Vec<u8> {
        let (o, l, _, _) = native::item(item, 0);
        storage_root_of_h(&item[o..o + l], h)
    }

    fn storage_root_of_h(account: &[u8], h: usize) -> Vec<u8> {
        let it = native::items(account);
        let (s, _) = it[2];
        account[s + 1..s + 1 + h].to_vec()
    }

    fn value_toy(item: &[u8], vb: usize) -> Vec<u8> {
        let (o, l, _, _) = native::item(item, 0);
        let inner = &item[o..o + l];
        let (o2, l2, _, _) = native::item(inner, 0);
        let mut w = vec![0u8; vb - l2];
        w.extend_from_slice(&inner[o2..o2 + l2]);
        w
    }

    /// The whole circuit at tiny bounds, every hint bit of every slot enumerated jointly: `valid` implies the
    /// value read is the trie's (or a hashed preimage differs from the true node: a stand-in hash collision,
    /// counted, which collision resistance excludes for Keccak), and the honest hints give `valid`.
    #[test]
    fn bounded_exhaustive_whole_circuit() {
        use native::Level::{Branch, Ext};
        for (acct_levels, stor_levels) in [
            (vec![Branch(3)], vec![]),
            (vec![Ext(2)], vec![]),
            (vec![], vec![Branch(2)]),
            (vec![], vec![Ext(1)]),
        ] {
            let p = Params::toy(acct_levels.len(), stor_levels.len());
            let mut s = 77u64;
            let mut rng = move || {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                s >> 17
            };
            let (addr, slot) = (vec![0x5a, 0x3c], vec![0x00, 0x07]);
            let value = vec![0x00, 0x99];
            let levels_s: Vec<Level> = stor_levels.clone();
            let (sroot, sproof) = native::synth_path::<Toy>(
                &Toy::native_key(&slot),
                &native::rlp_str(&native::minimal(&value)),
                &levels_s,
                &mut rng,
            );
            let acct = native::account(1, &[2], &sroot, &[0xee, 0xef]);
            let (root, aproof) = native::synth_path::<Toy>(&Toy::native_key(&addr), &acct, &acct_levels, &mut rng);
            let honest = native::witness(&p, &root, &addr, &slot, &aproof, &sproof).unwrap();
            let mut c = Ckt::new();
            let b = build_mpt::<Toy>(&mut c, &p);
            let rows = c.rows();
            let (circuit, _) = c.finish(&b.public);
            // The hint bits: every slot's.
            let offs = native::slot_offsets(&p, Toy::H);
            let mut hint_bits = Vec::new();
            for (si, &(h, _)) in offs.iter().enumerate() {
                let is_leaf = si == p.acct_inner || si == p.acct_inner + 1 + p.stor_inner;
                hint_bits.extend(h..h + if is_leaf { 3 } else { 20 });
            }
            let nh = hint_bits.len();
            let true_nodes: Vec<Vec<u8>> = aproof.iter().chain(&sproof).cloned().collect();
            let true_lens: Vec<usize> = {
                // Slot order: account inner slots (idle first), account leaf, storage inner, storage leaf.
                let mut v = Vec::new();
                for (proof, inner) in [(&aproof, p.acct_inner), (&sproof, p.stor_inner)] {
                    let (leaf, nodes) = proof.split_last().unwrap();
                    for i in 0..inner {
                        v.push(if i >= inner - nodes.len() {
                            nodes[i - (inner - nodes.len())].len()
                        } else {
                            0
                        });
                    }
                    v.push(leaf.len());
                }
                v
            };
            let _ = true_nodes;
            let total = 1u64 << nh;
            let collisions = std::sync::atomic::AtomicUsize::new(0);
            let accepted = std::sync::atomic::AtomicUsize::new(0);
            let threads = 8u64;
            std::thread::scope(|scope| {
                for th in 0..threads {
                    let (circuit, b, honest, hint_bits, true_lens, collisions, accepted, value) = (
                        &circuit,
                        &b,
                        &honest,
                        &hint_bits,
                        &true_lens,
                        &collisions,
                        &accepted,
                        &value,
                    );
                    scope.spawn(move || {
                        let per = total / threads;
                        let mut a = th * per;
                        while a < (th + 1) * per {
                            // 64 consecutive assignments: hint bit `i < 6` follows the lane, the others `a`.
                            let mut words: Vec<u64> = honest.iter().map(|&b| if b { u64::MAX } else { 0 }).collect();
                            for (i, &at) in hint_bits.iter().enumerate() {
                                words[at] = if i < 6 {
                                    (0..64u64).map(|l| ((l >> i) & 1) << l).sum()
                                } else if (a >> i) & 1 == 1 {
                                    u64::MAX
                                } else {
                                    0
                                };
                            }
                            let v = eval64(circuit, &words);
                            let valid = wire64(b.valid, &v);
                            for lane in 0..64 {
                                if (valid >> lane) & 1 == 0 {
                                    continue;
                                }
                                accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if bytes64(&b.value, &v, lane) != *value {
                                    // A stand-in collision: some active slot hashed other than its true length.
                                    let differs = b.slots.iter().zip(true_lens).any(|((act, len), &tl)| {
                                        (wire64(*act, &v) >> lane) & 1 == 1 && word64(len, &v, lane) as usize != tl
                                    });
                                    assert!(differs, "accepted a wrong value with every node's true length");
                                    collisions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            a += 64;
                        }
                    });
                }
            });
            // The honest hints.
            let vals = circuit.values(&honest);
            assert!(b.valid.value(&vals));
            println!(
                "bounded whole circuit {acct_levels:?}/{stor_levels:?}: {rows} rows, 2^{nh} hint assignments, \
                 {} accepted, {} stand-in collisions",
                accepted.into_inner(),
                collisions.into_inner()
            );
        }
    }
}
