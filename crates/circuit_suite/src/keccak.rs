//! Keccak-f[1600] and Keccak-256 (Ethereum's, padding `0x01 .. 0x80`, rate 136 bytes) in rows.
//!
//! # Statement `Keccak256OneKiB`
//!
//! Free inputs: a 1,024-byte message, byte `i` bit `j` (low first) the input `8 i + j`. Statement bytes `0..32`
//! are `keccak256(message)`, bytes `32..64` are zero. There is nothing to check, so there is no invalid instance.
//!
//! # How a round is laid out
//!
//! A row adds two bits and a carry. Its sum is a three-input XOR when one input is a carry, and its carry is an
//! AND (or an OR) when the third input is a constant. Keccak has exactly one nonlinear gate a state bit a round,
//! `~b & c` in chi, so a round needs at least 1,600 AND rows; everything else is XOR, and the point is to make
//! every XOR row take three inputs with no conversion rows. A round costs `3 * 1600 + 320` rows plus about 43
//! (`Stats`): 5,163 rows a round in the steady state, 3.23 a state bit.
//!
//! * **chi, one AND/OR row a bit.** With `b = p1 ^ a1` and `c = p2 ^ a2` (`p` the rows' positive bits, `a` the
//!   negations the wires carry for free), `~b & c` is `p1 p2` plus a linear part. When `a1 != a2` the AND row
//!   (`a1 = 1`) or the OR row (`a2 = 1`) gives `~b & c` up to a constant, so the chi output is `a ^ k`: *two*
//!   terms, one of them the carry `k`. When `a1 == a2` there is a third term `p1` or `p2`.
//! * **the output is never formed; theta's column parity chains through it, one row a bit.** The next round's
//!   column parity `C[x][z]` is a chain over the column's five outputs, `P <- a ^ P ^ k`, a full row each, the
//!   carry `k` in the carry slot. The first output of each column starts the chain: it is the one with three
//!   terms, made into a bit with one full row.
//! * **theta, one row a bit, plus one row a column bit for `D`.** `D[x][z] = C[x-1][z] ^ C[x+1][z-1]` is one
//!   row, and each state bit is then `a ^ k ^ D` in one full row (`k` again in the carry slot), or `s ^ D` for
//!   the column's start `s`. rho and pi are re-indexing; iota is a free negation.
//! * **polarity.** The two-term case needs the negations of `b` and `c` to differ. They are set per round: a
//!   chi row of five bits is a 5-cycle and has one pair with equal negations at best; it is put where each
//!   output column gets exactly one, which is then that column's chain start. A theta row with a free slot sets
//!   its output's negation with a constant one; the full rows `a ^ k ^ D` take it from `D`, whose polarity is
//!   chosen per `(x, z)` by simulated annealing over the chi rows' patterns; a `D` both of whose polarities
//!   are needed costs one more row. Round 0 of every permutation takes a fixed pattern, so the later rounds
//!   see the same search problem in every permutation and the (cached) search runs once per round.
//!
//! So a round is 1,600 AND/OR rows, 1,600 chain rows (chi XOR and column parity at once), 1,600 theta rows and
//! 320 `D` rows, plus about 40 `D` columns needing both polarities and 3 chi outputs of three terms past their
//! column's first. The first round of a permutation computes its column parities from scratch, and absorbing a
//! block costs about one row a rate bit (a carry absorbed into a two-term bit is folded with one row); a
//! permutation is about 124,000 rows (125,135 for `keccak_f` with every output reduced). The last round of a
//! hash computes only the 256 output bits. `Keccak256OneKiB` (8 blocks) is 1,003,539 rows with its 8,192 input
//! rows and the 512 public rows, closing on 2^20.
//!
//! This layout's own floor is 5,120 rows a round (three rows a state bit and `D`), and it is within 0.9% of it.
//! The only floor proven is 1,600 nonlinear rows a round; a cheaper layout would have to fold the column
//! parities or `D` into rows that already have three inputs, and we know of none.

use std::collections::HashMap;

use crate::{Ckt, Instance, Kind, PUBLIC_BITS, Wire, Workload};

pub const RC: [u64; 24] = [
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
/// `ROT[x][y]`, the rho offset of lane `(x, y)`.
pub const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub const STATE: usize = 1600;
/// Bytes absorbed a permutation by Keccak-256.
pub const RATE: usize = 136;

/// The index of bit `z` of lane `(x, y)`.
pub const fn at(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}

fn strip(w: Wire) -> Wire {
    Wire { neg: false, ..w }
}

fn negate_if(w: Wire, n: bool) -> Wire {
    if n { w.not() } else { w }
}

/// A bit not yet reduced to one wire: the XOR of positive bits, positive carries and a constant.
#[derive(Clone, Debug, Default)]
pub struct Lin {
    bits: Vec<Wire>,
    carries: Vec<Wire>,
    neg: bool,
}

impl Lin {
    pub fn of(w: Wire) -> Lin {
        let mut l = Lin::default();
        l.push(w);
        l
    }

    pub fn push(&mut self, w: Wire) {
        self.neg ^= w.neg;
        let w = strip(w);
        match w.kind {
            Kind::Const(b) => self.neg ^= b,
            Kind::Carry(_) => self.carries.push(w),
            Kind::Sum(_) => self.bits.push(w),
        }
    }

    pub fn extend(&mut self, other: &Lin) {
        self.bits.extend_from_slice(&other.bits);
        self.carries.extend_from_slice(&other.carries);
        self.neg ^= other.neg;
    }

    fn plus(&self, w: Wire) -> Lin {
        let mut l = self.clone();
        l.push(w);
        l
    }
}

/// The rows [`reduce`] makes for `b` bits and `k` carries: per row, whether it has a free slot.
fn plan(mut b: usize, mut k: usize) -> Vec<bool> {
    let mut rows = Vec::new();
    while b + k > 1 {
        let c = k > 0;
        k -= c as usize;
        // Bit slots take bits, then carries (converted).
        let mut taken = 0;
        while taken < 2 && b + k > 0 {
            if b > 0 {
                b -= 1
            } else {
                k -= 1
            }
            taken += 1;
        }
        rows.push(!c || taken < 2);
        b += 1;
    }
    rows
}

/// Whether reducing `l` can choose the negation of its result for free.
fn free_polarity(l: &Lin) -> bool {
    plan(l.bits.len(), l.carries.len()).contains(&true)
}

/// `l` as one wire. With `want`, a row with a free slot takes a constant one if needed so that the result's
/// positive row holds `value ^ want` (its negation flag is `want`); without a free slot `want` is ignored.
pub fn reduce(c: &mut Ckt, l: &Lin, want: Option<bool>) -> Wire {
    let (mut bits, mut carries, neg) = (l.bits.clone(), l.carries.clone(), l.neg);
    if bits.len() + carries.len() == 0 {
        return Wire::constant(neg);
    }
    let rows = plan(bits.len(), carries.len());
    if rows.is_empty() {
        let w = bits.pop().or_else(|| carries.pop()).unwrap();
        return negate_if(w, neg);
    }
    let last_free = rows.iter().rposition(|&f| f);
    // Ones inserted so far: the result's negation flag is `neg ^ ones`.
    let one = match (want, last_free) {
        (Some(w), Some(_)) => w ^ neg,
        _ => false,
    };
    let mut out = Wire::ZERO;
    for (i, &free) in rows.iter().enumerate() {
        let k = carries.pop();
        let mut slots: Vec<Wire> = Vec::with_capacity(3);
        while slots.len() < 2 && !(bits.is_empty() && carries.is_empty()) {
            slots.push(bits.pop().unwrap_or_else(|| carries.pop().unwrap()));
        }
        let mut operands = slots;
        if free && Some(i) == last_free && one {
            operands.push(Wire::ONE);
        }
        if let Some(k) = k {
            operands.push(k);
        }
        while operands.len() < 3 {
            operands.push(Wire::ZERO);
        }
        let (s, _) = c.fa(operands[0], operands[1], operands[2]);
        debug_assert!(!s.neg);
        out = s;
        bits.push(s);
    }
    negate_if(out, neg ^ one)
}

/// Counts of the rows of each kind a permutation used.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub rounds: usize,
    /// `D` columns whose two polarities were both needed.
    pub d_both: usize,
    /// Chi outputs of three terms beyond a column's first.
    pub extra_three: usize,
}

/// The state of a sponge: 1,600 bits as [`Lin`]s, and, when known, its 320 column parities `C[x][z]`
/// (`64 x + z`).
#[derive(Clone)]
pub struct State {
    pub lanes: Vec<Lin>,
    pub parity: Option<Vec<Wire>>,
}

impl State {
    pub fn zero() -> State {
        State {
            lanes: vec![Lin::default(); STATE],
            parity: Some(vec![Wire::ZERO; 320]),
        }
    }

    pub fn from_wires(w: &[Wire]) -> State {
        assert_eq!(w.len(), STATE);
        State {
            lanes: w.iter().map(|&w| Lin::of(w)).collect(),
            parity: None,
        }
    }

    /// XOR `bits` into the state's first bits (the rate).
    pub fn absorb(&mut self, bits: &[Wire]) {
        for (l, &b) in self.lanes.iter_mut().zip(bits) {
            l.push(b);
        }
        if bits.iter().any(|b| b.as_const().is_none()) {
            self.parity = None;
        } else if let Some(p) = &mut self.parity {
            for (i, b) in bits.iter().enumerate() {
                if b.as_const() == Some(true) {
                    let col = 64 * ((i / 64) % 5) + i % 64;
                    p[col] = p[col].not();
                }
            }
        }
    }

    /// Bit `i` as one wire; the lane keeps it.
    pub fn bit(&mut self, c: &mut Ckt, i: usize) -> Wire {
        let w = reduce(c, &self.lanes[i], None);
        self.lanes[i] = Lin::of(w);
        w
    }
}

/// The post-pi position of pre-pi bit `(x, y, z)`.
fn pi(x: usize, y: usize, z: usize) -> usize {
    at(y, (2 * x + 3 * y) % 5, (z + ROT[x][y]) % 64)
}

/// Whether the chi-input pattern of a row whose pair of equal negations is at output `bad` negates position `x`.
fn pattern(bad: usize, x: usize) -> bool {
    let d = (x + 5 - bad) % 5;
    d == 0 || d == 3
}

/// The column parities of `lanes`, chaining through each column; a column's first bit is reduced to one wire
/// (and kept so), and so is any other that is not one bit and at most one carry.
fn parity_chain(c: &mut Ckt, lanes: &mut [Lin], stats: &mut Stats) -> Vec<Wire> {
    // A bit with two carries (a chi output and an absorbed carry): one row folds a carry with its bits, so it
    // is again one bit and one carry.
    for l in lanes.iter_mut() {
        while l.carries.len() > 1 {
            let kc = l.carries.pop().unwrap();
            let x = l.bits.pop().unwrap_or_else(|| l.carries.pop().unwrap());
            let y = l.bits.pop().unwrap_or(Wire::ZERO);
            let (s, _) = c.fa(x, y, kc);
            l.bits.push(s);
        }
    }
    let mut out = Vec::with_capacity(320);
    for x in 0..5 {
        for z in 0..64 {
            let idx: Vec<usize> = (0..5).map(|y| at(x, y, z)).collect();
            let simple = |l: &Lin| l.bits.len() <= 1 && l.carries.len() <= 1;
            let start = idx.iter().copied().find(|&i| !simple(&lanes[i])).unwrap_or(idx[0]);
            let s = reduce(c, &lanes[start], None);
            lanes[start] = Lin::of(s);
            let mut p = s;
            for &i in &idx {
                if i == start {
                    continue;
                }
                let l = &lanes[i];
                if !simple(l) {
                    stats.extra_three += 1;
                    let m = reduce(c, l, None);
                    lanes[i] = Lin::of(m);
                }
                p = reduce(c, &lanes[i].plus(p), None);
            }
            out.push(p);
        }
    }
    out
}

/// Choose, for each chi row `(y, z)` (index `64 y + z`), where its pair of equal negations goes (`bad`, a
/// permutation of `y` for each `z`) and its complement bit, minimising the `D` columns that need both
/// polarities. `fixed[i]` is, for a pre-pi bit whose theta row is full, the negation it gets besides `D`'s.
/// Per chi row, where its pair of equal negations goes, and its complement bit.
type Patterns = (Vec<usize>, Vec<bool>);

fn choose_patterns(fixed: &[Option<bool>], needed: &[bool]) -> Patterns {
    // The search depends only on its arguments, which repeat from permutation to permutation (from round 1
    // on, every permutation's rounds see the same arguments, round 0 being canonical).
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<Vec<u8>, Patterns>>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key: Vec<u8> = fixed
        .iter()
        .zip(needed)
        .map(|(f, &n)| if !n { 3 } else { f.map_or(2, |b| b as u8) })
        .collect();
    if let Some(hit) = cache.lock().unwrap().get(&key).cloned() {
        return hit;
    }
    let result = search_patterns(fixed, needed);
    cache.lock().unwrap().insert(key, result.clone());
    result
}

/// The canonical patterns: row `(y, z)`'s equal pair at output `y`, no complement.
fn canonical_patterns() -> Patterns {
    ((0..320).map(|r| r / 64).collect(), vec![false; 320])
}

fn search_patterns(fixed: &[Option<bool>], needed: &[bool]) -> Patterns {
    // For each chi row, its five post-pi bits' pre-pi origin (bit, D node), when fixed.
    let mut members: Vec<Vec<(usize, usize, bool)>> = vec![Vec::new(); 320];
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..64 {
                let i = at(x, y, z);
                if let (Some(f), true) = (fixed[i], needed[i]) {
                    let j = pi(x, y, z);
                    let (xx, yy, zz) = ((j / 64) % 5, j / 320, j % 64);
                    members[64 * yy + zz].push((xx, 64 * x + z, f));
                }
            }
        }
    }
    // Simulated annealing from four seeds in parallel, keeping the best.
    let runs: Vec<(i64, Patterns)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4u64)
            .map(|seed| {
                let members = &members;
                scope.spawn(move || anneal(members, seed))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    runs.into_iter().min_by_key(|r| r.0).unwrap().1
}

/// One annealing run: its cost (`D` columns needing both polarities, plus three-term chi outputs past a
/// column's first) and patterns.
fn anneal(members: &[Vec<(usize, usize, bool)>], seed: u64) -> (i64, Patterns) {
    let (mut bad, mut comp) = canonical_patterns();
    // Requests per D node and polarity.
    let mut count = vec![[0u32; 2]; 320];
    let req = |bad: usize, comp: bool, xx: usize, f: bool| (pattern(bad, xx) ^ comp ^ f) as usize;
    for r in 0..320 {
        for &(xx, node, f) in &members[r] {
            count[node][req(bad[r], comp[r], xx, f)] += 1;
        }
    }
    let cost = |count: &[[u32; 2]], node: usize| (count[node][0] > 0 && count[node][1] > 0) as i64;
    let mut cols = vec![0u32; 320];
    for r in 0..320 {
        cols[64 * bad[r] + r % 64] += 1;
    }
    // Change row `r` from `from` to `to` (bad position, complement); returns the cost delta, the change applied.
    let apply = |count: &mut [[u32; 2]], cols: &mut [u32], r: usize, from: (usize, bool), to: (usize, bool)| -> i64 {
        let mut delta = 0;
        for &(xx, node, f) in &members[r] {
            delta -= cost(count, node);
            count[node][req(from.0, from.1, xx, f)] -= 1;
            count[node][req(to.0, to.1, xx, f)] += 1;
            delta += cost(count, node);
        }
        let (c0, c1) = (64 * from.0 + r % 64, 64 * to.0 + r % 64);
        if c0 != c1 {
            delta -= (cols[c0] > 1) as i64;
            cols[c0] -= 1;
            delta += (cols[c1] > 0) as i64;
            cols[c1] += 1;
        }
        delta
    };
    let total = |count: &[[u32; 2]], cols: &[u32]| -> i64 {
        (0..320).map(|n| cost(count, n)).sum::<i64>() + cols.iter().map(|&n| n.saturating_sub(1) as i64).sum::<i64>()
    };
    let mut current = total(&count, &cols);
    let (mut best, mut best_bad, mut best_comp) = (current, bad.clone(), comp.clone());
    let mut rng = 0x2545_f491_4f6c_dd1du64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    const STEPS: usize = 3_000_000;
    for step in 0..STEPS {
        if best == 0 {
            break;
        }
        let temp = 0.6 * (1.0 - step as f64 / STEPS as f64) + 0.02;
        let v = next();
        let r = (v % 320) as usize;
        let to = (((v >> 16) % 5) as usize, (v >> 24) & 1 == 1);
        let from = (bad[r], comp[r]);
        if to == from {
            continue;
        }
        let d = apply(&mut count, &mut cols, r, from, to);
        let accept = d <= 0 || ((next() >> 11) as f64 / (1u64 << 53) as f64) < (-(d as f64) / temp).exp();
        if accept {
            bad[r] = to.0;
            comp[r] = to.1;
            current += d;
            if current < best {
                best = current;
                best_bad.clone_from(&bad);
                best_comp.clone_from(&comp);
            }
        } else {
            apply(&mut count, &mut cols, r, to, from);
        }
    }
    (best, (best_bad, best_comp))
}

/// One round on `st`. `out_lanes`, when given, are the only output lanes needed (the others are left zero);
/// `chain` computes the output's column parities.
#[allow(clippy::too_many_arguments)]
fn round(
    c: &mut Ckt,
    st: State,
    rc: u64,
    out_lanes: Option<&[bool; 25]>,
    chain: bool,
    canonical: bool,
    stats: &mut Stats,
) -> State {
    let State { mut lanes, parity } = st;
    stats.rounds += 1;
    // Which post-pi lanes (chi inputs) and so which pre-pi bits are needed.
    let mut need_b = [true; 25];
    if let Some(o) = out_lanes {
        need_b = [false; 25];
        for yy in 0..5 {
            if (0..5).any(|xx| o[xx + 5 * yy]) {
                for xx in 0..5 {
                    need_b[xx + 5 * yy] = true;
                }
            }
        }
    }
    let mut needed = vec![false; STATE];
    for x in 0..5 {
        for y in 0..5 {
            let lane_b = y + 5 * ((2 * x + 3 * y) % 5);
            if need_b[lane_b] {
                for z in 0..64 {
                    needed[at(x, y, z)] = true;
                }
            }
        }
    }
    let parity = match parity {
        Some(p) => p,
        None => {
            let mut p = Vec::with_capacity(320);
            for x in 0..5 {
                for z in 0..64 {
                    let mut l = Lin::default();
                    for y in 0..5 {
                        l.extend(&lanes[at(x, y, z)]);
                    }
                    p.push(reduce(c, &l, None));
                }
            }
            p
        }
    };
    // Theta rows that are full get their negation from D.
    let fixed: Vec<Option<bool>> = lanes
        .iter()
        .map(|l| {
            if free_polarity(&l.plus_term()) {
                None
            } else {
                Some(l.neg)
            }
        })
        .collect();
    let (bad, comp) = if canonical {
        canonical_patterns()
    } else {
        choose_patterns(&fixed, &needed)
    };
    let desired = |j: usize| -> bool {
        let (xx, yy, zz) = ((j / 64) % 5, j / 320, j % 64);
        let r = 64 * yy + zz;
        pattern(bad[r], xx) ^ comp[r]
    };
    // D nodes, by polarity.
    let mut dcache: HashMap<(usize, bool), Wire> = HashMap::new();
    let mut d_wire = |c: &mut Ckt, x: usize, z: usize, pol: bool| -> Wire {
        *dcache.entry((64 * x + z, pol)).or_insert_with(|| {
            let mut l = Lin::of(parity[64 * ((x + 4) % 5) + z]);
            l.push(parity[64 * ((x + 1) % 5) + (z + 63) % 64]);
            reduce(c, &l, Some(pol))
        })
    };
    let mut b = vec![Wire::ZERO; STATE];
    let mut pols_used = vec![[false; 2]; 320];
    // Full rows first, so free rows can reuse whichever polarity exists.
    for pass in 0..2 {
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let i = at(x, y, z);
                    if !needed[i] || (fixed[i].is_some() != (pass == 0)) {
                        continue;
                    }
                    let j = pi(x, y, z);
                    let want = desired(j);
                    let l = &lanes[i];
                    let w = match fixed[i] {
                        Some(f) => {
                            let d = d_wire(c, x, z, want ^ f);
                            pols_used[64 * x + z][(want ^ f) as usize] = true;
                            reduce(c, &l.plus(d), None)
                        }
                        None => {
                            let pol = if pols_used[64 * x + z][1] && !pols_used[64 * x + z][0] {
                                true
                            } else {
                                pols_used[64 * x + z][0] = true;
                                false
                            };
                            let d = d_wire(c, x, z, pol);
                            reduce(c, &l.plus(d), Some(want))
                        }
                    };
                    b[j] = w;
                }
            }
        }
    }
    stats.d_both += pols_used.iter().filter(|p| p[0] && p[1]).count();
    // Chi and iota.
    let mut out = vec![Lin::default(); STATE];
    for yy in 0..5 {
        for xx in 0..5 {
            if !out_lanes.is_none_or(|o| o[xx + 5 * yy]) {
                continue;
            }
            for z in 0..64 {
                let (b0, b1, b2) = (b[at(xx, yy, z)], b[at((xx + 1) % 5, yy, z)], b[at((xx + 2) % 5, yy, z)]);
                let (p1, p2) = (strip(b1), strip(b2));
                let mut l = Lin::of(b0);
                match (b1.neg, b2.neg) {
                    // ~b & c = p1 & p2.
                    (true, false) => l.push(c.and(p1, p2)),
                    // ~b & c = ~p1 & ~p2 = ~(p1 | p2).
                    (false, true) => l.push(c.or(p1, p2).not()),
                    // ~p1 & p2 = p2 ^ p1 p2.
                    (false, false) => {
                        l.push(c.and(p1, p2));
                        l.push(p2);
                    }
                    // p1 & ~p2 = p1 ^ p1 p2.
                    (true, true) => {
                        l.push(c.and(p1, p2));
                        l.push(p1);
                    }
                }
                if xx == 0 && yy == 0 && (rc >> z) & 1 == 1 {
                    l.neg = !l.neg;
                }
                out[at(xx, yy, z)] = l;
            }
        }
    }
    lanes.clear();
    let parity = if chain {
        Some(parity_chain(c, &mut out, stats))
    } else {
        None
    };
    State { lanes: out, parity }
}

impl Lin {
    /// `self` with a placeholder bit standing for `D`, for planning only.
    fn plus_term(&self) -> Lin {
        let mut l = self.clone();
        l.bits.push(Wire::ZERO);
        l
    }
}

/// Keccak-f[1600] on `st`. With `out_lanes`, the last round computes only those lanes; with `chain`, the
/// output's column parities are computed (for a following permutation with nothing absorbed).
pub fn permute(c: &mut Ckt, mut st: State, out_lanes: Option<&[bool; 25]>, chain: bool, stats: &mut Stats) -> State {
    for (r, &rc) in RC.iter().enumerate() {
        let last = r + 1 == RC.len();
        st = round(
            c,
            st,
            rc,
            if last { out_lanes } else { None },
            !last || chain,
            r == 0,
            stats,
        );
    }
    st
}

/// Make sure `st` knows its column parities (after absorbing), chaining through its bits.
pub fn settle(c: &mut Ckt, st: &mut State, stats: &mut Stats) {
    if st.parity.is_none() {
        st.parity = Some(parity_chain(c, &mut st.lanes, stats));
    }
}

/// Keccak-f[1600] on 1,600 wires, every output bit reduced to one wire.
pub fn keccak_f(c: &mut Ckt, state: &[Wire]) -> Vec<Wire> {
    if c.native_keccak_enabled() {
        return c.keccak_permutation(state);
    }
    let mut stats = Stats::default();
    let mut st = permute(c, State::from_wires(state), None, false, &mut stats);
    (0..STATE).map(|i| st.bit(c, i)).collect()
}

/// The 1,088-bit blocks of `msg` (bits, a whole number of bytes) padded by Keccak-256.
pub fn pad(msg: &[Wire]) -> Vec<Vec<Wire>> {
    assert_eq!(msg.len() % 8, 0);
    let rate = 8 * RATE;
    let n = msg.len() / rate + 1;
    let mut bits = msg.to_vec();
    bits.resize(n * rate, Wire::ZERO);
    bits[msg.len()] = Wire::ONE;
    bits[n * rate - 1] = Wire::ONE;
    bits.chunks(rate).map(|b| b.to_vec()).collect()
}

/// The digest lanes.
const DIGEST_LANES: [bool; 25] = {
    let mut l = [false; 25];
    l[0] = true;
    l[1] = true;
    l[2] = true;
    l[3] = true;
    l
};

/// The sponge over padded `blocks`; for each `i` in `digests` (block counts, increasing), the 256-bit digest
/// after `i` blocks. Blocks past the last digest are not absorbed.
pub fn sponge(c: &mut Ckt, blocks: &[Vec<Wire>], digests: &[usize], stats: &mut Stats) -> Vec<Vec<Wire>> {
    if c.native_keccak_enabled() {
        let last = *digests.last().expect("a digest");
        assert!(last >= 1 && last <= blocks.len());
        let mut state = vec![Wire::ZERO; STATE];
        let mut outputs = Vec::new();
        for (i, block) in blocks[..last].iter().enumerate() {
            assert_eq!(block.len(), RATE * 8);
            for (bit, &input) in block.iter().enumerate() {
                state[bit] = c.xor(state[bit], input);
            }
            state = c.keccak_permutation(&state);
            if digests.contains(&(i + 1)) {
                outputs.push(state[..256].to_vec());
            }
        }
        return outputs;
    }

    let last = *digests.last().expect("a digest");
    assert!(last >= 1 && last <= blocks.len());
    let mut st = State::zero();
    let mut out = Vec::new();
    for (i, block) in blocks[..last].iter().enumerate() {
        st.absorb(block);
        settle(c, &mut st, stats);
        let final_block = i + 1 == last;
        st = permute(
            c,
            st,
            if final_block { Some(&DIGEST_LANES) } else { None },
            false,
            stats,
        );
        if digests.contains(&(i + 1)) {
            out.push((0..256).map(|j| st.bit(c, j)).collect());
        }
    }
    out
}

/// As [`sponge`], but for each block count in `digests`, the 256 bits `digest ^ against` (zero where they
/// agree): each is one row from the state's two-term bits, the XOR folded into the row that forms the bit.
pub fn sponge_diff(
    c: &mut Ckt,
    blocks: &[Vec<Wire>],
    digests: &[usize],
    against: &[Wire],
    stats: &mut Stats,
) -> Vec<Vec<Wire>> {
    if c.native_keccak_enabled() {
        assert_eq!(against.len(), 256);
        return sponge(c, blocks, digests, stats)
            .into_iter()
            .map(|digest| digest.into_iter().zip(against).map(|(a, &b)| c.xor(a, b)).collect())
            .collect();
    }
    let last = *digests.last().expect("a digest");
    assert!(last >= 1 && last <= blocks.len() && against.len() == 256);
    let mut st = State::zero();
    let mut out = Vec::new();
    for (i, block) in blocks[..last].iter().enumerate() {
        st.absorb(block);
        settle(c, &mut st, stats);
        let final_block = i + 1 == last;
        st = permute(
            c,
            st,
            if final_block { Some(&DIGEST_LANES) } else { None },
            false,
            stats,
        );
        if digests.contains(&(i + 1)) {
            out.push(
                (0..256)
                    .map(|j| reduce(c, &st.lanes[j].plus(against[j]), None))
                    .collect(),
            );
        }
    }
    out
}

/// Keccak-256 of `msg` (bits, a whole number of bytes, low bit first in each byte): 256 bits, the digest's
/// bytes in order, low bit first.
pub fn keccak256(c: &mut Ckt, msg: &[Wire]) -> Vec<Wire> {
    let blocks = pad(msg);
    let mut stats = Stats::default();
    sponge(c, &blocks, &[blocks.len()], &mut stats).pop().unwrap()
}

/// The bits of `bytes`, low bit first in each byte.
pub fn bits_of(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .collect()
}

/// A deterministic stream of bytes from a seed (splitmix64).
pub fn seeded_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..n)
        .map(|_| {
            s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

/// `keccak256` of a private 1,024-byte message.
pub struct Keccak256OneKiB;

pub const ONE_KIB: usize = 1024;

impl Workload for Keccak256OneKiB {
    const NAME: &'static str = "keccak256-1KiB";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        let msg = c.inputs(8 * ONE_KIB);
        let mut public = keccak256(c, &msg);
        public.resize(PUBLIC_BITS, Wire::ZERO);
        public
    }

    fn instance(seed: u64) -> Instance {
        use sha3::Digest;
        let msg = seeded_bytes(seed, ONE_KIB);
        let digest = sha3::Keccak256::digest(&msg);
        let mut statement = [0u8; 64];
        statement[..32].copy_from_slice(&digest);
        Instance {
            inputs: bits_of(&msg),
            statement,
        }
    }

    fn invalid_instance(_seed: u64) -> Option<Instance> {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Circuit, PUBLIC_ROWS, Src, build, read_statement};

    /// The native round, for the exhaustive test.
    pub fn native_round(a: &mut [u64; 25], rc: u64) {
        let mut cc = [0u64; 5];
        for x in 0..5 {
            cc[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = cc[(x + 4) % 5] ^ cc[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x][y] as u32);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }

    /// The native round on 64 states at once, bit `i` of the state in word `i` (one state a bit position).
    fn native_round_sliced(a: &[u64], rc: u64) -> Vec<u64> {
        let mut cc = vec![0u64; 320];
        for x in 0..5 {
            for z in 0..64 {
                cc[64 * x + z] = (0..5).fold(0, |acc, y| acc ^ a[at(x, y, z)]);
            }
        }
        let mut t = a.to_vec();
        for x in 0..5 {
            for z in 0..64 {
                let d = cc[64 * ((x + 4) % 5) + z] ^ cc[64 * ((x + 1) % 5) + (z + 63) % 64];
                for y in 0..5 {
                    t[at(x, y, z)] ^= d;
                }
            }
        }
        let mut b = vec![0u64; STATE];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    b[pi(x, y, z)] = t[at(x, y, z)];
                }
            }
        }
        let mut out = vec![0u64; STATE];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    out[at(x, y, z)] = b[at(x, y, z)] ^ (!b[at((x + 1) % 5, y, z)] & b[at((x + 2) % 5, y, z)]);
                }
            }
        }
        for z in 0..64 {
            if (rc >> z) & 1 == 1 {
                out[z] = !out[z];
            }
        }
        out
    }

    #[test]
    fn sliced_round_is_the_native_round() {
        let states: Vec<[u64; 25]> = (0..64)
            .map(|k| {
                let b = seeded_bytes(k + 99, 200);
                std::array::from_fn(|l| u64::from_le_bytes(b[8 * l..8 * l + 8].try_into().unwrap()))
            })
            .collect();
        let sliced: Vec<u64> = (0..STATE)
            .map(|i| (0..64).map(|k| ((states[k][i / 64] >> (i % 64)) & 1) << k).sum())
            .collect();
        let got = native_round_sliced(&sliced, RC[5]);
        for (k, s) in states.iter().enumerate() {
            let mut e = *s;
            native_round(&mut e, RC[5]);
            for i in 0..STATE {
                assert_eq!((got[i] >> k) & 1, (e[i / 64] >> (i % 64)) & 1);
            }
        }
    }

    fn bits_of_lanes(a: &[u64; 25]) -> Vec<bool> {
        (0..STATE).map(|i| (a[i / 64] >> (i % 64)) & 1 == 1).collect()
    }

    /// Evaluate a finished circuit on 64 input vectors at once: each row's (bits, carries).
    pub fn eval64(circuit: &Circuit, inputs: &[u64]) -> Vec<(u64, u64)> {
        let rows = circuit.rows();
        let mut v = vec![(0u64, 0u64); rows.len()];
        let mut next = 0;
        let read = |v: &[(u64, u64)], s: Src| match s {
            Src::Zero => (0, 0),
            Src::One => (u64::MAX, 0),
            Src::Row(r) => v[r as usize],
        };
        for r in PUBLIC_ROWS..rows.len() {
            let row = rows[r];
            if row.x == Src::Row(r as u32) {
                v[r] = (inputs[next], 0);
                next += 1;
                continue;
            }
            let (x, y, k) = (read(&v, row.x).0, read(&v, row.y).0, read(&v, row.c).1);
            v[r] = (x ^ y ^ k, (x & y) | (k & (x ^ y)));
        }
        assert_eq!(next, inputs.len());
        v
    }

    pub fn wire64(w: Wire, v: &[(u64, u64)]) -> u64 {
        let m = if w.neg { u64::MAX } else { 0 };
        m ^ match w.kind {
            Kind::Const(b) => {
                if b {
                    u64::MAX
                } else {
                    0
                }
            }
            Kind::Sum(r) => v[r as usize].0,
            Kind::Carry(r) => v[r as usize].1,
        }
    }

    /// One round from 1,600 free bits, with the next column parities, every output reduced.
    fn one_round_circuit(rc: u64) -> (Circuit, Vec<Wire>, Vec<Wire>, usize) {
        let mut c = Ckt::new();
        let ins = c.inputs(STATE);
        let before = c.rows();
        let mut stats = Stats::default();
        let mut st = round(&mut c, State::from_wires(&ins), rc, None, true, false, &mut stats);
        let outs: Vec<Wire> = (0..STATE).map(|i| st.bit(&mut c, i)).collect();
        let par = st.parity.clone().unwrap();
        let rows = c.rows() - before;
        let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
        (circuit, outs, par, rows)
    }

    #[test]
    fn native_round_is_keccak_f() {
        let mut a: [u64; 25] = std::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.wrapping_mul(i as u64 + 7));
        let mut b = a;
        for &rc in &RC {
            native_round(&mut a, rc);
        }
        keccak::Keccak::new().with_f1600(|f| f(&mut b));
        assert_eq!(a, b);
    }

    /// A round has degree two: the AND/OR rows read only XORs of the inputs, and every other carry read is one
    /// of theirs, so agreeing with the native round on every input of weight at most two is agreeing
    /// everywhere. Also checks the column parities the round chains for the next one.
    #[test]
    fn one_round_on_every_input_of_weight_at_most_two() {
        let rc = RC[3];
        let (circuit, outs, par, rows) = one_round_circuit(rc);
        println!("one round from free bits: {rows} rows");
        // An upper bound on each row's degree in the inputs, bit and carry.
        let all = circuit.rows();
        let mut deg = vec![(0usize, 0usize); all.len()];
        for r in PUBLIC_ROWS..all.len() {
            let row = all[r];
            if row.x == Src::Row(r as u32) {
                deg[r] = (1, 0);
                continue;
            }
            let d = |s: Src, carry: bool| match s {
                Src::Row(f) => {
                    if carry {
                        deg[f as usize].1
                    } else {
                        deg[f as usize].0
                    }
                }
                _ => 0,
            };
            let (dx, dy, dc) = (d(row.x, false), d(row.y, false), d(row.c, true));
            deg[r] = (dx.max(dy).max(dc), (dx + dy).max(dc + dx.max(dy)));
        }
        let wdeg = |w: Wire| match w.kind {
            Kind::Const(_) => 0,
            Kind::Sum(r) => deg[r as usize].0,
            Kind::Carry(r) => deg[r as usize].1,
        };
        assert!(
            outs.iter().chain(&par).all(|&w| wdeg(w) <= 2),
            "a round of degree above two"
        );
        let mut vectors: Vec<Vec<usize>> = vec![vec![]];
        vectors.extend((0..STATE).map(|i| vec![i]));
        for i in 0..STATE {
            for j in i + 1..STATE {
                vectors.push(vec![i, j]);
            }
        }
        for chunk in vectors.chunks(64) {
            let mut inputs = vec![0u64; STATE];
            for (k, v) in chunk.iter().enumerate() {
                for &i in v {
                    inputs[i] |= 1 << k;
                }
            }
            let v = eval64(&circuit, &inputs);
            let expect = native_round_sliced(&inputs, rc);
            let mask = if chunk.len() == 64 {
                u64::MAX
            } else {
                (1u64 << chunk.len()) - 1
            };
            for i in 0..STATE {
                assert_eq!(
                    (wire64(outs[i], &v) ^ expect[i]) & mask,
                    0,
                    "bit {i} near {:?}",
                    chunk[0]
                );
            }
            for x in 0..5 {
                for z in 0..64 {
                    let cx = (0..5).fold(0, |acc, y| acc ^ expect[at(x, y, z)]);
                    assert_eq!(
                        (wire64(par[64 * x + z], &v) ^ cx) & mask,
                        0,
                        "parity near {:?}",
                        chunk[0]
                    );
                }
            }
        }
    }

    #[test]
    fn keccak_f_on_random_states() {
        let mut c = Ckt::new();
        let ins = c.inputs(STATE);
        let before = c.rows();
        let outs = keccak_f(&mut c, &ins);
        println!("keccak-f[1600]: {} rows", c.rows() - before);
        let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
        let states: Vec<[u64; 25]> = (0..64)
            .map(|k| {
                let b = seeded_bytes(k, 200);
                std::array::from_fn(|l| u64::from_le_bytes(b[8 * l..8 * l + 8].try_into().unwrap()))
            })
            .collect();
        let inputs: Vec<u64> = (0..STATE)
            .map(|i| (0..64).map(|k| ((states[k][i / 64] >> (i % 64)) & 1) << k).sum())
            .collect();
        let v = eval64(&circuit, &inputs);
        for (k, s) in states.iter().enumerate() {
            let mut e = *s;
            keccak::Keccak::new().with_f1600(|f| f(&mut e));
            let expect = bits_of_lanes(&e);
            for i in 0..STATE {
                assert_eq!((wire64(outs[i], &v) >> k) & 1 == 1, expect[i]);
            }
        }
    }

    /// Keccak-256 of every length around the block boundaries.
    #[test]
    fn keccak256_of_several_lengths() {
        use sha3::Digest;
        for len in [0usize, 1, 31, 135, 136, 137, 271, 272, 300] {
            let mut c = Ckt::new();
            let msg = c.inputs(8 * len);
            let d = keccak256(&mut c, &msg);
            let (circuit, _) = c.finish(&vec![Wire::ZERO; PUBLIC_BITS]);
            for seed in 0..3u64 {
                let m = seeded_bytes(seed * 1000 + len as u64, len);
                let v = circuit.values(&bits_of(&m));
                let got: Vec<u8> = (0..32)
                    .map(|i| (0..8).map(|j| (d[8 * i + j].value(&v) as u8) << j).sum())
                    .collect();
                assert_eq!(got, sha3::Keccak256::digest(&m).to_vec(), "length {len}");
            }
        }
    }

    #[test]
    fn workload_one_kib() {
        let (circuit, srcs, used) = build::<Keccak256OneKiB>();
        circuit.check_wired().unwrap();
        for seed in 0..3 {
            let inst = Keccak256OneKiB::instance(seed);
            let v = circuit.values(&inst.inputs);
            assert_eq!(read_statement(&v, &srcs), inst.statement);
            // One flipped message bit changes the digest.
            let mut bad = inst.inputs.clone();
            let flip = (seed as usize * 977) % bad.len();
            bad[flip] ^= true;
            assert_ne!(read_statement(&circuit.values(&bad), &srcs), inst.statement);
        }
        println!("{}: {used} rows, log_rows {}", Keccak256OneKiB::NAME, circuit.log_rows);
    }

    #[test]
    fn report_counts() {
        let mut c = Ckt::new();
        let msg = c.inputs(8 * ONE_KIB);
        let r0 = c.rows();
        let blocks = pad(&msg);
        let mut stats = Stats::default();
        let d = sponge(&mut c, &blocks, &[blocks.len()], &mut stats).pop().unwrap();
        let hash_rows = c.rows() - r0;
        let mut public = d;
        public.resize(PUBLIC_BITS, Wire::ZERO);
        let n_inputs = c.n_inputs();
        let log = c.log_rows_for(&public);
        // One full permutation in the middle of a sponge, alone.
        let mut c2 = Ckt::new();
        let ins = c2.inputs(STATE);
        let mut st = State::from_wires(&ins);
        let mut s2 = Stats::default();
        st = round(&mut c2, st, RC[0], None, true, true, &mut s2);
        let r1 = c2.rows();
        let mut s3 = Stats::default();
        for &rc in &RC[1..] {
            st = round(&mut c2, st, rc, None, true, false, &mut s3);
        }
        let per_round = (c2.rows() - r1) as f64 / 23.0;
        println!(
            "keccak256 of 1 KiB: {} blocks, {hash_rows} rows for hashing, {} rows total (with the 512 public rows), \
             {n_inputs} inputs, closes on 2^{log}",
            blocks.len(),
            c.rows(),
        );
        println!(
            "  per steady round: {per_round:.1} rows (= 3 x 1600 + 320 + {:.1} D columns needing both polarities \
             + {:.1} extra three-term chi bits a round)",
            s3.d_both as f64 / 23.0,
            s3.extra_three as f64 / 23.0
        );
        println!("  sponge stats: {stats:?}");
    }
}
