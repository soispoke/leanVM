//! The circuit format of `flock::quotient` (rows of full adders, a wiring, 512 public bits) proved over packed
//! bits: the same [`Circuit`], the same Boolean statement, a different proof system.
//!
//! A row reads the sum bits `x`, `y` of two sources and the carry `c` of a third, and outputs `s = x + y + c` and
//! `k = maj(x, y, c)`. The witness is four bit columns `x, y, c, k`, committed packed (four bits a row); `s` is
//! linear in them and never committed. The proof is
//!
//! 1. **Gate**: `k = (x + c)(y + c) + c` on every row, flock's packed zerocheck `a b + d = 0` on `a = x + c`,
//!    `b = y + c`, `d = k + c`. It leaves the three claims at one point, which the prover's bit slices of the four
//!    columns there must reproduce.
//! 2. **Copy**: every row has five cells, `X, Y, C` (the bits read) and `S, K` (the bits written). The wiring is a
//!    permutation `sigma` of the `5n` cells whose cycles are a source and the cells reading it: `S_j` and the `X`,
//!    `Y` cells reading row `j`, `K_j` and the `C` cells reading it, one cycle of the cells reading zero (an `X` or
//!    `Y` reading the constant zero, a `C` reading either constant, whose carry is zero) and one of those reading
//!    one. `prod (alpha + id + beta v) = prod (alpha + sigma + beta v)` over the cells, two grand products sharing
//!    one root (`leanvm_core::gkr`), makes the value constant on every cycle. `sigma` is the preprocessed index,
//!    committed once as bits.
//! 3. **Public**: the `X` and `Y` cells of the 512 public rows equal the statement's pattern (its 512 bits, then
//!    the anchors: a one at row 256, zeros after), one multilinear claim at a random point of those rows. The
//!    anchors are on the constant cycles, so they pin every constant read.
//! 4. **Openings**: every claim is a bit-slice claim on one of the two packed commitments, discharged by ring
//!    switching and one WHIR run per commitment (`pcs::stack_open`).
//!
//! The verifier reads the log row count, the index root and the statement: it never walks the circuit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use fiat_shamir::merkle::Hash;
use fiat_shamir::transcript::{Challenger, Proof, ProverState, Receiver, Transmitter, VerifierState};
use flock::quotient::circuit::{Circuit, PUBLIC_ROWS, Src, WORD_BITS};
use flock::zerocheck::{self, K_SKIP, PaddingSpec};
use leanvm_core::gkr::{self, RootShape};
use pcs::ring_switch::fold_1b_rows;
use pcs::stack_open::{
    RingSwitchClaim, RingSwitchOpen, RingSwitchVerify, RingSwitchVerifyClaim, open_batch_mixed_whir_stacked,
    verify_opening_batch_mixed_whir_stacked,
};
use pcs::whir::{self, ProverConfig, ProverData};
use primitives::field::{F64, F192};
use primitives::multilinear::{eq_table, lagrange_weights_naive};

/// The zerocheck wants `K_SKIP + 7` row variables; a smaller circuit is padded with idle rows.
pub const MIN_LOG_ROWS: usize = 13;
/// WHIR's smallest commitment, in words.
const MIN_LOG_WORDS: usize = 15;
/// The Merkle leaf width, which is WHIR's first fold.
const LOG_BATCH: usize = whir::INITIAL_FOLDING_FACTOR;
/// The rate both commitments are encoded at (leanVM's benchmarks use the same).
pub const LOG_INV_RATE: usize = 1;
/// Cells a row: `X, Y, C, S, K`.
pub const ROLES: usize = 5;
/// Committed bit columns: `x, y, c, k`.
pub const COLUMNS: usize = 4;
/// The public rows span this many row variables.
const PUBLIC_LOG: usize = 9;
const _: () = assert!(1 << PUBLIC_LOG == PUBLIC_ROWS);
const WORD: usize = 64;

/// Where everything lives, a function of the log row count alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The circuit's own `log_rows`.
    pub circuit_log_rows: usize,
    /// The rows proved, `2^log_rows`: the circuit's, idle rows padding it to [`MIN_LOG_ROWS`].
    pub log_rows: usize,
    /// Bits of a cell's identity: `5 n` cells, numbered `r + n role`.
    pub id_bits: usize,
    /// `log_2` of the index words a row takes: `5 id_bits` slots of the permutation's bits.
    pub log_index_words_per_row: usize,
    /// `log_2` of the witness commitment's words: four columns of `n / 64` words, zero past them.
    pub witness_log_words: usize,
    /// `log_2` of the index commitment's words.
    pub index_log_words: usize,
}

impl Shape {
    pub fn new(circuit_log_rows: usize) -> Self {
        let log_rows = circuit_log_rows.max(MIN_LOG_ROWS);
        let id_bits = log_rows + 3;
        let words_per_row = (ROLES * id_bits).div_ceil(WORD).next_power_of_two();
        let log_index_words_per_row = words_per_row.trailing_zeros() as usize;
        Self {
            circuit_log_rows,
            log_rows,
            id_bits,
            log_index_words_per_row,
            witness_log_words: (log_rows + 2 - 6).max(MIN_LOG_WORDS),
            index_log_words: (log_rows + log_index_words_per_row).max(MIN_LOG_WORDS),
        }
    }

    pub fn rows(&self) -> usize {
        1 << self.log_rows
    }

    /// Words of one witness column.
    fn column_words(&self) -> usize {
        self.rows() / WORD
    }

    /// The index slot of bit `b` of the successor of a row's cell of `role`.
    fn slot(&self, role: usize, b: usize) -> usize {
        role * self.id_bits + b
    }

    /// Committed bits a row, witness and index.
    pub fn committed_bits_per_row(&self) -> (usize, usize) {
        (COLUMNS, WORD << self.log_index_words_per_row)
    }
}

/// A cell's identity as a field element: its number's bits as the coordinates of `c0`, a linear map.
#[inline]
fn id(k: u64) -> F192 {
    F192::new(k, 0, 0)
}

/// The wiring as a permutation of the `5 n` cells, cell `r + n role`.
pub fn permutation(circuit: &Circuit, shape: &Shape) -> Vec<u32> {
    let n = shape.rows();
    let rows = circuit.rows();
    const NONE: u32 = u32::MAX;
    // Slot 0: the cells reading zero; 1: reading one; 2 + 2j: S_j and its readers; 3 + 2j: K_j and its readers.
    let slots = 2 + 2 * n;
    let (mut first, mut last) = (vec![NONE; slots], vec![NONE; slots]);
    let mut sigma: Vec<u32> = (0..(ROLES * n) as u32).collect();
    let mut join = |at: usize, cell: u32, sigma: &mut Vec<u32>| {
        if first[at] == NONE {
            first[at] = cell;
        } else {
            sigma[last[at] as usize] = cell;
        }
        last[at] = cell;
        sigma[cell as usize] = first[at];
    };
    let cell = |r: usize, role: usize| (r + n * role) as u32;
    for r in 0..n {
        join(2 + 2 * r, cell(r, 3), &mut sigma);
        join(3 + 2 * r, cell(r, 4), &mut sigma);
    }
    for r in 0..n {
        // Idle padding rows read three zeros.
        let row = rows.get(r).map_or([Src::Zero; 3], |row| [row.x, row.y, row.c]);
        for (role, src) in row.into_iter().enumerate() {
            let at = match (role, src) {
                (_, Src::Zero) | (2, Src::One) => 0,
                (_, Src::One) => 1,
                (2, Src::Row(j)) => 3 + 2 * j as usize,
                (_, Src::Row(j)) => 2 + 2 * j as usize,
            };
            join(at, cell(r, role), &mut sigma);
        }
    }
    sigma
}

/// The committed index: the permutation's bits, `5 id_bits` slots a row over `2^log_index_words_per_row` words,
/// word `r + n h` holding slots `64 h ..`.
pub struct Index {
    pub shape: Shape,
    pub root: Hash,
    sigma: Vec<u32>,
    stack: Vec<F64>,
    data: ProverData,
}

impl Index {
    /// The index of a circuit meeting the format's hypotheses (`Circuit::check_wired`), which is what puts the
    /// constants' anchors on their cycles.
    pub fn new(circuit: &Circuit) -> Self {
        circuit.check_wired().expect("a wired circuit");
        let shape = Shape::new(circuit.log_rows);
        Self::from_permutation(shape, permutation(circuit, &shape))
    }

    /// The index of any permutation of the cells (a test's tampered wiring, say).
    pub fn from_permutation(shape: Shape, sigma: Vec<u32>) -> Self {
        let n = shape.rows();
        assert_eq!(sigma.len(), ROLES * n);
        let mut stack = vec![F64::ZERO; 1 << shape.index_log_words];
        let per_row = 1usize << shape.log_index_words_per_row;
        {
            let (body, _) = stack.split_at_mut(per_row * n);
            // Half `h` of every row is the contiguous block `[h n, (h + 1) n)`.
            for (h, half) in body.chunks_mut(n).enumerate() {
                let fill = |r: usize| {
                    let mut word = 0u64;
                    for bit in 0..WORD {
                        let slot = WORD * h + bit;
                        if slot >= ROLES * shape.id_bits {
                            break;
                        }
                        let (role, b) = (slot / shape.id_bits, slot % shape.id_bits);
                        word |= ((sigma[r + n * role] as u64 >> b) & 1) << bit;
                    }
                    F64(word)
                };
                let words = parallel::map_collect(n, fill);
                half.copy_from_slice(&words);
            }
        }
        let (commitment, data) = whir::commit(&stack, shape.index_log_words, LOG_BATCH, LOG_INV_RATE);
        Self {
            shape,
            root: commitment.root,
            sigma,
            stack,
            data,
        }
    }
}

/// The four witness columns, `n / 64` words each, row `r` at bit `r % 64` of word `r / 64`.
#[derive(Clone)]
pub struct Witness {
    pub columns: [Vec<u64>; COLUMNS],
}

impl Witness {
    /// From the circuit's free inputs: `x, y` the sum bits read, `c` the carry read, `k` the row's carry.
    pub fn new(circuit: &Circuit, shape: &Shape, inputs: &[bool]) -> Self {
        let v = circuit.values(inputs);
        let rows = circuit.rows();
        let read = |src: Src| match src {
            Src::Zero => 0u8,
            Src::One => 1,
            Src::Row(j) => v[j as usize],
        };
        let column = |col: usize| {
            parallel::map_collect(shape.column_words(), |w| {
                let mut word = 0u64;
                for i in 0..WORD {
                    let r = WORD * w + i;
                    let Some(row) = rows.get(r) else { break };
                    let bit = match col {
                        0 => read(row.x) & 1,
                        1 => read(row.y) & 1,
                        2 => read(row.c) >> 1,
                        _ => v[r] >> 1,
                    };
                    word |= (bit as u64) << i;
                }
                word
            })
        };
        Self {
            columns: std::array::from_fn(column),
        }
    }

    pub fn bit(&self, col: usize, r: usize) -> bool {
        (self.columns[col][r / WORD] >> (r % WORD)) & 1 == 1
    }

    pub fn flip(&mut self, col: usize, r: usize) {
        self.columns[col][r / WORD] ^= 1 << (r % WORD);
    }

    /// The bit of a row's cell of `role`.
    fn cell(&self, role: usize, r: usize) -> bool {
        match role {
            3 => self.bit(0, r) ^ self.bit(1, r) ^ self.bit(2, r),
            4 => self.bit(3, r),
            _ => self.bit(role, r),
        }
    }

    /// The committed stack: the four columns one after another, zero past them.
    fn stack(&self, shape: &Shape) -> Vec<F64> {
        let mut stack = vec![F64::ZERO; 1 << shape.witness_log_words];
        for (col, words) in self.columns.iter().enumerate() {
            let at = col * shape.column_words();
            for (dst, &w) in stack[at..at + words.len()].iter_mut().zip(words) {
                *dst = F64(w);
            }
        }
        stack
    }
}

/// The statement's pattern on the public rows' `X` and `Y` cells: word `J` of 128 bits is two bits a row over 64
/// rows; words 0 to 3 are the statement as `quotient::circuit::public_words` reads it, word 4 a one then zeros
/// (the one's anchor), the rest zeros (the zero's anchor among them).
pub fn public_pattern(statement: &[u8; 64]) -> [Vec<bool>; 2] {
    let bit = |word: usize, j: usize| match word {
        0..4 => {
            let i = 256 * (word / 2) + 8 * (16 * (word % 2) + 15 - j / 8) + j % 8;
            (statement[i / 8] >> (i % 8)) & 1 == 1
        }
        4 => j == 0,
        _ => false,
    };
    std::array::from_fn(|role| {
        (0..PUBLIC_ROWS)
            .map(|r| {
                let (word, pair) = (r / (WORD_BITS / 2), r % (WORD_BITS / 2));
                bit(word, 2 * pair + role)
            })
            .collect()
    })
}

/// `sum_r eq(t, r) bits[r]` over the public rows.
fn public_eval(bits: &[bool], t: &[F192]) -> F192 {
    eq_table(t)
        .iter()
        .zip(bits)
        .filter(|(_, b)| **b)
        .fold(F192::ZERO, |acc, (e, _)| acc + *e)
}

/// `sum_j eq(tau, j) slices[j]`, one combined family of 64 slices.
fn combine(slices: &[Vec<F192>], tau: &[F192]) -> Vec<F192> {
    let eq = eq_table(tau);
    assert!(slices.len() <= eq.len());
    (0..WORD)
        .map(|i| slices.iter().zip(&eq).fold(F192::ZERO, |acc, (s, &e)| acc + e * s[i]))
        .collect()
}

/// A column's value at a row point from its slices at the point's word coordinates.
fn at(slices: &[F192], low: &[F192]) -> F192 {
    debug_assert_eq!(low.len(), 6);
    eq_table(low)
        .iter()
        .zip(slices)
        .fold(F192::ZERO, |acc, (&e, &s)| acc + e * s)
}

/// `head ++ tail ++ 0...`, `len` coordinates.
fn suffix(head: &[F192], tail: &[F192], len: usize) -> Vec<F192> {
    let mut point: Vec<F192> = head.iter().chain(tail).copied().collect();
    assert!(point.len() <= len);
    point.resize(len, F192::ZERO);
    point
}

/// The 64 bit slices of each block of `words` at `point`, a block being `2^|point|` words.
fn slices(blocks: &[&[u64]], point: &[F192]) -> Vec<Vec<F192>> {
    let eq = eq_table(point);
    blocks
        .iter()
        .map(|block| {
            let words: Vec<F64> = block.iter().map(|&w| F64(w)).collect();
            fold_1b_rows(&words, &eq)
        })
        .collect()
}

fn index_slices(index: &Index, rho: &[F192]) -> Vec<Vec<F192>> {
    let n = index.shape.rows();
    let eq = eq_table(rho);
    (0..1usize << index.shape.log_index_words_per_row)
        .map(|h| fold_1b_rows(&index.stack[h * n..(h + 1) * n], &eq))
        .collect()
}

fn whir_config(log_words: usize) -> Arc<ProverConfig> {
    type Cache = Mutex<HashMap<usize, Arc<ProverConfig>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let mut map = CACHE.get_or_init(Default::default).lock().unwrap();
    Arc::clone(
        map.entry(log_words)
            .or_insert_with(|| Arc::new(whir::config_for_rate(log_words, LOG_INV_RATE).expect("a WHIR configuration"))),
    )
}

/// The transcript's seed: the index root, the size and the statement.
fn label(root: &Hash, shape: &Shape, statement: &[u8; 64]) -> Vec<u8> {
    let mut label = b"packed-format/v1".to_vec();
    label.extend_from_slice(root);
    label.push(shape.circuit_log_rows as u8);
    label.extend_from_slice(statement);
    label
}

/// The gate's three zerocheck columns, as bytes: `x + c`, `y + c`, `k + c`.
fn gate_columns(w: &Witness) -> [Vec<u8>; 3] {
    let [x, y, c, k] = &w.columns;
    let col = |a: &[u64]| -> Vec<u8> { a.iter().zip(c).flat_map(|(&a, &c)| (a ^ c).to_le_bytes()).collect() };
    [col(x), col(y), col(k)]
}

/// The two leaf columns of the permutation argument.
fn leaves(index: &Index, w: &Witness, alpha: F192, beta: F192) -> [Vec<F192>; 2] {
    let n = index.shape.rows();
    let leaf = |k: usize, with: u64| {
        let (r, role) = (k % n, k / n);
        alpha + id(with) + if w.cell(role, r) { beta } else { F192::ZERO }
    };
    [
        primitives::par_collect(ROLES * n, |k| leaf(k, k as u64)),
        primitives::par_collect(ROLES * n, |k| leaf(k, index.sigma[k] as u64)),
    ]
}

/// Where the prover's time went, in microseconds.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub commit_us: u64,
    pub zerocheck_us: u64,
    pub copy_us: u64,
    /// Of `copy_us`: the two leaf columns, the grand products, the slices of both commitments at the point.
    pub leaves_us: u64,
    pub gkr_us: u64,
    pub copy_slices_us: u64,
    pub public_us: u64,
    pub open_witness_us: u64,
    pub open_index_us: u64,
}

impl Timings {
    pub fn total_us(&self) -> u64 {
        self.commit_us + self.zerocheck_us + self.copy_us + self.public_us + self.open_witness_us + self.open_index_us
    }
}

fn us(t: Instant) -> u64 {
    t.elapsed().as_micros() as u64
}

/// Prove that `w` satisfies the circuit `index` commits to and that its public cells hold `statement`.
pub fn prove(index: &Index, statement: &[u8; 64], w: &Witness) -> (Proof, Timings) {
    let shape = index.shape;
    let (l, nw) = (shape.log_rows, shape.column_words());
    assert!(w.columns.iter().all(|c| c.len() == nw));
    let mut timings = Timings::default();
    let mut ps = ProverState::from_label(&label(&index.root, &shape, statement));

    let t = Instant::now();
    let stack = tracing::info_span!("Pack").in_scope(|| w.stack(&shape));
    let (commitment, data) = tracing::info_span!("Commit")
        .in_scope(|| whir::commit(&stack, shape.witness_log_words, LOG_BATCH, LOG_INV_RATE));
    ps.add_root(&commitment.root);
    timings.commit_us = us(t);

    let cols: [&[u64]; COLUMNS] = std::array::from_fn(|i| w.columns[i].as_slice());

    // 1. The gate.
    let t = Instant::now();
    let (claim_gate, s_gate) = tracing::info_span!("Gate").in_scope(|| {
        let [a, b, d] = gate_columns(w);
        let zc = zerocheck::prove_packed_padded(&a, &b, &d, l, &PaddingSpec::dense(l), &mut ps);
        let s = slices(&cols, &zc.mlv_challenges);
        s.iter().for_each(|s| ps.add_scalars(s));
        let tau = ps.sample_vec(2);
        (
            suffix(&zc.mlv_challenges, &tau, shape.witness_log_words),
            combine(&s, &tau),
        )
    });
    timings.zerocheck_us = us(t);

    // 2. The copy constraints.
    let t = Instant::now();
    let (claim_copy, s_copy, claim_index, s_index) = tracing::info_span!("Copy").in_scope(|| {
        let (alpha, beta) = (ps.sample(), ps.sample());
        let t = Instant::now();
        let [ids, sigmas] = tracing::info_span!("Leaves").in_scope(|| leaves(index, w, alpha, beta));
        timings.leaves_us = us(t);
        let t = Instant::now();
        let product = tracing::info_span!("GKR")
            .in_scope(|| gkr::prove_product_triple([ids, sigmas, vec![F192::ONE]], &mut ps, RootShape::Distinct));
        timings.gkr_us = us(t);
        let t = Instant::now();
        let rho = &product.point[..l];
        let s = slices(&cols, &rho[6..]);
        s.iter().for_each(|s| ps.add_scalars(s));
        let si = index_slices(index, rho);
        si.iter().for_each(|s| ps.add_scalars(s));
        let tau = ps.sample_vec(2);
        let tau_index = ps.sample_vec(shape.log_index_words_per_row);
        timings.copy_slices_us = us(t);
        (
            suffix(&rho[6..], &tau, shape.witness_log_words),
            combine(&s, &tau),
            suffix(rho, &tau_index, shape.index_log_words),
            combine(&si, &tau_index),
        )
    });
    timings.copy_us = us(t);

    // 3. The public cells.
    let t = Instant::now();
    let (claim_public, s_public) = {
        let t = ps.sample_vec(PUBLIC_LOG);
        let high = suffix(&t[6..], &[], l - 6);
        let s = slices(&cols[..2], &high);
        s.iter().for_each(|s| ps.add_scalars(s));
        let tau = [ps.sample(), F192::ZERO];
        (suffix(&high, &tau, shape.witness_log_words), combine(&s, &tau))
    };
    timings.public_us = us(t);

    // 4. The openings.
    let t = Instant::now();
    let claims = [(claim_gate, s_gate), (claim_copy, s_copy), (claim_public, s_public)]
        .into_iter()
        .map(|(suffix_point, s)| RingSwitchClaim {
            suffix_point,
            s_hat_v: Some(s),
        })
        .collect();
    tracing::info_span!("Open witness").in_scope(|| {
        open_batch_mixed_whir_stacked(
            &mut ps,
            shape.witness_log_words,
            &stack,
            &data,
            &whir_config(shape.witness_log_words),
            &[],
            &RingSwitchOpen {
                offset: 0,
                qflock_vars: shape.witness_log_words,
                claims,
            },
        )
    });
    timings.open_witness_us = us(t);
    let t = Instant::now();
    tracing::info_span!("Open index").in_scope(|| {
        open_batch_mixed_whir_stacked(
            &mut ps,
            shape.index_log_words,
            &index.stack,
            &index.data,
            &whir_config(shape.index_log_words),
            &[],
            &RingSwitchOpen {
                offset: 0,
                qflock_vars: shape.index_log_words,
                claims: vec![RingSwitchClaim {
                    suffix_point: claim_index,
                    s_hat_v: Some(s_index),
                }],
            },
        )
    });
    timings.open_index_us = us(t);
    (ps.into_proof(), timings)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Transcript(fiat_shamir::transcript::Error),
    Zerocheck(zerocheck::VerifyError),
    Gate,
    Product(gkr::GkrError),
    Copy,
    Public,
    OpenWitness(whir::VerifyError),
    OpenIndex(whir::VerifyError),
}

impl From<fiat_shamir::transcript::Error> for VerifyError {
    fn from(e: fiat_shamir::transcript::Error) -> Self {
        VerifyError::Transcript(e)
    }
}

fn read_slices(vs: &mut VerifierState<'_>, count: usize) -> Result<Vec<Vec<F192>>, VerifyError> {
    (0..count).map(|_| Ok(vs.next_scalars(WORD)?)).collect()
}

/// Accept iff the proof shows the statement is the output of the circuit of log size `log_rows` whose index root
/// is `root`, on some inputs. Reads nothing of the circuit but its root.
pub fn verify(log_rows: usize, root: &Hash, statement: &[u8; 64], proof: &Proof) -> Result<(), VerifyError> {
    let shape = Shape::new(log_rows);
    let (l, n) = (shape.log_rows, shape.rows());
    let mut vs = VerifierState::from_label(&label(root, &shape, statement), proof);
    let witness_root = vs.next_root()?;

    // 1. The gate: the zerocheck's three claims are the slices' at its point.
    let zc = zerocheck::verify(l, &mut vs).map_err(VerifyError::Zerocheck)?;
    let s = read_slices(&mut vs, COLUMNS)?;
    let lagrange = lagrange_weights_naive(K_SKIP, zc.z);
    let quirky = |a: &[F192], b: &[F192]| -> F192 {
        lagrange
            .iter()
            .zip(a.iter().zip(b))
            .fold(F192::ZERO, |acc, (&w, (&a, &b))| acc + w * (a + b))
    };
    if quirky(&s[0], &s[2]) != zc.a_eval || quirky(&s[1], &s[2]) != zc.b_eval || quirky(&s[3], &s[2]) != zc.c_eval {
        return Err(VerifyError::Gate);
    }
    let tau = vs.sample_vec(2);
    let gate = (
        suffix(&zc.mlv_challenges, &tau, shape.witness_log_words),
        combine(&s, &tau),
    );

    // 2. The copy constraints: both leaf columns at the product's point, from the slices.
    let (alpha, beta) = (vs.sample(), vs.sample());
    // Three roots ride the stream, so a prover holding an unbalanced pair can still be refused rather than
    // stopped: the two products must agree and the padding tree is all ones.
    let product = gkr::verify_product_triple(l + 3, &mut vs, RootShape::Distinct).map_err(VerifyError::Product)?;
    if product.roots[0] != product.roots[1] || product.roots[2] != F192::ONE {
        return Err(VerifyError::Copy);
    }
    let (rho, tau_role) = product.point.split_at(l);
    let s = read_slices(&mut vs, COLUMNS)?;
    let si = read_slices(&mut vs, 1 << shape.log_index_words_per_row)?;
    let [x, y, c, k] = std::array::from_fn(|col| at(&s[col], &rho[..6]));
    let values = [x, y, c, x + y + c, k];
    let rho_id = rho
        .iter()
        .enumerate()
        .fold(F192::ZERO, |acc, (i, &z)| acc + z * id(1 << i));
    let sigma = |role: usize| -> F192 {
        (0..shape.id_bits).fold(F192::ZERO, |acc, b| {
            let slot = shape.slot(role, b);
            acc + id(1 << b) * si[slot / WORD][slot % WORD]
        })
    };
    let eq_role = eq_table(tau_role);
    let (mut v_id, mut v_sigma) = (F192::ZERO, F192::ZERO);
    for (role, &e) in eq_role.iter().enumerate() {
        if role < ROLES {
            v_id += e * (alpha + rho_id + id((role * n) as u64) + beta * values[role]);
            v_sigma += e * (alpha + sigma(role) + beta * values[role]);
        } else {
            v_id += e;
            v_sigma += e;
        }
    }
    if product.values != [v_id, v_sigma, F192::ONE] {
        return Err(VerifyError::Copy);
    }
    let tau = vs.sample_vec(2);
    let tau_index = vs.sample_vec(shape.log_index_words_per_row);
    let copy = (suffix(&rho[6..], &tau, shape.witness_log_words), combine(&s, &tau));
    let index_claim = (suffix(rho, &tau_index, shape.index_log_words), combine(&si, &tau_index));

    // 3. The public cells.
    let t = vs.sample_vec(PUBLIC_LOG);
    let high = suffix(&t[6..], &[], l - 6);
    let s = read_slices(&mut vs, 2)?;
    let pattern = public_pattern(statement);
    for (slices, bits) in s.iter().zip(&pattern) {
        if at(slices, &t[..6]) != public_eval(bits, &t) {
            return Err(VerifyError::Public);
        }
    }
    let tau = [vs.sample(), F192::ZERO];
    let public = (suffix(&high, &tau, shape.witness_log_words), combine(&s, &tau));

    // 4. The openings.
    let witness_claims = [&gate, &copy, &public];
    let ring = RingSwitchVerify {
        offset: 0,
        qflock_vars: shape.witness_log_words,
        claims: witness_claims
            .iter()
            .map(|(point, s)| RingSwitchVerifyClaim {
                suffix_point: point,
                s_hat_v: s.as_slice().try_into().unwrap(),
            })
            .collect(),
    };
    verify_opening_batch_mixed_whir_stacked(
        &mut vs,
        &whir_config(shape.witness_log_words),
        shape.witness_log_words,
        1 << LOG_BATCH,
        &witness_root,
        &[],
        &ring,
    )
    .map_err(VerifyError::OpenWitness)?;
    let ring = RingSwitchVerify {
        offset: 0,
        qflock_vars: shape.index_log_words,
        claims: vec![RingSwitchVerifyClaim {
            suffix_point: &index_claim.0,
            s_hat_v: index_claim.1.as_slice().try_into().unwrap(),
        }],
    };
    verify_opening_batch_mixed_whir_stacked(
        &mut vs,
        &whir_config(shape.index_log_words),
        shape.index_log_words,
        1 << LOG_BATCH,
        root,
        &[],
        &ring,
    )
    .map_err(VerifyError::OpenIndex)?;
    vs.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests;
