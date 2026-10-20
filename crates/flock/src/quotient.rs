//! The membership statement of [`crate::membership`], reduced to four evaluation claims by five field elements
//! and no sumcheck. `doc/quotient/main.tex` is its description.
//!
//! A multilinear claim at a point built from one field element `t` is a univariate evaluation ([`domain`]), so
//! this is a gate-and-copy argument on an additive subspace: one full-adder gate on four cells a row
//! ([`circuit`]), copy constraints and the public bits as one sum of logarithmic derivatives, and two quotients.
//! No quotient value is sent, an identity being one claim on the table that holds its polynomials. The verifier
//! is [`reduce`], generic in its scalar like `membership::reduce`, and checks nothing but one nonzero product.

use fiat_shamir::merkle::{Hash, scalars_to_hash};
use fiat_shamir::transcript::{Challenger, Proof, ProverState, Transmitter, VerifierState};
use primitives::field::{F64, F192};

use crate::membership::{Channel, Scalar, Statement, Stream, VerifyError};
use crate::standalone::Claim;

pub mod circuit;
pub mod domain;
pub mod opening;

use circuit::Circuit;
use domain::{beta, chain, coordinates, point, row_vanishing};
use opening::Layout;
pub use opening::Table;

/// The public bits are cells of the span of this many basis vectors: the `X` and `Y` cells of
/// [`circuit::PUBLIC_ROWS`] rows.
const REGION: usize = 11;

/// The circuit as the verifier's commitment sees it: the coefficients of its wiring polynomial, which sends a
/// cell's point to its successor's.
pub struct Index {
    pub log_rows: usize,
    table: Table,
    /// Its values on the prover's coset.
    sigma_values: Vec<F64>,
}

impl Index {
    pub fn new(circuit: &Circuit) -> Self {
        let m = circuit.log_rows + 2;
        let mut sigma = parallel::map_collect(circuit.sigma.len(), |i| point(circuit.sigma[i] as usize));
        domain::coefficients(&mut sigma, F64::ZERO);
        let table = Table::new(Layout::new(m, m, (m, 6, 3), &[(0, 1 << m)]), |_, j, lane| {
            lane.copy_from_slice(&sigma[j * lane.len()..(j + 1) * lane.len()])
        });
        Self {
            log_rows: circuit.log_rows,
            sigma_values: coset_values(1 << m, &[&sigma]),
            table,
        }
    }

    /// The wiring polynomial's table, as it is committed.
    pub fn table(&self) -> &Table {
        &self.table
    }

    fn sigma(&self) -> &[F64] {
        &self.table.lanes
    }
}

/// The polynomial of coefficients `parts`, the `k`-th from `k * n` on, on the quotients' coset four times the `n`
/// cells.
fn coset_values(n: usize, parts: &[&[F64]]) -> Vec<F64> {
    let mut data = vec![F64::ZERO; 4 * n];
    for (k, part) in parts.iter().enumerate() {
        data[k * n..k * n + part.len()].copy_from_slice(part);
    }
    domain::values(&mut data, coset(n.trailing_zeros() as usize));
    data
}

/// The offset of the quotients' coset, for `2^m` cells.
fn coset(m: usize) -> F64 {
    beta()[m + 2]
}

/// Where the witness table can be nonzero: the four polynomials, and their masks.
pub fn witness_layout(log_rows: usize) -> Layout {
    let m = log_rows + 2;
    Layout::new(m + 1, m, (m + 1, 6, 3), &[(0, 1 << m), (1, 16)])
}

/// The quotient table's first fold, and how much its code's domain shrinks after it.
const QUOTIENT_FOLD: (usize, usize) = (7, 4);

/// Where the quotient table can be nonzero: three limbs of `h` below `2^m`, of `q` below `3 * 2^m` plus what the
/// public weight's degree adds, and the gate's quotient below `(4 - 1/4) * 2^m` plus what the masks add.
pub fn quotient_layout(log_rows: usize) -> Layout {
    let m = log_rows + 2;
    let n = 1usize << m;
    let mut chunks = vec![];
    for e in 0..3 {
        chunks.push((16 * e, n));
        chunks.extend((0..3).map(|digit| (16 * e + 4 + digit, n)));
        chunks.push((16 * e + 7, 1 << 14));
    }
    chunks.extend((0..3).map(|digit| (8 + digit, n)));
    chunks.push((11, 3 * n / 4 + 64));
    let (fold, reduction) = QUOTIENT_FOLD;
    Layout::new(m + 6, m, (m + 5, fold, reduction), &chunks)
}

/// What a proof leaves: one claim on the witness table, one on the circuit's, two on the quotient table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub witness: Claim,
    pub wiring: Claim,
    pub quotient: Claim,
    /// At a fixed point: the top coefficient of the sum's polynomial.
    pub sum: Claim,
}

/// The weight of bit `j` of a public word: the sum of a word's weighted bits is the element it is read as.
fn bit_weight(j: usize) -> F192 {
    if j < 64 {
        F192::new(1 << j, 0, 0)
    } else {
        F192::new(0, 1 << (j - 64), 0)
    }
}

/// The weight of a cell of the public region: `gamma^J` times its bit's, or zero off the `X` and `Y` cells.
fn public_weight(cell: usize, gamma: F192) -> F192 {
    if cell & 2 != 0 {
        return F192::ZERO;
    }
    let (j, word) = ((cell & 1) | ((cell >> 2) & 63) << 1, cell >> 8);
    (0..word).fold(bit_weight(j), |acc, _| acc * gamma)
}

/// `m_k` for coordinate `k` of the public region, `None` where it is a power of `gamma`: the region's weight is
/// the product of `1 + x_k (1 + m_k)`.
fn coordinate_weight(k: usize) -> Option<F192> {
    match k {
        0 => Some(bit_weight(1)),
        1 => Some(F192::ZERO),
        2..8 => Some(bit_weight(1 << (k - 1))),
        _ => None,
    }
}

/// The two coordinates of the extension over the base field, and the scale of their weights `(1, Y, Y^2, Y^3)`.
fn extension() -> ([F192; 2], F192) {
    let (y, y2) = (F192::Y, F192::Y * F192::Y);
    let (d0, d1) = (F192::ONE + y, F192::ONE + y2);
    ([y * d0.inv(), y2 * d1.inv()], (d0 * d1).inv())
}

/// The fixed point of the second claim on the quotient table: the top coefficient of its first chunk.
pub fn sum_point(log_rows: usize) -> Vec<F192> {
    let m = log_rows + 2;
    [&vec![F192::ONE; m][..], &[F192::ZERO; 4], &extension().0].concat()
}

/// The random oracle's instantiation: Keccak-256 for a verifier that is an EVM contract, or the VM's BLAKE2s chain
/// ([`fiat_shamir::FiatShamirState::new`]) for a verifier that runs in leanVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oracle {
    Keccak,
    Blake2s,
}

/// The BLAKE2s chain's seed: a digest of the circuit, then a digest of the statement's four 128-bit halves.
pub fn vm_seed(index_root: &Hash, statement: &Statement) -> [[F64; 4]; 2] {
    let circuit = primitives::hash::hash(&[b"flock-quotient-vm-1".as_slice(), index_root].concat());
    let halves: Vec<u8> = statement
        .halves()
        .iter()
        .flat_map(|x| [x.c0.to_le_bytes(), x.c1.to_le_bytes()].concat())
        .collect();
    [
        fiat_shamir::digest_words(&circuit),
        fiat_shamir::digest_words(&primitives::hash::hash(&halves)),
    ]
}

/// The transcript's seed: the circuit and the statement.
pub fn label(index_root: &Hash, statement: &Statement) -> Vec<u8> {
    [
        b"flock-quotient-1".as_slice(),
        index_root,
        &statement.y,
        &statement.root,
    ]
    .concat()
}

fn gate(theta: F64, [x, y, c, v]: [F64; 4]) -> F64 {
    let bit = |v: F64| v * (theta * v + theta * theta);
    let (x, y, c) = (bit(x), bit(y), c * c + c);
    v + x + y + c + theta * (x * y + c * (x + y))
}

fn batch_inverse(values: &mut [F192]) {
    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = F192::ONE;
    for &v in values.iter() {
        prefix.push(acc);
        acc *= v;
    }
    let mut inverse = acc.inv();
    for (v, p) in values.iter_mut().zip(prefix).rev() {
        let next = inverse * *v;
        *v = inverse * p;
        inverse = next;
    }
}

/// `x^-1` for a nonzero `x`, by its norm to `GF(2^64)`: `m = x^(2^64) x^(2^128)` makes `x m` the norm, whose
/// inverse is its power `2^64 - 2`, reached through the powers `2^k - 1`.
fn inverse<S: Scalar>(x: S) -> S {
    let m = x.frobenius() * x.frobenius().frobenius();
    let norm = x * m;
    // `ones` is the norm to the power `2^k - 1`: doubling `k` is `k` squarings and a product.
    let (mut ones, mut k) = (norm, 1);
    for bit in (0..5).rev() {
        let mut shifted = ones;
        for _ in 0..k {
            shifted = shifted * shifted;
        }
        (ones, k) = (shifted * ones, 2 * k);
        if (63 >> bit) & 1 == 1 {
            (ones, k) = (ones * ones * norm, k + 1);
        }
    }
    debug_assert_eq!(k, 63);
    m * (ones * ones)
}

pub struct Proved {
    pub proof: Proof,
    pub claims: Claims,
    /// The two tables the prover committed.
    pub witness: Table,
    pub quotient: Table,
}

/// Prove `statement` from the cells of a witness, against the circuit committed as `index_root`. `masks` must be
/// uniformly random, and `commit` returns a table's root. Panics on a challenge the verifier rejects.
pub fn prove(
    circuit: &Circuit,
    index: &Index,
    index_root: &Hash,
    statement: &Statement,
    cells: &[F64],
    masks: &[[F64; 3]; 4],
    commit: &mut dyn FnMut(&Table) -> Hash,
) -> Proved {
    prove_with(
        Oracle::Keccak,
        circuit,
        index,
        index_root,
        statement,
        cells,
        masks,
        commit,
    )
}

/// [`prove`] with the random oracle `oracle`.
pub fn prove_with(
    oracle: Oracle,
    circuit: &Circuit,
    index: &Index,
    index_root: &Hash,
    statement: &Statement,
    cells: &[F64],
    masks: &[[F64; 3]; 4],
    commit: &mut dyn FnMut(&Table) -> Hash,
) -> Proved {
    let m = circuit.log_rows + 2;
    let n = 1usize << m;
    assert_eq!(cells.len(), n);
    // The public weight's polynomial has degree `2^m + 9 * 2^10`, and the quotient must stay below `2^(m+2)`.
    assert!(m > REGION + 2 && m + 3 <= domain::BASIS);
    let mut ps = match oracle {
        Oracle::Keccak => ProverState::keccak(&label(index_root, statement)),
        Oracle::Blake2s => {
            let [iv, public] = vm_seed(index_root, statement);
            ProverState::new(iv, public)
        }
    };

    // The witness: four polynomials in the row, each with a multiple of the rows' vanishing polynomial.
    let span = tracing::info_span!("Witness").entered();
    let mut w_hat = cells.to_vec();
    domain::coefficients(&mut w_hat, F64::ZERO);
    let mut mask = [F64::ZERO; 16];
    for (j, coeffs) in masks.iter().enumerate() {
        for (i, &coeff) in coeffs.iter().enumerate() {
            mask[4 * i + j] = coeff;
        }
    }
    let witness = Table::new(witness_layout(circuit.log_rows), |c, j, lane| {
        let len = lane.len();
        if c == 0 {
            lane.copy_from_slice(&w_hat[j * len..(j + 1) * len]);
        } else {
            lane.fill(F64::ZERO);
            lane[..16].copy_from_slice(&mask);
        }
    });
    drop(w_hat);
    let w_hat = &witness.lanes[..n];
    ps.add_root(&commit(&witness));
    drop(span);
    let [alpha, beta_, gamma] = [(); 3].map(|_| ps.sample());

    // The sum's polynomial on the cells.
    let span = tracing::info_span!("Sum").entered();
    let mut h = vec![F192::ZERO; n];
    parallel::chunks_mut(&mut h, 1 << 12, |chunk_index, chunk| {
        let base = chunk_index << 12;
        let mut d: Vec<F192> = (0..chunk.len())
            .flat_map(|k| {
                let i = base + k;
                let common = alpha + F192::from(cells[i]);
                [point(i), point(circuit.sigma[i] as usize)].map(|to| common + beta_.mul_base(to))
            })
            .collect();
        batch_inverse(&mut d);
        for (k, out) in chunk.iter_mut().enumerate() {
            *out = d[2 * k] + d[2 * k + 1];
            if base + k < 1 << REGION {
                *out += public_weight(base + k, gamma).mul_base(cells[base + k]);
            }
        }
    });
    domain::coefficients(&mut h, F64::ZERO);
    let h_hat = h;
    drop(span);

    // Both quotients, on a coset four times the cells.
    let span = tracing::info_span!("Quotients").entered();
    let big = 4 * n;
    let offset = coset(m);
    let offsets = chain(offset, m + 1);
    let w_values = coset_values(n, &[w_hat, &mask]);
    let sigma_values = &index.sigma_values;
    let mut q = vec![F192::ZERO; big];
    q[..n].copy_from_slice(&h_hat);
    domain::values(&mut q, offset);
    let mut q_gate = vec![F64::ZERO; big];

    let (theta, b, tau) = (beta()[1], coordinates(REGION), row_vanishing(m));
    let row_poly = |x: F64| {
        chain(x, m - 1)
            .iter()
            .zip(&tau)
            .fold(F64::ZERO, |acc, (&w, &t)| acc + t * w)
    };
    let row_low: [F64; 4] = std::array::from_fn(|c| row_poly(point(c)));
    let gammas = [gamma, gamma * gamma, (gamma * gamma) * (gamma * gamma)];
    parallel::chunks_mut2(&mut q, &mut q_gate, 1 << REGION, |high, q, q_gate| {
        let base = high << REGION;
        let w_at = |k: usize| offsets[k] + point(base >> k);
        // The public weight on this block: its region coordinates are the low index's bits, shifted.
        let indicator = (REGION..m).fold(F64::ONE, |acc, k| acc * (F64::ONE + w_at(k)));
        let mut weights = vec![F192::from(indicator)];
        if !indicator.is_zero() {
            for k in 0..REGION {
                let shift = (k..REGION).fold(F64::ZERO, |acc, j| acc + b[j - k] * w_at(j));
                let slope = F192::ONE + coordinate_weight(k).unwrap_or_else(|| gammas[k - 8]);
                let low = F192::ONE + slope.mul_base(shift);
                for i in 0..weights.len() {
                    weights.push(weights[i] * (low + slope));
                    weights[i] *= low;
                }
            }
        }
        let cell_vanishing = w_at(m).inv();
        let row_base = row_poly(offset + point(base));
        let row_vanishing: [F64; 4] = std::array::from_fn(|c| (row_base + row_low[c]).inv());
        for (low, (q, q_gate)) in q.iter_mut().zip(q_gate.iter_mut()).enumerate() {
            let i = base + low;
            let w = w_values[i];
            let common = alpha + F192::from(w);
            let d = common + beta_.mul_base(offset + point(i));
            let d_next = common + beta_.mul_base(sigma_values[i]);
            let public = weights.get(low).map_or(F192::ZERO, |weight| weight.mul_base(w));
            *q = ((*q + public) * d * d_next + d + d_next).mul_base(cell_vanishing);
            let row = [w, w_values[i ^ 1], w_values[i ^ 2], w_values[i ^ 3]];
            *q_gate = gate(theta, row) * row_vanishing[low & 3];
        }
    });
    drop(w_values);
    domain::coefficients(&mut q, offset);
    domain::coefficients(&mut q_gate, offset);

    // The quotient table: 22 variables of a polynomial, two more digits, `h` or `q`, that pair or the gate's
    // quotient, and the extension's two. `q`'s top digit holds only what the public weight's degree adds.
    let layout = quotient_layout(circuit.log_rows);
    assert!(
        q[3 * n + layout.covered(7)..].iter().all(|v| v.is_zero()),
        "q above its layout"
    );
    assert!(
        q_gate[3 * n + layout.covered(11)..].iter().all(|v| v.is_zero()),
        "the gate's quotient above its layout"
    );
    let quotient = Table::new(layout, |c, j, lane| {
        let len = lane.len();
        let (digit, limb) = (c & 3, c >> 4);
        let mut at = |values: &[F192]| {
            let values = &values[digit * n + j * len..][..len];
            for (out, v) in lane.iter_mut().zip(values) {
                *out = F64([v.c0, v.c1, v.c2][limb]);
            }
        };
        match c & 12 {
            0 => at(&h_hat),
            4 => at(&q),
            _ => lane.copy_from_slice(&q_gate[digit * n + j * len..][..len]),
        }
    });
    drop((h_hat, q, q_gate));
    ps.add_root(&commit(&quotient));
    drop(span);

    let t = ps.sample();
    let digits: Vec<F192> = std::iter::successors(Some(t), |&w| Some(w * w + w))
        .take(m + 1)
        .collect();
    let a: [F192; 4] = std::array::from_fn(|j| {
        domain::evaluate(w_hat, j, 4, &digits[2..m]) + digits[m] * domain::evaluate(&mask, j, 4, &digits[2..4])
    });
    ps.add_scalars(&a);
    ps.add_scalar(domain::evaluate(index.sigma(), 0, 1, &digits[..m]));

    let proof = ps.into_proof();
    let (_, claims) =
        verify_with(oracle, index_root, statement, &proof, circuit.log_rows).expect("a challenge to reject");
    Proved {
        proof,
        claims,
        witness,
        quotient,
    }
}

/// What [`reduce`] leaves: the two commitments, each as its two scalars, three claims as a point and a value, and
/// the value of the one at [`sum_point`].
pub struct Reduced<S> {
    pub roots: [[S; 2]; 2],
    pub witness: (Vec<S>, S),
    pub wiring: (Vec<S>, S),
    pub quotient: (Vec<S>, S),
    pub sum: S,
}

/// The verifier, on any [`Scalar`]: the proof read from `channel`, down to the commitments it names and the four
/// claims. It rejects only a challenge at which a denominator vanishes.
pub fn reduce<S: Scalar>(channel: &mut impl Channel<S>, log_rows: usize) -> Result<Reduced<S>, VerifyError> {
    let transcript = VerifyError::Transcript;
    let m = log_rows + 2;
    let base = |x: F64| S::constant(F192::from(x));
    let one = S::constant(F192::ONE);

    let statement = channel.statement();
    let witness_root = channel.next_root().map_err(transcript)?;
    let [alpha, beta_, gamma] = [(); 3].map(|_| channel.sample());
    let quotient_root = channel.next_root().map_err(transcript)?;
    let t = channel.sample();
    let mut a = [t; 4];
    for value in &mut a {
        *value = channel.next().map_err(transcript)?;
    }
    let next = channel.next().map_err(transcript)?;
    let rho = channel.sample();
    channel.finish().map_err(transcript)?;

    // `w_k(t)`, up to the two digits past the cells.
    let mut w = vec![t];
    for k in 0..m + 1 {
        w.push(w[k] * w[k] + w[k]);
    }

    // The four cells of the row of `t`, and its gate.
    let theta = beta()[1];
    let cell = |shift: F64, second: bool| {
        let (first, second) = (t + base(shift), if second { w[1] + one } else { w[1] });
        a[0] + first * a[1] + second * (a[2] + first * a[3])
    };
    let [x, y, c, v] = [
        cell(F64::ZERO, false),
        cell(F64::ONE, false),
        cell(theta, true),
        cell(theta + F64::ONE, true),
    ];
    let bit = |v: S| v * (base(theta) * v + base(theta * theta));
    let (bx, by, carry) = (bit(x), bit(y), c * c + c);
    let gate = v + bx + by + carry + base(theta) * (bx * by + carry * (bx + by));

    // The public weight at `t`, and what the weighted public bits must sum to.
    let b = coordinates(REGION);
    let gamma2 = gamma * gamma;
    let gammas = [gamma, gamma2, gamma2 * gamma2];
    let mut public = (REGION..m).fold(one, |acc, k| acc * (one + w[k]));
    for k in 0..REGION {
        let coordinate = (k + 1..REGION).fold(w[k], |acc, j| acc + base(b[j - k]) * w[j]);
        let slope = match coordinate_weight(k) {
            Some(weight) => S::constant(F192::ONE + weight),
            None => one + gammas[k - 8],
        };
        public = public * (one + coordinate * slope);
    }
    let target = statement[0] + gamma * statement[1] + gamma2 * (statement[2] + gamma * statement[3]) + gammas[2];

    let tau = row_vanishing(m);
    let rows = (0..m - 1).fold(S::constant(F192::ZERO), |acc, k| acc + base(tau[k]) * w[k]);
    let (d, d_next) = (alpha + x + beta_ * t, alpha + x + beta_ * next);
    let product = d * d_next;
    let copies = d + d_next + public * x * product;

    // One inversion: of every `1 + w_k`, of the copy identity's denominator, and of the rows' polynomial.
    let mut denominators: Vec<S> = w.iter().map(|&w| one + w).collect();
    denominators.extend([product + w[m], rows]);
    let mut prefix = vec![one];
    for &value in &denominators {
        prefix.push(*prefix.last().unwrap() * value);
    }
    if !prefix[denominators.len()].is_nonzero() {
        return Err(VerifyError::Degenerate);
    }
    let mut running = inverse(prefix[denominators.len()]);
    let mut inverses = denominators.clone();
    for i in (0..denominators.len()).rev() {
        inverses[i] = running * prefix[i];
        running = running * denominators[i];
    }
    let u: Vec<S> = (0..m + 2).map(|k| w[k] * inverses[k]).collect();
    let (copy_inverse, rows_inverse) = (inverses[m + 2], inverses[m + 3]);
    let middle = (3..m).fold(inverses[2], |acc, k| acc * inverses[k]);
    let wiring_scale = middle * inverses[0] * inverses[1];
    let quotient_scale = wiring_scale * inverses[m] * inverses[m + 1];

    let rho2 = rho * rho;
    let opened = (one + rho2) * (a[0] + rho * (a[0] + a[1])) + rho2 * (a[2] + rho * (a[2] + a[3]));
    let ([y0, y1], scale) = extension();
    let scale = S::constant(scale);
    let identities = (one + rho) * copies * rows + rho * product * gate;
    Ok(Reduced {
        roots: [witness_root, quotient_root],
        witness: ([&[rho, rho2][..], &u[2..m + 1]].concat(), opened * middle * inverses[m]),
        wiring: (u[..m].to_vec(), next * wiring_scale),
        quotient: (
            [&u[..], &[w[m] * copy_inverse, rho, S::constant(y0), S::constant(y1)]].concat(),
            scale * quotient_scale * copy_inverse * rows_inverse * identities,
        ),
        sum: scale * target,
    })
}

/// Verify a proof of `statement` against the circuit committed as `index_root`, down to the two commitments it
/// names (the witness table's, then the quotient table's) and four claims: it holds if all four are true.
pub fn verify(
    index_root: &Hash,
    statement: &Statement,
    proof: &Proof,
    log_rows: usize,
) -> Result<([Hash; 2], Claims), VerifyError> {
    verify_with(Oracle::Keccak, index_root, statement, proof, log_rows)
}

/// [`verify`] with the random oracle `oracle`.
pub fn verify_with(
    oracle: Oracle,
    index_root: &Hash,
    statement: &Statement,
    proof: &Proof,
    log_rows: usize,
) -> Result<([Hash; 2], Claims), VerifyError> {
    let vs = match oracle {
        Oracle::Keccak => VerifierState::keccak(&label(index_root, statement), proof),
        Oracle::Blake2s => {
            let [iv, public] = vm_seed(index_root, statement);
            VerifierState::new(iv, proof, public)
        }
    };
    let mut stream = Stream {
        vs,
        statement: *statement,
    };
    let reduced = reduce(&mut stream, log_rows)?;
    let [witness_root, quotient_root] = reduced.roots.map(|root| scalars_to_hash(&root));
    let roots = [
        witness_root.map_err(VerifyError::Transcript)?,
        quotient_root.map_err(VerifyError::Transcript)?,
    ];
    let claim = |(point, value)| Claim { point, value };
    Ok((
        roots,
        Claims {
            witness: claim(reduced.witness),
            wiring: claim(reduced.wiring),
            quotient: claim(reduced.quotient),
            sum: Claim {
                point: sum_point(log_rows),
                value: reduced.sum,
            },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::circuit::{Builder, Src, membership, membership_inputs, public_words};
    use super::*;
    use crate::membership::{DEPTH, Secret};
    use primitives::test_rng::Rng;

    /// A small circuit with the membership statement's shape: `y` is the input, `root` its sum with a rotation.
    fn toy() -> Circuit {
        let mut b = Builder::new();
        let x: Vec<Src> = (0..256).map(|_| b.input()).collect();
        let rotated: Vec<Src> = (0..256).map(|i| x[(i + 77) % 256]).collect();
        let sum = b.add(&x, &rotated);
        let pure = |b: &mut Builder, wires: &[Src]| -> Vec<Src> { wires.iter().map(|&w| b.bit(w)).collect() };
        let (y, root) = (pure(&mut b, &x), pure(&mut b, &sum));
        b.finish(12, &public_words(&y, &root))
    }

    fn toy_statement(x: &[bool]) -> Statement {
        let pack = |bits: &dyn Fn(usize) -> bool| -> [u8; 32] {
            std::array::from_fn(|byte| (0..8).fold(0, |acc, i| acc | (bits(8 * byte + i) as u8) << i))
        };
        let mut carry = false;
        let sum: Vec<bool> = (0..256)
            .map(|i| {
                let (a, b) = (x[i], x[(i + 77) % 256]);
                let out = a ^ b ^ carry;
                carry = (a & b) | (carry & (a ^ b));
                out
            })
            .collect();
        Statement {
            y: pack(&|i| x[i]),
            root: pack(&|i| sum[i]),
        }
    }

    fn masks(rng: &mut Rng) -> [[F64; 3]; 4] {
        std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())))
    }

    /// Which of the four claims the tables satisfy.
    fn truth(index: &Index, proved: &Proved) -> [bool; 4] {
        let holds = |table: &Table, claim: &Claim| table.eval(&claim.point) == claim.value;
        let claims = &proved.claims;
        [
            holds(&proved.witness, &claims.witness),
            holds(index.table(), &claims.wiring),
            holds(&proved.quotient, &claims.quotient),
            holds(&proved.quotient, &claims.sum),
        ]
    }

    fn run(circuit: &Circuit, index: &Index, statement: &Statement, cells: &[F64], rng: &mut Rng) -> Proved {
        let mut roots = 0u8;
        let mut commit = |_: &Table| {
            roots += 1;
            [roots; 32]
        };
        prove(circuit, index, &[7; 32], statement, cells, &masks(rng), &mut commit)
    }

    /// On a small circuit: an honest proof leaves four true claims, and a witness that breaks one gate, one copy,
    /// one input's range or one public bit leaves a false one.
    /// What `formal/quotient` assumes of the constants: a bit's weight is the product of the weights of the
    /// set bits of its index, each a coordinate's, and the weight of a cell is that product on its word's power.
    #[test]
    fn public_weights_are_products_over_coordinates() {
        let gamma = F192::new(3, 5, 7);
        for cell in 0..1usize << REGION {
            let product = (0..8)
                .filter(|k| (cell >> k) & 1 == 1)
                .fold(F192::ONE, |acc, k| acc * coordinate_weight(k).expect("a constant"));
            let word = (0..cell >> 8).fold(F192::ONE, |acc, _| acc * gamma);
            assert_eq!(public_weight(cell, gamma), product * word);
        }
    }

    #[test]
    fn claims_hold_exactly_for_a_witness() {
        let mut rng = Rng::new(0x51);
        let circuit = toy();
        let index = Index::new(&circuit);
        let x: Vec<bool> = (0..256).map(|_| rng.next_u64() & 1 == 1).collect();
        let statement = toy_statement(&x);
        let cells = circuit.cells(&x);
        let theta = beta()[1];
        for r in 0..cells.len() / 4 {
            assert!(gate(theta, std::array::from_fn(|c| cells[4 * r + c])).is_zero());
        }
        for (i, &next) in circuit.sigma.iter().enumerate() {
            assert_eq!(cells[i], cells[next as usize]);
        }

        let proved = run(&circuit, &index, &statement, &cells, &mut rng);
        assert_eq!(truth(&index, &proved), [true; 4]);
        assert_eq!(proved.proof.stream.len(), 9);
        let (roots, claims) = verify(&[7; 32], &statement, &proved.proof, circuit.log_rows).expect("a reduction");
        assert_eq!((roots, &claims), ([[1; 32], [2; 32]], &proved.claims));

        // A proof made for one statement, read against another.
        let mut other = statement;
        other.root[3] ^= 0x10;
        let wrong = run(&circuit, &index, &other, &cells, &mut rng);
        assert_eq!(truth(&index, &wrong), [true, true, true, false]);

        let input_row = circuit::PUBLIC_ROWS + 5;
        let sum_row = circuit::PUBLIC_ROWS + 256 + 9;
        type Tamper<'a> = &'a dyn Fn(&mut Vec<F64>);
        let cases: [(&str, Tamper); 5] = [
            // A row's output alone.
            ("gate", &|cells| cells[4 * sum_row + 3] += F64::ONE),
            // A reader that departs from what it reads, its own row kept consistent.
            ("copy", &|cells| {
                cells[4 * sum_row] += F64::ONE;
                cells[4 * sum_row + 3] += F64::ONE;
            }),
            // An input that is not a bit, wherever it is read.
            ("range", &|cells| {
                let (from, to) = (cells[4 * input_row + 3], F64(0x1234_5678));
                let cycle: Vec<usize> =
                    std::iter::successors(Some(4 * input_row + 3), |&i| Some(circuit.sigma[i] as usize))
                        .skip(1)
                        .take_while(|&i| i != 4 * input_row + 3)
                        .collect();
                assert_eq!(cells[cycle[0]], from);
                for i in cycle.into_iter().chain([4 * input_row + 3]) {
                    cells[i] = to;
                }
            }),
            // The constant one, read as zero everywhere.
            ("one", &|cells| {
                let anchor = 4 * (4 * 64);
                let mut i = anchor;
                loop {
                    cells[i] = F64::ZERO;
                    i = circuit.sigma[i] as usize;
                    if i == anchor {
                        break;
                    }
                }
            }),
            // The constant zero, read as another element of GF(4) everywhere.
            ("zero", &|cells| {
                let anchor = 4 * (5 * 64);
                let mut i = anchor;
                loop {
                    cells[i] = theta + F64::ONE;
                    i = circuit.sigma[i] as usize;
                    if i == anchor {
                        break;
                    }
                }
            }),
        ];
        for (name, tamper) in cases {
            let mut bad = cells.clone();
            tamper(&mut bad);
            let truth = truth(&index, &run(&circuit, &index, &statement, &bad, &mut rng));
            assert!(truth.contains(&false), "{name}: {truth:?}");
            assert!(truth[0] && truth[1], "{name}: {truth:?}");
        }
    }

    /// Each table's claims open against its commitment, the quotient table's two in one opening, and a claim with
    /// another value does not.
    /// Each oracle verifies its own proofs and nothing else, and the BLAKE2s seed binds the statement.
    #[test]
    fn oracles_do_not_cross() {
        let mut rng = Rng::new(0xB2);
        let circuit = toy();
        let index = Index::new(&circuit);
        let wiring = opening::commit(index.table());
        let x: Vec<bool> = (0..256).map(|_| rng.next_u64() & 1 == 1).collect();
        let statement = toy_statement(&x);
        let cells = circuit.cells(&x);
        for oracle in [Oracle::Keccak, Oracle::Blake2s] {
            let proved = prove_with(
                oracle,
                &circuit,
                &index,
                &wiring.root,
                &statement,
                &cells,
                &masks(&mut rng),
                &mut |table: &Table| opening::commit(table).root,
            );
            let other = if oracle == Oracle::Keccak {
                Oracle::Blake2s
            } else {
                Oracle::Keccak
            };
            let verdict = |o, s: &Statement| verify_with(o, &wiring.root, s, &proved.proof, circuit.log_rows);
            assert_eq!(verdict(oracle, &statement).expect("its own oracle").1, proved.claims);
            assert!(verdict(other, &statement).map_or(true, |(_, c)| c != proved.claims));
            let mut moved = statement;
            moved.root[0] ^= 1;
            assert!(verdict(oracle, &moved).map_or(true, |(_, c)| c != proved.claims));
        }
    }

    #[test]
    fn claims_open_against_the_commitments() {
        let mut rng = Rng::new(0x0E);
        let circuit = toy();
        let index = Index::new(&circuit);
        let wiring = opening::commit(index.table());
        let x: Vec<bool> = (0..256).map(|_| rng.next_u64() & 1 == 1).collect();
        let statement = toy_statement(&x);
        let cells = circuit.cells(&x);
        let mut committed = vec![];
        let mut commit = |table: &Table| {
            let table = opening::commit(table);
            let root = table.root;
            committed.push(table);
            root
        };
        let proved = prove(
            &circuit,
            &index,
            &wiring.root,
            &statement,
            &cells,
            &masks(&mut rng),
            &mut commit,
        );
        let (_, claims) = verify(&wiring.root, &statement, &proved.proof, circuit.log_rows).expect("a reduction");
        let tables = [
            (&proved.witness, &committed[0], vec![claims.witness.clone()]),
            (index.table(), &wiring, vec![claims.wiring.clone()]),
            (
                &proved.quotient,
                &committed[1],
                vec![claims.quotient.clone(), claims.sum.clone()],
            ),
        ];
        for (table, committed, claims) in &tables {
            let proof = opening::open(table, committed, claims);
            assert!(opening::verify(&table.layout, &committed.root, claims, &proof));

            let mut wrong = claims.clone();
            wrong[0].value += F192::ONE;
            let proof = opening::open(table, committed, &wrong);
            assert!(!opening::verify(&table.layout, &committed.root, &wrong, &proof));
        }
    }

    fn secret(rng: &mut Rng) -> Secret {
        let mut bytes = || std::array::from_fn(|_| rng.next_u64() as u8);
        Secret {
            x: bytes(),
            siblings: std::array::from_fn::<_, DEPTH, _>(|_| bytes()),
            directions: 0x3C5A_F096,
        }
    }

    /// The circuit computes the statement, and an honest proof of it leaves four true claims.
    #[test]
    fn membership_proof_leaves_true_claims() {
        let mut rng = Rng::new(0x9A7);
        let circuit = membership();
        let index = Index::new(&circuit);
        let secret = secret(&mut rng);
        let statement = secret.statement();
        let cells = circuit.cells(&membership_inputs(&secret));
        let theta = beta()[1];
        assert!((0..cells.len() / 4).all(|r| gate(theta, std::array::from_fn(|c| cells[4 * r + c])).is_zero()));
        assert!((0..cells.len()).all(|i| cells[i] == cells[circuit.sigma[i] as usize]));
        // The public cells hold the statement's bits.
        for (word, value) in statement.halves().into_iter().enumerate() {
            let sum = (0..circuit::WORD_BITS).fold(F192::ZERO, |acc, j| {
                acc + bit_weight(j).mul_base(cells[(j & 1) | (j >> 1) << 2 | word << 8])
            });
            assert_eq!(sum, value);
        }

        let proved = run(&circuit, &index, &statement, &cells, &mut rng);
        assert_eq!(truth(&index, &proved), [true; 4]);
    }
}
