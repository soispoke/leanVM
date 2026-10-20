//! The commitment the four claims are opened against. Each table is known to vanish outside a fixed set of its
//! chunks, so it is committed as the WHIR lanes those chunks fill and nothing else. A claim stays a plain multilinear
//! claim on the whole table: its opening's weight is the claim's `eq` on the committed lanes.

use fiat_shamir::digest_words;
use fiat_shamir::merkle::Hash;
use fiat_shamir::transcript::{Challenger, Proof, ProverState, VerifierState};
use pcs::whir::{
    LOG_INV_RATE_0, LaneWeight, ProverData, commit as whir_commit, config_for_shape,
    recursive_prover_with_lane_weights, recursive_verifier_with_basis_succinct,
};
use primitives::field::{F64, F192};
use primitives::hash::hash;
use primitives::multilinear::{eq_eval, eq_table, mle_eval_par};

use crate::standalone::Claim;

const LABEL: &[u8] = b"flock-quotient-opening";

/// Where a table's entries can be nonzero, and the shape of its WHIR commitment: lanes of
/// `2^(log_n - fold)` entries, each a slice of one chunk, and a first fold of `fold` variables after which
/// the code's domain shrinks by `reduction` bits.
pub struct Layout {
    pub vars: usize,
    pub log_chunk: usize,
    /// The committed message is `2^log_n` entries, of which only the lanes are encoded.
    pub log_n: usize,
    pub fold: usize,
    pub reduction: usize,
    /// Each lane's chunk, and its place in that chunk.
    lanes: Vec<(usize, usize)>,
}

impl Layout {
    /// Lanes enough for the leading `len` entries of each listed chunk.
    pub fn new(
        vars: usize,
        log_chunk: usize,
        (log_n, fold, reduction): (usize, usize, usize),
        chunks: &[(usize, usize)],
    ) -> Self {
        let log_lane = log_n - fold;
        assert!(log_lane <= log_chunk && log_chunk <= vars);
        assert!(
            chunks
                .iter()
                .all(|&(chunk, len)| chunk >> (vars - log_chunk) == 0 && len <= 1 << log_chunk)
        );
        let lanes: Vec<(usize, usize)> = chunks
            .iter()
            .flat_map(|&(chunk, len)| (0..len.div_ceil(1 << log_lane)).map(move |j| (chunk, j)))
            .collect();
        assert!(lanes.len() <= 1 << fold);
        Self {
            vars,
            log_chunk,
            log_n,
            fold,
            reduction,
            lanes,
        }
    }

    pub fn lane_map(&self) -> &[(usize, usize)] {
        &self.lanes
    }

    fn log_lane(&self) -> usize {
        self.log_n - self.fold
    }

    fn config(&self) -> Result<pcs::whir::ProverConfig, String> {
        config_for_shape(self.log_n, LOG_INV_RATE_0, self.fold, self.reduction)
    }

    /// How many leading entries of `chunk` its lanes hold.
    pub fn covered(&self, chunk: usize) -> usize {
        self.lanes.iter().filter(|&&(c, _)| c == chunk).count() << self.log_lane()
    }

    /// Each lane's weight in a claim at `point`: `eq` on the coordinates above a lane's own.
    fn lane_weights(&self, point: &[F192]) -> Vec<F192> {
        assert_eq!(point.len(), self.vars);
        let (log_lane, log_chunk) = (self.log_lane(), self.log_chunk);
        self.lanes
            .iter()
            .map(|&(chunk, j)| {
                let index = chunk << (log_chunk - log_lane) | j;
                point[log_lane..].iter().enumerate().fold(F192::ONE, |w, (k, &p)| {
                    w * if (index >> k) & 1 == 1 { p } else { F192::ONE + p }
                })
            })
            .collect()
    }
}

/// A table, as what is committed of it: the lanes of its layout, in order.
pub struct Table {
    pub layout: Layout,
    pub lanes: Vec<F64>,
}

impl Table {
    /// The table whose lane of chunk `c`, `j`-th in it, `fill(c, j, lane)` writes whole.
    pub fn new(layout: Layout, fill: impl Fn(usize, usize, &mut [F64]) + Sync) -> Self {
        let lane = 1 << layout.log_lane();
        // SAFETY: `fill` writes every lane whole.
        let mut lanes = unsafe { primitives::uninit_vec::<F64>(layout.lanes.len() * lane) };
        parallel::chunks_mut(&mut lanes, lane, |l, out| {
            let (c, j) = layout.lanes[l];
            fill(c, j, out);
        });
        Self { layout, lanes }
    }

    /// Its multilinear extension at `point`.
    pub fn eval(&self, point: &[F192]) -> F192 {
        let log_lane = self.layout.log_lane();
        let weights = self.layout.lane_weights(point);
        self.lanes
            .chunks_exact(1 << log_lane)
            .zip(weights)
            .fold(F192::ZERO, |acc, (lane, w)| {
                acc + w * mle_eval_par(lane, &point[..log_lane])
            })
    }
}

/// What a commitment keeps for its openings.
pub struct Committed {
    pub root: Hash,
    data: ProverData,
}

pub fn commit(table: &Table) -> Committed {
    let layout = &table.layout;
    let (commitment, data) = whir_commit(&table.lanes, layout.log_n, layout.fold, LOG_INV_RATE_0);
    Committed {
        root: commitment.root,
        data,
    }
}

/// The opening's transcript, seeded by the root and the claims, and the powers of its one challenge.
fn seed(root: &Hash, claims: &[Claim]) -> [[F64; 4]; 2] {
    let mut bytes = root.to_vec();
    for claim in claims {
        for x in claim.point.iter().chain([&claim.value]) {
            for limb in [x.c0, x.c1, x.c2] {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
    }
    [digest_words(&hash(LABEL)), digest_words(&hash(&bytes))]
}

fn powers(lambda: F192, count: usize) -> Vec<F192> {
    std::iter::successors(Some(F192::ONE), |&p| Some(p * lambda))
        .take(count)
        .collect()
}

/// Prove every claim of `claims` on one committed table, in one opening.
pub fn open(table: &Table, committed: &Committed, claims: &[Claim]) -> Proof {
    let layout = &table.layout;
    let config = layout.config().expect("WHIR configuration");
    let [iv, statement] = seed(&committed.root, claims);
    let mut ps = ProverState::new(iv, statement);
    let lambdas = powers(ps.sample(), claims.len());
    let target = claims
        .iter()
        .zip(&lambdas)
        .fold(F192::ZERO, |acc, (c, &l)| acc + l * c.value);
    let weights: Vec<LaneWeight> = claims
        .iter()
        .zip(&lambdas)
        .map(|(claim, &lambda)| LaneWeight {
            lanes: layout
                .lane_weights(&claim.point)
                .into_iter()
                .map(|w| lambda * w)
                .collect(),
            block: eq_table(&claim.point[..layout.log_lane()]),
        })
        .collect();
    recursive_prover_with_lane_weights(
        &config,
        layout.log_n,
        &table.lanes,
        &weights,
        target,
        &committed.data.codeword,
        &committed.data.merkle_tree,
        &mut ps,
    );
    ps.into_proof()
}

/// Check an opening of `claims` against `root`.
pub fn verification_trace(
    layout: &Layout,
    root: &Hash,
    claims: &[Claim],
    proof: &Proof,
) -> Option<fiat_shamir::transcript::RawProof> {
    let Ok(config) = layout.config() else {
        return None;
    };
    if claims.iter().any(|claim| claim.point.len() != layout.vars) {
        return None;
    }
    let [iv, statement] = seed(root, claims);
    let mut vs = VerifierState::new(iv, proof, statement);
    let lambdas = powers(vs.sample(), claims.len());
    let target = claims
        .iter()
        .zip(&lambdas)
        .fold(F192::ZERO, |acc, (c, &l)| acc + l * c.value);
    let log_lane = layout.log_lane();
    let lanes: Vec<Vec<F192>> = claims.iter().map(|claim| layout.lane_weights(&claim.point)).collect();
    let weight_at = |x: &[F192]| {
        let (low, high) = x.split_at(log_lane);
        let lane_eq: Vec<F192> = (0..layout.lanes.len())
            .map(|l| {
                high.iter().enumerate().fold(F192::ONE, |w, (k, &p)| {
                    w * if (l >> k) & 1 == 1 { p } else { F192::ONE + p }
                })
            })
            .collect();
        claims
            .iter()
            .zip(&lambdas)
            .zip(&lanes)
            .fold(F192::ZERO, |acc, ((claim, &lambda), lanes)| {
                let on_lanes = lanes.iter().zip(&lane_eq).fold(F192::ZERO, |s, (&w, &e)| s + w * e);
                acc + lambda * eq_eval(&claim.point[..log_lane], low) * on_lanes
            })
    };
    let accepted = recursive_verifier_with_basis_succinct(
        &config,
        layout.log_n,
        layout.lanes.len(),
        target,
        root,
        weight_at,
        &mut vs,
    )
    .is_ok()
        && vs.finish().is_ok();
    accepted.then(|| vs.into_raw_proof())
}

/// Original boolean entry point, sharing the exact verification path with trace extraction.
pub fn verify(layout: &Layout, root: &Hash, claims: &[Claim], proof: &Proof) -> bool {
    verification_trace(layout, root, claims, proof).is_some()
}
