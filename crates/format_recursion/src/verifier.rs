use crate::trace::{self, S, Trace, digest_constant, hash};
use fiat_shamir::{
    merkle::{Hash, hash_to_scalars},
    transcript::{Proof, RawProof},
};
use flock::{
    membership::{Channel, Statement},
    quotient::{self, opening::Layout},
};
use primitives::field::F192;

pub struct Child {
    pub log_rows: usize,
    pub index_root: Hash,
    pub statement: Statement,
    pub piop: Proof,
    pub openings: [RawProof; 3],
}

pub(crate) struct Transcript<'a> {
    proof: std::borrow::Cow<'a, RawProof>,
    compressed: Option<&'a Proof>,
    state: [S; 2],
    cursor: usize,
    phase: usize,
}

impl<'a> Transcript<'a> {
    pub(crate) fn new(proof: &'a RawProof, iv: [S; 2], public: [S; 2]) -> Self {
        let state = hash(&[(iv[0], 16), (iv[1], 16), (public[0], 16), (public[1], 16)]);
        Self {
            proof: std::borrow::Cow::Borrowed(proof),
            compressed: None,
            state,
            cursor: 0,
            phase: 0,
        }
    }
    /// Expand compressed paths only as witness generation. Every expanded leaf,
    /// query bit and sibling is authenticated again by symbolic hash constraints.
    pub(crate) fn from_state(proof: &'a Proof, state: [S; 2]) -> Self {
        Self {
            proof: std::borrow::Cow::Owned(RawProof {
                stream: proof.stream.clone(),
                merkle: Vec::new(),
            }),
            compressed: Some(proof),
            state,
            cursor: 0,
            phase: 0,
        }
    }
    pub(crate) fn round(&mut self, n: usize, claim: S, equality: S) -> Vec<S> {
        assert!(n >= 2);
        let mut coefficients = vec![S::u(0)];
        coefficients.extend(self.scalars(n - 1));
        coefficients[0] = claim + equality * coefficients[1..].iter().copied().fold(S::u(0), |a, b| a + b);
        coefficients
    }
    fn step(&mut self, x: S, tag: u64) -> [S; 2] {
        self.state = hash(&[(self.state[0], 16), (self.state[1], 16), (x, 24), (S::u(tag), 8)]);
        self.state
    }
    pub(crate) fn sample(&mut self) -> S {
        let h = self.step(S::u(0), 2);
        S::pack(&[(h[0], 128), (h[1], 64)])
    }
    fn raw(&mut self) -> S {
        let x = S::input(self.proof.stream[self.cursor]);
        self.cursor += 1;
        x
    }
    pub(crate) fn next(&mut self) -> S {
        let x = self.raw();
        self.step(x, 1);
        x
    }
    pub(crate) fn scalars(&mut self, n: usize) -> Vec<S> {
        (0..n).map(|_| self.next()).collect()
    }
    pub(crate) fn root(&mut self) -> [S; 2] {
        let h = [self.next(), self.next()];
        for a in h {
            a.slice(128, 64).assert_eq(S::u(0));
        }
        h
    }
    pub(crate) fn quad(&mut self, target: S) -> [S; 3] {
        let a = self.next();
        let b = self.next();
        [a, target + b, b]
    }
    pub(crate) fn grind(&mut self, bits: usize) {
        let nonce = self.raw();
        if bits == 0 {
            nonce.assert_eq(S::u(0));
        } else {
            let base = hash(&[(self.state[0], 16), (self.state[1], 16), (S::u(0), 24), (S::u(3), 8)]);
            let digest = hash(&[(base[0], 16), (base[1], 16), (nonce, 24), (S::u(4), 8)]);
            digest[0].slice(0, bits).assert_eq(S::u(0));
        }
        self.step(nonce, 4);
    }
    pub(crate) fn queries(&mut self, depth: usize, count: usize) -> Vec<S> {
        let mut out = Vec::new();
        while out.len() < count {
            let x = self.sample();
            for j in 0..(192 / depth).min(count - out.len()) {
                out.push(x.slice(j * depth, depth));
            }
        }
        out
    }
    pub(crate) fn merkle(
        &mut self,
        root: [S; 2],
        depth: usize,
        queries: &[S],
        lanes: usize,
        base: bool,
        live_lanes: usize,
    ) -> Vec<Vec<S>> {
        let expanded;
        let paths = if let Some(proof) = self.compressed {
            let root_bytes = fiat_shamir::merkle::scalars_to_hash(&root.map(S::value)).expect("canonical root");
            let query_values: Vec<_> = queries.iter().map(|q| q.value().c0 as usize).collect();
            let row_words = if base { live_lanes } else { 3 * lanes };
            let leaf_words = if base { lanes } else { 3 * lanes };
            expanded = proof.merkle[self.phase]
                .open(&root_bytes, 1 << depth, &query_values, row_words, leaf_words)
                .expect("well-formed compressed Merkle witness");
            self.phase += 1;
            expanded.as_slice()
        } else {
            let paths = &self.proof.merkle[self.phase..self.phase + queries.len()];
            self.phase += queries.len();
            paths
        };
        let mut rows = Vec::new();
        for (&query, path) in queries.iter().zip(paths) {
            assert_eq!(path.path.len(), depth);
            let words = if base { lanes } else { 3 * lanes };
            assert_eq!(path.leaf_data.len(), words);
            let leaf: Vec<S> = path
                .leaf_data
                .iter()
                .map(|x| S::input(F192::from(*x)).slice(0, 64))
                .collect();
            if base {
                for &word in &leaf[..lanes - live_lanes] {
                    word.assert_eq(S::u(0));
                }
            }
            let mut node = hash(&leaf.iter().map(|&w| (w, 8)).collect::<Vec<_>>());
            for (level, sibling) in path.path.iter().enumerate() {
                let sibling = hash_to_scalars(sibling).map(|x| S::input(x).slice(0, 128));
                let bit = query.slice(level, 1);
                let left = [S::select(bit, node[0], sibling[0]), S::select(bit, node[1], sibling[1])];
                let right = [S::select(bit, sibling[0], node[0]), S::select(bit, sibling[1], node[1])];
                node = hash(&[(left[0], 16), (left[1], 16), (right[0], 16), (right[1], 16)]);
            }
            for i in 0..2 {
                node[i].assert_eq(root[i]);
            }
            rows.push(if base {
                leaf.into_iter().rev().collect()
            } else {
                leaf.chunks(3)
                    .map(|a| S::pack(&[(a[0], 64), (a[1], 64), (a[2], 64)]))
                    .collect()
            });
        }
        rows
    }
    pub(crate) fn finish(&self) {
        assert_eq!(self.cursor, self.proof.stream.len(), "all scalars consumed");
        assert_eq!(
            self.phase,
            self.compressed.map_or(self.proof.merkle.len(), |p| p.merkle.len()),
            "all Merkle paths consumed"
        );
    }
}

struct Piop<'a> {
    transcript: Transcript<'a>,
    statement: [S; 4],
}
impl Channel<S> for Piop<'_> {
    fn statement(&mut self) -> [S; 4] {
        self.statement
    }
    fn next_root(&mut self) -> Result<[S; 2], fiat_shamir::transcript::Error> {
        Ok(self.transcript.root())
    }
    fn next(&mut self) -> Result<S, fiat_shamir::transcript::Error> {
        Ok(self.transcript.next())
    }
    fn sample(&mut self) -> S {
        self.transcript.sample()
    }
    fn finish(&mut self) -> Result<(), fiat_shamir::transcript::Error> {
        self.transcript.finish();
        Ok(())
    }
}

pub(crate) fn powers(x: S, n: usize) -> Vec<S> {
    let mut out = vec![S::u(1)];
    for i in 1..n {
        out.push(out[i - 1] * x);
    }
    out.truncate(n);
    out
}
pub(crate) fn eq(a: &[S], b: &[S]) -> S {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).fold(S::u(1), |acc, (&a, &b)| acc * (S::u(1) + a + b))
}
pub(crate) fn kernel(point: &[S]) -> Vec<S> {
    let mut out = vec![S::u(1)];
    for &x in point {
        for i in 0..out.len() {
            let high = out[i] * x;
            out.push(high);
            out[i] = out[i] + high;
        }
    }
    out
}
pub(crate) fn mle(table: &[S], point: &[S]) -> S {
    assert_eq!(table.len(), 1 << point.len());
    let mut values = table.to_vec();
    for &x in point {
        let n = values.len() / 2;
        for i in 0..n {
            values[i] = values[2 * i] + x * (values[2 * i] + values[2 * i + 1]);
        }
        values.truncate(n);
    }
    values[0]
}
pub(crate) fn poly(q: [S; 3], x: S) -> S {
    q[0] + x * (q[1] + x * q[2])
}
pub(crate) fn induced(message_log: usize, queries: &[S], weights: &[S], point: &[S]) -> S {
    assert_eq!(message_log, point.len());
    let roots = pcs::whir::eval_sk_at_vks(message_log);
    queries.iter().zip(weights).fold(S::u(0), |acc, (&query, &weight)| {
        let mut basis = query;
        let mut product = weight;
        for (k, &x) in point.iter().enumerate() {
            product = product * (S::u(1) + x * (S::u(1) + basis * S::c(F192::from(roots[k].inv()))));
            basis = basis * basis + S::c(F192::from(roots[k])) * basis;
        }
        acc + product
    })
}

enum Weight {
    Query(usize, Vec<S>, Vec<S>),
    Ood(Vec<S>),
}
struct Glued {
    scalar: S,
    start: usize,
    weight: Weight,
}

fn verify_opening(layout: &Layout, root: [S; 2], claims: &[(Vec<S>, S)], proof: &RawProof) {
    let config =
        pcs::whir::config_for_shape(layout.log_n, pcs::whir::LOG_INV_RATE_0, layout.fold, layout.reduction).unwrap();
    let mut seed = vec![(root[0], 16), (root[1], 16)];
    for (point, value) in claims {
        seed.extend(point.iter().chain([value]).map(|&x| (x, 24)));
    }
    let public = hash(&seed);
    let iv = digest_constant(&primitives::hash::hash(b"flock-quotient-opening"));
    let mut t = Transcript::new(proof, iv, public);
    let lambda = t.sample();
    let lambdas = powers(lambda, claims.len());
    let target = claims
        .iter()
        .zip(&lambdas)
        .fold(S::u(0), |acc, ((_, v), &l)| acc + l * (*v));
    let log_lane = layout.log_n - layout.fold;
    let lanes: Vec<Vec<S>> = claims
        .iter()
        .map(|(point, _)| {
            layout
                .lane_map()
                .iter()
                .map(|&(chunk, j)| {
                    let index = (chunk << (layout.log_chunk - log_lane)) | j;
                    point[log_lane..].iter().enumerate().fold(S::u(1), |acc, (k, &p)| {
                        acc * if (index >> k) & 1 == 1 { p } else { S::u(1) + p }
                    })
                })
                .collect()
        })
        .collect();
    let basis = |point: &[S]| {
        let low = &point[..log_lane];
        let high = &point[log_lane..];
        let lane_eq = kernel(high);
        claims
            .iter()
            .zip(&lambdas)
            .zip(&lanes)
            .fold(S::u(0), |acc, (((p, _), &l), lanes)| {
                let on_lanes = lanes.iter().zip(&lane_eq).fold(S::u(0), |acc, (&w, &e)| acc + w * e);
                acc + l * eq(&p[..log_lane], low) * on_lanes
            })
    };
    verify_basis_opening_inner(
        &mut t,
        &config,
        layout.log_n,
        layout.lane_map().len(),
        root,
        target,
        basis,
    );
    t.finish();
}

pub(crate) fn verify_basis_opening(
    t: &mut Transcript<'_>,
    log_n: usize,
    root: [S; 2],
    target: S,
    basis: impl Fn(&[S]) -> S,
) {
    let config = pcs::whir::config_for_rate(log_n, 1).expect("supported WHIR shape");
    verify_basis_opening_inner(t, &config, log_n, 1 << config.initial_k, root, target, basis);
}

fn verify_basis_opening_inner(
    t: &mut Transcript<'_>,
    config: &pcs::whir::VerifierConfig,
    log_n: usize,
    live_lanes: usize,
    root: [S; 2],
    target: S,
    basis: impl Fn(&[S]) -> S,
) {
    let folds_per_level: Vec<_> = std::iter::once(config.initial_k)
        .chain(config.level_ks.iter().copied())
        .collect();
    let mut running = t.quad(target);
    let mut folds = Vec::new();
    let mut glued = Vec::new();
    let mut current_root = root;
    for (level, &count) in folds_per_level.iter().enumerate() {
        let start = folds.len();
        for _ in 0..count {
            let x = t.sample();
            folds.push(x);
            running = t.quad(poly(running, x));
        }
        let message_log = log_n - folds.len();
        let last = level + 1 == folds_per_level.len();
        let mut pending = Vec::new();
        let mut next_root = None;
        let mut residual = Vec::new();
        if last {
            residual = t.scalars(1 << message_log);
        } else {
            next_root = Some(t.root());
            for _ in 0..config.ood_samples[level + 1] {
                let z = (0..message_log).map(|_| t.sample()).collect();
                let value = t.next();
                let intro = t.quad(value);
                pending.push((intro, Weight::Ood(z)));
            }
        }
        t.grind(config.grinding_bits[level]);
        let depth = message_log + config.log_inv_rates[level];
        let queries = t.queries(depth, config.queries[level]);
        let lambda = t.sample();
        let weights = powers(lambda, queries.len());
        let rows = t.merkle(current_root, depth, &queries, 1 << count, level == 0, live_lanes);
        let lane_weights = kernel(&folds[start..]);
        let enforced = rows.iter().zip(&weights).fold(S::u(0), |acc, (row, &w)| {
            assert_eq!(row.len(), lane_weights.len());
            acc + w * row.iter().zip(&lane_weights).fold(S::u(0), |s, (&v, &e)| s + v * e)
        });
        pending.push((t.quad(enforced), Weight::Query(message_log, queries, weights)));
        let mut scalar = S::u(1);
        for (intro, weight) in pending {
            scalar = scalar * lambda;
            for i in 0..3 {
                running[i] = running[i] + scalar * intro[i];
            }
            glued.push(Glued {
                scalar,
                start: folds.len(),
                weight,
            });
        }
        if last {
            let mut tail = Vec::new();
            let mut running_target = S::u(0);
            for j in 0..message_log {
                let x = t.sample();
                tail.push(x);
                running_target = poly(running, x);
                if j + 1 < message_log {
                    running = t.quad(running_target);
                }
            }
            let mut point = folds.clone();
            point.extend_from_slice(&tail);
            point.rotate_left(config.initial_k);
            let mut weight = basis(&point);
            for claim in glued {
                let mut p = folds[claim.start..].to_vec();
                p.extend_from_slice(&tail);
                let at = match claim.weight {
                    Weight::Ood(z) => eq(&z, &p),
                    Weight::Query(m, q, w) => induced(m, &q, &w, &p),
                };
                weight = weight + claim.scalar * at;
            }
            (weight * mle(&residual, &tail)).assert_eq(running_target);
            return;
        }
        current_root = next_root.unwrap();
    }
    unreachable!()
}

pub fn record(child: &Child) -> Trace {
    record_with_identity(child, None)
}

pub fn record_bound(child: &Child, app_id: &Hash) -> Trace {
    record_with_identity(child, Some(app_id))
}

fn record_with_identity(child: &Child, app_id: Option<&Hash>) -> Trace {
    trace::start();
    trace::mark("piop");
    let statement = child.statement.halves().map(|x| S::input(x).slice(0, 128));
    // Statement::halves reads each 16-byte block big endian; the transcript hashes its little-endian limbs.
    let public = hash(&statement.iter().map(|&x| (x, 16)).collect::<Vec<_>>());
    let label = [b"flock-quotient-vm-1".as_slice(), &child.index_root].concat();
    let iv = digest_constant(&primitives::hash::hash(&label));
    let raw = RawProof {
        stream: child.piop.stream.clone(),
        merkle: Vec::new(),
    };
    let mut piop = Piop {
        transcript: Transcript::new(&raw, iv, public),
        statement,
    };
    let reduced = quotient::reduce(&mut piop, child.log_rows).unwrap();
    let layouts = [
        quotient::witness_layout(child.log_rows),
        quotient::quotient_layout(child.log_rows),
    ];
    trace::mark("witness_opening");
    verify_opening(&layouts[0], reduced.roots[0], &[reduced.witness], &child.openings[0]);
    trace::mark("wiring_opening");
    let m = child.log_rows + 2;
    let index_layout = Layout::new(m, m, (m, 6, 3), &[(0, 1 << m)]);
    verify_opening(
        &index_layout,
        digest_constant(&child.index_root),
        &[reduced.wiring],
        &child.openings[1],
    );
    let sum_point = quotient::sum_point(child.log_rows).into_iter().map(S::c).collect();
    trace::mark("quotient_opening");
    verify_opening(
        &layouts[1],
        reduced.roots[1],
        &[reduced.quotient, (sum_point, reduced.sum)],
        &child.openings[2],
    );
    let output = if let Some(id) = app_id {
        let id = digest_constant(id);
        let mut parts = vec![(id[0], 16), (id[1], 16)];
        parts.extend(statement.iter().map(|&s| (s, 16)));
        hash(&parts)
    } else {
        public
    };
    let mut trace = trace::take();
    trace.public = output.to_vec();
    trace
}

#[cfg(test)]
mod tests {
    use super::*;
    use fiat_shamir::merkle::RawMerklePath;

    #[test]
    fn merkle_paths_enforce_omitted_zero_lanes() {
        for prefix in [0u64, 1] {
            trace::start();
            let leaf_data = vec![primitives::field::F64(prefix), primitives::field::F64(37)];
            let sibling = [17u8; 32];
            let path = RawMerklePath {
                leaf_index: 0,
                leaf_data,
                path: vec![sibling],
            };
            let root = path.root(0);
            let proof = RawProof {
                stream: Vec::new(),
                merkle: vec![path],
            };
            let mut transcript = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
            let query = S::input(F192::ZERO).slice(0, 1);
            transcript.merkle(digest_constant(&root), 1, &[query], 2, true, 1);
            let trace = trace::take();
            assert_eq!(trace.satisfied(), prefix == 0);
            let lower = trace.lower(1 << 20).ok().unwrap();
            let eval =
                |inputs: &[bool]| circuit_suite::read_statement(&lower.circuit.values(inputs), &lower.sources)[0];
            assert_eq!(eval(&lower.inputs), u8::from(prefix == 0));
            if prefix == 0 {
                let mut bad = lower.inputs.clone();
                bad[0] = true;
                assert_eq!(eval(&bad), 0, "path must follow the transcript query bit");
            }
        }
    }
}
