#[cfg(all(feature = "keccak-merkle-cap", feature = "keccak-merkle-arity4"))]
compile_error!("quaternary caps are not yet supported");
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

#[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
fn cap_input_digest(digest: &Hash) -> [S; 2] {
    hash_to_scalars(digest).map(|v| {
        let word = S::input(v);
        let low = word.slice(0, 128);
        word.assert_eq(low);
        low
    })
}

#[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
fn cap_select(nodes: &[[S; 2]], query: S, start: usize, sibling: bool) -> [S; 2] {
    let mut selected = nodes.to_vec();
    let mut level = 0;
    while selected.len() > 1 {
        let bit = query.slice(start + level, 1);
        let bit = if sibling && level == 0 { S::u(1) + bit } else { bit };
        selected = selected
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| std::array::from_fn(|i| S::select(bit, pair[0][i], pair[1][i])))
            .collect();
        level += 1;
    }
    selected[0]
}

#[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
fn cap_arity(width: usize) -> usize {
    if primitives::protocol_hash::MERKLE_ARITY4 && width >= 4 {
        4
    } else {
        2
    }
}

#[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
fn cap_fixed_child(nodes: &[[S; 2]], query: S, start: usize, arity: usize, slot: usize) -> [S; 2] {
    let selected: Vec<_> = nodes.chunks(arity).map(|group| group[slot]).collect();
    cap_select(&selected, query, start + arity.ilog2() as usize, false)
}

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
    placeholder: bool,
    well_formed: bool,
    state: [S; 2],
    #[cfg(feature = "keccak-batched-transcript")]
    pending: Vec<S>,
    cursor: usize,
    phase: usize,
}

impl<'a> Transcript<'a> {
    pub(crate) fn new(proof: &'a RawProof, iv: [S; 2], public: [S; 2]) -> Self {
        let state = hash(&[(iv[0], 16), (iv[1], 16), (public[0], 16), (public[1], 16)]);
        Self {
            proof: std::borrow::Cow::Borrowed(proof),
            compressed: None,
            placeholder: false,
            well_formed: true,
            state,
            #[cfg(feature = "keccak-batched-transcript")]
            pending: Vec::new(),
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
            placeholder: false,
            well_formed: true,
            state,
            #[cfg(feature = "keccak-batched-transcript")]
            pending: Vec::new(),
            cursor: 0,
            phase: 0,
        }
    }
    /// Generate dummy inputs for a branch whose verification equations the
    /// caller explicitly disables. This does not accept or verify a proof.
    pub(crate) fn placeholder(state: [S; 2]) -> Self {
        Self {
            proof: std::borrow::Cow::Owned(RawProof {
                stream: Vec::new(),
                merkle: Vec::new(),
            }),
            compressed: None,
            placeholder: true,
            well_formed: true,
            state,
            #[cfg(feature = "keccak-batched-transcript")]
            pending: Vec::new(),
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
    #[cfg(feature = "keccak-batched-transcript")]
    fn batch(&mut self, tag: u64) {
        let mut parts = vec![
            (self.state[0], 16),
            (self.state[1], 16),
            (S::u(self.pending.len() as u64), 8),
        ];
        parts.extend(self.pending.drain(..).map(|x| (x, 24)));
        parts.push((S::u(tag), 8));
        self.state = hash(&parts);
    }
    #[cfg(feature = "keccak-batched-transcript")]
    fn flush(&mut self) {
        if !self.pending.is_empty() {
            self.batch(1);
        }
    }
    fn step(&mut self, x: S, tag: u64) -> [S; 2] {
        #[cfg(feature = "keccak-batched-transcript")]
        {
            if tag == 1 {
                self.pending.push(x);
                return self.state;
            }
            if tag == 2 {
                self.batch(2);
                return self.state;
            }
            self.flush();
        }
        self.state = hash(&[(self.state[0], 16), (self.state[1], 16), (x, 24), (S::u(tag), 8)]);
        self.state
    }
    pub(crate) fn sample(&mut self) -> S {
        let h = self.step(S::u(0), 2);
        S::pack(&[(h[0], 128), (h[1], 64)])
    }
    fn raw(&mut self) -> S {
        let x = S::input(if self.placeholder {
            F192::ZERO
        } else {
            self.proof.stream.get(self.cursor).copied().unwrap_or_else(|| {
                self.well_formed = false;
                F192::ZERO
            })
        });
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
            a.assert_eq(a.slice(0, 128));
        }
        h
    }
    pub(crate) fn quad(&mut self, target: S) -> [S; 3] {
        let a = self.next();
        let b = self.next();
        [a, target + b, b]
    }
    pub(crate) fn grind(&mut self, bits: usize) {
        #[cfg(feature = "keccak-batched-transcript")]
        self.flush();
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
        let words = if base { lanes } else { 3 * lanes };
        let dummy_paths = || {
            queries
                .iter()
                .map(|query| fiat_shamir::merkle::RawMerklePath {
                    leaf_index: query.value().c0 as usize,
                    leaf_data: vec![primitives::field::F64::ZERO; words],
                    path: vec![[0; 32]; fiat_shamir::merkle::path_hash_count(depth)],
                })
                .collect::<Vec<_>>()
        };
        let expanded;
        let paths = if self.placeholder {
            expanded = dummy_paths();
            self.phase += queries.len();
            expanded.as_slice()
        } else if let Some(proof) = self.compressed {
            let query_values: Vec<_> = queries.iter().map(|q| q.value().c0 as usize).collect();
            let row_words = if base { live_lanes } else { 3 * lanes };
            let opened = fiat_shamir::merkle::scalars_to_hash(&root.map(S::value))
                .ok()
                .and_then(|root_bytes| {
                    proof
                        .merkle
                        .get(self.phase)?
                        .open(&root_bytes, 1 << depth, &query_values, row_words, words)
                });
            expanded = opened.unwrap_or_else(|| {
                self.well_formed = false;
                dummy_paths()
            });
            self.phase += 1;
            expanded.as_slice()
        } else {
            let supplied = self.proof.merkle.get(self.phase..self.phase + queries.len());
            self.phase += queries.len();
            match supplied {
                Some(paths)
                    if paths.iter().all(|p| {
                        p.path.len() == fiat_shamir::merkle::path_hash_count(depth) && p.leaf_data.len() == words
                    }) =>
                {
                    paths
                }
                _ => {
                    self.well_formed = false;
                    expanded = dummy_paths();
                    expanded.as_slice()
                }
            }
        };
        let section = trace::section_name();
        #[cfg(feature = "keccak-merkle-cap")]
        let cap_height = depth.min(queries.len().ilog2() as usize).min(4);
        #[cfg(feature = "keccak-quad-cap")]
        let cap_height = if queries.len() == 1 {
            0
        } else {
            depth.min((queries.len().ilog2() as usize).min(6) / 2 * 2 + depth % 2)
        };
        #[cfg(not(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap")))]
        let cap_height = 0;
        let cut = depth - cap_height;
        #[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
        let cap = self.merkle_cap(root, depth, cap_height, queries, paths);
        let mut rows = Vec::new();
        for (&query, path) in queries.iter().zip(paths) {
            assert_eq!(path.path.len(), fiat_shamir::merkle::path_hash_count(depth));
            let words = if base { lanes } else { 3 * lanes };
            assert_eq!(path.leaf_data.len(), words);
            let leaf: Vec<S> = path
                .leaf_data
                .iter()
                .map(|x| {
                    // Serialized leaves are F64 words. State that range in the
                    // circuit so a private compiler can use a 64-bit source.
                    let word = S::input(F192::from(*x));
                    let low = word.slice(0, 64);
                    word.assert_eq(low);
                    low
                })
                .collect();
            if base {
                for &word in &leaf[..lanes - live_lanes] {
                    word.assert_eq(S::u(0));
                }
            }
            trace::mark(&format!(
                "{section}/whir-leaf/phase-{}/depth-{depth}/words-{words}/queries-{}",
                self.phase,
                queries.len()
            ));
            let mut node = hash(
                &leaf
                    .iter()
                    .enumerate()
                    .map(|(i, &w)| {
                        // Omitted lanes are already constrained to zero above.
                        // Expose that fixed prefix to compiler constant folding.
                        (if base && i < lanes - live_lanes { S::u(0) } else { w }, 8)
                    })
                    .collect::<Vec<_>>(),
            );
            trace::mark(&format!(
                "{section}/whir-path/phase-{}/depth-{depth}/queries-{}",
                self.phase,
                queries.len()
            ));
            let mut level = 0;
            let mut cursor = 0;
            while level < cut {
                let arity = if primitives::protocol_hash::MERKLE_ARITY4 && cut - level >= 2 {
                    4
                } else {
                    2
                };
                let siblings: Vec<[S; 2]> = path.path[cursor..cursor + arity - 1]
                    .iter()
                    .map(|sibling| {
                        hash_to_scalars(sibling).map(|x| {
                            let word = S::input(x);
                            #[cfg(feature = "keccak-canonical-route")]
                            {
                                word
                            }
                            #[cfg(not(feature = "keccak-canonical-route"))]
                            {
                                let low = word.slice(0, 128);
                                word.assert_eq(low);
                                low
                            }
                        })
                    })
                    .collect();
                let bit = query.slice(level, 1);
                let children: Vec<[S; 2]> = if arity == 2 {
                    vec![
                        std::array::from_fn(|i| S::select(bit, node[i], siblings[0][i])),
                        std::array::from_fn(|i| S::select(bit, siblings[0][i], node[i])),
                    ]
                } else {
                    let high = query.slice(level + 1, 1);
                    let choices = [
                        [node, siblings[0], siblings[1], siblings[2]],
                        [siblings[0], node, siblings[1], siblings[2]],
                        [siblings[0], siblings[1], node, siblings[2]],
                        [siblings[0], siblings[1], siblings[2], node],
                    ];
                    (0..4)
                        .map(|slot| {
                            std::array::from_fn(|i| {
                                let lo = S::select(bit, choices[0][slot][i], choices[1][slot][i]);
                                let hi = S::select(bit, choices[2][slot][i], choices[3][slot][i]);
                                S::select(high, lo, hi)
                            })
                        })
                        .collect()
                };
                // A Boolean query permutes node + siblings bijectively.
                // Canonicality of every output therefore enforces canonicality
                // of every supplied sibling, including those not in our slot.
                #[cfg(feature = "keccak-canonical-route")]
                let children: Vec<[S; 2]> = children
                    .into_iter()
                    .map(|child| {
                        child.map(|word| {
                            let low = word.slice(0, 128);
                            word.assert_eq(low);
                            low
                        })
                    })
                    .collect();
                let parts: Vec<_> = children
                    .iter()
                    .flat_map(|child| child.iter().map(|&v| (v, 16)))
                    .collect();
                node = hash(&parts);
                cursor += arity - 1;
                level += if arity == 4 { 2 } else { 1 };
            }
            trace::mark(&section);
            #[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
            {
                let expected = cap_select(&cap[0], query, cut, false);
                for i in 0..2 {
                    node[i].assert_eq(expected[i]);
                }
                // Bind all supplied siblings, even if another query also
                // reconstructs their region. Only their hashing is shared.
                let mut bits = cut;
                for nodes in cap.iter().take(cap.len() - 1) {
                    let arity = cap_arity(nodes.len());
                    let children: Vec<_> = (0..arity)
                        .map(|slot| cap_fixed_child(nodes, query, bits, arity, slot))
                        .collect();
                    for rank in 0..arity - 1 {
                        #[cfg(feature = "keccak-quad-cap-fast")]
                        let supplied = hash_to_scalars(&path.path[cursor + rank]).map(S::input);
                        #[cfg(not(feature = "keccak-quad-cap-fast"))]
                        let supplied = cap_input_digest(&path.path[cursor + rank]);
                        // The equality below is over the full F192 value.
                        // Its selected cap digest is already canonical, so an
                        // additional range decomposition of this alias is redundant.
                        let choices: Vec<_> = (0..arity)
                            .map(|own| children[if rank < own { rank } else { rank + 1 }])
                            .collect();
                        let expected = cap_select(&choices, query, bits, false);
                        for i in 0..2 {
                            supplied[i].assert_eq(expected[i]);
                        }
                    }
                    cursor += arity - 1;
                    bits += arity.ilog2() as usize;
                }
            }
            #[cfg(not(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap")))]
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
    #[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
    fn merkle_cap(
        &self,
        root: [S; 2],
        depth: usize,
        height: usize,
        queries: &[S],
        paths: &[fiat_shamir::merkle::RawMerklePath],
    ) -> Vec<Vec<[S; 2]>> {
        if height == 0 {
            return vec![vec![root]];
        }
        let cut = depth - height;
        let mut widths = vec![1usize << height];
        let mut shifts = vec![0usize];
        while *widths.last().unwrap() > 1 {
            let width = *widths.last().unwrap();
            let arity = cap_arity(width);
            widths.push(width / arity);
            shifts.push(shifts.last().unwrap() + arity.ilog2() as usize);
        }
        let mut known: Vec<Vec<Hash>> = widths.iter().map(|&width| vec![[0; 32]; width]).collect();
        for (&query, path) in queries.iter().zip(paths) {
            let bytes: Vec<_> = path.leaf_data.iter().flat_map(|w| w.0.to_le_bytes()).collect();
            let mut digest = fiat_shamir::merkle::hash_leaf(&bytes);
            let mut index = query.value().c0 as usize;
            let mut cursor = 0;
            let mut bits = 0;
            while bits < depth {
                let arity = cap_arity(1usize << (depth - bits));
                let own = index % arity;
                let mut children = Vec::new();
                for child in 0..arity {
                    children.push(if child == own {
                        digest
                    } else {
                        let sibling = path.path[cursor];
                        cursor += 1;
                        sibling
                    });
                }
                if bits >= cut {
                    let level = shifts.iter().position(|&shift| cut + shift == bits).unwrap();
                    let start = index / arity * arity;
                    known[level][start..start + arity].copy_from_slice(&children);
                }
                let bytes: Vec<_> = children.iter().flat_map(|h| h.iter().copied()).collect();
                digest = primitives::protocol_hash::hash(&bytes);
                index /= arity;
                bits += arity.ilog2() as usize;
            }
            *known.last_mut().unwrap().first_mut().unwrap() = digest;
        }
        let mut layers = vec![known[0].iter().map(cap_input_digest).collect::<Vec<_>>()];
        #[cfg(feature = "keccak-quad-cap-fast")]
        let mut present: Vec<_> = {
            let mut absent = vec![S::u(1); 1 << height];
            for &query in queries {
                let bits: Vec<_> = (0..height).map(|bit| query.slice(cut + bit, 1)).collect();
                // Product indicators form a Boolean one-hot vector because
                // every query bit is constrained. Share their common prefixes.
                let matches = kernel(&bits);
                for (absent, matched) in absent.iter_mut().zip(matches) {
                    *absent = *absent * (S::u(1) + matched);
                }
            }
            absent.into_iter().map(|absent| S::u(1) + absent).collect()
        };
        #[cfg(not(feature = "keccak-quad-cap-fast"))]
        let mut present: Vec<_> = (0..1 << height)
            .map(|index| {
                let absent = queries.iter().fold(S::u(1), |absent, &query| {
                    let matches = (0..height).fold(S::u(1), |same, bit| {
                        let value = query.slice(cut + bit, 1);
                        same * if (index >> bit) & 1 == 0 {
                            S::u(1) + value
                        } else {
                            value
                        }
                    });
                    absent * (S::u(1) + matches)
                });
                S::u(1) + absent
            })
            .collect();
        for level in 1..widths.len() {
            let mut parents = Vec::new();
            let mut parent_present = Vec::new();
            let arity = cap_arity(widths[level - 1]);
            for (index, children) in layers[level - 1].chunks(arity).enumerate() {
                let absent = present[index * arity..(index + 1) * arity]
                    .iter()
                    .fold(S::u(1), |absent, &p| absent * (S::u(1) + p));
                let occupied = S::u(1) + absent;
                let parts: Vec<_> = children
                    .iter()
                    .flat_map(|child| child.iter().map(|&v| (v, 16)))
                    .collect();
                let computed = hash(&parts);
                let opaque = cap_input_digest(&known[level][index]);
                parents.push(std::array::from_fn(|i| S::select(occupied, opaque[i], computed[i])));
                parent_present.push(occupied);
            }
            layers.push(parents);
            present = parent_present;
        }
        present[0].assert_eq(S::u(1));
        for i in 0..2 {
            layers.last().unwrap()[0][i].assert_eq(root[i]);
        }
        layers
    }

    pub(crate) fn finish(&self) {
        let consumed = self.placeholder
            || (self.cursor == self.proof.stream.len()
                && self.phase == self.compressed.map_or(self.proof.merkle.len(), |p| p.merkle.len()));
        // Witness decoding failures become a fixed acceptance equation. The
        // caller gates it with the other equations for an inactive branch.
        S::input(F192::new(u64::from(self.well_formed && consumed), 0, 0)).assert_eq(S::u(1));
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
    let iv = digest_constant(&primitives::protocol_hash::hash(b"flock-quotient-opening"));
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

pub(crate) fn verify_basis_opening_lanes_rate(
    t: &mut Transcript<'_>,
    log_n: usize,
    log_inv_rate: usize,
    live_lanes: usize,
    root: [S; 2],
    target: S,
    basis: impl Fn(&[S]) -> S,
) {
    let config = pcs::whir::config_for_rate(log_n, log_inv_rate).expect("supported WHIR shape");
    assert!((1..=1 << config.initial_k).contains(&live_lanes));
    verify_basis_opening_inner(t, &config, log_n, live_lanes, root, target, basis);
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
    let iv = digest_constant(&primitives::protocol_hash::hash(&label));
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
    fn merkle_sources_enforce_serialized_word_and_digest_ranges() {
        trace::start();
        let path = RawMerklePath {
            leaf_index: 0,
            leaf_data: vec![primitives::field::F64(37)],
            path: vec![[17; 32]],
        };
        let root = path.root(0);
        let proof = RawProof {
            stream: Vec::new(),
            merkle: vec![path],
        };
        let mut t = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
        let query = S::input(F192::ZERO).slice(0, 1);
        t.merkle(digest_constant(&root), 1, &[query], 1, true, 1);
        t.finish();
        let mut program = trace::take();
        assert!(program.satisfied());
        let ranges: Vec<_> = program
            .checks
            .iter()
            .filter_map(|&(source, narrow)| {
                if let trace::Op::Slice(input, 0, width) = program.nodes[narrow.0].op
                    && input == source
                    && matches!(program.nodes[source.0].op, trace::Op::Input)
                {
                    Some((source.0, width))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            ranges.iter().map(|(_, width)| *width).collect::<Vec<_>>(),
            if cfg!(feature = "keccak-canonical-route") {
                vec![64]
            } else {
                vec![64, 128, 128]
            }
        );
        for (input, width) in ranges {
            let old = program.nodes[input].value;
            let high = if width == 64 {
                F192::new(0, 1, 0)
            } else {
                F192::new(0, 0, 1)
            };
            program.nodes[input].value += high;
            assert!(!program.satisfied(), "discarded high bits must be constrained");
            program.nodes[input].value = old;
        }
    }

    #[cfg(feature = "keccak-canonical-route")]
    #[test]
    fn routed_children_reject_coherent_high_limb_mutations_in_every_slot() {
        use primitives::field::F64;
        fn replay(mut p: Trace, target: usize) -> Trace {
            fn project(v: F192, start: usize, len: usize) -> F192 {
                let x = [v.c0, v.c1, v.c2];
                let mut out = [0u64; 3];
                for bit in 0..len {
                    out[bit / 64] |= ((x[(start + bit) / 64] >> ((start + bit) % 64)) & 1) << (bit % 64);
                }
                F192::new(out[0], out[1], out[2])
            }
            let mut high = std::collections::HashMap::new();
            for at in 0..p.nodes.len() {
                let get = |s: S| p.nodes[s.0].value;
                let value = match p.nodes[at].op.clone() {
                    trace::Op::Constant => p.nodes[at].value,
                    trace::Op::Input => p.nodes[at].value + if at == target { F192::new(0, 0, 1) } else { F192::ZERO },
                    trace::Op::Add(a, b) => get(a) + get(b),
                    trace::Op::Mul(a, b) => get(a) * get(b),
                    trace::Op::Frobenius(a) => get(a).frobenius(),
                    trace::Op::Slice(a, start, len) => project(get(a), start, len),
                    trace::Op::Pack(parts) => {
                        let mut out = [0u64; 3];
                        let mut offset = 0;
                        for (a, len) in parts {
                            let v = get(a);
                            let x = [v.c0, v.c1, v.c2];
                            for bit in 0..len {
                                out[(offset + bit) / 64] |= ((x[bit / 64] >> (bit % 64)) & 1) << ((offset + bit) % 64);
                            }
                            offset += len;
                        }
                        F192::new(out[0], out[1], out[2])
                    }
                    trace::Op::Select(bit, a, b) => {
                        if get(bit) == F192::ZERO {
                            get(a)
                        } else {
                            get(b)
                        }
                    }
                    trace::Op::Hash(parts) => {
                        let mut bytes = Vec::new();
                        for (a, len) in parts {
                            let v = get(a);
                            let all: Vec<_> = [v.c0, v.c1, v.c2].iter().flat_map(|x| x.to_le_bytes()).collect();
                            bytes.extend_from_slice(&all[..len]);
                        }
                        let digest = hash_to_scalars(&primitives::protocol_hash::hash(&bytes));
                        high.insert(at, digest[1]);
                        digest[0]
                    }
                    trace::Op::HashHigh(a) => high[&a.0],
                };
                p.nodes[at].value = value;
            }
            p
        }
        for depth in 1..=6 {
            let n = 1usize << depth;
            let rows: Vec<_> = (0..n).map(|i| F64(i as u64 + 1)).collect();
            let bytes: Vec<_> = rows.iter().flat_map(|v| v.0.to_le_bytes()).collect();
            let tree = pcs::merkle::merkle_tree(&bytes, n);
            let root = *tree.last().unwrap();
            for q in [0, n / 4, n / 2, n - 1] {
                let paths = fiat_shamir::merkle::PrunedMerklePaths::prune(&tree, n, &[q], |i| vec![rows[i]])
                    .open(&root, n, &[q], 1, 1)
                    .unwrap();
                trace::start();
                let proof = RawProof {
                    stream: Vec::new(),
                    merkle: paths,
                };
                let mut t = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
                let query = S::input(F192::from(F64(q as u64))).slice(0, depth);
                t.merkle(digest_constant(&root), depth, &[query], 1, true, 1);
                t.finish();
                let p = trace::take();
                assert!(p.satisfied());
                let inputs: Vec<_> = p
                    .nodes
                    .iter()
                    .enumerate()
                    .filter_map(|(at, node)| (node.op == trace::Op::Input && node.value.c1 != 0).then_some(at))
                    .collect();
                assert_eq!(inputs.len(), 2 * fiat_shamir::merkle::path_hash_count(depth));
                for input in inputs {
                    let bad = replay(p.clone(), input);
                    assert!(!bad.satisfied(), "depth={depth} q={q} input={input}");
                    let lowered = crate::private_trace::lower(&p, &bad).unwrap();
                    let v = &lowered.values;
                    assert!(
                        lowered
                            .circuit
                            .rows
                            .iter()
                            .any(|&[a, b, c, d]| v[a] * v[b] + v[c] != v[d]),
                        "raw native rows reject high limbs after coherent replay"
                    );
                }
            }
        }
    }

    #[cfg(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap"))]
    #[test]
    fn cap_binds_every_sibling_and_query_in_fixed_shape() {
        use primitives::field::F64;
        let rows: Vec<_> = (0..64).map(|i| F64(i + 1)).collect();
        let bytes: Vec<_> = rows.iter().flat_map(|w| w.0.to_le_bytes()).collect();
        let tree = pcs::merkle::merkle_tree(&bytes, 64);
        let root = *tree.last().unwrap();
        let make = |q: &[usize]| {
            fiat_shamir::merkle::PrunedMerklePaths::prune(&tree, 64, q, |i| vec![rows[i]])
                .open(&root, 64, q, 1, 1)
                .unwrap()
        };
        let record = |queries: &[usize], paths: Vec<RawMerklePath>| {
            trace::start();
            let proof = RawProof {
                stream: Vec::new(),
                merkle: paths,
            };
            let mut t = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
            let q: Vec<_> = queries
                .iter()
                .map(|&q| S::input(F192::from(F64(q as u64))).slice(0, 6))
                .collect();
            t.merkle(digest_constant(&root), 6, &q, 1, true, 1);
            t.finish();
            trace::take()
        };
        let sparse = [0; 8];
        let distributed = [0, 8, 16, 24, 32, 40, 48, 63];
        let a = record(&sparse, make(&sparse));
        let b = record(&distributed, make(&distributed));
        assert!(a.satisfied() && b.satisfied());
        assert!(a.same_program(&b));
        for q in [&sparse, &distributed] {
            for level in 0..fiat_shamir::merkle::path_hash_count(6) {
                for query in 0..q.len() {
                    let mut bad = make(q);
                    bad[query].path[level][0] ^= 1;
                    assert!(!record(q, bad).satisfied(), "sibling query={query} level={level}");
                }
            }
            let mut bad = make(q);
            bad[0].leaf_data[0] += F64::ONE;
            assert!(!record(q, bad).satisfied(), "wrong leaf");
            let mut badq = *q;
            badq[0] ^= 1;
            assert!(!record(&badq, make(q)).satisfied(), "wrong query challenge");
        }
    }

    #[cfg(feature = "keccak-merkle-arity4")]
    #[test]
    fn quad_paths_bind_every_sibling_leaf_packing_and_query() {
        use primitives::field::F64;
        for depth in 1..=6 {
            let count = 1usize << depth;
            let rows: Vec<_> = (0..count).map(|i| F64(i as u64 + 1)).collect();
            let bytes: Vec<_> = rows.iter().flat_map(|w| w.0.to_le_bytes()).collect();
            let tree = pcs::merkle::merkle_tree(&bytes, count);
            let root = *tree.last().unwrap();
            let queries = [0, count - 1, count / 2, 0];
            let proof = fiat_shamir::merkle::PrunedMerklePaths::prune(&tree, count, &queries, |q| vec![rows[q]]);
            let paths = proof.open(&root, count, &queries, 1, 1).unwrap();
            for (&q, path) in queries.iter().zip(&paths) {
                assert_eq!(path.root(q), root);
            }
            let record = |q: &[usize], paths: Vec<RawMerklePath>| {
                trace::start();
                let proof = RawProof {
                    stream: Vec::new(),
                    merkle: paths,
                };
                let mut t = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
                let q: Vec<_> = q
                    .iter()
                    .map(|&q| S::input(F192::from(F64(q as u64))).slice(0, depth))
                    .collect();
                t.merkle(digest_constant(&root), depth, &q, 1, true, 1);
                t.finish();
                trace::take()
            };
            assert!(record(&queries, paths.clone()).satisfied());
            for position in 0..paths[0].path.len() {
                let mut bad = paths.clone();
                bad[0].path[position][0] ^= 1;
                assert!(
                    !record(&queries, bad).satisfied(),
                    "wrong sibling depth={depth} position={position}"
                );
            }
            let mut bad = paths.clone();
            bad[0].leaf_data[0] += F64::ONE;
            assert!(!record(&queries, bad).satisfied());
            let mut badq = queries;
            badq[0] ^= 1;
            assert!(!record(&badq, paths).satisfied());
            let mut bad = proof.clone();
            bad.leaf_data[0].push(F64::ZERO);
            assert!(bad.open(&root, count, &queries, 1, 1).is_none());
            for position in 0..proof.sibling_hashes.len() {
                let mut bad = proof.clone();
                bad.sibling_hashes[position][0] ^= 1;
                assert!(bad.open(&root, count, &queries, 1, 1).is_none());
            }
        }
    }

    #[cfg(feature = "keccak-quad-cap")]
    #[test]
    fn full_size_quad_cap_handles_sparse_and_distributed_occupancy() {
        use primitives::field::F64;
        let depth = 9;
        let rows: Vec<_> = (0..512).map(|i| F64(i + 1)).collect();
        let bytes: Vec<_> = rows.iter().flat_map(|w| w.0.to_le_bytes()).collect();
        let tree = pcs::merkle::merkle_tree(&bytes, 512);
        let root = *tree.last().unwrap();
        let make = |q: &[usize]| {
            fiat_shamir::merkle::PrunedMerklePaths::prune(&tree, 512, q, |i| vec![rows[i]])
                .open(&root, 512, q, 1, 1)
                .unwrap()
        };
        let record = |q: &[usize], paths: Vec<RawMerklePath>| {
            trace::start();
            let proof = RawProof {
                stream: Vec::new(),
                merkle: paths,
            };
            let mut t = Transcript::new(&proof, digest_constant(&[0; 32]), digest_constant(&[1; 32]));
            let queries: Vec<_> = q
                .iter()
                .map(|&q| S::input(F192::from(F64(q as u64))).slice(0, depth))
                .collect();
            t.merkle(digest_constant(&root), depth, &queries, 1, true, 1);
            t.finish();
            trace::take()
        };
        let sparse = vec![0; 112];
        let distributed: Vec<_> = (0..112).map(|i| i * 73 % 512).collect();
        let a = record(&sparse, make(&sparse));
        let b = record(&distributed, make(&distributed));
        assert!(a.satisfied() && b.satisfied());
        assert!(
            a.same_program(&b),
            "128 cap regions must keep a fixed key under arbitrary occupancy"
        );
        for q in [&sparse, &distributed] {
            let mut bad = make(q);
            bad[0].path.last_mut().unwrap()[0] ^= 1;
            assert!(!record(q, bad).satisfied(), "shared upper sibling remains bound");
            #[cfg(feature = "keccak-quad-cap-fast")]
            {
                let paths = make(q);
                let half = hash_to_scalars(paths[0].path.last().unwrap())[0];
                let mut program = record(q, paths);
                let input = program
                    .nodes
                    .iter()
                    .rposition(|n| n.op == trace::Op::Input && n.value == half)
                    .unwrap();
                program.nodes[input].value += F192::new(0, 0, 1);
                assert!(
                    !program.satisfied(),
                    "full-field sibling equality rejects discarded high limbs"
                );
            }
        }
    }

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
