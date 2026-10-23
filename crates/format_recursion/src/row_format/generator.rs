//! A fixed source-program walk for matrix evaluations, without CSR matrices.
use super::{Form, Origin, Source, remap, sum};
use fiat_shamir::merkle::Hash;
use primitives::{
    field::{F192, mul4},
    multilinear::eq_table,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

#[derive(Clone)]
enum Row {
    Product([usize; 4]),
    Linear {
        other: usize,
        scale: F192,
        u: usize,
        d: usize,
    },
    Port {
        dest: usize,
        source: Origin,
    },
}

enum Binding {
    Constant(F192),
    Column(usize),
    Affine(Form),
}

/// Trusted compilation metadata for a source generator, never a stored A/B/C.
/// Definitions are bounded affine source instructions, shared across their uses.
pub struct Generator {
    pub app_key: Hash,
    pub row_log: usize,
    pub col_log: usize,
    bindings: Vec<Binding>,
    rows: Vec<Row>,
}

fn mul(k: F192, v: F192) -> F192 {
    if k == F192::ZERO {
        F192::ZERO
    } else if k == F192::ONE {
        v
    } else {
        k * v
    }
}

fn form(id: usize, defs: &[Option<Form>], fixed: &HashMap<usize, F192>) -> Arc<Form> {
    Arc::new(if let Some(&v) = fixed.get(&id) {
        if v == F192::ZERO { vec![] } else { vec![(1, v)] }
    } else {
        defs[id].clone().unwrap_or_else(|| vec![(id, F192::ONE)])
    })
}
fn scalar(f: &Form) -> Option<F192> {
    if f.is_empty() {
        Some(F192::ZERO)
    } else if f.len() == 1 && f[0].0 == 1 {
        Some(f[0].1)
    } else {
        None
    }
}
impl Generator {
    pub fn new(source: &Source, cap: usize, app_key: Hash) -> Self {
        let c = &source.circuit;
        let fixed: HashMap<_, _> = c.public[..source.fixed_len]
            .iter()
            .map(|&i| (i, source.values[i]))
            .collect();
        let mut defs = vec![None; c.variables];
        let mut used = vec![false; c.variables];
        let mut assigned = vec![false; c.variables];
        let mut removed = vec![false; c.rows.len()];
        for (r, &[a, b, u, d]) in c.rows.iter().enumerate() {
            let factor = fixed
                .get(&a)
                .map(|&k| (b, k))
                .or_else(|| fixed.get(&b).map(|&k| (a, k)));
            if cap > 0 && !used[d] && !assigned[d] && !fixed.contains_key(&d) && d != a && d != b && d != u {
                if let Some((v, k)) = factor {
                    let candidate = sum([(form(v, &defs, &fixed), k), (form(u, &defs, &fixed), F192::ONE)]);
                    if candidate.len() <= cap {
                        defs[d] = Some(candidate);
                        removed[r] = true;
                    }
                }
            }
            for i in [a, b, u] {
                used[i] = true;
            }
            assigned[d] = true;
        }
        let public_len = 1 + c.public.len() - source.fixed_len;
        let blocks = source.connectors.len().max(128).next_power_of_two();
        let port_start = public_len.next_power_of_two().next_multiple_of(blocks);
        let mut origins = vec![Origin::Constant(F192::ZERO); port_start];
        origins[0] = Origin::Constant(F192::ONE);
        let mut map = vec![usize::MAX; c.variables];
        map[1] = 0;
        for (j, &id) in c.public[source.fixed_len..].iter().enumerate() {
            origins[j + 1] = Origin::Variable(id);
            if defs[id].is_none() && !fixed.contains_key(&id) {
                map[id] = j + 1;
            }
        }
        let padding = flock::hash::padding_block();
        let padding = crate::private_bridge::io_words(
            &padding,
            &flock::hash::blake2s_compress(&padding.0, &padding.1, padding.2, padding.3, padding.4),
        );
        for slot in 0..18 {
            for block in 0..blocks {
                origins.push(
                    source
                        .connectors
                        .get(block)
                        .map_or(Origin::Constant(F192::new(padding[slot], 0, 0)), |io| {
                            Origin::Variable(io[slot])
                        }),
                );
            }
        }
        let mut rows = Vec::new();
        let mut insert = |forms: &[Arc<Form>]| {
            for f in forms {
                for &(id, _) in f.iter() {
                    if map[id] == usize::MAX {
                        map[id] = origins.len();
                        origins.push(Origin::Variable(id));
                    }
                }
            }
        };
        for (r, &[a, b, u, d]) in c.rows.iter().enumerate() {
            if removed[r] {
                continue;
            }
            let fa = form(a, &defs, &fixed);
            let fb = form(b, &defs, &fixed);
            let fc = Arc::new(sum([
                (form(u, &defs, &fixed), F192::ONE),
                (form(d, &defs, &fixed), F192::ONE),
            ]));
            if let Some((other, scale, f)) = scalar(&fa)
                .map(|k| (b, k, fb.clone()))
                .or_else(|| scalar(&fb).map(|k| (a, k, fa.clone())))
            {
                let relation = Arc::new(sum([(f, scale), (fc, F192::ONE)]));
                if !relation.is_empty() {
                    insert(&[relation, Arc::new(vec![(1, F192::ONE)])]);
                    rows.push(Row::Linear { other, scale, u, d });
                }
            } else {
                insert(&[fa, fb, fc]);
                rows.push(Row::Product([a, b, u, d]));
            }
        }
        let mut materialized = Vec::new();
        for (j, &id) in c.public[source.fixed_len..].iter().enumerate() {
            materialized.push((j + 1, Origin::Variable(id), form(id, &defs, &fixed)));
        }
        for slot in 0..18 {
            for block in 0..blocks {
                let origin = source
                    .connectors
                    .get(block)
                    .map_or(Origin::Constant(F192::new(padding[slot], 0, 0)), |io| {
                        Origin::Variable(io[slot])
                    });
                let f = match origin {
                    Origin::Variable(id) => form(id, &defs, &fixed),
                    Origin::Constant(v) => Arc::new(if v == F192::ZERO { vec![] } else { vec![(1, v)] }),
                };
                materialized.push((port_start + slot * blocks + block, origin, f));
            }
        }
        for (_, _, f) in &materialized {
            insert(&[f.clone()]);
        }
        for (dest, source, f) in materialized {
            let mut relation: BTreeMap<usize, F192> = remap(&f, &map).into_iter().collect();
            *relation.entry(dest).or_insert(F192::ZERO) += F192::ONE;
            if relation.values().any(|&v| v != F192::ZERO) {
                rows.push(Row::Port { dest, source });
            }
        }
        // Only source wires consumed by retained instructions need a forward
        // value or transpose adjoint. Compile their affine addressing once.
        let mut ids = HashMap::new();
        let mut bindings = Vec::new();
        let mut compact = |id: &mut usize| {
            let index = *ids.entry(*id).or_insert_with(|| {
                let binding = if let Some(&v) = fixed.get(id) {
                    Binding::Constant(v)
                } else if let Some(f) = &defs[*id] {
                    Binding::Affine(
                        f.iter()
                            .filter_map(|&(j, k)| (map[j] != usize::MAX).then_some((map[j], k)))
                            .collect(),
                    )
                } else if map[*id] != usize::MAX {
                    Binding::Column(map[*id])
                } else {
                    Binding::Constant(F192::ZERO)
                };
                let index = bindings.len();
                bindings.push(binding);
                index
            });
            *id = index;
        };
        for row in &mut rows {
            match row {
                Row::Product(ids) => {
                    for id in ids {
                        compact(id);
                    }
                }
                Row::Linear { other, u, d, .. } => {
                    compact(other);
                    compact(u);
                    compact(d);
                }
                Row::Port {
                    source: Origin::Variable(id),
                    ..
                } => compact(id),
                _ => {}
            }
        }
        Self {
            app_key,
            row_log: rows.len().next_power_of_two().trailing_zeros() as usize,
            col_log: origins.len().next_power_of_two().trailing_zeros() as usize,
            bindings,
            rows,
        }
    }
    pub fn rows(&self) -> usize {
        self.rows.len()
    }
    fn source_values(&self, cw: &[F192]) -> Vec<F192> {
        parallel::map_collect(self.bindings.len(), |i| match &self.bindings[i] {
            Binding::Constant(v) => mul(*v, cw[0]),
            Binding::Column(j) => cw[*j],
            Binding::Affine(f) => f.iter().fold(F192::ZERO, |s, &(j, k)| s + mul(k, cw[j])),
        })
    }
    fn row_values(&self, r: usize, at: &[F192], cw: &[F192]) -> [F192; 3] {
        match &self.rows[r] {
            Row::Product([a, b, u, d]) => [at[*a], at[*b], at[*u] + at[*d]],
            Row::Linear { other, scale, u, d } => [mul(*scale, at[*other]) + at[*u] + at[*d], cw[0], F192::ZERO],
            Row::Port { dest, source } => {
                let v = match *source {
                    Origin::Variable(i) => at[i],
                    Origin::Constant(v) => mul(v, cw[0]),
                };
                [cw[*dest] + v, cw[0], F192::ZERO]
            }
        }
    }
    /// Forward source walk: the batched A/B/C product at every native row.
    pub fn row_product(&self, cw: &[F192], theta: F192) -> Vec<F192> {
        assert_eq!(cw.len(), 1 << self.col_log);
        let at = self.source_values(cw);
        let theta2 = theta * theta;
        parallel::map_collect(1 << self.row_log, |r| {
            if r >= self.rows.len() {
                return F192::ZERO;
            }
            let [a, b, c] = self.row_values(r, &at, cw);
            a + theta * b + theta2 * c
        })
    }
    /// Transpose source walk. Accumulate adjoints on source wires, then
    /// distribute bounded affine definitions to native witness columns.
    pub fn column_products(&self, rw: &[F192]) -> [Vec<F192>; 3] {
        assert_eq!(rw.len(), 1 << self.row_log);
        let products = parallel::map_collect(3, |matrix| {
            let mut adj = vec![F192::ZERO; self.bindings.len()];
            let mut out = vec![F192::ZERO; 1 << self.col_log];
            for (r, row) in self.rows.iter().enumerate() {
                let w = rw[r];
                match (matrix, row) {
                    (0, Row::Product([a, _, _, _])) => adj[*a] += w,
                    (1, Row::Product([_, b, _, _])) => adj[*b] += w,
                    (2, Row::Product([_, _, u, d])) => {
                        adj[*u] += w;
                        adj[*d] += w;
                    }
                    (0, Row::Linear { other, scale, u, d }) => {
                        adj[*other] += mul(*scale, w);
                        adj[*u] += w;
                        adj[*d] += w;
                    }
                    (0, Row::Port { dest, source }) => {
                        out[*dest] += w;
                        match *source {
                            Origin::Variable(i) => adj[i] += w,
                            Origin::Constant(v) => out[0] += mul(v, w),
                        }
                    }
                    (1, Row::Linear { .. } | Row::Port { .. }) => out[0] += w,
                    _ => {}
                }
            }
            for (i, w) in adj.into_iter().enumerate() {
                if w == F192::ZERO {
                    continue;
                }
                match &self.bindings[i] {
                    Binding::Constant(v) => out[0] += mul(*v, w),
                    Binding::Column(j) => out[*j] += w,
                    Binding::Affine(f) => {
                        for &(j, k) in f {
                            out[j] += mul(k, w);
                        }
                    }
                }
            }
            out
        });
        products.try_into().unwrap()
    }
    #[tracing::instrument(skip_all, name = "Generator matrix settlement")]
    pub fn evaluate(&self, row_point: &[F192], col_point: &[F192]) -> [F192; 3] {
        assert_eq!(row_point.len(), self.row_log);
        assert_eq!(col_point.len(), self.col_log);
        let rw = eq_table(row_point);
        let cw = eq_table(col_point);
        let at = self.source_values(&cw);
        parallel::map_reduce(
            self.rows.len().div_ceil(4),
            || [F192::ZERO; 3],
            |block| {
                let values: [[F192; 3]; 4] = std::array::from_fn(|k| {
                    let r = 4 * block + k;
                    if r < self.rows.len() {
                        self.row_values(r, &at, &cw)
                    } else {
                        [F192::ZERO; 3]
                    }
                });
                let weights = std::array::from_fn(|k| rw.get(4 * block + k).copied().unwrap_or(F192::ZERO));
                std::array::from_fn(|j| {
                    mul4(weights, std::array::from_fn(|k| values[k][j]))
                        .into_iter()
                        .fold(F192::ZERO, |x, y| x + y)
                })
            },
            |a, b| std::array::from_fn(|i| a[i] + b[i]),
        )
    }
    pub fn settle(&self, claim: &super::spartan::DeferredClaim) -> bool {
        claim.app_key == self.app_key
            && claim.row_point.len() == self.row_log
            && claim.col_point.len() == self.col_log
            && self.evaluate(&claim.row_point, &claim.col_point) == claim.matrix_values
    }
}
