//! A fixed source-program walk for matrix evaluations, without CSR matrices.
use super::{Form, Origin, Source, remap, sum};
use fiat_shamir::merkle::Hash;
use primitives::{
    field::{F64, F192, F192Unreduced, mul_unreduced4},
    multilinear::eq_table,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
enum Binding {
    Constant(F192),
    Column(usize),
    Affine(Form),
}

/// Trusted compilation metadata for a source generator, never a stored A/B/C.
/// Definitions are bounded affine source instructions, shared across their uses.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Generator {
    pub app_key: Hash,
    pub row_log: usize,
    pub col_log: usize,
    bindings: Vec<Binding>,
    rows: Vec<Row>,
    #[serde(skip)]
    evaluation_plan: OnceLock<EvaluationPlan>,
}

fn mul(k: F192, v: F192) -> F192 {
    if k == F192::ZERO {
        F192::ZERO
    } else if k == F192::ONE {
        v
    } else if k.c1 == 0 && k.c2 == 0 {
        v.mul_base(F64(k.c0))
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
        Self::new_with_blocks(source, cap, app_key, 128)
    }
    pub fn new_with_blocks(source: &Source, cap: usize, app_key: Hash, minimum_blocks: usize) -> Self {
        assert!(minimum_blocks.is_power_of_two() && minimum_blocks >= 128);
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
            if cap > 0
                && !used[d]
                && !assigned[d]
                && !fixed.contains_key(&d)
                && d != a
                && d != b
                && d != u
                && let Some((v, k)) = factor
            {
                let candidate = sum([(form(v, &defs, &fixed), k), (form(u, &defs, &fixed), F192::ONE)]);
                if candidate.len() <= cap {
                    defs[d] = Some(candidate);
                    removed[r] = true;
                }
            }
            for i in [a, b, u] {
                used[i] = true;
            }
            assigned[d] = true;
        }
        let public_len = 1 + c.public.len() - source.fixed_len;
        let blocks = source.connectors.len().max(minimum_blocks).next_power_of_two();
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
        let padding = crate::row_hash::padding();
        for slot in 0..crate::row_hash::PORTS {
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
        for slot in 0..crate::row_hash::PORTS {
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
            insert(std::slice::from_ref(f));
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
        let mut expressions = HashMap::new();
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
                // Canonical source expressions can be shared even when the
                // original compiler assigned them different wire identities.
                let binding = match binding {
                    Binding::Affine(mut f) => {
                        f.sort_unstable_by_key(|&(j, _)| j);
                        match f.as_slice() {
                            [] => Binding::Constant(F192::ZERO),
                            &[(0, k)] => Binding::Constant(k),
                            &[(j, F192::ONE)] => Binding::Column(j),
                            _ => Binding::Affine(f),
                        }
                    }
                    other => other,
                };
                *expressions.entry(binding.clone()).or_insert_with(|| {
                    let index = bindings.len();
                    bindings.push(binding);
                    index
                })
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
            evaluation_plan: OnceLock::new(),
        }
    }
    pub fn rows(&self) -> usize {
        self.rows.len()
    }
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }
    fn source_values(&self, cw: &[F192]) -> Vec<F192> {
        parallel::map_collect(self.bindings.len(), |i| match &self.bindings[i] {
            Binding::Constant(v) => mul(*v, cw[0]),
            Binding::Column(j) => cw[*j],
            Binding::Affine(f) => f.iter().fold(F192::ZERO, |s, &(j, k)| s + mul(k, cw[j])),
        })
    }
    fn row_values(&self, r: usize, at: &[F192], cw: &[F192]) -> [F192; 3] {
        self.row_values_at(r, at, |j| cw[j])
    }
    fn row_values_at(&self, r: usize, at: &[F192], cw: impl Fn(usize) -> F192) -> [F192; 3] {
        match &self.rows[r] {
            Row::Product([a, b, u, d]) => [at[*a], at[*b], at[*u] + at[*d]],
            Row::Linear { other, scale, u, d } => [mul(*scale, at[*other]) + at[*u] + at[*d], cw(0), F192::ZERO],
            Row::Port { dest, source } => {
                let v = match *source {
                    Origin::Variable(i) => at[i],
                    Origin::Constant(v) => mul(v, cw(0)),
                };
                [cw(*dest) + v, cw(0), F192::ZERO]
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
    /// Public-only compilation of constant padding runs; no matrix claim is cached.
    pub fn prepare_evaluation(&self) {
        self.evaluation_plan.get_or_init(|| {
            let mut plan = Vec::new();
            let mut i = 0;
            while i < self.rows.len() {
                let mut run = 1;
                if let Row::Port {
                    dest,
                    source: Origin::Constant(value),
                } = self.rows[i]
                {
                    while i + run < self.rows.len() {
                        if let Row::Port {
                            dest: next,
                            source: Origin::Constant(v),
                        } = self.rows[i + run]
                            && next == dest + run
                            && v == value
                        {
                            run += 1;
                        } else {
                            break;
                        }
                    }
                    if run >= 8 {
                        plan.push(EvaluationPart::ConstantPorts {
                            start: i,
                            dest,
                            len: run,
                            value,
                        });
                        i += run;
                        continue;
                    }
                }
                // Keep walk chunks within one low equality-table block.
                match plan.last_mut() {
                    Some(EvaluationPart::Walk { start, len }) if (*start >> 10) == (i >> 10) && *start + *len == i => {
                        *len += 1
                    }
                    _ => plan.push(EvaluationPart::Walk { start: i, len: 1 }),
                }
                i += 1;
            }
            let mut constants = Vec::new();
            let mut constant_ids = HashMap::new();
            let mut constant = |value: F192| {
                *constant_ids.entry((value.c0, value.c1, value.c2)).or_insert_with(|| {
                    let id = u32::try_from(constants.len()).unwrap();
                    constants.push(value);
                    id
                })
            };
            let narrow = |value: usize| {
                assert!(value < (1 << 30), "evaluation index exceeds packed plan bound");
                value as u32
            };
            let rows = self
                .rows
                .iter()
                .map(|row| match *row {
                    Row::Product(ids) => ids.map(narrow),
                    Row::Linear { other, scale, u, d } => {
                        [narrow(other) | (1 << 30), narrow(u), narrow(d), constant(scale)]
                    }
                    Row::Port {
                        dest,
                        source: Origin::Variable(id),
                    } => [narrow(dest) | (2 << 30), narrow(id), 0, 0],
                    Row::Port {
                        dest,
                        source: Origin::Constant(value),
                    } => [narrow(dest) | (3 << 30), constant(value), 0, 0],
                })
                .collect();
            let mut affine_groups = Vec::new();
            let mut affine_terms = Vec::new();
            let affine_ranges = self
                .bindings
                .iter()
                .map(|binding| {
                    let start = affine_groups.len();
                    if let Binding::Affine(form) = binding {
                        let mut i = 0;
                        while i < form.len() {
                            let high = form[i].0 >> 10;
                            let begin = affine_terms.len();
                            while i < form.len() && form[i].0 >> 10 == high {
                                affine_terms.push(((form[i].0 & 1023) as u16, form[i].1));
                                i += 1;
                            }
                            affine_groups.push((high, begin, affine_terms.len()));
                        }
                    }
                    (start, affine_groups.len())
                })
                .collect();
            EvaluationPlan {
                parts: plan,
                rows,
                constants,
                affine_ranges,
                affine_groups,
                affine_terms,
            }
        });
    }
    /// Logical retained allocation size of the public evaluation plan. Whole
    /// process RSS also includes allocator overhead and the original generator.
    pub fn evaluation_plan_bytes(&self) -> usize {
        self.prepare_evaluation();
        let p = self.evaluation_plan.get().unwrap();
        std::mem::size_of::<EvaluationPlan>()
            + p.parts.capacity() * std::mem::size_of::<EvaluationPart>()
            + p.rows.capacity() * std::mem::size_of::<[u32; 4]>()
            + p.constants.capacity() * std::mem::size_of::<F192>()
            + p.affine_ranges.capacity() * std::mem::size_of::<(usize, usize)>()
            + p.affine_groups.capacity() * std::mem::size_of::<(usize, usize, usize)>()
            + p.affine_terms.capacity() * std::mem::size_of::<(u16, F192)>()
    }
    /// Evaluate exactly the same matrix, summing fixed padding runs by binary
    /// carry dynamic programming instead of materializing every padding row.
    #[tracing::instrument(skip_all, name = "Generator structured matrix settlement")]
    pub fn evaluate(&self, row_point: &[F192], col_point: &[F192]) -> [F192; 3] {
        assert_eq!(row_point.len(), self.row_log);
        assert_eq!(col_point.len(), self.col_log);
        self.prepare_evaluation();
        let plan = self.evaluation_plan.get().unwrap();
        let low_log = row_point.len().min(10);
        let low = eq_table(&row_point[..low_log]);
        let high = eq_table(&row_point[low_log..]);
        let col_low_log = col_point.len().min(10);
        let col_low = eq_table(&col_point[..col_low_log]);
        let col_high = eq_table(&col_point[col_low_log..]);
        let column = |j: usize| col_low[j & (col_low.len() - 1)] * col_high[j >> col_low_log];
        let at = parallel::map_collect(self.bindings.len(), |i| match &self.bindings[i] {
            Binding::Constant(v) => mul(*v, column(0)),
            Binding::Column(j) => column(*j),
            Binding::Affine(_) => {
                let (start, end) = plan.affine_ranges[i];
                plan.affine_groups[start..end]
                    .iter()
                    .fold(F192::ZERO, |sum, &(high, start, end)| {
                        let lo = plan.affine_terms[start..end]
                            .iter()
                            .fold(F192::ZERO, |sum, &(j, k)| sum + mul(k, col_low[j as usize]));
                        sum + lo * col_high[high]
                    })
            }
        });
        parallel::map_reduce(
            plan.parts.len(),
            || [F192::ZERO; 3],
            |part| match plan.parts[part] {
                EvaluationPart::ConstantPorts {
                    start,
                    dest,
                    len,
                    value,
                } => {
                    let rows = interval_equality(row_point, &[], start, 0, len);
                    let pairs = interval_equality(row_point, col_point, start, dest, len);
                    [pairs + mul(value, column(0) * rows), column(0) * rows, F192::ZERO]
                }
                EvaluationPart::Walk { start, len } => {
                    let mut sums = [F192Unreduced::ZERO; 3];
                    for base in (0..len).step_by(4) {
                        let values: [[F192; 3]; 4] = std::array::from_fn(|k| {
                            if base + k < len {
                                packed_row_values(plan, start + base + k, &at, column)
                            } else {
                                [F192::ZERO; 3]
                            }
                        });
                        let weights = std::array::from_fn(|k| {
                            if base + k < len {
                                low[(start + base + k) & (low.len() - 1)]
                            } else {
                                F192::ZERO
                            }
                        });
                        for j in 0..3 {
                            for v in mul_unreduced4(weights, std::array::from_fn(|k| values[k][j])) {
                                sums[j] ^= v;
                            }
                        }
                    }
                    sums.map(|s| s.reduce() * high[start >> low_log])
                }
            },
            |a, b| std::array::from_fn(|i| a[i] + b[i]),
        )
    }

    #[tracing::instrument(skip_all, name = "Generator matrix settlement")]
    pub fn evaluate_walk(&self, row_point: &[F192], col_point: &[F192]) -> [F192; 3] {
        assert_eq!(row_point.len(), self.row_log);
        assert_eq!(col_point.len(), self.col_log);
        // Factor the row equality table. Each block shares its high weight,
        // so accumulate its low-weighted instruction values before scaling.
        let low_log = row_point.len().min(10);
        let low = eq_table(&row_point[..low_log]);
        let high = eq_table(&row_point[low_log..]);
        let col_low_log = col_point.len().min(10);
        let col_low = eq_table(&col_point[..col_low_log]);
        let col_high = eq_table(&col_point[col_low_log..]);
        let column = |j: usize| col_low[j & (col_low.len() - 1)] * col_high[j >> col_low_log];
        let at = parallel::map_collect(self.bindings.len(), |i| match &self.bindings[i] {
            Binding::Constant(v) => mul(*v, column(0)),
            Binding::Column(j) => column(*j),
            Binding::Affine(f) => f.iter().fold(F192::ZERO, |s, &(j, k)| s + mul(k, column(j))),
        });
        parallel::map_reduce(
            self.rows.len().div_ceil(low.len()),
            || [F192::ZERO; 3],
            |block| {
                let start = block * low.len();
                let count = low.len().min(self.rows.len() - start);
                let mut sums = [F192Unreduced::ZERO; 3];
                for base in (0..count).step_by(4) {
                    let values: [[F192; 3]; 4] = std::array::from_fn(|k| {
                        if base + k < count {
                            self.row_values_at(start + base + k, &at, column)
                        } else {
                            [F192::ZERO; 3]
                        }
                    });
                    let weights = std::array::from_fn(|k| low.get(base + k).copied().unwrap_or(F192::ZERO));
                    for j in 0..3 {
                        for v in mul_unreduced4(weights, std::array::from_fn(|k| values[k][j])) {
                            sums[j] ^= v;
                        }
                    }
                }
                sums.map(|s| s.reduce() * high[block])
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

#[derive(Clone, Copy)]
enum EvaluationPart {
    Walk {
        start: usize,
        len: usize,
    },
    ConstantPorts {
        start: usize,
        dest: usize,
        len: usize,
        value: F192,
    },
}

/// Sum eq(r,start+i)*eq(c,dest+i), 0<=i<len. Empty c omits its factor.
/// State bits are the two addition carries and the borrow in i-len.
fn interval_equality(r: &[F192], c: &[F192], start: usize, dest: usize, len: usize) -> F192 {
    assert!(start + len <= 1usize << r.len());
    assert!(c.is_empty() || dest + len <= 1usize << c.len());
    let mut state = [F192::ZERO; 8];
    state[0] = F192::ONE;
    for bit in 0..=r.len().max(c.len()) {
        let mut next = [F192::ZERO; 8];
        for (s, weight) in state.into_iter().enumerate() {
            if weight == F192::ZERO {
                continue;
            }
            for digit in 0..2 {
                let a = digit + ((start >> bit) & 1) + (s & 1);
                let b = digit + ((dest >> bit) & 1) + ((s >> 1) & 1);
                let borrow = usize::from(digit < ((len >> bit) & 1) + (s >> 2));
                let row_weight = r
                    .get(bit)
                    .map_or(if a & 1 == 0 { F192::ONE } else { F192::ZERO }, |&p| {
                        if a & 1 == 1 { p } else { F192::ONE + p }
                    });
                let col_weight = if c.is_empty() {
                    F192::ONE
                } else {
                    c.get(bit)
                        .map_or(if b & 1 == 0 { F192::ONE } else { F192::ZERO }, |&p| {
                            if b & 1 == 1 { p } else { F192::ONE + p }
                        })
                };
                let carry_b = if c.is_empty() { 0 } else { b >> 1 };
                next[(a >> 1) | (carry_b << 1) | (borrow << 2)] += weight * row_weight * col_weight;
            }
        }
        state = next;
    }
    state[4]
}

#[cfg(test)]
mod structured_tests {
    use super::*;
    #[test]
    fn affine_blocks_and_packed_rows_match_independent_walk() {
        let g = Generator {
            app_key: [0; 32],
            row_log: 11,
            col_log: 12,
            bindings: vec![
                Binding::Constant(F192::new(9, 7, 5)),
                Binding::Column(1031),
                Binding::Affine(vec![
                    (0, F192::ONE),
                    (1, F192::new(3, 2, 1)),
                    (1023, F192::ONE),
                    (1024, F192::new(7, 0, 0)),
                    (2049, F192::ONE),
                ]),
                Binding::Affine(vec![(7, F192::ONE), (1023, F192::ONE), (1031, F192::ONE)]),
            ],
            rows: vec![
                Row::Product([0, 1, 2, 3]),
                Row::Linear {
                    other: 2,
                    scale: F192::new(3, 4, 5),
                    u: 1,
                    d: 3,
                },
                Row::Port {
                    dest: 3073,
                    source: Origin::Variable(2),
                },
                Row::Port {
                    dest: 4095,
                    source: Origin::Constant(F192::new(1, 2, 3)),
                },
            ],
            evaluation_plan: OnceLock::new(),
        };
        for seed in 0..8 {
            let row: Vec<_> = (0..11).map(|i| F192::new(i + seed + 3, i + 7, i + 11)).collect();
            let col: Vec<_> = (0..12).map(|i| F192::new(i + seed + 17, i + 23, i + 31)).collect();
            assert_eq!(g.evaluate(&row, &col), g.evaluate_walk(&row, &col));
        }
    }
    #[test]
    fn offset_interval_equality_matches_enumeration() {
        let r: Vec<_> = (0..5).map(|i| F192::new(i + 3, i + 7, i + 11)).collect();
        let c: Vec<_> = (0..5).map(|i| F192::new(i + 17, i + 23, i + 31)).collect();
        let er = eq_table(&r);
        let ec = eq_table(&c);
        for start in 0..32 {
            for dest in 0..32 {
                for len in 0..=(32 - start).min(32 - dest) {
                    assert_eq!(
                        interval_equality(&r, &c, start, dest, len),
                        (0..len).fold(F192::ZERO, |v, i| v + er[start + i] * ec[dest + i]),
                        "start={start} dest={dest} len={len}"
                    );
                    assert_eq!(
                        interval_equality(&r, &[], start, 0, len),
                        (0..len).fold(F192::ZERO, |v, i| v + er[start + i])
                    );
                }
            }
        }
    }
}

/// Public-only packed addressing plan. Four u32s per row replace a wide Rust
/// enum in the root hot loop; top two bits tag the first bounded index.
struct EvaluationPlan {
    parts: Vec<EvaluationPart>,
    rows: Vec<[u32; 4]>,
    constants: Vec<F192>,
    affine_ranges: Vec<(usize, usize)>,
    affine_groups: Vec<(usize, usize, usize)>,
    affine_terms: Vec<(u16, F192)>,
}
fn packed_row_values(plan: &EvaluationPlan, row: usize, at: &[F192], column: impl Fn(usize) -> F192) -> [F192; 3] {
    let [tag, b, c, d] = plan.rows[row];
    let a = (tag & 0x3fff_ffff) as usize;
    let (b, c, d) = (b as usize, c as usize, d as usize);
    match tag >> 30 {
        0 => [at[a], at[b], at[c] + at[d]],
        1 => [mul(plan.constants[d], at[a]) + at[b] + at[c], column(0), F192::ZERO],
        2 => [column(a) + at[b], column(0), F192::ZERO],
        3 => [column(a) + mul(plan.constants[b], column(0)), column(0), F192::ZERO],
        _ => unreachable!(),
    }
}
