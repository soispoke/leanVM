//! Exact tagged hash-chain workload using the canonical VM recursive verifier.
//!
//! Each level has an authorized program. Deferred claims for older programs are
//! authenticated in the public digest and forwarded, then discharged by the root
//! verifier. This is a diagnostic tree with growing metadata, not fixed-shape
//! recursion. All metadata is part of the serialized proof and verification cost.
use super::*;

pub type Digest = [u8; 32];

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TreeProof {
    pub proof: leanvm_core::cpu::Proof,
    records: Vec<Vec<F192>>,
}

impl TreeProof {
    pub fn encoded_size(&self) -> usize {
        bincode::serialized_size(self).expect("serializable proof") as usize
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

pub struct Prepared {
    log_inv_rate: usize,
    program: Program,
    public: [F192; 2],
    records: Vec<Vec<F192>>,
}
impl Prepared {
    pub fn prove(self) -> Result<(TreeProof, leanvm_core::cpu::Stats), AggregationError> {
        let (proof, stats) =
            prove(&self.program, self.public, self.log_inv_rate).map_err(AggregationError::ProofError)?;
        Ok((
            TreeProof {
                proof,
                records: self.records,
            },
            stats,
        ))
    }
}

pub struct Setup {
    pub program: Program,
    pub level: usize,
    pub log_inv_rate: usize,
    schema: Vec<usize>,
    bytecode: Bytecode,
}

fn helpers() -> &'static str {
    include_str!("../../guests/chain_tree.py")
}

pub(super) fn canonical_source(cell_counts: &[usize]) -> String {
    let source = include_str!("../../guests/lean_ethereum.py");
    let first = "\ndef main():";
    let second = "\ndef aggregate_claims(";
    assert_eq!(source.matches(first).count(), 1);
    assert_eq!(source.matches(second).count(), 1);
    let a = source.find(first).unwrap();
    let b = source.find(second).unwrap();
    assert!(a < b);
    let cut = helpers().find("\ndef chain_wrap(").unwrap();
    let mut text = source[..a].to_owned() + &source[b..] + &helpers()[..cut];
    let mut counts = cell_counts.to_vec();
    counts.sort_unstable();
    counts.dedup();
    for n in counts {
        let specialized = helpers()[cut..]
            .replace("def chain_wrap(", &format!("def chain_wrap_{n}("))
            .replace(", n: Const)", ")")
            .replace("(n +", &format!("({n} +"))
            .replace(" == n):", &format!(" == {n}):"));
        text += &specialized;
    }
    text
}

pub(super) fn compile_source(source: String, kbc: usize) -> Program {
    let mut p = compile(&parse_with_replacements(&source, &placeholder_map(kbc)).expect("tree guest parses"));
    p.min_log_committed = MU_MIN;
    p
}

fn wrap(mut digest: [F192; 2], records: &[Vec<F192>], schema: &[usize], keys: &[Setup]) -> [F192; 2] {
    assert_eq!(records.len(), schema.len());
    for (cells, &key) in records.iter().zip(schema) {
        let kbcv = keys[key].program.prog.len().trailing_zeros() as usize + leanvm_core::leaf::N_BYTECODE_SELECTORS;
        assert_eq!(cells.len(), kbcv + 1 + 2 * flock::hash::K_LOG + 2);
        let mut padded = cells.clone();
        if !padded.len().is_multiple_of(2) {
            padded.push(F192::ZERO);
        }
        let seed = leanvm_core::cpu::fs_seed(&keys[key].program);
        let header = [seed[0], seed[1], digest[0], digest[1], F192::ZERO, F192::ZERO];
        digest = lane_hash(
            header
                .iter()
                .flat_map(|x| [x.c0, x.c1])
                .chain(padded.iter().flat_map(|x| [x.c0, x.c1, x.c2])),
        );
    }
    digest
}

impl Setup {
    pub fn leaf(chain: usize) -> Self {
        Self::leaf_with_rate(chain, leanvm_core::pcs::TEST_LOG_INV_RATE)
    }

    pub fn leaf_with_rate(chain: usize, log_inv_rate: usize) -> Self {
        pcs::whir::validate_log_inv_rate(log_inv_rate).expect("production WHIR rate");
        assert!(chain <= 1 << 20);
        let source = "from snark_lib import *\n".to_owned()
            + helpers().split("\ndef chain_wrap(").next().unwrap()
            + &format!(
                "\ndef main():\n    state = HeapBuf({})\n    hint_witness(state[0:2], \"start\")\n    for i in mul_range(1, GEN ** {chain}):\n        p = state * i * i\n        h = chain_hash32(p[1], p[GEN], 67, 0, 33)\n        p[GEN ** 2] = h[0]\n        p[GEN ** 3] = h[1]\n    h = chain_hash32(state[GEN ** {}], state[GEN ** {}], 76, {}, 41)\n    out = GEN ** 0\n    out[1] = h[0]\n    out[GEN] = h[1]\n    return\n",
                2 * (chain + 1),
                2 * chain,
                2 * chain + 1,
                chain * 256
            );
        let program = compile_source(source, 10);
        let bytecode = Bytecode::of(&program);
        Self {
            program,
            bytecode,
            level: 0,
            log_inv_rate,
            schema: Vec::new(),
        }
    }

    pub fn parent(keys: &[Setup]) -> Self {
        let child = keys.last().expect("child key");
        let seed = leanvm_core::cpu::fs_seed(&child.program);
        let zero = DeferredClaim::leaf(&child.bytecode);
        let mut main = String::from(
            "\ndef main():\n    g_logs_pow2, g_squares = exponent_tables()\n    child_pi = HeapBuf(4)\n    child_fresh = HeapBuf(2 * DEFER_SIZE)\n    child_carried = HeapBuf(2 * DEFER_STMT_CELLS)\n    digests = StackBuf(4)\n    hint_witness(digests, \"tree_digests\")\n",
        );
        let mut pending = Vec::<(String, usize)>::new();
        for c in 0..2 {
            main += &format!(
                "    pi{c}_0 = digests[{}]\n    pi{c}_1 = digests[{}]\n",
                2 * c,
                2 * c + 1
            );
            for (j, &key) in child.schema.iter().enumerate() {
                let n = keys[key].program.prog.len().trailing_zeros() as usize
                    + leanvm_core::leaf::N_BYTECODE_SELECTORS
                    + 1
                    + 2 * flock::hash::K_LOG
                    + 2;
                let name = format!("rec{c}_{j}");
                main += &format!("    {name} = HeapBuf({n})\n    hint_witness({name}[0:{n}], \"tree_record\")\n");
                let s = leanvm_core::cpu::fs_seed(&keys[key].program);
                main += &format!(
                    "    pi{c}_0, pi{c}_1 = chain_wrap_{n}({}, {}, pi{c}_0, pi{c}_1, {name})\n",
                    f192_literal(s[0]),
                    f192_literal(s[1])
                );
                pending.push((name, key));
            }
            for (j, value) in zero.cells().iter().enumerate() {
                main += &format!(
                    "    child_carried[GEN ** ({c} * DEFER_STMT_CELLS + {j})] = {}\n",
                    f192_literal(*value)
                );
            }
            main += &format!(
                "    child_pi[GEN ** {}] = pi{c}_0\n    child_pi[GEN ** {}] = pi{c}_1\n    verify_sub(pi{c}_0, pi{c}_1, {}, {}, g_logs_pow2, g_squares, child_fresh * GEN ** ({c} * DEFER_SIZE))\n",
                2 * c,
                2 * c + 1,
                f192_literal(seed[0]),
                f192_literal(seed[1])
            );
        }
        main += "    defer_stmt = HeapBuf(DEFER_STMT_CELLS)\n    aggregate_claims(GEN ** 2, child_pi, child_fresh, child_carried, defer_stmt)\n    h = chain_hash_node(digests[0], digests[1], digests[2], digests[3])\n    own_0 = h[0]\n    own_1 = h[1]\n";
        let mut schema = Vec::new();
        for (name, key) in &pending {
            let n = keys[*key].program.prog.len().trailing_zeros() as usize
                + leanvm_core::leaf::N_BYTECODE_SELECTORS
                + 1
                + 2 * flock::hash::K_LOG
                + 2;
            let s = leanvm_core::cpu::fs_seed(&keys[*key].program);
            main += &format!(
                "    own_0, own_1 = chain_wrap_{n}({}, {}, own_0, own_1, {name})\n",
                f192_literal(s[0]),
                f192_literal(s[1])
            );
            schema.push(*key);
        }
        let own_cells = zero.cells().len();
        main += &format!(
            "    own_0, own_1 = chain_wrap_{own_cells}({}, {}, own_0, own_1, defer_stmt)\n    out = GEN ** 0\n    out[1] = own_0\n    out[GEN] = own_1\n    return\n",
            f192_literal(seed[0]),
            f192_literal(seed[1])
        );
        schema.push(child.level);
        let program = compile_source(
            canonical_source(
                &keys
                    .iter()
                    .map(|k| k.bytecode.vars() + 1 + 2 * flock::hash::K_LOG + 2)
                    .collect::<Vec<_>>(),
            ) + &main,
            child.program.prog.len().trailing_zeros() as usize,
        );
        let bytecode = Bytecode::of(&program);
        Self {
            program,
            bytecode,
            level: keys.len(),
            log_inv_rate: child.log_inv_rate,
            schema,
        }
    }

    pub fn prove_leaf(
        &self,
        start: Digest,
        digest: Digest,
    ) -> Result<(TreeProof, leanvm_core::cpu::Stats), AggregationError> {
        assert_eq!(self.level, 0);
        let mut p = self.program.clone();
        p.set_witness("start", vec![pack_hash_state(&start).to_vec()]);
        let (proof, stats) =
            prove(&p, pack_hash_state(&digest), self.log_inv_rate).map_err(AggregationError::ProofError)?;
        Ok((
            TreeProof {
                proof,
                records: Vec::new(),
            },
            stats,
        ))
    }

    pub fn prepare_parent(
        &self,
        keys: &[Setup],
        children: [(&Digest, &TreeProof); 2],
        digest: Digest,
    ) -> Result<Prepared, AggregationError> {
        let child = &keys[self.level - 1];
        let zero = DeferredClaim::leaf(&child.bytecode);
        let mut hints = Hints(Vec::new());
        hints.push(
            "tree_digests",
            children.iter().flat_map(|(d, _)| pack_hash_state(d)).collect(),
        );
        let mut subs = Vec::new();
        let mut records = Vec::new();
        for (d, proof) in children {
            child
                .validate_records(keys, proof)
                .map_err(AggregationError::InvalidChild)?;
            let public = wrap(pack_hash_state(d), &proof.records, &child.schema, keys);
            let summary = verify(&child.program, &public, &proof.proof)
                .map_err(|e| AggregationError::InvalidChild(AggregateVerifyError::Snark(e)))?;
            let (sub, fresh) = gen_verify(&child.program, public, summary)?;
            for (name, entry) in sub {
                hints.push(name, entry);
            }
            for record in &proof.records {
                hints.push("tree_record", record.clone());
                records.push(record.clone());
            }
            subs.push(fresh);
        }
        let (batch, defer) = aggregate_deferred_claims(&child.bytecode, &subs, &[&zero, &zero]);
        for (name, entry) in batch {
            hints.push(name, entry);
        }
        records.push(defer.cells());
        let public = wrap(pack_hash_state(&digest), &records, &self.schema, keys);
        let mut p = self.program.clone();
        hints.install(&mut p);
        Ok(Prepared {
            log_inv_rate: self.log_inv_rate,
            program: p,
            public,
            records,
        })
    }

    fn validate_records(&self, keys: &[Setup], proof: &TreeProof) -> Result<(), AggregateVerifyError> {
        if proof.records.len() != self.schema.len() || proof.encoded_size() > 1 << 20 {
            return Err(AggregateVerifyError::MalformedClaim);
        }
        for (cells, &key) in proof.records.iter().zip(&self.schema) {
            let bytecode = &keys[key].bytecode;
            let n = bytecode.vars();
            if cells.len() != n + 1 + 2 * flock::hash::K_LOG + 2 {
                return Err(AggregateVerifyError::MalformedClaim);
            }
            let checked = DeferredClaim::recompute(
                bytecode,
                cells[..n].to_vec(),
                cells[n + 1..n + 1 + 2 * flock::hash::K_LOG].to_vec(),
            )?;
            if checked.cells() != *cells {
                return Err(AggregateVerifyError::MalformedClaim);
            }
        }
        Ok(())
    }

    pub fn verify(&self, keys: &[Setup], digest: &Digest, proof: &TreeProof) -> Result<(), AggregateVerifyError> {
        self.validate_records(keys, proof)?;
        let public = wrap(pack_hash_state(digest), &proof.records, &self.schema, keys);
        verify(&self.program, &public, &proof.proof).map_err(AggregateVerifyError::Snark)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected(start: Digest, n: usize) -> Digest {
        let mut d = start;
        for _ in 0..n {
            let mut b = vec![0x43];
            b.extend(d);
            d = primitives::hash::hash(&b);
        }
        let mut b = vec![0x4c];
        b.extend(d);
        b.extend((n as u64).to_le_bytes());
        primitives::hash::hash(&b)
    }
    #[test]
    fn exact_tagged_leaf_execution() {
        for n in [0, 1, 16] {
            let setup = Setup::leaf(n);
            let start = primitives::hash::hash(&(20261022u64 + n as u64).to_le_bytes());
            let digest = expected(start, n);
            let mut p = setup.program.clone();
            p.set_witness("start", vec![pack_hash_state(&start).to_vec()]);
            let execution = p.execute(pack_hash_state(&digest)).expect("exact tagged leaf");
            assert_eq!(execution.base_counts[5], n + 1);
            let mut wrong = pack_hash_state(&digest);
            wrong[0] += F192::ONE;
            assert!(p.execute(wrong).is_err());
        }
    }
    #[test]
    fn forwarded_claim_schema_is_exact() {
        let mut keys = vec![Setup::leaf(1)];
        keys.push(Setup::parent(&keys));
        keys.push(Setup::parent(&keys));
        keys.push(Setup::parent(&keys));
        assert_eq!(keys[1].schema, vec![0]);
        assert_eq!(keys[2].schema, vec![0, 0, 1]);
        assert_eq!(keys[3].schema, vec![0, 0, 1, 0, 0, 1, 2]);
    }
    #[test]
    fn actual_root_rejects_deferred_record_attacks() {
        parallel::init();
        let mut keys = vec![Setup::leaf_with_rate(1, 1)];
        let mut layer = Vec::new();
        for i in 0..4u64 {
            let start = primitives::hash::hash(&(20261022 + i).to_le_bytes());
            let digest = expected(start, 1);
            let (proof, _) = keys[0].prove_leaf(start, digest).expect("leaf");
            keys[0].verify(&keys, &digest, &proof).expect("leaf verifies");
            layer.push((digest, proof));
        }
        for level in 1..=2 {
            keys.push(Setup::parent(&keys));
            let mut next = Vec::new();
            for pair in layer.as_chunks::<2>().0 {
                let mut bytes = vec![0x4e];
                bytes.extend(pair[0].0);
                bytes.extend(pair[1].0);
                let digest = primitives::hash::hash(&bytes);
                let (proof, _) = keys[level]
                    .prepare_parent(&keys, [(&pair[0].0, &pair[0].1), (&pair[1].0, &pair[1].1)], digest)
                    .expect("prepare node")
                    .prove()
                    .expect("prove node");
                keys[level].verify(&keys, &digest, &proof).expect("node verifies");
                next.push((digest, proof));
            }
            layer = next;
        }
        let (digest, proof) = layer.pop().unwrap();
        assert_eq!(proof.records.len(), 3);
        let root = &keys[2];
        let mut rejected = 0;
        let mut reject = |bad: &TreeProof| {
            assert!(root.verify(&keys, &digest, bad).is_err());
            rejected += 1;
        };
        let mut bad = proof.clone();
        bad.records[0][0] += F192::ONE;
        reject(&bad);
        let mut bad = proof.clone();
        let n = keys[0].bytecode.vars();
        bad.records[0][n] += F192::ONE;
        reject(&bad);
        let mut bad = proof.clone();
        bad.records.pop();
        reject(&bad);
        let mut bad = proof.clone();
        bad.records[0].pop();
        reject(&bad);
        let mut bad = proof.clone();
        bad.records.push(proof.records[0].clone());
        reject(&bad);
        // Both reordered records remain valid against exactly the same key.
        assert_ne!(proof.records[0], proof.records[1]);
        let mut bad = proof.clone();
        bad.records.swap(0, 1);
        assert!(root.validate_records(&keys, &bad).is_ok());
        reject(&bad);
        // A newly and correctly evaluated record must not replace the one the
        // actual root proof authenticated, even when it uses the right key.
        let mut bad = proof.clone();
        bad.records[0] = DeferredClaim::recompute(
            &keys[0].bytecode,
            vec![F192::ONE; n],
            vec![F192::ONE; 2 * flock::hash::K_LOG],
        )
        .unwrap()
        .cells();
        assert_ne!(bad.records[0], proof.records[0]);
        assert!(root.validate_records(&keys, &bad).is_ok());
        reject(&bad);
        let mut bad = proof.clone();
        bad.proof.stream[0] += F192::ONE;
        reject(&bad);
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(root.verify(&keys, &wrong, &proof).is_err());
        rejected += 1;
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(bincode::deserialize::<TreeProof>(&bytes[..bytes.len() - 1]).is_err());
        rejected += 1;
        // Substitute a same-sized foreign leaf key and recompute every affected
        // record correctly for that key. Polynomial checks now pass, but the
        // root's authenticated public hash must still reject the substitution.
        let mut bad = proof.clone();
        let original_key = std::mem::replace(&mut keys[0], Setup::leaf_with_rate(2, 1));
        assert_eq!(keys[0].bytecode.vars(), n);
        for (cells, &key) in bad.records.iter_mut().zip(&keys[2].schema) {
            if key == 0 {
                *cells = DeferredClaim::recompute(
                    &keys[0].bytecode,
                    cells[..n].to_vec(),
                    cells[n + 1..n + 1 + 2 * flock::hash::K_LOG].to_vec(),
                )
                .unwrap()
                .cells();
            }
        }
        assert!(keys[2].validate_records(&keys, &bad).is_ok());
        assert!(keys[2].verify(&keys, &digest, &bad).is_err());
        rejected += 1;
        keys[0] = original_key;
        assert!(keys[2].verify(&keys, &digest, &proof).is_ok());
        println!(
            "{}",
            serde_json::json!({"kind":"deferred_record_adversarial_controls","verified_proofs":7,"rejected":rejected,"log_inv_rate":1})
        );
        assert_eq!(rejected, 11);
    }
}
