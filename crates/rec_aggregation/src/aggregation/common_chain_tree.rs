//! Tagged hash-chain recursion using one self-referential VM program at every height.
//! The canonical verifier batches fresh and carried claims into one deferred
//! claim per fixed polynomial. The consumer discharges those claims.
use super::*;

pub type Digest = [u8; 32];
const PROOF_CAP: usize = 1 << 20;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TreeProof {
    pub height: u32,
    pub statement: Digest,
    proof: leanvm_core::cpu::Proof,
    bytecode_point: Vec<F192>,
    matrix_point: Vec<F192>,
}

impl TreeProof {
    pub fn encode(&self) -> Result<Vec<u8>, AggregateVerifyError> {
        wire()
            .with_limit(PROOF_CAP as u64)
            .serialize(self)
            .map_err(|_| AggregateVerifyError::MalformedEncoding)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AggregateVerifyError> {
        if bytes.len() > PROOF_CAP {
            return Err(AggregateVerifyError::MalformedEncoding);
        }
        wire()
            .with_limit(PROOF_CAP as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|_| AggregateVerifyError::MalformedEncoding)
    }

    pub fn stream_scalars(&self) -> usize {
        self.proof.stream.len()
    }

    pub fn merkle_phases(&self) -> usize {
        self.proof.merkle.len()
    }
}

pub struct Prepared {
    program: Program,
    hints: Hints,
    public: [F192; 2],
    height: u32,
    statement: Digest,
    defer: DeferredClaim,
    log_inv_rate: usize,
}

impl Prepared {
    pub fn prove(mut self) -> Result<(TreeProof, leanvm_core::cpu::Stats), AggregationError> {
        self.hints.install(&mut self.program);
        let (proof, stats) =
            prove(&self.program, self.public, self.log_inv_rate).map_err(AggregationError::ProofError)?;
        Ok((
            TreeProof {
                height: self.height,
                statement: self.statement,
                proof,
                bytecode_point: self.defer.bytecode_point,
                matrix_point: self.defer.matrix_point,
            },
            stats,
        ))
    }
}

pub struct Setup {
    program: Program,
    bytecode: Bytecode,
    seed: [F192; 2],
    chain: usize,
    log_inv_rate: usize,
}

impl Setup {
    pub fn new(chain: usize, log_inv_rate: usize) -> Self {
        assert!(chain <= 1 << 20);
        pcs::whir::validate_log_inv_rate(log_inv_rate).expect("production WHIR rate");
        let source = chain_tree::canonical_source(&[])
            + &include_str!("../../guests/common_chain_tree.py")
                .replace("TREE_CHAIN_TAIL", &(chain * 256).to_string())
                .replace("TREE_CHAIN", &chain.to_string());
        let mut guess = 20;
        for _ in 0..8 {
            let program = chain_tree::compile_source(source.clone(), guess);
            let actual = program.prog.len().trailing_zeros() as usize;
            if actual == guess {
                let bytecode = Bytecode::of(&program);
                let seed = leanvm_core::cpu::fs_seed(&program);
                return Self {
                    program,
                    bytecode,
                    seed,
                    chain,
                    log_inv_rate,
                };
            }
            guess = actual;
        }
        panic!("common hash-chain bytecode must converge");
    }

    pub fn key(&self) -> [F192; 2] {
        self.seed
    }

    pub fn code_len(&self) -> usize {
        self.program.code_len()
    }

    fn public(&self, height: u32, statement: &Digest, defer: &DeferredClaim) -> [F192; 2] {
        seeded_statement_digest(
            self.seed,
            pack_hash_state(statement),
            [F192::new(height as u64, 0, 0), F192::ZERO],
            defer,
        )
    }

    fn hints(&self, height: u32, children: usize) -> Hints {
        let mut hints = Hints::default();
        hints.push(
            "tree_meta",
            vec![
                self.seed[0],
                self.seed[1],
                count(children),
                F192::new(height as u64, 0, 0),
            ],
        );
        hints
    }

    pub fn prepare_leaf(&self, start: &Digest) -> Prepared {
        let mut state = *start;
        for _ in 0..self.chain {
            let mut bytes = vec![0x43];
            bytes.extend(state);
            state = primitives::hash::hash(&bytes);
        }
        let mut bytes = vec![0x4c];
        bytes.extend(state);
        bytes.extend((self.chain as u64).to_le_bytes());
        let statement = primitives::hash::hash(&bytes);
        let defer = DeferredClaim::leaf(&self.bytecode);
        let mut hints = self.hints(0, 0);
        hints.push("start", pack_hash_state(start).to_vec());
        hints.push(
            "leaf_defer",
            vec![defer.bytecode_value, defer.matrix_a_value, defer.matrix_b_value],
        );
        Prepared {
            program: self.program.clone(),
            public: self.public(0, &statement, &defer),
            hints,
            height: 0,
            statement,
            defer,
            log_inv_rate: self.log_inv_rate,
        }
    }

    fn checked_claim(&self, proof: &TreeProof) -> Result<DeferredClaim, AggregateVerifyError> {
        if wire()
            .serialized_size(proof)
            .map_err(|_| AggregateVerifyError::MalformedEncoding)?
            > PROOF_CAP as u64
        {
            return Err(AggregateVerifyError::MalformedEncoding);
        }
        DeferredClaim::recompute(&self.bytecode, proof.bytecode_point.clone(), proof.matrix_point.clone())
    }

    pub fn verify(&self, proof: &TreeProof) -> Result<(), AggregateVerifyError> {
        let defer = self.checked_claim(proof)?;
        verify(
            &self.program,
            &self.public(proof.height, &proof.statement, &defer),
            &proof.proof,
        )
        .map_err(AggregateVerifyError::Snark)?;
        Ok(())
    }

    pub fn prepare_node(&self, left: &TreeProof, right: &TreeProof) -> Result<Prepared, AggregationError> {
        let height = left
            .height
            .max(right.height)
            .checked_add(1)
            .ok_or(AggregationError::TooLarge)?;
        let mut bytes = vec![0x4e];
        bytes.extend(left.statement);
        bytes.extend(right.statement);
        let statement = primitives::hash::hash(&bytes);
        let mut hints = self.hints(height, 2);
        hints.push(
            "tree_digests",
            [pack_hash_state(&left.statement), pack_hash_state(&right.statement)].concat(),
        );
        hints.push(
            "tree_heights",
            vec![
                F192::new(left.height as u64, 0, 0),
                F192::new(right.height as u64, 0, 0),
            ],
        );
        let mut subs = Vec::new();
        let mut carried = Vec::new();
        for child in [left, right] {
            let claim = self.checked_claim(child).map_err(AggregationError::InvalidChild)?;
            let public = self.public(child.height, &child.statement, &claim);
            let summary = verify(&self.program, &public, &child.proof)
                .map_err(|e| AggregationError::InvalidChild(AggregateVerifyError::Snark(e)))?;
            let (sub, fresh) = gen_verify(&self.program, public, summary)?;
            for (name, entry) in sub {
                hints.push(name, entry);
            }
            hints.push("child_defer", claim.cells());
            subs.push(fresh);
            carried.push(claim);
        }
        let (batch, defer) = aggregate_deferred_claims(&self.bytecode, &subs, &[&carried[0], &carried[1]]);
        for (name, entry) in batch {
            hints.push(name, entry);
        }
        Ok(Prepared {
            program: self.program.clone(),
            public: self.public(height, &statement, &defer),
            hints,
            height,
            statement,
            defer,
            log_inv_rate: self.log_inv_rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executes(mut prepared: Prepared) -> bool {
        prepared.hints.install(&mut prepared.program);
        prepared.program.execute(prepared.public).is_ok()
    }

    #[test]
    fn guest_height_matches_checked_integer_successor() {
        let helper = include_str!("../../guests/common_chain_tree.py")
            .split("\ndef main():")
            .next()
            .unwrap();
        let source = format!(
            "{helper}\ndef main():\n    h = StackBuf(3)\n    hint_witness(h, \"heights\")\n    common_height(h[0], h[1], h[2])\n    return\n"
        );
        let program = chain_tree::compile_source(source, 20);
        for left in [0, 1, 255, 65535, u32::MAX - 1, u32::MAX] {
            for right in [0, 1, 255, 65535, u32::MAX - 1, u32::MAX] {
                let expected = left.max(right).checked_add(1);
                let mut guest = program.clone();
                guest.set_witness(
                    "heights",
                    vec![vec![
                        F192::new(expected.unwrap_or(0) as u64, 0, 0),
                        F192::new(left as u64, 0, 0),
                        F192::new(right as u64, 0, 0),
                    ]],
                );
                assert_eq!(
                    guest.execute([F192::ZERO; 2]).is_ok(),
                    expected.is_some(),
                    "{left}, {right}"
                );
                if let Some(height) = expected {
                    let mut guest = program.clone();
                    guest.set_witness(
                        "heights",
                        vec![vec![
                            F192::new(height.wrapping_add(1) as u64, 0, 0),
                            F192::new(left as u64, 0, 0),
                            F192::new(right as u64, 0, 0),
                        ]],
                    );
                    assert!(guest.execute([F192::ZERO; 2]).is_err());
                }
            }
        }
        for coordinate in 0..3 {
            let mut values = vec![F192::ONE, F192::ZERO, F192::ZERO];
            values[coordinate] = F192::new(1 << 32, 0, 0);
            let mut guest = program.clone();
            guest.set_witness("heights", vec![values]);
            assert!(guest.execute([F192::ZERO; 2]).is_err());
        }
    }

    #[test]
    fn common_key_leaf_execution_and_binding() {
        for chain in [0, 1, 16] {
            let setup = Setup::new(chain, 1);
            let start = primitives::hash::hash(&20261023u64.to_le_bytes());
            assert!(executes(setup.prepare_leaf(&start)));
            let mut bad = setup.prepare_leaf(&start);
            bad.hints.entries("tree_meta")[0][3] = F192::ONE;
            assert!(!executes(bad));
            let mut bad = setup.prepare_leaf(&start);
            bad.hints.entries("tree_meta")[0][2] = count(1);
            assert!(!executes(bad));
            let mut bad = setup.prepare_leaf(&start);
            bad.public[0] += F192::ONE;
            assert!(!executes(bad));
            let mut bad = setup.prepare_leaf(&start);
            bad.hints.entries("leaf_defer")[0][0] += F192::ONE;
            assert!(!executes(bad));
        }
    }

    #[test]
    fn actual_common_key_repeated_and_mixed_height_composition() {
        parallel::init();
        let setup = Setup::new(1, 1);
        let start = primitives::hash::hash(&20261023u64.to_le_bytes());
        let (leaf, _) = setup.prepare_leaf(&start).prove().expect("leaf proof");
        setup.verify(&leaf).expect("leaf verifies");
        let (node, _) = setup.prepare_node(&leaf, &leaf).unwrap().prove().expect("node proof");
        setup.verify(&node).expect("node verifies");
        let (mixed, _) = setup
            .prepare_node(&leaf, &node)
            .unwrap()
            .prove()
            .expect("mixed-height proof");
        assert_eq!(mixed.height, 2);
        setup.verify(&mixed).expect("mixed-height verifies");
        let (repeated, _) = setup
            .prepare_node(&mixed, &node)
            .unwrap()
            .prove()
            .expect("repeated proof");
        assert_eq!(repeated.height, 3);
        setup.verify(&repeated).expect("repeated verifies");
        let bytes = repeated.encode().unwrap();
        setup.verify(&TreeProof::decode(&bytes).unwrap()).unwrap();
        assert!(TreeProof::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(TreeProof::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        assert!(TreeProof::decode(&vec![0; PROOF_CAP + 1]).is_err());
        for mutation in 0..6 {
            let mut bad = repeated.clone();
            match mutation {
                0 => bad.height += 1,
                1 => bad.statement[0] ^= 1,
                2 => bad.proof.stream[0] += F192::ONE,
                3 => bad.bytecode_point[0] += F192::ONE,
                4 => bad.matrix_point[0] += F192::ONE,
                _ => {
                    bad.bytecode_point.pop();
                }
            }
            assert!(setup.verify(&bad).is_err(), "mutation {mutation}");
            assert!(setup.prepare_node(&leaf, &bad).is_err(), "child mutation {mutation}");
        }
        assert!(Setup::new(2, 1).verify(&repeated).is_err());
        let mut bad = repeated.clone();
        bad.height = u32::MAX;
        assert!(setup.prepare_node(&leaf, &bad).is_err());
        for (name, coordinate) in [
            ("tree_heights", 0),
            ("tree_digests", 0),
            ("child_defer", 0),
            ("tree_meta", 0),
            ("tree_meta", 3),
        ] {
            let mut bad = setup.prepare_node(&leaf, &node).unwrap();
            bad.hints.entries(name)[0][coordinate] += F192::ONE;
            assert!(!executes(bad), "untrusted {name}[{coordinate}]");
        }
    }
}
