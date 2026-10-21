//! Two-level aggregation trees over any leaf program.
//!
//! The root runs the recursion guest's own in-circuit verifier (`verify_sub`) on each
//! leaf proof, batches the claims those verifications defer onto the leaf's bytecode and
//! flock's matrices into one (`aggregate_claims`), and publishes the usual statement
//! digest over the leaf program's seed, the ordered leaf public inputs (in the signer-set
//! slot) and that one claim. Verification recomputes the claim natively against the leaf
//! bytecode, rebuilds the statement and checks the root proof.
//!
//! A leaf states nothing deferred of its own, so each is batched with an honest
//! claim at the all-zeros point, as upstream leaves are. The values of every batched
//! claim enter with random weights, so a false one makes the single claim the verifier
//! recomputes false.
use super::*;

const DOMAIN: &[u8] = b"leanvm-aggregate-tree-v1";

/// A root proof: the claim its leaves' verification defers (points only are needed,
/// the values being recomputed) and the VM proof.
#[derive(Clone, Debug)]
pub struct RootProof {
    defer: DeferredClaim,
    pub proof: leanvm_core::cpu::Proof,
}

/// `BLAKE2s(H(DOMAIN) || n || leaves)`, cells as their two little-endian lanes: the
/// root's stand-in for a signer set, so the statement binds each leaf and its position.
pub fn leaf_list_digest(leaves: &[[F192; 2]]) -> [F192; 2] {
    let mut bytes = primitives::hash::hash(DOMAIN).to_vec();
    bytes.extend((leaves.len() as u128).to_le_bytes());
    bytes.extend([0u8; 16]);
    for x in leaves.iter().flatten() {
        assert_eq!(x.c2, 0, "a public input is a canonical cell");
        bytes.extend(x.c0.to_le_bytes());
        bytes.extend(x.c1.to_le_bytes());
    }
    pack_hash_state(&primitives::hash::hash(&bytes))
}

/// The root guest for `n` proofs of `leaf`: upstream's guest with its node `main`
/// replaced, its placeholders baked for the leaf's bytecode size.
pub fn root_guest(leaf: &Program, n: usize) -> Program {
    assert!(
        (1..=MAX_RECURSIONS).contains(&n),
        "a root has 1..=MAX_RECURSIONS leaves"
    );
    let source = include_str!("../../guests/lean_ethereum.py");
    let marker = |m: &str| {
        assert_eq!(
            source.matches(m).count(),
            1,
            "guest marker must occur exactly once: {m}"
        );
        source.find(m).unwrap()
    };
    let (main, after) = (marker("\ndef main():"), marker("\ndef aggregate_claims("));
    assert!(main < after, "the node's main precedes the claim batching");
    let seed = leanvm_core::cpu::fs_seed(leaf);
    let domain = pack_hash_state(&primitives::hash::hash(DOMAIN));
    let mut m = format!(
        "\ndef main():\n    seed_0 = {}\n    seed_1 = {}\n    g_logs_pow2, g_squares = exponent_tables()\n    n_children_g = GEN ** {n}\n    child_pi = HeapBuf(n_children_g * n_children_g)\n    child_fresh = HeapBuf(n_children_g ** DEFER_SIZE)\n    child_carried = HeapBuf(n_children_g ** DEFER_STMT_CELLS)\n    leaves = StackBuf({})\n    hint_witness(leaves, \"leaf_pis\")\n",
        f192_literal(seed[0]),
        f192_literal(seed[1]),
        2 * n
    );
    // The child slots aggregate_claims walks: pi at g^(2c), fresh and carried claims at g^(c * size).
    for c in 0..n {
        m += &format!(
            "    carried{c} = child_carried * GEN ** ({c} * DEFER_STMT_CELLS)\n    hint_witness(carried{c}[0:DEFER_STMT_CELLS], \"child_defer\")\n    child_pi[GEN ** {}] = leaves[{}]\n    child_pi[GEN ** {}] = leaves[{}]\n    verify_sub(leaves[{}], leaves[{}], seed_0, seed_1, g_logs_pow2, g_squares, child_fresh * GEN ** ({c} * DEFER_SIZE))\n",
            2 * c,
            2 * c,
            2 * c + 1,
            2 * c + 1,
            2 * c,
            2 * c + 1
        );
    }
    m += "    defer_stmt = HeapBuf(DEFER_STMT_CELLS)\n    aggregate_claims(n_children_g, child_pi, child_fresh, child_carried, defer_stmt)\n";
    // leaf_list_digest: domain and count, then two leaves a block.
    m += &format!(
        "    lh0 = StackBuf(2)\n    blake2s([{}, {}], [{n}, 0], lh0, counter=64, final={})\n",
        f192_literal(domain[0]),
        f192_literal(domain[1]),
        u8::from(n == 0)
    );
    for pair in 0..n.div_ceil(2) {
        let (i, last) = (2 * pair, 2 * pair + 2 >= n);
        let right = if i + 1 < n {
            format!("[leaves[{}], leaves[{}]]", 2 * i + 2, 2 * i + 3)
        } else {
            "[0, 0]".into()
        };
        m += &format!(
            "    lh{} = StackBuf(2)\n    blake2s([leaves[{}], leaves[{}]], {right}, lh{}, cv=lh{pair}, counter={}, final={})\n",
            pair + 1,
            2 * i,
            2 * i + 1,
            pair + 1,
            64 + 32 * (i + 2).min(n),
            u8::from(last)
        );
    }
    let last = n.div_ceil(2);
    m += &format!(
        "    signers_hash = HeapBuf(WORDS_PER_BLOCK)\n    signers_hash[1] = lh{last}[0]\n    signers_hash[GEN] = lh{last}[1]\n    own_0, own_1 = statement_digest(seed_0, seed_1, signers_hash, 0, 0, defer_stmt)\n    pub_ptr = GEN ** 0\n    assert pub_ptr[1] == own_0\n    assert pub_ptr[GEN] == own_1\n    return\n"
    );
    let kbc = leaf.prog.len().trailing_zeros() as usize;
    let text = source[..main].to_owned() + &source[after..] + &m;
    compile(&parse_with_replacements(&text, &placeholder_map(kbc)).expect("the root guest parses"))
}

fn root_statement(leaf: &Program, leaves: &[[F192; 2]], defer: &DeferredClaim) -> [F192; 2] {
    seeded_statement_digest(
        leanvm_core::cpu::fs_seed(leaf),
        leaf_list_digest(leaves),
        [F192::ZERO; 2],
        defer,
    )
}

/// Prove a root over `leaves`, each a public input and a proof of `leaf`.
pub fn prove_root(
    leaf: &Program,
    root: &Program,
    leaves: &[([F192; 2], leanvm_core::cpu::Proof)],
    log_inv_rate: usize,
) -> Result<(RootProof, leanvm_core::cpu::Stats), AggregationError> {
    let bytecode = Bytecode::of(leaf);
    let carried = DeferredClaim::leaf(&bytecode);
    let mut hints = Hints(Vec::new());
    hints.push("leaf_pis", leaves.iter().flat_map(|(pi, _)| *pi).collect());
    let mut subs = Vec::with_capacity(leaves.len());
    for (pi, proof) in leaves {
        let summary =
            verify(leaf, pi, proof).map_err(|e| AggregationError::InvalidChild(AggregateVerifyError::Snark(e)))?;
        hints.push("child_defer", carried.cells());
        let (sub, defer) = gen_verify(leaf, *pi, summary)?;
        for (name, entry) in sub {
            hints.push(name, entry);
        }
        subs.push(defer);
    }
    let (batch, defer) = aggregate_deferred_claims(&bytecode, &subs, &vec![&carried; leaves.len()]);
    for (name, entry) in batch {
        hints.push(name, entry);
    }
    let publics: Vec<_> = leaves.iter().map(|(pi, _)| *pi).collect();
    let public = root_statement(leaf, &publics, &defer);
    let mut program = root.clone();
    hints.install(&mut program);
    let (proof, stats) = prove(&program, public, log_inv_rate).map_err(AggregationError::ProofError)?;
    Ok((RootProof { defer, proof }, stats))
}

/// Accept `root` only as a proof that each of `leaves`, in order, is the public input of
/// a valid proof of `leaf`.
pub fn verify_root(
    leaf: &Program,
    root_program: &Program,
    leaves: &[[F192; 2]],
    root: &RootProof,
) -> Result<(), AggregateVerifyError> {
    let defer = DeferredClaim::recompute(
        &Bytecode::of(leaf),
        root.defer.bytecode_point.clone(),
        root.defer.matrix_point.clone(),
    )?;
    if defer != root.defer {
        return Err(AggregateVerifyError::MalformedClaim);
    }
    let public = root_statement(leaf, leaves, &defer);
    verify(root_program, &public, &root.proof).map_err(AggregateVerifyError::Snark)?;
    Ok(())
}

impl RootProof {
    /// A copy whose deferred claim names a different bytecode point, for adversarial tests.
    pub fn with_moved_claim(&self) -> Self {
        let mut moved = self.clone();
        moved.defer.bytecode_point[0] += F192::ONE;
        moved
    }
}
