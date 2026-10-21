use super::*;
use circuit_suite::{Ckt, Wire, read_statement};

/// A small circuit: two 32-bit sums, a xor and an and of the inputs, published.
fn small() -> (Circuit, Vec<bool>, [u8; 64]) {
    let mut c = Ckt::new();
    let a = c.inputs(32);
    let b = c.inputs(32);
    let mut public = c.add(&a, &b);
    let ab = c.xor_word(&a, &b);
    public.extend(c.add(&ab, &b));
    public.extend(c.and_word(&a, &b));
    public.push(c.eq(&a, &b));
    public.push(Wire::ONE);
    public.resize(512, Wire::ZERO);
    let (circuit, srcs) = c.finish(&public);
    let inputs: Vec<bool> = (0..64).map(|i| (0x9e37_79b9_7f4a_7c15u64 >> i) & 1 == 1).collect();
    let statement = read_statement(&circuit.values(&inputs), &srcs);
    (circuit, inputs, statement)
}

struct Setup {
    circuit: Circuit,
    index: Index,
    witness: Witness,
    statement: [u8; 64],
}

fn setup() -> Setup {
    let (circuit, inputs, statement) = small();
    let index = Index::new(&circuit);
    let witness = Witness::new(&circuit, &index.shape, &inputs);
    Setup {
        circuit,
        index,
        witness,
        statement,
    }
}

fn check(s: &Setup, witness: &Witness, statement: &[u8; 64]) -> Result<(), VerifyError> {
    let (proof, _) = prove(&s.index, statement, witness);
    verify(s.circuit.log_rows, &s.index.root, statement, &proof)
}

#[test]
fn the_witness_is_wired_and_public() {
    let s = setup();
    let n = s.index.shape.rows();
    let sigma = permutation(&s.circuit, &s.index.shape);
    let mut seen = vec![false; sigma.len()];
    for k in 0..sigma.len() {
        assert!(!seen[sigma[k] as usize], "a permutation");
        seen[sigma[k] as usize] = true;
        let j = sigma[k] as usize;
        assert_eq!(s.witness.cell(k / n, k % n), s.witness.cell(j / n, j % n), "cell {k}");
    }
    let pattern = public_pattern(&s.statement);
    for r in 0..PUBLIC_ROWS {
        assert_eq!(s.witness.bit(0, r), pattern[0][r], "x of public row {r}");
        assert_eq!(s.witness.bit(1, r), pattern[1][r], "y of public row {r}");
    }
    for r in 0..n {
        let [x, y, c, k] = [0, 1, 2, 3].map(|col| s.witness.bit(col, r));
        assert_eq!(k, (x & y) | (c & (x ^ y)), "the gate on row {r}");
    }
}

#[test]
fn an_honest_proof_verifies() {
    let s = setup();
    check(&s, &s.witness, &s.statement).unwrap();
}

#[test]
fn a_wrong_witness_bit_breaks_the_gate() {
    let s = setup();
    // A carry flipped alone: the gate fails on that row (and the carry's readers disagree with it).
    for r in [PUBLIC_ROWS + 3, PUBLIC_ROWS + 100, s.circuit.rows().len() - 1] {
        let mut w = s.witness.clone();
        w.flip(3, r);
        assert!(check(&s, &w, &s.statement).is_err(), "row {r}");
    }
    // A bit flipped on a padding row, which nothing reads: only the gate sees it.
    let mut w = s.witness.clone();
    w.flip(3, s.index.shape.rows() - 1);
    assert_eq!(check(&s, &w, &s.statement), Err(VerifyError::Gate));
}

/// The first non-public row reading row `j` in its `x` slot, with `j` itself not an input row.
fn a_read(s: &Setup) -> usize {
    (PUBLIC_ROWS..s.circuit.rows().len())
        .find(|&r| matches!(s.circuit.rows()[r].x, Src::Row(j) if j as usize != r))
        .unwrap()
}

#[test]
fn a_copy_violation_is_refused() {
    let s = setup();
    let r = a_read(&s);
    let mut w = s.witness.clone();
    // The read bit differs from its source, the row's gate still holds.
    w.flip(0, r);
    let [x, y, c] = [0, 1, 2].map(|col| w.bit(col, r));
    if w.bit(3, r) != ((x & y) | (c & (x ^ y))) {
        w.flip(3, r);
    }
    assert_eq!(check(&s, &w, &s.statement), Err(VerifyError::Copy));
}

#[test]
fn a_wrong_statement_bit_is_refused() {
    let s = setup();
    let (proof, _) = prove(&s.index, &s.statement, &s.witness);
    for bit in [0usize, 1, 100, 255, 256, 300, 511] {
        let mut other = s.statement;
        other[bit / 8] ^= 1 << (bit % 8);
        assert!(
            verify(s.circuit.log_rows, &s.index.root, &other, &proof).is_err(),
            "bit {bit}"
        );
        // A prover that commits to the true witness but claims the other statement fails the public check.
        assert_eq!(check(&s, &s.witness, &other), Err(VerifyError::Public), "bit {bit}");
    }
}

#[test]
fn a_wrong_index_is_refused() {
    let s = setup();
    // Another circuit's root.
    let mut rows = s.circuit.rows().to_vec();
    let r = a_read(&s);
    rows[r].y = if rows[r].y == Src::Zero { Src::One } else { Src::Zero };
    let other = Index::new(&Circuit::from_rows(s.circuit.log_rows, rows));
    assert_ne!(other.root, s.index.root);
    let (proof, _) = prove(&s.index, &s.statement, &s.witness);
    assert!(verify(s.circuit.log_rows, &other.root, &s.statement, &proof).is_err());

    // A prover committing to no wiring at all proves a witness that ignores its copy constraints: the proof holds
    // for that index and not for the circuit's.
    let shape = s.index.shape;
    let unwired = Index::from_permutation(shape, (0..(ROLES * shape.rows()) as u32).collect());
    let mut w = s.witness.clone();
    w.flip(0, r);
    let [x, y, c] = [0, 1, 2].map(|col| w.bit(col, r));
    if w.bit(3, r) != ((x & y) | (c & (x ^ y))) {
        w.flip(3, r);
    }
    let (proof, _) = prove(&unwired, &s.statement, &w);
    verify(s.circuit.log_rows, &unwired.root, &s.statement, &proof).unwrap();
    assert!(verify(s.circuit.log_rows, &s.index.root, &s.statement, &proof).is_err());
    // And the wrong size.
    let (proof, _) = prove(&s.index, &s.statement, &s.witness);
    assert!(verify(s.circuit.log_rows + 1, &s.index.root, &s.statement, &proof).is_err());
}

#[test]
fn tampered_scalars_are_refused() {
    let s = setup();
    let (proof, _) = prove(&s.index, &s.statement, &s.witness);
    let len = proof.stream.len();
    let mut positions: Vec<usize> = (0..len).step_by(len / 97 + 1).collect();
    positions.extend((0..40).chain(len - 40..len));
    for at in positions {
        let mut bad = proof.clone();
        bad.stream[at].c1 ^= 1 << 17;
        assert!(
            verify(s.circuit.log_rows, &s.index.root, &s.statement, &bad).is_err(),
            "scalar {at} of {len}"
        );
    }
    let mut bad = proof.clone();
    bad.stream.push(F192::ONE);
    assert!(verify(s.circuit.log_rows, &s.index.root, &s.statement, &bad).is_err());
    let mut bad = proof.clone();
    bad.stream.pop();
    assert!(verify(s.circuit.log_rows, &s.index.root, &s.statement, &bad).is_err());
}

#[test]
fn membership_proves() {
    use flock::membership::{DEPTH, Secret};
    let circuit = flock::quotient::circuit::membership();
    let secret = Secret {
        x: [7; 32],
        siblings: std::array::from_fn(|i| [i as u8; 32]),
        directions: 0x2b5 & (u32::MAX >> (32 - DEPTH)),
    };
    let st = secret.statement();
    let mut statement = [0u8; 64];
    statement[..32].copy_from_slice(&st.y);
    statement[32..].copy_from_slice(&st.root);
    let index = Index::new(&circuit);
    let witness = Witness::new(
        &circuit,
        &index.shape,
        &flock::quotient::circuit::membership_inputs(&secret),
    );
    let (proof, _) = prove(&index, &statement, &witness);
    verify(circuit.log_rows, &index.root, &statement, &proof).unwrap();
    statement[5] ^= 4;
    assert!(verify(circuit.log_rows, &index.root, &statement, &proof).is_err());
}
