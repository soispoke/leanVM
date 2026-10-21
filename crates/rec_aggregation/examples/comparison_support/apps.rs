//! The matched applications as a node sees them: proving a client, admitting it, and the
//! aggregate program and public input over a batch. Shared by the evaluator and the tree driver.
use super::*;
use fiat_shamir::transcript::{Proof, RawProof};
use flock::{
    membership::{Secret, Statement},
    quotient::{self, Index, Oracle, Table, circuit, opening},
};
use leanvm_core::cpu;
use primitives::field::{F64, F192};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub(crate) const LOG_ROWS: usize = 20;
/// The baseline PCS rate; the verifier rejects any other, all being 128-bit but trading proof size for speed.
pub(crate) const LOG_INV_RATE: usize = 2;

#[derive(Serialize, Deserialize)]
pub(crate) struct Witness {
    pub x: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: u32,
}
/// One application's client proof, as a node receives it.
#[derive(Serialize, Deserialize)]
pub(crate) struct Client {
    pub y: [u8; 32],
    pub root: [u8; 32],
    pub piop: Proof,
    pub openings: [Proof; 3],
}
pub(crate) struct Setup {
    pub circuit: circuit::Circuit,
    pub index: Index,
    pub wiring: opening::Committed,
    pub app_id: [u8; 32],
}
pub(crate) fn setup() -> Setup {
    let circuit = circuit::membership();
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let app_id = r1cs::identity(&circuit);
    Setup {
        circuit,
        index,
        wiring,
        app_id,
    }
}
pub(crate) fn statement(c: &Client) -> Statement {
    Statement { y: c.y, root: c.root }
}
pub(crate) fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|p| p[0] == name)
        .map(|p| p[1].clone())
        .unwrap_or_else(|| panic!("missing {name}"))
}
/// Whether the aggregate checks the PIOP, and the PIOP's random oracle.
pub(crate) fn interface(args: &[String]) -> (bool, Oracle) {
    match arg(args, "--interface").as_str() {
        "pcs" => (false, Oracle::Keccak),
        "r1cs" => (true, Oracle::Keccak),
        "r1cs-vm" => (true, Oracle::Blake2s),
        other => panic!("unknown interface {other}"),
    }
}

/// Native admission: the PIOP and all three openings, returning the aggregate's inputs.
pub(crate) fn admit<'a>(
    s: &'a Setup,
    layouts: &'a [opening::Layout; 2],
    oracle: Oracle,
    c: &Client,
) -> Option<(Vec<Opened<'a>>, Vec<RawProof>)> {
    let (roots, claims) = quotient::verify_with(oracle, &s.wiring.root, &statement(c), &c.piop, LOG_ROWS).ok()?;
    let opened: Vec<Opened> = [
        (&layouts[0], roots[0], vec![claims.witness]),
        (&s.index.table().layout, s.wiring.root, vec![claims.wiring]),
        (&layouts[1], roots[1], vec![claims.quotient, claims.sum]),
    ]
    .into_iter()
    .zip(&c.openings)
    .map(|((layout, root, claims), proof)| Opened {
        layout,
        root,
        claims,
        proof: proof.clone(),
    })
    .collect();
    let raws = opened
        .iter()
        .map(|o| opening::verification_trace(o.layout, &o.root, &o.claims, &o.proof))
        .collect::<Option<Vec<_>>>()?;
    Some((opened, raws))
}
/// The process's peak resident memory, where the kernel reports it (Linux and Android).
pub(crate) fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}
pub(crate) fn layouts() -> [opening::Layout; 2] {
    [quotient::witness_layout(LOG_ROWS), quotient::quotient_layout(LOG_ROWS)]
}
/// The aggregate's public input: the ordered list of per-application claims.
pub(crate) fn public(
    s: &Setup,
    full: bool,
    clients: &[Client],
    admitted: &[(Vec<Opened>, Vec<RawProof>)],
) -> [F192; 2] {
    let claims: Vec<_> = clients
        .iter()
        .zip(admitted)
        .map(|(c, (opened, _))| {
            if full {
                r1cs::public_claim(&s.app_id, &statement(c))
            } else {
                pcs_public(opened)
            }
        })
        .collect();
    batch_public(&claims)
}
pub(crate) fn program(
    s: &Setup,
    (full, oracle): (bool, Oracle),
    admitted: &[(Vec<Opened>, Vec<RawProof>)],
) -> cpu::Program {
    assert!(admitted.len() >= 2, "a batch aggregates at least two applications");
    let (opened, raws) = &admitted[0];
    for (_, rs) in admitted {
        for (a, b) in rs.iter().zip(raws) {
            assert_eq!(
                a.stream.len(),
                b.stream.len(),
                "every application has the compiled shape"
            );
        }
    }
    build(opened, raws, &s.wiring.root, &s.app_id, full, oracle, admitted.len())
}

/// One application's device work: witness, PIOP on `oracle`'s transcript, and the three openings,
/// with each stage's time in microseconds.
pub(crate) fn prove_client(s: &Setup, oracle: Oracle, w: &Witness, rng: &mut impl RngCore) -> (Client, [f64; 3]) {
    let t = Instant::now();
    let secret = Secret {
        x: w.x,
        siblings: w.siblings.clone().try_into().expect("Merkle depth"),
        directions: w.directions,
    };
    let st = secret.statement();
    let cells = s.circuit.cells(&circuit::membership_inputs(&secret));
    let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
    let mut committed = Vec::new();
    let mut commit = |table: &Table| {
        let c = opening::commit(table);
        let root = c.root;
        committed.push(c);
        root
    };
    let witness_us = elapsed(t);
    let t = Instant::now();
    let p = quotient::prove_with(
        oracle,
        &s.circuit,
        &s.index,
        &s.wiring.root,
        &st,
        &cells,
        &masks,
        &mut commit,
    );
    let piop_us = elapsed(t);
    let t = Instant::now();
    let client = Client {
        y: st.y,
        root: st.root,
        piop: p.proof,
        openings: [
            opening::open(&p.witness, &committed[0], std::slice::from_ref(&p.claims.witness)),
            opening::open(s.index.table(), &s.wiring, std::slice::from_ref(&p.claims.wiring)),
            opening::open(&p.quotient, &committed[1], &[p.claims.quotient, p.claims.sum]),
        ],
    };
    let opening_us = elapsed(t);
    (client, [witness_us, piop_us, opening_us])
}
