//! Prove and verify the suite's statements with the packed-binary backend, one JSON line a statement.
//!
//! `packed [--repeat R] [--seed S] NAME...`; the names are the workloads' `NAME`s, or `membership`. Each proof is
//! made `R` times (default 3) after one warmup, and the fastest and the median are reported; the machine may be
//! shared, so the timings are as noisy as it is.
use circuit_suite::{Circuit, Ckt, Instance, Src, Workload, blake2s, describe, read_statement};
use packed_format::{Index, Shape, Witness, prove, verify};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::time::Instant;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn us(t: Instant) -> u64 {
    t.elapsed().as_micros() as u64
}

fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

struct Built {
    name: &'static str,
    circuit: Circuit,
    srcs: Vec<Src>,
    used: usize,
    valid: Instance,
}

fn build<W: Workload>(seed: u64) -> Built {
    let mut c = Ckt::new();
    let public = W::build(&mut c);
    let used = c.rows();
    let (circuit, srcs) = c.finish(&public);
    Built {
        name: W::NAME,
        circuit,
        srcs,
        used,
        valid: W::instance(seed),
    }
}

fn membership(seed: u64) -> Built {
    use flock::membership::{DEPTH, Secret};
    let circuit = flock::quotient::circuit::membership();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = || {
        let mut b = [0; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let secret = Secret {
        x: bytes(),
        siblings: std::array::from_fn(|_| bytes()),
        directions: (seed as u32).wrapping_mul(0x9E37_79B9) & (u32::MAX >> (32 - DEPTH)),
    };
    let st = secret.statement();
    let mut statement = [0u8; 64];
    statement[..32].copy_from_slice(&st.y);
    statement[32..].copy_from_slice(&st.root);
    let srcs = describe::public_sources(&circuit);
    let used = circuit.rows().len();
    Built {
        name: "membership",
        circuit,
        srcs,
        used,
        valid: Instance {
            inputs: flock::quotient::circuit::membership_inputs(&secret),
            statement,
        },
    }
}

fn get(name: &str, seed: u64) -> Built {
    use circuit_suite::{sha256::Sha256OneKiB, shielded::ShieldedTransfer};
    match name {
        "membership" => membership(seed),
        n if n == blake2s::Blake2sOneKiB::NAME => build::<blake2s::Blake2sOneKiB>(seed),
        n if n == Sha256OneKiB::NAME => build::<Sha256OneKiB>(seed),
        n if n == ShieldedTransfer::NAME => build::<ShieldedTransfer>(seed),
        n if n == circuit_suite::keccak::Keccak256OneKiB::NAME => build::<circuit_suite::keccak::Keccak256OneKiB>(seed),
        n if n == circuit_suite::falcon::Falcon512::NAME => build::<circuit_suite::falcon::Falcon512>(seed),
        n if n == circuit_suite::mpt::MptStorageProof::NAME => build::<circuit_suite::mpt::MptStorageProof>(seed),
        n if n == circuit_suite::secp256k1::Ecdsa::NAME => build::<circuit_suite::secp256k1::Ecdsa>(seed),
        n if n == circuit_suite::poseidon::PoseidonSponge::<1024>::NAME => {
            build::<circuit_suite::poseidon::PoseidonSponge<1024>>(seed)
        }
        n if n == blake2s::Blake2s64::NAME => build::<blake2s::Blake2s64>(seed),
        n if n == blake2s::Blake2s256::NAME => build::<blake2s::Blake2s256>(seed),
        n if n == blake2s::Blake2s4KiB::NAME => build::<blake2s::Blake2s4KiB>(seed),
        n if n == blake2s::Blake2s16KiB::NAME => build::<blake2s::Blake2s16KiB>(seed),
        other => panic!("unknown statement {other}"),
    }
}

fn main() {
    parallel::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    let seed: u64 = flag("--seed").map_or(1, |s| s.parse().unwrap());
    let repeat: usize = flag("--repeat").map_or(3, |s| s.parse().unwrap());
    assert!(repeat > 0, "--repeat must be positive");
    let names: Vec<&String> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| !a.starts_with("--") && (*i == 0 || !matches!(args[i - 1].as_str(), "--seed" | "--repeat")))
        .map(|(_, a)| a)
        .collect();
    for name in names {
        let b = get(name, seed);
        let statement = b.valid.statement;
        assert_eq!(
            read_statement(&b.circuit.values(&b.valid.inputs), &b.srcs),
            statement,
            "the reference statement"
        );
        let shape = Shape::new(b.circuit.log_rows);
        let t = Instant::now();
        let index = Index::new(&b.circuit);
        let setup_us = us(t);
        let t = Instant::now();
        let witness = Witness::new(&b.circuit, &shape, &b.valid.inputs);
        let witness_us = us(t);

        // One warmup, then `repeat` measured proofs.
        let (mut proof, _) = prove(&index, &statement, &witness);
        verify(b.circuit.log_rows, &index.root, &statement, &proof).expect("warmup proof verifies");
        let mut runs = Vec::new();
        for _ in 0..repeat {
            let t = Instant::now();
            let (p, timings) = prove(&index, &statement, &witness);
            runs.push((us(t), timings));
            verify(b.circuit.log_rows, &index.root, &statement, &p).expect("every measured proof verifies");
            proof = p;
        }
        runs.sort_by_key(|r| r.0);
        let (fastest, median) = (runs[0], runs[runs.len() / 2]);

        let t = Instant::now();
        verify(b.circuit.log_rows, &index.root, &statement, &proof).expect("the honest proof verifies");
        let verify_us = us(t);
        let mut rejected = 0;
        for bit in [0usize, 300, 511] {
            let mut other = statement;
            other[bit / 8] ^= 1 << (bit % 8);
            assert!(verify(b.circuit.log_rows, &index.root, &other, &proof).is_err());
            rejected += 1;
        }
        let proof_bytes = bincode::serialize(&proof).unwrap().len();
        let (witness_bits, index_bits) = shape.committed_bits_per_row();
        let component = |r: &packed_format::Timings| {
            serde_json::json!({"commit_us": r.commit_us, "zerocheck_us": r.zerocheck_us, "copy_us": r.copy_us, "leaves_us": r.leaves_us, "gkr_us": r.gkr_us, "copy_slices_us": r.copy_slices_us,
                "public_us": r.public_us, "open_witness_us": r.open_witness_us, "open_index_us": r.open_index_us})
        };
        let report = serde_json::json!({
            "statement": b.name, "rows_used": b.used, "log_rows": b.circuit.log_rows, "proved_log_rows": shape.log_rows,
            "inputs": b.circuit.n_inputs(),
            "committed_bits_per_row": witness_bits, "index_bits_per_row": index_bits,
            "witness_committed_words": 1u64 << shape.witness_log_words, "index_committed_words": 1u64 << shape.index_log_words,
            "setup_us": setup_us, "witness_us": witness_us,
            "prove_us_fastest": fastest.0, "prove_us_median": median.0, "prove_us_all": runs.iter().map(|r| r.0).collect::<Vec<_>>(),
            "components_fastest": component(&fastest.1),
            "verify_us": verify_us, "proof_bytes": proof_bytes, "negative_cases": rejected,
            "peak_rss_kib": peak_rss_kib(), "threads": parallel::num_threads(),
        });
        println!("{report}");
    }
}
