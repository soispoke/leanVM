//! Export the compact-description benchmark's ROWS interchange file, without building a proof index.
use circuit_suite::{Circuit, Src, Workload};
use std::io::{BufWriter, Write};

fn emit<W: Workload>(dir: &std::path::Path) {
    let (circuit, public, _) = circuit_suite::build::<W>();
    circuit.check_wired().expect("wired circuit");
    let instance = W::instance(2026102200);
    assert_eq!(
        circuit_suite::read_statement(&circuit.values(&instance.inputs), &public),
        instance.statement,
        "independent reference"
    );
    export(dir, W::NAME, &circuit, &public);
}

fn export(dir: &std::path::Path, name: &str, circuit: &Circuit, public: &[Src]) {
    let last_public = public.iter().filter_map(|s| match s {
        Src::Row(r) => Some(*r as usize + 1),
        _ => None,
    });
    let idle = circuit_suite::Row {
        x: Src::Zero,
        y: Src::Zero,
        c: Src::Zero,
    };
    let used = circuit
        .rows()
        .iter()
        .rposition(|r| *r != idle)
        .map(|r| r + 1)
        .into_iter()
        .chain(last_public)
        .fold(512, usize::max);

    let path = dir.join(format!("{name}.rows"));
    let mut out = BufWriter::new(std::fs::File::create(path).unwrap());
    out.write_all(b"ROWS").unwrap();
    out.write_all(&[circuit.log_rows as u8]).unwrap();
    out.write_all(&u32::try_from(used).unwrap().to_le_bytes()).unwrap();
    let encode = |src: Src| match src {
        Src::Zero => 0,
        Src::One => 1,
        Src::Row(r) => r + 2,
    };
    for &src in public {
        out.write_all(&encode(src).to_le_bytes()).unwrap();
    }
    for row in &circuit.rows()[512..used] {
        for src in [row.x, row.y, row.c] {
            out.write_all(&encode(src).to_le_bytes()).unwrap();
        }
    }
    out.flush().unwrap();
    println!(
        "{}",
        serde_json::json!({"workload":name,"rows_used":used,"log_rows":circuit.log_rows})
    );
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() >= 3, "export_rows OUT_DIR WORKLOAD...");
    let dir = std::path::Path::new(&args[1]);
    std::fs::create_dir_all(dir).unwrap();
    for name in &args[2..] {
        match name.as_str() {
            "membership" => {
                let circuit = flock::quotient::circuit::membership();
                circuit.check_wired().expect("wired membership circuit");
                let public = circuit_suite::describe::public_sources(&circuit);
                export(dir, "membership", &circuit, &public);
            }
            "blake2s-1kib" => emit::<circuit_suite::blake2s::Blake2sOneKiB>(dir),
            "sha256-1kib" => emit::<circuit_suite::sha256::Sha256OneKiB>(dir),
            "keccak256-1KiB" => emit::<circuit_suite::keccak::Keccak256OneKiB>(dir),
            "shielded-transfer" => emit::<circuit_suite::shielded::ShieldedTransfer>(dir),
            "falcon512" => emit::<circuit_suite::falcon::Falcon512>(dir),
            "mpt-storage-proof" => emit::<circuit_suite::mpt::MptStorageProof>(dir),
            "ecdsa-secp256k1" => emit::<circuit_suite::secp256k1::Ecdsa>(dir),
            "poseidon-bn254" => emit::<circuit_suite::poseidon::PoseidonSponge<1024>>(dir),
            other => panic!("unknown workload {other}"),
        }
    }
}
