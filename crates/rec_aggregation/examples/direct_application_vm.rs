//! Direct application execution in leanVM, without a quotient proof or recursive verifier.
use circuit_suite::Workload;
use lean_compiler::{compile, parse};
use leanvm_core::cpu;
use primitives::field::F192;
use std::{path::Path, time::Instant};

#[global_allocator]
static ALLOC: bench::Jemalloc = bench::Jemalloc;

fn public(statement: &[u8]) -> [F192; 2] {
    assert_eq!(statement.len(), 64);
    assert!(statement[32..].iter().all(|&b| b == 0));
    std::array::from_fn(|i| {
        F192::new(
            u64::from_le_bytes(statement[16 * i..16 * i + 8].try_into().unwrap()),
            u64::from_le_bytes(statement[16 * i + 8..16 * i + 16].try_into().unwrap()),
            0,
        )
    })
}

fn source(bytes: usize) -> String {
    assert!(bytes > 0 && bytes.is_multiple_of(64));
    let blocks = bytes / 64;
    let mut s = format!(
        "from snark_lib import *\n\ndef main():\n    message = StackBuf({})\n    hint_witness(message, \"message\")\n",
        bytes / 16
    );
    for block in 0..blocks {
        let at = block * 4;
        let chaining = if block == 0 {
            String::new()
        } else {
            format!(", cv=h{}", block - 1)
        };
        s.push_str(&format!("    h{block} = StackBuf(2)\n    blake2s(message[{at}:{}], message[{}:{}], h{block}{chaining}, counter={}, final={})\n",
            at+2,at+2,at+4,64*(block+1),usize::from(block+1==blocks)));
    }
    s.push_str(&format!(
        "    output = GEN ** 0\n    output[1] = h{}[0]\n    output[GEN] = h{}[1]\n    return\n",
        blocks - 1,
        blocks - 1
    ));
    s
}

fn peak_rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn run<W: Workload>(bytes: usize, seed: u64, output: Option<&Path>, saved: Option<&Path>) {
    let start = Instant::now();
    let source = source(bytes);
    let mut program = compile(&parse(&source).expect("direct application parses"));
    let identity = primitives::hash::hash(&bincode::serialize(&cpu::fs_seed(&program)).unwrap());
    let setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let instance = W::instance(seed);
    let public_input = public(&instance.statement);
    if let Some(path) = saved {
        let certificate = std::fs::read(path).unwrap();
        assert_eq!(certificate[..32], identity);
        assert_eq!(certificate[32..96], instance.statement);
        let proof = bincode::deserialize(&certificate[96..]).unwrap();
        cpu::verify(&program, &public_input, &proof).expect("saved direct application proof verifies");
        println!(
            "{}",
            serde_json::json!({"kind":"independent_verification","backend":"leanVM-direct","workload":W::NAME,"status":"verified"})
        );
        return;
    }
    let start = Instant::now();
    let message: Vec<u8> = instance
        .inputs
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bits| {
            bits.iter()
                .enumerate()
                .fold(0, |acc, (i, &bit)| acc | (u8::from(bit) << i))
        })
        .collect();
    assert_eq!(message.len(), bytes);
    let words: Vec<_> = message
        .as_chunks::<16>()
        .0
        .iter()
        .map(|chunk| {
            F192::new(
                u64::from_le_bytes(chunk[..8].try_into().unwrap()),
                u64::from_le_bytes(chunk[8..].try_into().unwrap()),
                0,
            )
        })
        .collect();
    program.set_witness("message", vec![words]);
    let witness_transport_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let (proof, stats) = cpu::prove(&program, public_input, 2).expect("direct application proof");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    cpu::verify(&program, &public_input, &proof).expect("direct application verifies");
    let verify_ms = start.elapsed().as_secs_f64() * 1000.;
    let mut wrong = public_input;
    wrong[0] += F192::ONE;
    assert!(cpu::verify(&program, &wrong, &proof).is_err());
    let mut wrong_program = program.clone();
    let mut bad_message = message;
    bad_message[0] ^= 1;
    let words: Vec<_> = bad_message
        .as_chunks::<16>()
        .0
        .iter()
        .map(|chunk| {
            F192::new(
                u64::from_le_bytes(chunk[..8].try_into().unwrap()),
                u64::from_le_bytes(chunk[8..].try_into().unwrap()),
                0,
            )
        })
        .collect();
    wrong_program.set_witness("message", vec![words]);
    assert!(wrong_program.execute(public_input).is_err());
    let mut certificate = identity.to_vec();
    certificate.extend(instance.statement);
    certificate.extend(bincode::serialize(&proof).unwrap());
    if let Some(path) = output {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&certificate)
            .unwrap();
    }
    println!(
        "{}",
        serde_json::json!({"kind":"client","backend":"leanVM-direct","workload":W::NAME,
        "seed":seed,"program_identity":identity,"statement":instance.statement.to_vec(),"setup_ms":setup_ms,
        "witness_transport_ms":witness_transport_ms,"vm_execution_and_proving_ms":prove_ms,
        "create_ms":witness_transport_ms+prove_ms,"verify_ms":verify_ms,"certificate_bytes":certificate.len(),
        "proof_digest":primitives::hash::hash(&certificate),"base_counts":stats.base_counts,"padded_cycles":stats.cycles,
        "peak_rss_kib":peak_rss_kib(),"log_inv_rate":2,"status":"verified",
        "scope":"direct application proof, no quotient wrapper, no recursion, Ethereum compatibility not established"})
    );
}

fn main() {
    parallel::init();
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str, default: &str| {
        args.windows(2)
            .find(|p| p[0] == name)
            .map_or_else(|| default.to_owned(), |p| p[1].clone())
    };
    let name = arg("--workload", "blake2s-64b");
    let seed = arg("--seed", "20261024").parse().unwrap();
    let output = args.windows(2).find(|p| p[0] == "--out").map(|p| Path::new(&p[1]));
    let saved = args.windows(2).find(|p| p[0] == "--verify").map(|p| Path::new(&p[1]));
    assert!(!(output.is_some() && saved.is_some()));
    match name.as_str() {
        "blake2s-64b" => run::<circuit_suite::blake2s::Blake2s64>(64, seed, output, saved),
        "blake2s-1kib" => run::<circuit_suite::blake2s::Blake2sOneKiB>(1024, seed, output, saved),
        other => panic!("no direct leanVM application implementation for {other}"),
    }
}
