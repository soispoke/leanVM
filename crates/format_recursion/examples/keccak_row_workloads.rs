//! Matched application digest with bit-level or native-row Keccak.
use circuit_suite::{Ckt, Workload};
use format_recursion::{boolean_application, native_hash::Builder};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn create<W: Workload>(
    circuit: &circuit_suite::Circuit,
    sources: &[circuit_suite::Src],
    calls: &[circuit_suite::KeccakCall],
    seed: u64,
    identity: [u8; 32],
) -> Builder {
    let instance = W::instance(seed);
    let mut b = Builder::default();
    let inputs: Vec<_> = instance.inputs.iter().map(|&v| b.input(u64::from(v))).collect();
    let bits = boolean_application::lower_with_keccak(&mut b, circuit, sources, &inputs, calls);
    let mut statement = [0u8; 64];
    for (i, bit) in bits.iter().enumerate() {
        statement[i / 8] |= (b.value(*bit).c0 as u8) << (i % 8);
    }
    assert_eq!(statement, instance.statement, "independent application statement");
    let mut message: Vec<_> = identity
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| b.constant(u64::from_le_bytes(*word)))
        .collect();
    for chunk in bits.as_chunks::<128>().0.iter() {
        let reversed: Vec<_> = (0..16)
            .rev()
            .flat_map(|byte| (0..8).map(move |bit| chunk[8 * byte + bit]))
            .collect();
        for word in reversed.as_chunks::<64>().0.iter() {
            message.push(b.pack(word));
        }
    }
    let digest = b.hash_words(&message);
    let mut expected = identity.to_vec();
    for chunk in statement.as_chunks::<16>().0.iter() {
        expected.extend(chunk.iter().rev());
    }
    let expected = primitives::protocol_hash::hash(&expected);
    let actual: Vec<_> = digest.iter().flat_map(|&word| b.value(word).c0.to_le_bytes()).collect();
    assert_eq!(actual, expected, "canonical application claim");
    for word in digest {
        b.expose(word);
    }
    if calls.is_empty() {
        b.keccak_f([format_recursion::native_hash::Word::ZERO; 25]);
    }
    b
}
fn run<W: Workload>(args: &[String]) {
    let native = args[2] == "rows";
    let seed: u64 = args.get(5).map_or(20261024, |v| v.parse().unwrap());
    let mut c = Ckt::new();
    if native {
        c.enable_native_keccak();
    }
    let public = W::build(&mut c);
    let core_rows = c.rows();
    let (circuit, sources, calls) = if native {
        c.finish_native_keccak(&public)
    } else {
        let (ckt, srcs) = c.finish(&public);
        (ckt, srcs, Vec::new())
    };
    let identity = if native {
        let (original, _, _) = circuit_suite::build::<W>();
        format_recursion::application_lowering::identity(&original)
    } else {
        format_recursion::application_lowering::identity(&circuit)
    };
    let canonical = create::<W>(&circuit, &sources, &calls, seed, identity);
    let public = canonical.public_values();
    let start = Instant::now();
    let setup = canonical.setup_mixed().unwrap();
    let shape = setup.verifier_shape();
    println!(
        "{}",
        serde_json::json!({"kind":"setup","setup_s":start.elapsed().as_secs_f64(),"core_rows":core_rows,"native_rows":canonical.rows(),"permutations":calls.len(),"shape":format!("{shape:?}")})
    );
    let context = primitives::protocol_hash::hash(format!("keccak-rows-relation:{}", W::NAME).as_bytes());
    if args[3] == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = create::<W>(&circuit, &sources, &calls, seed, identity);
        let proof = setup
            .prove_mixed(&witness.values, &witness.permutations, &witness.compressions, &context)
            .unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        std::fs::write(&args[4], &encoded).unwrap();
        println!(
            "{}",
            serde_json::json!({"kind":"wallet","workload":W::NAME,"native_keccak":native,"wallet_prove_s":elapsed,"proof_bytes":encoded.len(),"permutations":witness.permutations.len(),"application_permutations":calls.len(),"blake2s_compressions":witness.compressions.len(),"arithmetic_rows":witness.rows(),"padded_arithmetic_rows":1usize<<shape.index.log_rows,"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"statement":W::instance(seed).statement.to_vec()})
        );
    } else {
        let encoded = std::fs::read(&args[4]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"kind":"verify","verify_ms":start.elapsed().as_secs_f64()*1000.})
        );
    }
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "shielded" => run::<circuit_suite::shielded_keccak::ShieldedTransfer>(&args),
        "falcon" => run::<circuit_suite::falcon::Falcon512>(&args),
        "keccak" => run::<circuit_suite::keccak::Keccak256OneKiB>(&args),
        "mpt" => run::<circuit_suite::mpt::MptStorageProof>(&args),
        _ => panic!("unknown workload"),
    }
}
