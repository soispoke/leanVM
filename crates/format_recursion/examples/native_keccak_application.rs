//! Application hash-row experiment. Transcript and WHIR remain BLAKE2s.
use circuit_suite::{Workload, keccak::Keccak256OneKiB};
use format_recursion::native_hash::{Builder, Word};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn application(seed: u64, bit_circuit: Option<&(circuit_suite::Circuit, Vec<circuit_suite::Src>)>) -> Builder {
    let instance = Keccak256OneKiB::instance(seed);
    let mut b = Builder::default();
    if let Some((circuit, sources)) = bit_circuit {
        let inputs: Vec<_> = instance.inputs.iter().map(|&v| b.input(u64::from(v))).collect();
        let bits = format_recursion::boolean_application::lower(&mut b, circuit, sources, &inputs);
        for chunk in bits[..256].chunks(64) {
            let word = b.pack(chunk);
            b.expose(word);
        }
        // The same bridge opens an unused honest permutation anchor in the
        // bit-level control. This does not replace any application hash gate.
        b.keccak_f([Word::ZERO; 25]);
        return b;
    }
    let message: Vec<_> = instance
        .inputs
        .chunks(64)
        .map(|bits| {
            let word = bits
                .iter()
                .enumerate()
                .fold(0, |v, (i, &bit)| v | (u64::from(bit) << i));
            b.input(word)
        })
        .collect();
    let mut state = [Word::ZERO; 25];
    for block in 0..8 {
        for (i, word) in state.iter_mut().enumerate().take(17) {
            let pos = block * 17 + i;
            let input = if pos < message.len() {
                message[pos]
            } else if pos == message.len() {
                b.constant(1)
            } else {
                Word::ZERO
            };
            *word = b.gate(*word, b.one(), input);
        }
        if block == 7 {
            let padding = b.constant(1u64 << 63);
            state[16] = b.gate(state[16], b.one(), padding);
        }
        state = b.keccak_f(state);
    }
    for &word in &state[..4] {
        b.expose(word);
    }
    let expected: Vec<_> = instance.statement[..32]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|v| primitives::field::F192::new(u64::from_le_bytes(*v), 0, 0))
        .collect();
    let public = b.public_values();
    assert_eq!(&public[public.len() - 4..], expected);
    b
}
fn peak_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|s| {
            s.strip_prefix("VmHWM:")
                .map(|v| v.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let seed = args.get(3).map_or(20261024, |s| s.parse().unwrap());
    let bit_circuit = if args.iter().any(|s| s == "--bits") {
        let (circuit, sources, _) = circuit_suite::build::<Keccak256OneKiB>();
        Some((circuit, sources))
    } else {
        None
    };
    let canonical = application(seed, bit_circuit.as_ref());
    let setup = canonical.setup_keccak().unwrap();
    let public = canonical.public_values();
    let context = primitives::protocol_hash::hash(b"hometurf-keccak-native-application-v1");
    if mode == "prove" {
        drop(canonical);
        let start = Instant::now();
        let witness = application(seed, bit_circuit.as_ref());
        let proof = setup.prove(&witness.values, &witness.permutations, &context).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        std::fs::write(&args[2], &encoded).unwrap();
        let shape = setup.verifier_shape();
        println!(
            "{}",
            serde_json::json!({"wallet_prove_s":elapsed,"wallet_peak_rss_kib":peak_rss(),"proof_bytes":encoded.len(),"permutations":witness.permutations.len(),"arithmetic_rows":witness.rows(),"padded_arithmetic_rows":1usize<<shape.index.log_rows,"committed_words":shape.committed_lanes()*(1usize<<(shape.stack_log-pcs::whir::INITIAL_FOLDING_FACTOR)),"shape":format!("{shape:?}"),"raw_digest":Keccak256OneKiB::instance(seed).statement[..32]})
        );
    } else {
        let encoded = std::fs::read(&args[2]).unwrap();
        let start = Instant::now();
        let proof = bincode::deserialize(&encoded).unwrap();
        assert!(setup.verify(&public, &context, &proof));
        println!(
            "{}",
            serde_json::json!({"verify_ms":start.elapsed().as_secs_f64()*1000.,"peak_rss_kib":peak_rss()})
        );
    }
}
