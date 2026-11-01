#[cfg(not(feature = "keccak-protocol"))]
mod blake_control {
    //! Reconcile automatic native lowering with previously accepted keys and claims.
    use circuit_suite::Workload;
    use format_recursion::{application_lowering, private_recursion::Setup};
    use std::path::Path;

    #[global_allocator]
    static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

    fn check<W: Workload>(reference: &serde_json::Value) {
        let (circuit, sources, _) = circuit_suite::build::<W>();
        let id = application_lowering::identity(&circuit);
        let selected = application_lowering::select(&circuit, &sources).unwrap();
        let expected = reference["trim"].as_bool().unwrap();
        assert_eq!(selected.trim_outputs, expected, "{}", W::NAME);
        let instance = W::instance(20261024);
        let automatic = application_lowering::lower(&circuit, &sources, id, &instance.inputs, selected.trim_outputs);
        let control = application_lowering::lower(&circuit, &sources, id, &instance.inputs, expected);
        assert!(automatic.trace.same_program(&control.trace));
        assert!(
            automatic
                .trace
                .nodes
                .iter()
                .zip(&control.trace.nodes)
                .all(|(a, b)| a.value == b.value)
        );
        drop(control);
        let words: Vec<_> = automatic
            .trace
            .public
            .iter()
            .map(|at| automatic.trace.nodes[at.0].value)
            .collect();
        let claim = fiat_shamir::merkle::scalars_to_hash(&words.try_into().unwrap()).unwrap();
        assert_eq!(serde_json::json!(claim), reference["claim"]);
        let setup = Setup::new(automatic.trace).unwrap();
        assert_eq!(serde_json::json!(setup.bridge.index.root), reference["key"]);
        assert_eq!(
            setup.bridge.verifier_shape(),
            if selected.trim_outputs {
                selected.trimmed
            } else {
                selected.untrimmed
            }
        );
        println!(
            "{}",
            serde_json::json!({"workload":W::NAME,"trim":selected.trim_outputs,
        "untrimmed_shape":format!("{:?}",selected.untrimmed),"trimmed_shape":format!("{:?}",selected.trimmed),
        "key":setup.bridge.index.root,"identity":id,"claim":claim,
        "same_program":true,"same_key":true,"same_claim":true,"retiming_needed":false})
        );
    }

    pub fn main() {
        parallel::init();
        let args: Vec<_> = std::env::args().collect();
        let reference: serde_json::Value =
            serde_json::from_slice(&std::fs::read(Path::new(&args[1])).unwrap()).unwrap();
        let workload = &args[2];
        let reference = &reference[workload];
        match workload.as_str() {
            "blake2s-64b" => check::<circuit_suite::blake2s::Blake2s64>(reference),
            "blake2s-1kib" => check::<circuit_suite::blake2s::Blake2sOneKiB>(reference),
            "sha256-1kib" => check::<circuit_suite::sha256::Sha256OneKiB>(reference),
            "keccak256-1KiB" => check::<circuit_suite::keccak::Keccak256OneKiB>(reference),
            "mpt-storage-proof" => check::<circuit_suite::mpt::MptStorageProof>(reference),
            "shielded-transfer" => check::<circuit_suite::shielded::ShieldedTransfer>(reference),
            "falcon512" => check::<circuit_suite::falcon::Falcon512>(reference),
            _ => panic!("unknown verification workload"),
        }
    }
}

fn main() {
    #[cfg(not(feature = "keccak-protocol"))]
    blake_control::main();
    #[cfg(feature = "keccak-protocol")]
    panic!("this example reconciles legacy BLAKE2s keys; use a Keccak-native application driver");
}
