//! Matched tagged hash-chain tree. Each level uses a separate authorized VM key.
use bench::Jemalloc;
use format_recursion::recursion_fast;
use rec_aggregation::aggregation::chain_tree::{Setup, TreeProof};
use std::time::Instant;
#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str, default: usize| {
        args.windows(2)
            .find(|a| a[0] == name)
            .map_or(default, |a| a[1].parse().expect("integer"))
    };
    let depth = arg("--depth", 1);
    let chain = arg("--chain", 16);
    assert!((1..=3).contains(&depth));
    assert!(chain <= recursion_fast::CHAIN_CAP as usize);
    parallel::init();
    let mut keys = Vec::<Setup>::new();
    let t = Instant::now();
    keys.push(Setup::leaf(chain));
    println!(
        "{}",
        serde_json::json!({"kind":"setup","level":0,"setup_s":t.elapsed().as_secs_f64(),"code_len":keys[0].program.code_len(),"backend":"vm"})
    );
    if args.iter().any(|a| a == "--shape") {
        let start = primitives::hash::hash(&20261022u64.to_le_bytes());
        let digest = recursion_fast::expected_leaf(&start, chain as u64).unwrap();
        let mut p = keys[0].program.clone();
        p.set_witness("start", vec![fiat_shamir::merkle::hash_to_scalars(&start).to_vec()]);
        let execution = p
            .execute(fiat_shamir::merkle::hash_to_scalars(&digest))
            .expect("tagged leaf execution");
        println!(
            "{}",
            serde_json::json!({"kind":"leaf_execution","base_cycles":execution.base_counts.iter().sum::<usize>(),"hash_compressions":execution.base_counts[5]})
        );
        for level in 1..=depth {
            let t = Instant::now();
            keys.push(Setup::parent(&keys));
            println!(
                "{}",
                serde_json::json!({"kind":"setup","level":level,"setup_s":t.elapsed().as_secs_f64(),"code_len":keys[level].program.code_len(),"backend":"vm","shape_only":true})
            );
        }
        return;
    }
    let mut children = Vec::<([u8; 32], TreeProof)>::new();
    for i in 0..1usize << depth {
        let start = primitives::hash::hash(&(i as u64 + 20261022).to_le_bytes());
        let digest = recursion_fast::expected_leaf(&start, chain as u64).unwrap();
        let t = Instant::now();
        let (proof, stats) = keys[0].prove_leaf(start, digest).expect("VM leaf");
        let proving = t.elapsed().as_secs_f64();
        let t = Instant::now();
        keys[0].verify(&keys, &digest, &proof).expect("VM leaf verifies");
        let verification = t.elapsed().as_secs_f64();
        println!(
            "{}",
            serde_json::json!({"kind":"proof","level":0,"index":i,"statement":digest,"proving_s":proving,"verification_ms":verification*1000.,"proof_bytes":proof.encoded_size(),"base_cycles":stats.base_counts.iter().sum::<usize>(),"padded_cycles":stats.cycles,"deferred_records":proof.record_count(),"verified":true})
        );
        children.push((digest, proof));
    }
    for level in 1..=depth {
        let t = Instant::now();
        keys.push(Setup::parent(&keys));
        println!(
            "{}",
            serde_json::json!({"kind":"setup","level":level,"setup_s":t.elapsed().as_secs_f64(),"code_len":keys[level].program.code_len(),"backend":"vm"})
        );
        let mut next = Vec::new();
        for (i, pair) in children.as_chunks::<2>().0.iter().enumerate() {
            let digest = recursion_fast::node_statement(&pair[0].0, &pair[1].0);
            let t = Instant::now();
            let prepared = keys[level]
                .prepare_parent(&keys, [(&pair[0].0, &pair[0].1), (&pair[1].0, &pair[1].1)], digest)
                .expect("VM parent preparation");
            let preparation = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let (proof, stats) = prepared.prove().expect("VM parent");
            let proving = t.elapsed().as_secs_f64();
            let t = Instant::now();
            keys[level].verify(&keys, &digest, &proof).expect("VM parent verifies");
            let verification = t.elapsed().as_secs_f64();
            let mut wrong = digest;
            wrong[0] ^= 1;
            assert!(keys[level].verify(&keys, &wrong, &proof).is_err());
            println!(
                "{}",
                serde_json::json!({"kind":"proof","level":level,"index":i,"statement":digest,"preparation_s":preparation,"proving_s":proving,"verification_ms":verification*1000.,"proof_bytes":proof.encoded_size(),"base_cycles":stats.base_counts.iter().sum::<usize>(),"padded_cycles":stats.cycles,"deferred_records":proof.record_count(),"verified":true})
            );
            next.push((digest, proof));
        }
        children = next;
    }
    println!(
        "{}",
        serde_json::json!({"kind":"complete","backend":"vm","levels":depth,"chain":chain,"root":children[0].0,"status":"locally_verified","single_fixed_circuit":false,"forwarded_deferred_claims":true,"contract_revision":recursion_fast::CONTRACT_REVISION,"measurement":"one trial per proof; no warmup; not a quiet matched benchmark","threads":std::env::var("LEANVM_NUM_THREADS").ok(),"oracle_mode":"existing untagged BLAKE2s; tagged statement hashes; challenge ROM adapter pending","lean_certificate":false,"official_score":false})
    );
}
