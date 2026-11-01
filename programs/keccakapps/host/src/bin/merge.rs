//! Fresh-process merges over the exact wallet receipts.
use leanvm::aggregate::{Kind, Leaf, LeafShape, Tree, TreeProof, TreeShape};
use leanvm::{Output, Program, Proof, Rate};
use serde_json::json;
use std::{fs, time::Instant};

#[global_allocator]
static ALLOC: bench::Jemalloc = bench::Jemalloc;

fn load(elf: &str, prefix: &str) -> (Program, Proof, Output) {
    let program = Program::from_elf(&fs::read(elf).unwrap()).unwrap();
    let proof = Proof::from_bytes(&fs::read(format!("{prefix}.proof")).unwrap()).unwrap();
    let output: [u64; 4] = serde_json::from_slice(&fs::read(format!("{prefix}.output")).unwrap()).unwrap();
    (program, proof, Output::new(output))
}
fn main() {
    bench::init_tracing_from_env();
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 9,
        "mode case elf0 receipt0 elf1 receipt1 output-prefix child-prefix"
    );
    let (mode, case, prefix) = (&args[1], &args[2], &args[7]);
    let p0 = load(&args[3], &args[4]);
    let p1 = load(&args[5], &args[6]);
    let setup = Instant::now();
    let tree = if case.contains("mixed") {
        Tree::new_mixed(
            [
                (&p0.0, LeafShape::of(&p0.1).unwrap()),
                (&p1.0, LeafShape::of(&p1.1).unwrap()),
            ],
            2,
            Rate::MIN,
        )
        .unwrap()
    } else {
        assert_eq!(p0.0.digest(), p1.0.digest());
        Tree::new(
            &p0.0,
            TreeShape {
                leaf: LeafShape::of(&p0.1).unwrap(),
                arity_0: 2,
                arity: 2,
                rate: Rate::MIN,
            },
        )
        .unwrap()
    };
    let setup_s = setup.elapsed().as_secs_f64();
    let pair = [(*p0.0.digest(), p0.2), (*p1.0.digest(), p1.2)];
    let node = case.starts_with("node");
    let claims = if node { pair.repeat(2) } else { pair.to_vec() };
    if mode == "verify" || mode == "reject" {
        let bytes = fs::read(format!("{prefix}.proof")).unwrap();
        let root = TreeProof::from_bytes(&bytes).unwrap();
        let start = Instant::now();
        tree.verify_claims(&root, &claims).unwrap();
        let verify_ms = start.elapsed().as_secs_f64() * 1000.;
        if mode == "reject" {
            let mut bad = claims.clone();
            bad[0].0[0] ^= 1;
            assert!(tree.verify_claims(&root, &bad).is_err());
            let mut bad = claims.clone();
            bad[0].1 = Output::new([0; 4]);
            assert!(tree.verify_claims(&root, &bad).is_err());
            let mut tampered = bytes.clone();
            let at = tampered.len() / 2;
            tampered[at] ^= 1;
            assert!(TreeProof::from_bytes(&tampered).map_or(true, |p| tree.verify_claims(&p, &claims).is_err()));
        }
        println!(
            "{}",
            json!({"kind":mode,"case":case,"verify_ms":verify_ms,"setup_s":setup_s,"proof_bytes":bytes.len(),"accepted":true})
        );
        return;
    }
    assert_eq!(mode, "prove");
    let child = node.then(|| TreeProof::from_bytes(&fs::read(format!("{}.proof", args[8])).unwrap()).unwrap());
    let start = Instant::now();
    let root = if let Some(child) = child {
        tree.prove_node(&[child.clone(), child]).unwrap()
    } else {
        tree.prove_first_claims(&[
            (*p0.0.digest(), Leaf::new(&p0.1, p0.2)),
            (*p1.0.digest(), Leaf::new(&p1.1, p1.2)),
        ])
        .unwrap()
    };
    let merge_s = start.elapsed().as_secs_f64();
    let bytes = root.to_bytes();
    fs::write(format!("{prefix}.proof"), &bytes).unwrap();
    let stats = tree.stats(if node { Kind::Node } else { Kind::First });
    println!(
        "{}",
        json!({"kind":"merge","case":case,"merge_s":merge_s,"setup_s":setup_s,"proof_bytes":bytes.len(),"committed_words":stats.committed,"tables":stats.tables.iter().map(|t|json!({"name":t.name,"rows":t.rows,"height_log":t.height_log})).collect::<Vec<_>>(),"rows":stats.tables.iter().map(|t|t.rows).sum::<usize>(),"recursion_log_inv_rate":1,"leaf_log_inv_rate":2,"protocol_hash":"keccak256"})
    );
}
