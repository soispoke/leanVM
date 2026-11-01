//! Fixed-pair heterogeneous first-node experiment, with independent-process verification.
use leanvm::aggregate::{Kind, Leaf, LeafShape, Tree, TreeProof, TreeShape};
use leanvm::{Output, Program, Proof, Rate};
use serde_json::json;
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: bench::Counting<bench::Jemalloc> = bench::Counting(bench::Jemalloc);

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(12).unwrap()).unwrap();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<String> = std::env::args().collect();
    let mode = &args[1];
    let case = &args[2];
    let prefix = &args[3];
    let directory = Path::new("../artifacts/hometurf-L2");
    let load = |name: &str, elf: &[u8]| {
        let program = Program::from_elf(elf).unwrap();
        let bytes = std::fs::read(directory.join(format!("{name}.proof"))).unwrap();
        let proof = Proof::from_bytes(&bytes).unwrap();
        let output: [u64; 4] =
            serde_json::from_slice(&std::fs::read(directory.join(format!("{name}.output.json"))).unwrap()).unwrap();
        (program, proof, Output::new(output))
    };
    let shielded = load("shielded", shielded_host::ELF);
    let xmss = load("leanxmss", leanxmss_host::ELF);
    let (p0, p1) = match case.as_str() {
        "same" | "same-stacked" => (&shielded, &shielded),
        "mixed" => (&shielded, &xmss),
        "xmss" => (&xmss, &xmss),
        _ => panic!("unknown case"),
    };
    let setup = Instant::now();
    let tree = if case == "mixed" || case == "same-stacked" {
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
    let claims = [(*p0.0.digest(), p0.2), (*p1.0.digest(), p1.2)];
    let start = Instant::now();
    if mode == "verify" {
        let bytes = std::fs::read(format!("{prefix}.proof")).unwrap();
        let begin = Instant::now();
        let root = TreeProof::from_bytes(&bytes).unwrap();
        tree.verify_claims(&root, &claims).unwrap();
        println!(
            "{}",
            json!({"case":case,"verify_ms":begin.elapsed().as_secs_f64()*1000.0,"setup_s":setup_s,"verified":true,"proof_bytes":bytes.len(),"threads":12})
        );
        return;
    }
    let root = tree
        .prove_first_claims(&[
            (*p0.0.digest(), Leaf::new(&p0.1, p0.2)),
            (*p1.0.digest(), Leaf::new(&p1.1, p1.2)),
        ])
        .unwrap();
    let bytes = root.to_bytes();
    let seconds = start.elapsed().as_secs_f64();
    let rss = bench::peak_rss_bytes() / 1024;
    std::fs::write(format!("{prefix}.proof"), &bytes).unwrap();
    if mode == "reject" {
        tree.verify_claims(&root, &claims).unwrap();
        let mut bad = claims;
        bad[1].0[0] ^= 1;
        assert!(tree.verify_claims(&root, &bad).is_err());
        let mut swapped = claims;
        swapped.swap(0, 1);
        assert!(tree.verify_claims(&root, &swapped).is_err());
        let mut tampered = bytes.clone();
        let i = tampered.len() / 2;
        tampered[i] ^= 1;
        assert!(match TreeProof::from_bytes(&tampered) {
            Err(_) => true,
            Ok(t) => tree.verify_claims(&t, &claims).is_err(),
        });
        assert!(
            tree.prove_first_claims(&[
                (*p1.0.digest(), Leaf::new(&p0.1, p0.2)),
                (*p0.0.digest(), Leaf::new(&p1.1, p1.2))
            ])
            .is_err()
        );
        println!(
            "{}",
            json!({"case":case,"swapped_program_rejected":true,"unknown_program_rejected":true,"tampered_root_rejected":true})
        );
        return;
    }
    let stats = tree.stats(Kind::First);
    println!(
        "{}",
        json!({"case":case,"merge_s":seconds,"setup_s":setup_s,"proof_bytes":bytes.len(),"rss_kib":rss,"committed_words":stats.committed,"rows":stats.tables.iter().map(|t|t.rows).sum::<usize>(),"tables":stats.tables.iter().map(|t|json!({"name":t.name,"rows":t.rows,"height_log":t.height_log})).collect::<Vec<_>>(),"program_digests":claims.map(|(d,_)|d),"threads":12})
    );
}
