//! Single-operation receipts with wallet, verification and merge in separate processes.
use leanvm::aggregate::{Kind, Leaf, LeafShape, Tree, TreeProof, TreeShape};
use leanvm::{Output, Program, Proof, Prover, Rate};
use leanvm_guest::{PublicValues, Run};
use primitives::hash::{digest_words, hash};
use serde_json::{Value, json};
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: bench::Counting<bench::Jemalloc> = bench::Counting(bench::Jemalloc);

fn emit(workload: &str, role: &str, data: Value) {
    let mut row = json!({"path":"leanvm-direct","leanvm_version":"riscv","commit":"a40a7fa6de0f5ba75214aa53aceff49a5c61d7e2","workload":workload,"role":role,"frequency":if role == "setup" {"one-time"} else {"per transaction or merge hop"},"threads":parallel::num_threads(),"cpus":"12-23","CARGO_BUILD_JOBS":4,"LEANVM_NUM_THREADS":12,"RAYON_NUM_THREADS":12,"kind":if role == "wallet" {"client"} else {"recursive_application"}});
    row.as_object_mut().unwrap().extend(data.as_object().unwrap().clone());
    println!("{row}");
}

fn fixture(name: &str) -> (Program, Run) {
    let (elf, run): (&[u8], Run) = match name {
        name if name.starts_with("hashchain-") || name.starts_with("merkle-") => {
            let n: usize = name.split('-').nth(1).unwrap().parse().unwrap();
            let mode = u64::from(name.starts_with("merkle-"));
            let index = if mode == 1 {0x55555555u64 & ((1u64 << n)-1)} else {0};
            let mut value = [0u64;4];
            let mut advice=vec![mode,n as u64]; advice.extend(value); advice.push(index);
            for level in 0..n {
                let sibling=if mode==0 {[0u64;4]} else {[level as u64 + 1;4]};
                if mode==1 {advice.extend(sibling);}
                let (a,b)=if mode==1 && (index>>level)&1==1 {(sibling,value)} else {(value,sibling)};
                let message: Vec<u8> = a.into_iter().chain(b).flat_map(u64::to_le_bytes).collect();
                value=digest_words(&hash(&message));
            }
            let mut public=PublicValues::new();
            public.commit(&[0u64;4]).commit(&mode).commit(&(n as u64)).commit(&index).commit(&value);
            (include_bytes!("../../../../programs/hometurf/hometurf.elf"),Run {advice,expected:public.digest()})
        }
        "sha256-1kib" | "keccak256-1kib" => {
            let bytes: Vec<u8>=(0..1024).map(|i|(i%251) as u8).collect();
            let words=bytes.chunks_exact(8).map(|c|u64::from_le_bytes(c.try_into().unwrap())).collect::<Vec<_>>();
            let digest: [u64;4] = if name.starts_with("sha") {
                let mut h=sha2::Sha256::new(); use sha2::Digest; h.update(&bytes); let d=h.finalize(); core::array::from_fn(|i|u64::from_le_bytes(d[i*8..i*8+8].try_into().unwrap()))
            } else { leanvm_guest::keccak::keccak256(&words,1024) };
            let mut public=PublicValues::new(); public.commit(&digest);
            (if name.starts_with("sha") {include_bytes!("../../../../programs/sha256-1kib/sha256-1kib.elf")} else {include_bytes!("../../../../programs/keccak256-1kib/keccak256-1kib.elf")},Run {advice:words,expected:public.digest()})
        }
        "leanxmss" => (leanxmss_host::ELF, leanxmss_host::batch(1)),
        "leansphincs" => (leansphincs_host::ELF, leansphincs_host::batch(1)),
        "mpt" => (stateproof_host::ELF, stateproof_host::reads(1)),
        "shielded" => (shielded_host::ELF, shielded_host::spends(1)),
        "falcon512" => (falcon_host::ELF, falcon_host::batch(1)),
        "blake2s-64b" | "blake2s-1kib" => {
            let n = if name == "blake2s-64b" {64} else {1024};
            let message: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let mut public = PublicValues::new();
            public.commit(&(n as u64)).commit(&digest_words(&hash(&message)));
            (include_bytes!("../../../../programs/hash/hash.elf"), Run {advice:vec![n as u64],expected:public.digest()})
        }
        _ => panic!("unsupported workload"),
    };
    (Program::from_elf(elf).unwrap(), run)
}

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(12).unwrap()).expect("exact total pool");
    assert_eq!(parallel::num_threads(),12);
    let args: Vec<String> = std::env::args().collect();
    let (mode, name, prefix) = (&args[1], &args[2], &args[3]);
    let setup = Instant::now();
    let (program, run) = fixture(name);
    let program_setup_s = setup.elapsed().as_secs_f64();
    if mode == "wallet" {
        emit(name,"setup",json!({"setup_s":program_setup_s,"scope":"fixture preparation and Program::from_elf, no trusted key generation"}));
        std::fs::write(format!("{prefix}.advice.json"),serde_json::to_vec(&run.advice).unwrap()).unwrap();
        let start = Instant::now();
        let proved = Prover::new(Rate::new(2).unwrap()).prove(&program, &run.advice).expect("native guest fits");
        assert_eq!(proved.output,run.expected,"native reference output");
        let proof = proved.proof.to_bytes();
        let seconds = start.elapsed().as_secs_f64();
        let peak = bench::peak_rss_bytes()/1024;
        std::fs::write(format!("{prefix}.proof"),&proof).unwrap();
        std::fs::write(format!("{prefix}.output.json"),serde_json::to_vec(proved.output.words()).unwrap()).unwrap();
        emit(name,"wallet",json!({"wallet_prove_s":seconds,"wallet_peak_rss_kib":peak,"wallet_proof_bytes":proof.len(),"blake2s_compressions":proved.stats.base_counts[leanvm::TableId::HASH],"stats_debug":format!("{:?}",proved.stats),"riscv_cycles":proved.stats.cycles(),"committed_words":proved.stats.committed,"log_inv_rate":2,"output":proved.output.words(),"wallet_wrap_s":0.0,"mempool_ready":true,"scope":"one cold proof including encoding; no verification or merge in wallet process; fixture preparation excluded"}));
        return;
    }
    let output: [u64;4] = serde_json::from_slice(&std::fs::read(format!("{prefix}.output.json")).unwrap()).unwrap();
    assert_eq!(output,run.expected);
    let output = Output::new(output);
    let bytes = std::fs::read(format!("{prefix}.proof")).unwrap();
    if mode == "reject" {
        let proof=Proof::from_bytes(&bytes).unwrap();
        let mut wrong=*output.words(); wrong[0]^=1;
        assert!(program.verify(Output::new(wrong),&proof).is_err(),"wrong digest must fail");
        let mut bad=bytes.clone(); let mid=bad.len()/2; bad[mid]^=1;
        assert!(match Proof::from_bytes(&bad) {Err(_)=>true,Ok(p)=>program.verify(output,&p).is_err()},"tampered proof must fail");
        if name.starts_with("merkle-") {
            let mut advice=run.advice.clone(); advice[7]^=1;
            let changed=Prover::new(Rate::new(2).unwrap()).prove(&program,&advice).unwrap();
            assert_ne!(changed.output,run.expected,"changed path must change public root");
            assert!(program.verify(output,&changed.proof).is_err(),"wrong path cannot prove original root");
        }
        emit(name,"test",json!({"wrong_digest_rejected":true,"tampered_proof_rejected":true,"wrong_path_rejected":name.starts_with("merkle-")}));
        return;
    }
    if mode == "verify" {
        let start=Instant::now();
        let proof=Proof::from_bytes(&bytes).unwrap();
        program.verify(output,&proof).expect("independent native verifier");
        emit(name,"mempool",json!({"mempool_verify_ms":start.elapsed().as_secs_f64()*1000.0,"proof_bytes":bytes.len(),"verified":true,"scope":"decode and native verify, independent process"}));
        return;
    }
    let proof=Proof::from_bytes(&bytes).unwrap();
    let start=Instant::now();
    let tree=Tree::new(&program,TreeShape {leaf:LeafShape::of(&proof).unwrap(),arity_0:if mode=="stats-one" {1} else {2},arity:2,rate:Rate::MIN}).expect("tree fits");
    emit(name,"setup",json!({"setup_s":start.elapsed().as_secs_f64(),"scope":"recursion circuits and fixed columns, reconstructed in each merge or verify process","program_setup_s":program_setup_s}));
    if mode=="stats-one" {
        let stats=tree.stats(Kind::First);
        emit(name,"merge",json!({"per_claim_committed_words":stats.committed,"recursion_stats":format!("{:?}",stats),"rows":stats.tables.iter().map(|t|t.rows).sum::<usize>(),"scope":"arity-one first circuit; includes complete recursion proof overhead, not half an arity-two circuit"}));
        return;
    }
    let stem = if mode.contains("node") {"node"} else {"leaf"};
    if mode.starts_with("verify-") {
        let bytes=std::fs::read(format!("{prefix}.{stem}.proof")).unwrap();
        let start=Instant::now();
        let root=TreeProof::from_bytes(&bytes).unwrap();
        tree.verify(&root,&vec![output;if stem=="leaf" {2} else {4}]).expect("independent root verifier");
        emit(name,"mempool",json!({"merged_verify_ms":start.elapsed().as_secs_f64()*1000.0,"merged_proof_bytes":bytes.len(),"merge_level":stem,"verified":true}));
        return;
    }
    let child=if mode=="node" {Some(TreeProof::from_bytes(&std::fs::read(format!("{prefix}.leaf.proof")).unwrap()).unwrap())} else {None};
    let start=Instant::now();
    let root=match child {Some(c)=>tree.prove_node(&[c.clone(),c]).expect("honest nodes"),None=>tree.prove_first(&[Leaf::new(&proof,output);2]).expect("honest unwrapped wallet proofs")};
    let encoded=root.to_bytes();
    let seconds=start.elapsed().as_secs_f64();
    let stats=tree.stats(if stem=="leaf" {Kind::First} else {Kind::Node});
    std::fs::write(format!("{prefix}.{stem}.proof"),&encoded).unwrap();
    emit(name,"mempool",json!({if stem=="leaf" {"merge2to1_leaf_s"} else {"merge2to1_node_s"}:seconds,"merge_s":seconds,"merged_proof_bytes":encoded.len(),"merge_peak_rss_kib":bench::peak_rss_bytes()/1024,"heterogeneous_merge":false,"aggregation_shape":"same application; repeated proof in both child slots","within_1s_budget":seconds<=1.0,"budget_multiple":seconds,"recursion_stats":format!("{:?}",stats),"committed_words":stats.committed,"scope":"merge including input verification, witness generation, proof and encoding; setup excluded; RSS includes setup"}));
    assert!(Path::new(&format!("{prefix}.{stem}.proof")).exists());
}
