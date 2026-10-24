use std::io::{BufRead, Write};
// Referee adapter over the baseline application row bridge.
use circuit_suite::{Ckt, Workload};
use format_recursion::{boolean_application, native_hash::Builder};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn create<W: Workload>(
    circuit: &circuit_suite::Circuit,
    sources: &[circuit_suite::Src],
    calls: &[circuit_suite::KeccakCall],
    instance: &circuit_suite::Instance,
    identity: [u8; 32],
) -> Builder {
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
    let canonical_instance = W::instance(0);
    let canonical = create::<W>(&circuit, &sources, &calls, &canonical_instance, identity);
    let start = Instant::now();
    let setup = canonical.setup_mixed().unwrap();
    let shape = setup.verifier_shape();
    println!(
        "{}",
        serde_json::json!({"kind":"setup","setup_s":start.elapsed().as_secs_f64(),"core_rows":core_rows,"native_rows":canonical.rows(),"permutations":calls.len(),"shape":format!("{shape:?}")})
    );
    let context = primitives::protocol_hash::hash(format!("keccak-rows-relation:{}", W::NAME).as_bytes());
    let fixed_public=canonical.public_values();
    drop(canonical);
    println!("{}",serde_json::json!({"kind":"ready"}));
    std::io::stdout().flush().unwrap();
    let input_paths: Box<dyn Iterator<Item=String>> = if args[3].starts_with("serve") { Box::new(std::io::stdin().lock().lines().map(|l|l.unwrap())) } else { Box::new(if args[3] == "warm" {
        serde_json::from_slice(&std::fs::read(&args[6]).unwrap()).unwrap()
    } else { vec![args.get(6).cloned().unwrap_or_default()] }.into_iter()) };
    for (round, request) in input_paths.enumerate() {
        let (path, output): (String,String) = if args[3].starts_with("serve") { let j:serde_json::Value=serde_json::from_str(&request).unwrap(); (j["input"].as_str().unwrap().into(),j["output"].as_str().unwrap().into()) } else { (request,args[4].clone()) };
        let start = Instant::now();
        if args[3]=="admit" || args[3]=="serve-admit" || args[3]=="reject-certificate" {
            let encoded=std::fs::read(&path).unwrap();
            let decoded:Result<(Vec<primitives::field::F192>,[u8;32],[u8;32],fiat_shamir::transcript::Proof),_>=bincode::deserialize(&encoded);
            let accepted=decoded.map_or(false,|(public,ctx,id,proof)| public.len()==fixed_public.len() && public[..public.len()-4]==fixed_public[..fixed_public.len()-4] && ctx==context && id==identity && setup.verify(&public,&context,&proof));
            if args[3]=="reject-certificate" {assert!(!accepted);}
            println!("{}",serde_json::json!({"kind":"verification","accepted":accepted,"verify_ms":start.elapsed().as_secs_f64()*1000.,"decode_included":true,"identity_and_constant_authentication_included":true}));std::io::stdout().flush().unwrap();continue;
        }
        let instance = if path.is_empty() { W::instance(seed) } else {
            let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if j["app"]=="A" {
                let payload=std::fs::read(std::path::Path::new(&path).parent().unwrap().join("payload.bin")).unwrap();
                circuit_suite::shielded_keccak::instance_of(&payload)
            } else if j["app"]=="B" {
                let e=&j["extra"];let h:Vec<u64>=serde_json::from_value(e["h"].clone()).unwrap();let msg:Vec<u8>=serde_json::from_value(e["msg"].clone()).unwrap();let nonce:Vec<u8>=serde_json::from_value(e["nonce"].clone()).unwrap();let s2:Vec<i64>=serde_json::from_value(e["s2"].clone()).unwrap();
                circuit_suite::falcon::instance_for(&circuit_suite::falcon::Params::falcon512(),&h,&msg,&nonce,&s2,None)
            } else { circuit_suite::Instance { inputs: serde_json::from_value(j["inputs"].clone()).unwrap(), statement: serde_json::from_value::<Vec<u8>>(j["statement"].clone()).unwrap().try_into().unwrap() } }
        };
        let witness = create::<W>(&circuit, &sources, &calls, &instance, identity);
        let public = witness.public_values();
        let file = if args[3] == "warm" { format!("{}-{round}.proof",args[4]) } else { output };
        if args[3] == "prove" || args[3] == "warm" || args[3].starts_with("serve") {
            let proof = setup.prove_mixed(&witness.values, &witness.permutations, &witness.compressions, &context).unwrap();
            let encoded = bincode::serialize(&(&public,context,identity,&proof)).unwrap();
            std::fs::write(&file, &encoded).unwrap();
            println!("{}",serde_json::json!({"kind":"wallet","round":round,"mode":args[3],"wallet_prove_s":start.elapsed().as_secs_f64(),"complete_forwarded_bytes":encoded.len(),"proof_bytes":bincode::serialized_size(&proof).unwrap(),"certificate_format":"public-context-identity-proof-v1","workload":W::NAME,"input_file":path,"statement":instance.statement.to_vec(),"protocol_hash":"keccak","serialized_write_included":true}));
        } else {
            let mut encoded = std::fs::read(&file).unwrap();
            if args[3] == "reject-proof" { let at=encoded.len()/2;encoded[at]^=1; }
            let begin=Instant::now();
            let proof = bincode::deserialize(&encoded);
            let accepted=proof.map_or(false,|p|setup.verify(&public,&context,&p));
            if args[3] == "reject-proof" { assert!(!accepted); } else { assert!(accepted); }
            println!("{}",serde_json::json!({"kind":args[3],"verify_ms":begin.elapsed().as_secs_f64()*1000.,"accepted":accepted,"decode_included":true}));
        }
        std::io::stdout().flush().unwrap();
    }
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "shielded" => run::<circuit_suite::shielded_keccak::ShieldedTransfer>(&args),
        "falcon" => run::<circuit_suite::falcon::Falcon512>(&args),
        "sha256" => run::<circuit_suite::sha256::Sha256OneKiB>(&args),
        "keccak" => run::<circuit_suite::keccak::Keccak256OneKiB>(&args),
        "mpt" => run::<circuit_suite::mpt::MptStorageProof>(&args),
        _ => panic!("unknown workload"),
    }
}
