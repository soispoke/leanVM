//! Trial adapter for one bounded, application-independent aggregate key.
use bincode::Options;
use format_recursion::{
    native_hash::Builder,
    private_recursion,
    row_format::{
        self, Source,
        first::SparseSetup,
        spartan::Setup,
        tree::{self, Certificate, Schema, Statement},
        universal::{self, Description},
    },
};
use primitives::field::F192;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{path::Path, time::Instant};
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
const N: usize = 6;
const ROW: usize = if cfg!(feature = "keccak-protocol") { 22 } else { 20 };
const COL: usize = ROW;
const BLOCK: usize = if cfg!(feature = "keccak-protocol") && !cfg!(feature = "trial-keccak-tight") {
    15
} else {
    14
};
const SCHEMA: Schema<N> = Schema {
    shapes: [(ROW, COL); N],
};
fn context() -> [u8; 32] {
    primitives::protocol_hash::hash(b"trial-entrant-universal-bounded-v1")
}
fn save<T: Serialize>(path: impl AsRef<Path>, value: &T) {
    std::fs::write(path, bincode::serialize(value).unwrap()).unwrap();
}
fn load<T: DeserializeOwned>(path: impl AsRef<Path>) -> T {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&std::fs::read(path).unwrap())
        .unwrap()
}
fn layout(s: &Setup) -> Vec<usize> {
    vec![
        s.row_log,
        s.z_log,
        s.r1cs.block_log,
        s.r1cs.public_len,
        s.r1cs.public_log,
        s.r1cs.port_start,
        s.q_offset,
        s.stack_log,
        s.committed_words,
    ]
}
fn hash_source(seed: usize, rounds: usize) -> Source {
    fn build(seed: usize, rounds: usize) -> Builder {
        let mut b = Builder::default();
        let mut words: Vec<_> = (0..4)
            .map(|i| b.input((seed as u64).wrapping_mul(65537).wrapping_add(i + 19)))
            .collect();
        for _ in 0..rounds {
            words = b.hash_words(&words).to_vec();
        }
        for w in words {
            b.expose(w);
        }
        b
    }
    let b = build(seed, rounds);
    let (circuit, connectors) = b.export_protocol_circuit();
    let fixed_len = circuit.public.len() - 4;
    Source {
        circuit,
        connectors,
        fixed_len,
        values: b.values.clone(),
        compressions: b.protocol_blocks(),
        rebuild: Box::new(move || {
            let b = build(seed, rounds);
            (b.values.clone(), b.protocol_blocks())
        }),
    }
}
fn leaf(source: &Source, s: &Setup) -> Certificate {
    let (values, blocks) = (source.rebuild)();
    let public = s.public(&values);
    let digest = std::array::from_fn(|i| {
        let field = public[2 + i / 16];
        [field.c0, field.c1][(i % 16) / 8].to_le_bytes()[i % 8]
    });
    let statement = Statement {
        kind: false,
        digest,
        slots: (0..N).map(|i| SCHEMA.empty(i)).collect(),
    };
    assert_eq!(public[1..], SCHEMA.fields(&statement));
    let proof = s.prove(&values, &blocks, &context());
    Certificate {
        key: s.key,
        statement,
        proof,
    }
}
fn freeze(out: &Path, compact: bool) {
    std::fs::create_dir_all(out).unwrap();
    assert!(!out.join("aggregate.key").exists(), "immutable setup exists");
    let start = Instant::now();
    let src = universal::wallet_source(hash_source(0, 1), SCHEMA);
    let (s, g) = universal::wallet_setup(&src, ROW, COL, BLOCK);
    let dummy = leaf(&src, &s);
    let fresh = std::array::from_fn(|_| {
        s.claim(
            &s.verify_deferred(&s.public(&src.values), &context(), &dummy.proof, false)
                .unwrap(),
        )
    });
    let (inputs, routes, digest) = universal::inputs(SCHEMA, [&dummy, &dummy], fresh, [0, 0]);
    let mut registry: [Option<(&Setup, &row_format::generator::Generator)>; N] = [None; N];
    registry[0] = Some((&s, &g));
    let reduction = tree::prove(SCHEMA, registry, &inputs, &routes, &digest);
    let trace = universal::record(SCHEMA, &s, [&dummy, &dummy], [0, 0], &context(), &reduction);
    assert!(trace.satisfied());
    let canonical = universal::canonical_trace(trace.clone());
    let aggregate = SparseSetup::new_envelope(canonical.clone(), false, 1 << BLOCK, Some((ROW, COL))).unwrap();
    assert_eq!(layout(&aggregate.setup), layout(&s));
    // Check a valid witness against the retained witness-free program.
    let statement = tree::statement(SCHEMA, digest, &inputs, &routes, &reduction);
    let proof = aggregate.prove(&trace, &context()).unwrap();
    let own = aggregate
        .verify(&SCHEMA.fields(&statement), &context(), &proof)
        .unwrap();
    assert!(aggregate.generator.settle(&own));
    save(out.join("aggregate.trace"), &canonical);
    if !compact {
        save(out.join("aggregate.setup"), &aggregate.setup);
        save(out.join("aggregate.public-cache"), &aggregate);
    }
    std::fs::write(out.join("aggregate.key"), aggregate.setup.key).unwrap();
    println!(
        "{}",
        serde_json::json!({"phase":"freeze","seconds":start.elapsed().as_secs_f64(),"layout":layout(&aggregate.setup),"aggregate_key":aggregate.setup.key,"max_real_applications":N-1,"max_total_identities":N,"row_log":ROW,"col_log":COL,"block_log":BLOCK,"dummy_generator_only":true,"actual_aggregate_hash_blocks":aggregate.setup.r1cs.actual_blocks,"actual_aggregate_rows":aggregate.generator.rows()})
    );
}
type AggregateCache = (
    std::sync::Arc<SparseSetup>,
    std::sync::Arc<format_recursion::trace::Trace>,
);
type AppCache = (std::sync::Arc<Setup>, std::sync::Arc<row_format::generator::Generator>);
thread_local! {
    static WARM_MODE:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static AGGREGATES:std::cell::RefCell<std::collections::HashMap<std::path::PathBuf,AggregateCache>>=std::cell::RefCell::new(std::collections::HashMap::new());
    static APPLICATIONS:std::cell::RefCell<std::collections::HashMap<std::path::PathBuf,AppCache>>=std::cell::RefCell::new(std::collections::HashMap::new());
}
fn restore(setup: &Path) -> AggregateCache {
    if let Some(cached) = AGGREGATES.with(|cache| cache.borrow().get(setup).cloned()) {
        return cached;
    }
    let canonical: format_recursion::trace::Trace = load(setup.join("aggregate.trace"));
    let aggregate: SparseSetup = if setup.join("aggregate.public-cache").exists() {
        load(setup.join("aggregate.public-cache"))
    } else {
        SparseSetup::new_envelope(canonical.clone(), false, 1 << BLOCK, Some((ROW, COL)))
            .expect("canonical public trace failed recompilation")
    };
    assert_eq!(std::fs::read(setup.join("aggregate.key")).unwrap(), aggregate.setup.key);
    if setup.join("aggregate.setup").exists() {
        let stored: Setup = load(setup.join("aggregate.setup"));
        assert_eq!(stored.key, aggregate.setup.key);
    }
    aggregate.generator.prepare_evaluation();
    let result = (std::sync::Arc::new(aggregate), std::sync::Arc::new(canonical));
    AGGREGATES.with(|cache| cache.borrow_mut().insert(setup.to_path_buf(), result.clone()));
    result
}
fn demo(setup: &Path, out: &Path, seed: usize) {
    std::fs::create_dir_all(out).unwrap();
    let (aggregate, canonical) = restore(setup);
    let frozen_key = aggregate.setup.key;
    // These three distinct generators are instantiated only after aggregate restore.
    let raw = [
        row_format::shielded_source(seed),
        row_format::merkle_source(seed + 1),
        hash_source(seed + 2, 3),
        row_format::shielded_source(seed + 3),
    ];
    for (i, s) in raw.iter().enumerate().take(3) {
        let description = Description::from_source(s);
        save(out.join(format!("app-{i}.generator")), &description);
    }
    let sources = raw.map(|s| universal::wallet_source(s, SCHEMA));
    let apps: Vec<_> = sources
        .iter()
        .take(3)
        .map(|s| universal::wallet_setup(s, ROW, COL, BLOCK))
        .collect();
    let mut certs = Vec::new();
    let wallets_start = Instant::now();
    for i in 0..4 {
        let slot = if i == 3 { 0 } else { i };
        let cert = leaf(&sources[i], &apps[slot].0);
        save(out.join(format!("wallet-{i}.cert")), &cert);
        certs.push(cert);
    }
    let wallets_s = wallets_start.elapsed().as_secs_f64();
    let mut firsts = Vec::new();
    let mut times = Vec::new();
    for pair in 0..2 {
        let children = [&certs[2 * pair], &certs[2 * pair + 1]];
        let slots = if pair == 0 { [0, 1] } else { [2, 0] };
        let start = Instant::now();
        let fresh = std::array::from_fn(|i| {
            let s = &apps[slots[i]].0;
            s.claim(
                &s.verify_deferred(
                    &[vec![F192::ONE], SCHEMA.fields(&children[i].statement)].concat(),
                    &context(),
                    &children[i].proof,
                    false,
                )
                .unwrap(),
            )
        });
        let (inputs, routes, digest) = universal::inputs(SCHEMA, children, fresh, slots);
        let mut registry: [Option<(&Setup, &row_format::generator::Generator)>; N] = [None; N];
        for &slot in &slots {
            registry[slot] = Some((&apps[slot].0, &apps[slot].1));
        }
        let reduction = tree::prove(SCHEMA, registry, &inputs, &routes, &digest);
        let trace = universal::record(SCHEMA, &aggregate.setup, children, slots, &context(), &reduction);
        assert!(trace.satisfied());
        assert!(trace.same_program(&canonical), "wallet and setup graph differ");
        let statement = tree::statement(SCHEMA, digest, &inputs, &routes, &reduction);
        assert_eq!(SCHEMA.fields(&statement), private_recursion::outputs(&trace));
        let proof = aggregate.prove(&trace, &context()).unwrap();
        let cert = Certificate {
            key: frozen_key,
            statement,
            proof,
        };
        save(out.join(format!("first-{pair}.cert")), &cert);
        times.push(start.elapsed().as_secs_f64());
        firsts.push(cert);
    }
    let start = Instant::now();
    let children = [&firsts[0], &firsts[1]];
    let fresh = std::array::from_fn(|i| {
        aggregate
            .verify(&SCHEMA.fields(&children[i].statement), &context(), &children[i].proof)
            .unwrap()
    });
    let (inputs, routes, digest) = universal::inputs(SCHEMA, children, fresh, [N - 1, N - 1]);
    let mut registry: [Option<(&Setup, &row_format::generator::Generator)>; N] = [None; N];
    for i in 0..3 {
        registry[i] = Some((&apps[i].0, &apps[i].1));
    }
    registry[N - 1] = Some((&aggregate.setup, &aggregate.generator));
    let reduction = tree::prove(SCHEMA, registry, &inputs, &routes, &digest);
    let trace = universal::record(
        SCHEMA,
        &aggregate.setup,
        children,
        [N - 1, N - 1],
        &context(),
        &reduction,
    );
    assert!(trace.satisfied());
    assert!(trace.same_program(&canonical), "node and wallet graph differ");
    let statement = tree::statement(SCHEMA, digest, &inputs, &routes, &reduction);
    let proof = aggregate.prove(&trace, &context()).unwrap();
    let cert = Certificate {
        key: frozen_key,
        statement,
        proof,
    };
    save(out.join("node.cert"), &cert);
    let node_s = start.elapsed().as_secs_f64();
    let root_registry = std::array::from_fn(|i| registry[i].map(|p| p.1));
    let root_start = Instant::now();
    assert!(universal::verify_root(
        SCHEMA,
        &aggregate,
        &digest,
        &cert.statement,
        &context(),
        &cert.proof,
        root_registry
    ));
    let root_ms = root_start.elapsed().as_secs_f64() * 1000.;
    let mut bad = cert.statement.clone();
    bad.slots[0].claim.matrix_values[0] += F192::ONE;
    assert!(!universal::verify_root(
        SCHEMA,
        &aggregate,
        &digest,
        &bad,
        &context(),
        &cert.proof,
        root_registry
    ));
    let mut bad = cert.statement.clone();
    bad.slots[0] = SCHEMA.empty(0);
    assert!(!universal::verify_root(
        SCHEMA,
        &aggregate,
        &digest,
        &bad,
        &context(),
        &cert.proof,
        root_registry
    ));
    assert_eq!(aggregate.setup.key, frozen_key);
    println!(
        "{}",
        serde_json::json!({"phase":"demo","wallets_s":wallets_s,"first_s":times,"node_s":node_s,"root_ms":root_ms,"real_applications":3,"matrix_identities":4,"same_aggregate_key_all_merges":true,"frozen_key":frozen_key,"independent_witnesses":true,"verified":true,"limitations":["BLAKE2s workloads and protocol","third app not referee held-out","uniform padding costs","not Falcon"]})
    );
}
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "setup" => freeze(Path::new(&args[2]), false),
        "setup-compact" => freeze(Path::new(&args[2]), true),
        "demo" => demo(Path::new(&args[2]), Path::new(&args[3]), args[4].parse().unwrap()),
        "serve" => serve(Path::new(&args[2]), &args[3]),
        "finalize-demo" => finalize_demo(Path::new(&args[2]), Path::new(&args[3])),
        "inspect-generator" => {
            let d: Description = load(Path::new(&args[2]));
            println!(
                "{}",
                serde_json::json!({"application_id_keccak256":d.application_id(),"rows":d.circuit.rows.len(),"variables":d.circuit.variables,"public_indices":d.circuit.public.len(),"fixed_values":d.fixed_values.len(),"hash_connectors":d.connectors.len()})
            );
        }
        "generator-setup" => generator_setup(Path::new(&args[2]), &args[3], Path::new(&args[4]), false),
        "generator-setup-compact" => generator_setup(Path::new(&args[2]), &args[3], Path::new(&args[4]), true),
        "export-witness" => export_witness(&args[2], args[3].parse().unwrap(), Path::new(&args[4])),
        "app-setup" => app_setup(Path::new(&args[2]), &args[3], false),
        "app-setup-compact" => app_setup(Path::new(&args[2]), &args[3], true),
        "wallet" => wallet_command(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4])),
        "merge" => merge_command(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4])),
        "root" => root_command(Path::new(&args[2]), Path::new(&args[3])),
        "admission" => admission_command(Path::new(&args[2]), Path::new(&args[3])),
        _ => panic!("setup OUT | app-setup SETUP CASE | wallet/merge SETUP INPUT OUTPUT | root/admission SETUP INPUT"),
    }
}

fn case_source(case: &str, seed: usize) -> Source {
    match case {
        "shielded" => row_format::shielded_source(seed),
        "merkle" => row_format::merkle_source(seed),
        #[cfg(feature = "keccak-protocol")]
        "keccak1k" => row_format::workload_source::<circuit_suite::keccak::Keccak256OneKiB>(seed as u64, false),
        #[cfg(feature = "keccak-protocol")]
        "mpt" => row_format::workload_source::<circuit_suite::mpt::MptStorageProof>(seed as u64, true),
        case if case.starts_with("hash") => hash_source(seed, case[4..].parse().expect("hash round count")),
        _ => panic!("unsupported generator"),
    }
}
fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn app_directory(setup: &Path, case: &str) -> std::path::PathBuf {
    assert!(case.chars().all(|c| c.is_ascii_alphanumeric()));
    setup.join("apps").join(case)
}
#[derive(Serialize, Deserialize)]
struct ExternalWitness {
    version: u32,
    seed: u64,
    values: Vec<F192>,
    blocks: Vec<format_recursion::row_hash::Block>,
}
fn generator_setup(setup: &Path, case: &str, path: &Path, compact: bool) {
    let start = Instant::now();
    let description: Description = load(path);
    assert!(
        description.validate(ROW.min(COL), 1 << BLOCK),
        "invalid or out-of-bounds generator"
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        bincode::serialize(&description).unwrap(),
        "noncanonical generator bytes"
    );
    let out = app_directory(setup, case);
    std::fs::create_dir_all(&out).unwrap();
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "immutable setup exists"
    );
    let source = universal::wallet_source(description.source(), SCHEMA);
    let (s, g) = universal::wallet_setup(&source, ROW, COL, BLOCK);
    let key = s.key;
    if !compact {
        save(out.join("public-cache"), &(s, g));
    }
    save(out.join("generator"), &description);
    std::fs::write(out.join("application-id"), description.application_id()).unwrap();
    std::fs::write(out.join("proof-key"), key).unwrap();
    std::fs::write(out.join("external-generator"), b"native-graph-v1").unwrap();
    let bytes = std::fs::read_dir(&out)
        .unwrap()
        .map(|f| f.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    println!(
        "{}",
        serde_json::json!({"phase":"generator-setup","case":case,"seconds":start.elapsed().as_secs_f64(),"retained_bytes":bytes,"application_id":description.application_id(),"key":key,"public_only":true})
    );
}
fn export_witness(case: &str, seed: u64, out: &Path) {
    std::fs::create_dir_all(out).unwrap();
    let source = case_source(case, seed as usize);
    save(out.join("generator"), &Description::from_source(&source));
    let (values, blocks) = (source.rebuild)();
    save(
        out.join("witness"),
        &ExternalWitness {
            version: 1,
            seed,
            values,
            blocks,
        },
    );
    println!(
        "{}",
        serde_json::json!({"phase":"export-witness","case":case,"seed":seed,"private_witness_export":true})
    );
}
fn external_source(setup: &Path, case: &str, request: &serde_json::Value) -> Source {
    let description: Description = load(app_directory(setup, case).join("generator"));
    assert!(description.validate(ROW.min(COL), 1 << BLOCK));
    let witness: ExternalWitness = load(Path::new(request["witness"].as_str().unwrap()));
    assert_eq!(witness.version, 1);
    assert_eq!(witness.seed, request["seed"].as_u64().unwrap());
    assert_eq!(witness.values.len(), description.circuit.variables);
    assert_eq!(witness.blocks.len(), description.connectors.len());
    for (&i, &v) in description.circuit.public[..description.fixed_len]
        .iter()
        .zip(&description.fixed_values)
    {
        assert_eq!(witness.values[i], v, "fixed generator constant changed");
    }
    let mut source = description.source();
    source.values = witness.values.clone();
    source.compressions = witness.blocks.clone();
    source.rebuild = Box::new(move || (witness.values.clone(), witness.blocks.clone()));
    source
}
fn app_setup(setup: &Path, case: &str, compact: bool) {
    let out = app_directory(setup, case);
    std::fs::create_dir_all(&out).unwrap();
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "immutable app setup exists"
    );
    let start = Instant::now();
    let original = case_source(case, 0);
    let description = Description::from_source(&original);
    save(out.join("generator"), &description);
    let source = universal::wallet_source(original, SCHEMA);
    let (s, g) = universal::wallet_setup(&source, ROW, COL, BLOCK);
    if !compact {
        save(out.join("public-cache"), &(&s, &g));
    }
    std::fs::write(out.join("application-id"), description.application_id()).unwrap();
    std::fs::write(out.join("proof-key"), s.key).unwrap();
    let bytes = std::fs::read_dir(&out)
        .unwrap()
        .map(|f| f.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    println!(
        "{}",
        serde_json::json!({"phase":"app-setup","case":case,"seconds":start.elapsed().as_secs_f64(),"retained_bytes":bytes,"application_id":description.application_id(),"key":s.key,"layout":layout(&s)})
    );
}
fn app_restore(setup: &Path, case: &str) -> AppCache {
    let dir = app_directory(setup, case);
    if let Some(cached) = APPLICATIONS.with(|cache| cache.borrow().get(&dir).cloned()) {
        return cached;
    }
    let (s, g): (Setup, row_format::generator::Generator) = if dir.join("public-cache").exists() {
        load(dir.join("public-cache"))
    } else {
        let description: Description = load(dir.join("generator"));
        assert!(description.validate(ROW.min(COL), 1 << BLOCK));
        assert_eq!(
            std::fs::read(dir.join("application-id")).unwrap(),
            description.application_id()
        );
        let source = universal::wallet_source(description.source(), SCHEMA);
        universal::wallet_setup(&source, ROW, COL, BLOCK)
    };
    assert_eq!(std::fs::read(dir.join("proof-key")).unwrap(), s.key);
    assert_eq!(s.key, g.app_key);
    assert_eq!(s.row_log, ROW);
    assert_eq!(s.z_log, COL);
    assert_eq!(s.r1cs.block_log, BLOCK);
    assert_eq!(s.r1cs.public_len, 4 + N * (6 + ROW + COL));
    g.prepare_evaluation();
    let result = (std::sync::Arc::new(s), std::sync::Arc::new(g));
    APPLICATIONS.with(|cache| cache.borrow_mut().insert(dir, result.clone()));
    result
}
fn cert_path(path: &str) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_dir() {
        p.join("certificate.bin")
    } else {
        p.to_path_buf()
    }
}
fn forward(out: &Path, cert: &Certificate) {
    std::fs::create_dir_all(out).unwrap();
    assert!(
        std::fs::read_dir(out).unwrap().next().is_none(),
        "proof output must be empty"
    );
    save(out.join("certificate.bin"), cert);
}
fn wallet_command(setup: &Path, input: &Path, out: &Path) {
    let start = Instant::now();
    let request = json(input);
    let case = request["case"].as_str().unwrap();
    let seed = request["seed"].as_u64().unwrap() as usize;
    let (s, g) = app_restore(setup, case);
    let original = if app_directory(setup, case).join("external-generator").exists() {
        external_source(setup, case, &request)
    } else {
        case_source(case, seed)
    };
    let description = Description::from_source(&original);
    assert_eq!(
        std::fs::read(app_directory(setup, case).join("application-id")).unwrap(),
        description.application_id(),
        "seed altered canonical generator"
    );
    let source = universal::wallet_source(original, SCHEMA);
    let cert = leaf(&source, &s);
    let verified = s.claim(
        &s.verify_deferred(
            &[vec![F192::ONE], SCHEMA.fields(&cert.statement)].concat(),
            &context(),
            &cert.proof,
            false,
        )
        .unwrap(),
    );
    assert!(g.settle(&verified));
    forward(out, &cert);
    println!(
        "{}",
        serde_json::json!({"phase":"wallet","seconds":start.elapsed().as_secs_f64(),"case":case,"seed":seed,"bytes":std::fs::metadata(out.join("certificate.bin")).unwrap().len(),"verified":true,"includes_public_cache_load":!WARM_MODE.with(|flag|flag.get())})
    );
}
fn merge_command(setup: &Path, input: &Path, out: &Path) {
    let start = Instant::now();
    let request = json(input);
    let (aggregate, canonical) = restore(setup);
    let certs: Vec<Certificate> = request["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| load(cert_path(p.as_str().unwrap())))
        .collect();
    assert_eq!(certs.len(), 2);
    let mut apps: Vec<(
        usize,
        std::sync::Arc<Setup>,
        std::sync::Arc<row_format::generator::Generator>,
    )> = Vec::new();
    for app in request["registry"].as_array().unwrap() {
        let slot = app["slot"].as_u64().unwrap() as usize;
        assert!(slot < N - 1);
        let (s, g) = app_restore(setup, app["case"].as_str().unwrap());
        apps.push((slot, s, g));
    }
    let mut registry: [Option<(&Setup, &row_format::generator::Generator)>; N] = [None; N];
    for (slot, s, g) in &apps {
        assert!(registry[*slot].is_none());
        registry[*slot] = Some((s, g));
    }
    registry[N - 1] = Some((&aggregate.setup, &aggregate.generator));
    let slots = std::array::from_fn(|i| {
        if certs[i].statement.kind {
            assert_eq!(certs[i].key, aggregate.setup.key);
            N - 1
        } else {
            apps.iter().find(|(_, s, _)| s.key == certs[i].key).unwrap().0
        }
    });
    let fresh = std::array::from_fn(|i| {
        assert!(SCHEMA.well_formed(&certs[i].statement));
        let (s, _) = registry[slots[i]].unwrap();
        let public = [vec![F192::ONE], SCHEMA.fields(&certs[i].statement)].concat();
        s.claim(&s.verify_deferred(&public, &context(), &certs[i].proof, false).unwrap())
    });
    let children = [&certs[0], &certs[1]];
    let (inputs, routes, digest) = universal::inputs(SCHEMA, children, fresh, slots);
    // An inactive identity is exactly zero in the output, including evaluations.
    for slot in 0..N {
        if !inputs.iter().zip(&routes).any(|(c, &r)| c.active && r == slot) {
            registry[slot] = None;
        }
    }
    let reduction = tree::prove(SCHEMA, registry, &inputs, &routes, &digest);
    let trace = universal::record(SCHEMA, &aggregate.setup, children, slots, &context(), &reduction);
    assert!(trace.satisfied());
    assert!(trace.same_program(&canonical));
    let statement = tree::statement(SCHEMA, digest, &inputs, &routes, &reduction);
    let proof = aggregate.prove(&trace, &context()).unwrap();
    let cert = Certificate {
        key: aggregate.setup.key,
        statement,
        proof,
    };
    forward(out, &cert);
    if cert.statement.slots[N - 1].active {
        let finalization = universal::finalize(SCHEMA, &aggregate, &cert, &context()).expect("root finalization");
        save(out.join("root-finalization.bin"), &finalization);
    }
    let forwarded_bytes = std::fs::read_dir(out)
        .unwrap()
        .map(|f| f.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    println!(
        "{}",
        serde_json::json!({"phase":"merge","seconds":start.elapsed().as_secs_f64(),"children_kinds":[certs[0].statement.kind,certs[1].statement.kind],"bytes":forwarded_bytes,"digest":digest,"same_frozen_key":true,"includes_public_cache_load":!WARM_MODE.with(|flag|flag.get())})
    );
}
fn root_command(setup: &Path, input: &Path) {
    let start = Instant::now();
    let request = json(input);
    let (aggregate, _) = restore(setup);
    let cert: Certificate = load(cert_path(request["certificate"].as_str().unwrap()));
    let expected: [u8; 32] = serde_json::from_value(request["expected_digest"].clone()).unwrap();
    let apps: Vec<_> = request["registry"]
        .as_array()
        .unwrap()
        .iter()
        .map(|app| {
            let slot = app["slot"].as_u64().unwrap() as usize;
            assert!(slot < N - 1);
            let (s, g) = app_restore(setup, app["case"].as_str().unwrap());
            (slot, s, g)
        })
        .collect();
    let mut registry: [Option<&row_format::generator::Generator>; N] = [None; N];
    for (slot, _, g) in &apps {
        assert!(registry[*slot].is_none());
        registry[*slot] = Some(g.as_ref());
    }
    registry[N - 1] = Some(&aggregate.generator);
    assert_eq!(cert.key, aggregate.setup.key);
    let finalization_path = cert_path(request["certificate"].as_str().unwrap())
        .parent()
        .unwrap()
        .join("root-finalization.bin");
    let finalization: Option<row_format::fold::Reduction> = if finalization_path.exists() {
        Some(load(finalization_path))
    } else {
        None
    };
    assert!(universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &expected,
        &cert,
        &context(),
        registry,
        finalization.as_ref()
    ));
    let complete_seconds = start.elapsed().as_secs_f64();
    let mut settlements = Vec::new();
    if request["profile"].as_bool().unwrap_or(false) {
        for (slot, _, g) in &apps {
            let claim = &cert.statement.slots[*slot];
            if claim.active {
                let start = Instant::now();
                assert!(g.settle(&claim.claim));
                settlements.push(
                    serde_json::json!({"slot":slot,"kind":"application","seconds":start.elapsed().as_secs_f64(),"public_evaluation_plan_bytes":g.evaluation_plan_bytes()}),
                );
            }
        }
        let own = aggregate
            .verify(&SCHEMA.fields(&cert.statement), &context(), &cert.proof)
            .unwrap();
        let carried = &cert.statement.slots[N - 1];
        let claim = if carried.active {
            let mut bytes = b"r1cs-universal-root-finalization-v1".to_vec();
            bytes.extend(bincode::serialize(&cert).unwrap());
            row_format::fold::verify_native(
                &[&aggregate.setup],
                &[carried.claim.clone(), own],
                &primitives::protocol_hash::hash(&bytes),
                finalization.as_ref().unwrap(),
            )
            .unwrap()
            .remove(0)
        } else {
            own
        };
        let start = Instant::now();
        assert!(aggregate.generator.settle(&claim));
        settlements.push(serde_json::json!({"slot":N-1,"kind":"aggregate","seconds":start.elapsed().as_secs_f64(),"public_evaluation_plan_bytes":aggregate.generator.evaluation_plan_bytes()}));
    }
    println!(
        "{}",
        serde_json::json!({"phase":"root","seconds":complete_seconds,"accepted":true,"includes_public_cache_load":!WARM_MODE.with(|flag|flag.get()),"decode_and_all_claims":true,"extra_profile_excluded_from_internal_timer":!settlements.is_empty(),"settlements":settlements})
    );
}
fn admission_command(setup: &Path, input: &Path) {
    let start = Instant::now();
    let request = json(input);
    let cert: Certificate = load(cert_path(request["certificate"].as_str().unwrap()));
    assert!(SCHEMA.well_formed(&cert.statement));
    if cert.statement.kind {
        let (aggregate, _) = restore(setup);
        assert_eq!(cert.key, aggregate.setup.key);
        assert!(
            aggregate
                .verify(&SCHEMA.fields(&cert.statement), &context(), &cert.proof)
                .is_some()
        );
    } else {
        let (s, _) = app_restore(setup, request["case"].as_str().unwrap());
        assert_eq!(cert.key, s.key);
        let public = [vec![F192::ONE], SCHEMA.fields(&cert.statement)].concat();
        assert!(s.verify_deferred(&public, &context(), &cert.proof, false).is_some());
    }
    println!(
        "{}",
        serde_json::json!({"phase":"admission","seconds":start.elapsed().as_secs_f64(),"accepted_outer_proof":true,"matrix_claims_deferred":true,"includes_public_cache_load":!WARM_MODE.with(|flag|flag.get())})
    );
}

fn finalize_demo(setup: &Path, demo: &Path) {
    let (aggregate, _) = restore(setup);
    let cert: Certificate = load(demo.join("node.cert"));
    let apps: Vec<_> = (0..3)
        .map(|i| {
            let description: Description = load(demo.join(format!("app-{i}.generator")));
            let source = universal::wallet_source(description.source(), SCHEMA);
            let (s, g) = universal::wallet_setup(&source, ROW, COL, BLOCK);
            assert_eq!(
                s.key, cert.statement.slots[i].claim.app_key,
                "authenticate deterministic key derivation"
            );
            (description, s, g)
        })
        .collect();
    let start = Instant::now();
    let finalization = universal::finalize(SCHEMA, &aggregate, &cert, &context()).unwrap();
    save(demo.join("root-finalization.bin"), &finalization);
    let finalize_s = start.elapsed().as_secs_f64();
    let mut registry: [Option<&row_format::generator::Generator>; N] = [None; N];
    for i in 0..3 {
        registry[i] = Some(&apps[i].2);
    }
    registry[N - 1] = Some(&aggregate.generator);
    let start = Instant::now();
    assert!(universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &cert.statement.digest,
        &cert,
        &context(),
        registry,
        Some(&finalization)
    ));
    let complete_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    assert!(aggregate.generator.settle(&finalization.carried[0]));
    let aggregate_ms = start.elapsed().as_secs_f64() * 1000.;
    // These tests go straight to the root verifier, with no call to finalize/prove.
    assert!(!universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &cert.statement.digest,
        &cert,
        &context(),
        registry,
        None
    ));
    let mut forged = finalization.clone();
    forged.carried[0].matrix_values[0] += F192::ONE;
    assert!(!universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &cert.statement.digest,
        &cert,
        &context(),
        registry,
        Some(&forged)
    ));
    let mut forged = finalization.clone();
    forged.proof.stream.push(F192::ONE);
    assert!(!universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &cert.statement.digest,
        &cert,
        &context(),
        registry,
        Some(&forged)
    ));
    let mut bad = cert.clone();
    bad.statement.slots[N - 1] = SCHEMA.empty(N - 1);
    assert!(!universal::verify_root_finalized(
        SCHEMA,
        &aggregate,
        &bad.statement.digest,
        &bad,
        &context(),
        registry,
        Some(&finalization)
    ));
    println!(
        "{}",
        serde_json::json!({"phase":"root-finalization","prover_finalize_s":finalize_s,"complete_resident_root_ms":complete_ms,"aggregate_identity_single_settle_ms":aggregate_ms,"sidecar_bytes":std::fs::metadata(demo.join("root-finalization.bin")).unwrap().len(),"real_applications":3,"identities":4,"aggregate_evaluation_inputs":2,"aggregate_evaluation_outputs":1,"generator_authentication":"deterministic recompilation before resident timer; excluded cost must be reported separately","verifier_rejections":["missing sidecar","false final evaluation","trailing proof scalar","omitted aggregate claim"],"application_ids":apps.iter().map(|a|a.0.application_id()).collect::<Vec<_>>()})
    );
}

/// Newline-delimited JSON requests. Retains only immutable public preprocessing;
/// every wallet request reconstructs independent witnesses after receipt.
fn serve(setup: &Path, cases: &str) {
    use std::io::{BufRead, Write};
    restore(setup);
    for case in cases.split(',') {
        app_restore(setup, case);
    }
    WARM_MODE.with(|flag| flag.set(true));
    println!("{}", serde_json::json!({"ready":true,"public_preprocessing_only":true}));
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let input = Path::new(request["input"].as_str().unwrap());
        match request["command"].as_str().unwrap() {
            "wallet" => wallet_command(setup, input, Path::new(request["output"].as_str().unwrap())),
            "merge" => merge_command(setup, input, Path::new(request["output"].as_str().unwrap())),
            "root" => root_command(setup, input),
            "admission" => admission_command(setup, input),
            _ => panic!("unsupported request"),
        }
        std::io::stdout().flush().unwrap();
    }
}
