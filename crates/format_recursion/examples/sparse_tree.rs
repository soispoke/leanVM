use format_recursion::{
    private_recursion, private_trace,
    row_format::{
        self, R1cs, first, fold,
        generator::Generator,
        spartan::Setup,
        tree::{self, Certificate, Schema},
    },
};
use std::time::Instant;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
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
fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let mixed = std::env::args().nth(1).as_deref() != Some("same");
    let context = primitives::protocol_hash::hash(b"sparse-carried-tree-measure-v1");
    let sources = [
        row_format::shielded_source(0),
        if mixed {
            row_format::merkle_source(1)
        } else {
            row_format::shielded_source(1)
        },
        row_format::shielded_source(2),
        if mixed {
            row_format::merkle_source(3)
        } else {
            row_format::shielded_source(3)
        },
    ];
    let make = |source: &row_format::Source| {
        Setup::new(
            R1cs::lower_bounded(&source.circuit, &source.connectors, &source.values, source.fixed_len, 8),
            false,
        )
    };
    let a = make(&sources[0]);
    let b = if mixed { Some(make(&sources[1])) } else { None };
    let apps: Vec<_> = if let Some(b) = &b { vec![&a, b] } else { vec![&a] };
    let indices = if mixed { [0, 1] } else { [0, 0] };
    let generators: Vec<_> = apps
        .iter()
        .enumerate()
        .map(|(i, s)| Generator::new(&sources[i], 8, s.key))
        .collect();
    let gs: Vec<_> = generators.iter().collect();
    let schema = Schema {
        #[cfg(not(feature = "keccak-protocol"))]
        shapes: [(16, 16), (12, 12), (20, 20), (20, 20)],
        #[cfg(feature = "keccak-protocol")]
        shapes: [
            (a.row_log, a.z_log),
            b.as_ref().map_or((a.row_log, a.z_log), |s| (s.row_log, s.z_log)),
            if cfg!(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap")) {
                (21, 21)
            } else {
                (22, 22)
            },
            if cfg!(feature = "keccak-quad-cap") {
                (21, 21)
            } else {
                (22, 22)
            },
        ],
    };
    let mut leafproofs = Vec::new();
    let mut publics = Vec::new();
    for i in 0..4 {
        let s = apps[indices[i % 2]];
        let (values, blocks) = (sources[i].rebuild)();
        publics.push(s.public(&values));
        leafproofs.push(s.prove(&values, &blocks, &context));
    }
    let mut firsttraces = Vec::new();
    let mut firststatements = Vec::new();
    for i in 0..2 {
        let children = [apps[indices[0]], apps[indices[1]]];
        let public = [publics[2 * i].as_slice(), publics[2 * i + 1].as_slice()];
        let ps = [&leafproofs[2 * i], &leafproofs[2 * i + 1]];
        let fresh: Vec<_> = (0..2)
            .map(|j| children[j].claim(&children[j].verify_deferred(public[j], &context, ps[j], false).unwrap()))
            .collect();
        let digest = first::statement_digest(children, public);
        let reduction = fold::prove_generated(&apps, &gs, &fresh, &digest);
        let trace = first::record(
            &apps,
            indices,
            [&children[0].key, &children[1].key],
            public,
            &context,
            ps,
            &reduction,
        );
        let (trace, statement) = schema.wrap_first(trace, digest, &reduction.carried);
        assert!(trace.satisfied());
        firsttraces.push(trace);
        firststatements.push(statement);
    }
    assert!(firsttraces[0].same_program(&firsttraces[1]));
    let first = first::SparseSetup::new_with_padding(
        firsttraces[0].clone(),
        false,
        if cfg!(feature = "keccak-protocol") {
            Some(
                if cfg!(any(feature = "keccak-merkle-cap", feature = "keccak-quad-cap")) {
                    (21, 21)
                } else {
                    (22, 22)
                },
            )
        } else {
            None
        },
    )
    .unwrap();
    eprintln!("first layout {:?}", layout(&first.setup));
    assert_eq!((first.setup.row_log, first.setup.z_log), schema.shapes[2]);
    let certs: Vec<_> = (0..2)
        .map(|i| Certificate {
            key: first.setup.key,
            statement: firststatements[i].clone(),
            proof: first.prove(&firsttraces[i], &context).unwrap(),
        })
        .collect();
    let children = [&certs[0], &certs[1]];
    let fresh = std::array::from_fn(|i| {
        first
            .verify(&schema.fields(&certs[i].statement), &context, &certs[i].proof)
            .unwrap()
    });
    let (inputs, routes, digest) = tree::inputs(schema, children, fresh);
    let registry = [
        Some((&a, &generators[0])),
        b.as_ref().map(|s| (s, &generators[1])),
        Some((&first.setup, &first.generator)),
        None,
    ];
    let reduction = tree::prove(schema, registry, &inputs, &routes, &digest);
    let canonical = tree::record(schema, &first.setup, children, &context, &reduction);
    assert!(canonical.satisfied(), "node replay");
    let lower = private_trace::lower(&canonical, &canonical).unwrap();
    let rows = lower.circuit.rows.len();
    let compressions = lower.compressions.len();
    let permutations = lower.permutations.len();
    let stages = lower.stage_census.clone();
    drop(lower);
    let node = first::SparseSetup::new_with_padding(
        canonical.clone(),
        false,
        if cfg!(feature = "keccak-protocol") {
            Some(if cfg!(feature = "keccak-quad-cap") {
                (21, 21)
            } else {
                (22, 22)
            })
        } else {
            None
        },
    )
    .unwrap();
    eprintln!("node layout {:?}", layout(&node.setup));
    assert_eq!((node.setup.row_log, node.setup.z_log), schema.shapes[3]);
    #[cfg(not(feature = "keccak-protocol"))]
    assert_eq!(layout(&first.setup), layout(&node.setup), "shared shape closure");
    let start = Instant::now();
    let fresh = std::array::from_fn(|i| {
        first
            .verify(&schema.fields(&certs[i].statement), &context, &certs[i].proof)
            .unwrap()
    });
    let (inputs, routes, digest) = tree::inputs(schema, children, fresh);
    let admitted = start.elapsed().as_secs_f64();
    let foldstart = Instant::now();
    let reduction = tree::prove(schema, registry, &inputs, &routes, &digest);
    let fold_s = foldstart.elapsed().as_secs_f64();
    let recordstart = Instant::now();
    let trace = tree::record(schema, &first.setup, children, &context, &reduction);
    let record_s = recordstart.elapsed().as_secs_f64();
    assert!(trace.same_program(&canonical));
    let statement = tree::statement(schema, digest, &inputs, &routes, &reduction);
    let outputs = schema.fields(&statement);
    assert_eq!(outputs, private_recursion::outputs(&trace));
    let proofstart = Instant::now();
    let proof = node.prove(&trace, &context).unwrap();
    let bytes = bincode::serialize(&proof).unwrap().len();
    let outer_s = proofstart.elapsed().as_secs_f64();
    let merge_s = start.elapsed().as_secs_f64();
    let rootstart = Instant::now();
    let own = node.verify(&outputs, &context, &proof).unwrap();
    let verify_ms = rootstart.elapsed().as_secs_f64() * 1000.;
    let mut settles = Vec::new();
    for (i, slot) in statement.slots.iter().enumerate() {
        if slot.active {
            let (_, g) = registry[i].unwrap();
            let start = Instant::now();
            assert!(g.settle(&slot.claim));
            settles.push(serde_json::json!({"slot":i,"ms":start.elapsed().as_secs_f64()*1000.}));
        }
    }
    let start = Instant::now();
    assert!(node.generator.settle(&own));
    let own_ms = start.elapsed().as_secs_f64() * 1000.;
    let root_ms = rootstart.elapsed().as_secs_f64() * 1000.;
    let root_registry = [
        Some(&generators[0]),
        generators.get(1),
        Some(&first.generator),
        Some(&node.generator),
    ];
    assert!(tree::verify_root(
        schema,
        &node,
        &digest,
        &statement,
        &context,
        &proof,
        root_registry
    ));
    if std::env::args().any(|a| a == "reuse") {
        let reversed = [&certs[1], &certs[0]];
        let fresh = std::array::from_fn(|i| {
            first
                .verify(&schema.fields(&reversed[i].statement), &context, &reversed[i].proof)
                .unwrap()
        });
        let (in2, routes2, digest2) = tree::inputs(schema, reversed, fresh);
        let red2 = tree::prove(schema, registry, &in2, &routes2, &digest2);
        let trace2 = tree::record(schema, &first.setup, reversed, &context, &red2);
        assert!(trace2.same_program(&canonical));
        let statement2 = tree::statement(schema, digest2, &in2, &routes2, &red2);
        let proof2 = node.prove(&trace2, &context).unwrap();
        let c0 = Certificate {
            key: node.setup.key,
            statement: statement.clone(),
            proof: proof.clone(),
        };
        let c1 = Certificate {
            key: node.setup.key,
            statement: statement2,
            proof: proof2,
        };
        let fresh = [
            node.verify(&schema.fields(&c0.statement), &context, &c0.proof).unwrap(),
            node.verify(&schema.fields(&c1.statement), &context, &c1.proof).unwrap(),
        ];
        let (in3, routes3, digest3) = tree::inputs(schema, [&c0, &c1], fresh);
        let registry3 = [
            registry[0],
            registry[1],
            registry[2],
            Some((&node.setup, &node.generator)),
        ];
        let red3 = tree::prove(schema, registry3, &in3, &routes3, &digest3);
        let trace3 = tree::record(schema, &first.setup, [&c0, &c1], &context, &red3);
        assert!(trace3.satisfied());
        assert!(trace3.same_program(&canonical));
        let statement3 = tree::statement(schema, digest3, &in3, &routes3, &red3);
        let proof3 = node.prove(&trace3, &context).unwrap();
        assert!(tree::verify_root(
            schema,
            &node,
            &digest3,
            &statement3,
            &context,
            &proof3,
            root_registry
        ));
        eprintln!(
            "same node key reused for node + node; all active slots settled; this reuse regression shares leaves across its two independently proved nodes"
        );
    }
    let one_start = Instant::now();
    let one = a.verify_deferred(&publics[0], &context, &leafproofs[0], false).unwrap();
    assert!(generators[0].settle(&a.claim(&one)));
    let one_root_ms = one_start.elapsed().as_secs_f64() * 1000.;
    let first_start = Instant::now();
    let first_own = first
        .verify(&schema.fields(&certs[0].statement), &context, &certs[0].proof)
        .unwrap();
    for (i, slot) in certs[0].statement.slots.iter().enumerate().filter(|(_, s)| s.active) {
        assert!(generators[i].settle(&slot.claim));
    }
    assert!(first.generator.settle(&first_own));
    let first_root_ms = first_start.elapsed().as_secs_f64() * 1000.;
    // Direct verifier probes; no call to a node prover admission API.
    let mut changed = certs[0].clone();
    changed.statement.slots[0].claim.matrix_values[0] += primitives::field::F192::ONE;
    assert!(!tree::record(schema, &first.setup, [&changed, &certs[1]], &context, &reduction).satisfied());
    let mut changed = certs[0].clone();
    changed.key[0] ^= 1;
    assert!(!tree::record(schema, &first.setup, [&changed, &certs[1]], &context, &reduction).satisfied());
    let mut changed = certs[0].clone();
    changed.statement.kind = true;
    assert!(!tree::record(schema, &first.setup, [&changed, &certs[1]], &context, &reduction).satisfied());
    assert!(!tree::record(schema, &first.setup, [&certs[1], &certs[0]], &context, &reduction).satisfied());
    let mut changed = certs[0].clone();
    *changed.proof.stream.last_mut().unwrap() += primitives::field::F192::ONE;
    assert!(!tree::record(schema, &first.setup, [&changed, &certs[1]], &context, &reduction).satisfied());
    let mut changed_statement = statement.clone();
    changed_statement.slots[0].claim.matrix_values[0] += primitives::field::F192::ONE;
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &changed_statement,
        &context,
        &proof,
        root_registry
    ));
    let mut changed_statement = statement.clone();
    changed_statement.slots[0].claim.app_key[0] ^= 1;
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &changed_statement,
        &context,
        &proof,
        root_registry
    ));
    let mut changed_statement = statement.clone();
    changed_statement.kind = false;
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &changed_statement,
        &context,
        &proof,
        root_registry
    ));
    let mut omitted = statement.clone();
    omitted.slots[0] = schema.empty(0);
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &omitted,
        &context,
        &proof,
        root_registry
    ));
    let mut omitted_child = certs[0].clone();
    omitted_child.statement.slots[0] = schema.empty(0);
    assert!(!tree::record(schema, &first.setup, [&omitted_child, &certs[1]], &context, &reduction).satisfied());
    let mut bad = statement.clone();
    bad.slots.remove(0);
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &bad,
        &context,
        &proof,
        root_registry
    ));
    let mut bad = statement.clone();
    bad.slots[3] = bad.slots[2].clone();
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &bad,
        &context,
        &proof,
        root_registry
    ));
    let mut bad = proof.clone();
    *bad.stream.last_mut().unwrap() += primitives::field::F192::ONE;
    assert!(!tree::verify_root(
        schema,
        &node,
        &digest,
        &statement,
        &context,
        &bad,
        root_registry
    ));
    println!(
        "{}",
        serde_json::json!({"leaf_root_distinct_apps":1,"leaf_complete_root_ms":one_root_ms,"first_root_distinct_apps":if mixed{3}else{2},"first_complete_root_ms":first_root_ms,"node_root_distinct_apps":if mixed{4}else{3},"case":if mixed{"mixed"}else{"same"},"merge_s":merge_s,"native_child_checks_s":admitted,"fold_prover_s":fold_s,"record_s":record_s,"outer_prover_s":outer_s,"rows":rows,"compressions":compressions,"permutations":permutations,"stage_census":stages,"committed_words":node.setup.committed_words,"proof_bytes":bytes,"first_generator_bindings":first.generator.binding_count(),"node_generator_bindings":node.generator.binding_count(),"carried_bytes":statement.slots.iter().filter(|s|s.active).map(|s|24*(5+s.claim.row_point.len()+s.claim.col_point.len())).sum::<usize>(),"statement_bytes":outputs.len()*24,"core_verify_ms":verify_ms,"own_settle_ms":own_ms,"settlements":settles,"complete_root_ms":root_ms,"first_key":format!("{:02x?}",first.setup.key),"node_key":format!("{:02x?}",node.setup.key),"verifier_rejections":["false carried evaluation","substituted app key","omitted claim","duplicated claim","wrong child kind","swapped children unchanged reduction","tampered child proof","tampered root proof"],"verified":true})
    );
}
