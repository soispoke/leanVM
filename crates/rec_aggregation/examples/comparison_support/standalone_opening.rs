//! Experimental wrapper reusing upstream WHIR recursion and its exact native opening transcript.
use fiat_shamir::{merkle::hash_to_scalars, transcript::RawProof};
use flock::{
    quotient::opening::{self, Layout, Table},
    standalone::Claim,
};
use leanvm_core::cpu::{self, Program};
use primitives::{
    field::{F64, F192},
    hash::hash,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::collections::BTreeMap;
use std::fmt::Write;
#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

fn literal(x: F192) -> String {
    format!("{}", (x.c0 as u128) | ((x.c1 as u128) << 64))
}
pub fn hints_named(program: &mut Program, raw: &RawProof, layout: &Layout, suffix: &str) {
    let config =
        pcs::whir::config_for_shape(layout.log_n, pcs::whir::LOG_INV_RATE_0, layout.fold, layout.reduction).unwrap();
    let shape = config.level_shapes(layout.log_n);
    let mut queues: BTreeMap<String, Vec<Vec<F192>>> = BTreeMap::new();
    let mut caps = Vec::new();
    let mut active_all = Vec::new();
    let mut paths = raw.merkle.iter();
    for (&queries, &block) in config.queries.iter().zip(&shape.block_len) {
        let depth = block.trailing_zeros() as usize;
        let cap_depth = (queries.next_power_of_two().ilog2() as usize).min(depth);
        let n = 1 << cap_depth;
        let path_depth = depth - cap_depth;
        let mut nodes = vec![[0u8; 32]; 2 * n];
        let mut active = vec![F192::ZERO; n];
        for _ in 0..queries {
            let opening = paths.next().unwrap();
            queues
                .entry("merkle_leaf_rows".into())
                .or_default()
                .push(opening.leaf_data.iter().copied().map(F192::from).collect());
            let bytes: Vec<_> = opening.leaf_data.iter().flat_map(|x| x.0.to_le_bytes()).collect();
            let mut node = pcs::merkle::hash_leaf(&bytes);
            let mut index = (1 << depth) + opening.leaf_index;
            let mut children = Vec::new();
            for (height, sibling) in opening.path.iter().enumerate() {
                if height >= path_depth {
                    nodes[index] = node;
                    nodes[index ^ 1] = *sibling;
                    active[index >> 1] = F192::ONE;
                }
                let (left, right) = if index & 1 == 0 {
                    (node, *sibling)
                } else {
                    (*sibling, node)
                };
                if height < path_depth {
                    children.extend(hash_to_scalars(&left));
                    children.extend(hash_to_scalars(&right));
                }
                node = pcs::merkle::hash_pair(&left, &right);
                index >>= 1;
            }
            nodes[1] = node;
            queues.entry("merkle_children".into()).or_default().push(children);
        }
        caps.extend(nodes.iter().flat_map(hash_to_scalars));
        active_all.extend(active);
    }
    assert!(paths.next().is_none());
    program.set_witness(format!("merkle_caps{suffix}"), vec![caps]);
    program.set_witness(format!("merkle_cap_active{suffix}"), vec![active_all]);
    for (name, entries) in queues {
        program.set_witness(format!("{name}{suffix}"), entries);
    }
    program.set_witness(format!("opening_stream{suffix}"), vec![raw.stream.clone()]);
}

pub fn guest_source(layout: &Layout, nclaims: usize, stream_len: usize) -> String {
    let replacements = rec_aggregation::aggregation::standalone_placeholder_map(
        4,
        Some((layout.log_n, layout.fold, layout.reduction)),
    );
    let source = include_str!("../../guests/lean_ethereum.py");
    let mut code = String::new();
    let n = nclaims * (layout.vars + 1);
    let limb_count = 4 + 3 * n;
    let byte_len = 8 * limb_count;
    let blocks = byte_len.div_ceil(64);
    let padded_limbs = 8 * blocks;
    writeln!(
        code,
        "\nCLAIM_VARS = {}\nCLAIM_COUNT = {}\nLOG_LANE = {}",
        layout.vars,
        nclaims,
        layout.log_n - layout.fold
    )
    .unwrap();
    let logical: Vec<_> = layout
        .lane_map()
        .iter()
        .map(|&(chunk, j)| (chunk << (layout.log_chunk - (layout.log_n - layout.fold))) | j)
        .collect();
    writeln!(code, "LANE_MAP = {:?}", logical).unwrap();
    let split = source
        .find("# =================================== field packing")
        .unwrap();
    let end = source
        .find("# ============================== inner-proof verification")
        .unwrap();
    code = source[..split].to_owned() + &code + &source[split..end] + "\ndef main():\n";
    writeln!(
        code,
        "    data = StackBuf({})\n    hint_witness(data, \"claim\")\n    limbs = StackBuf({padded_limbs})",
        n + 2
    )
    .unwrap();
    code.push_str("    a0, a1 = canonical_limbs(data[0])\n    a2, a3 = canonical_limbs(data[1])\n    limbs[0] = a0\n    limbs[1] = a1\n    limbs[2] = a2\n    limbs[3] = a3\n");
    writeln!(code,"    for k in unroll(0, {n}):\n        low = StackBuf(2)\n        hint_f192_limbs(low, data[2+k])\n        high = ((data[2+k] + low[0]) * Y_INV + low[1]) * Y_INV\n        assert_in_k(low[0], low[1])\n        assert_in_k(high, high)\n        limbs[4+3*k] = low[0]\n        limbs[5+3*k] = low[1]\n        limbs[6+3*k] = high").unwrap();
    writeln!(code,"    for k in unroll({limb_count}, {padded_limbs}):\n        limbs[k] = 0\n    packed = StackBuf({})\n    for k in unroll(0, {}):\n        packed[k] = pack64x2(limbs[2*k], limbs[2*k+1])",padded_limbs/2,padded_limbs/2).unwrap();
    for b in 0..blocks {
        let counter = if b + 1 == blocks { byte_len } else { 64 * (b + 1) };
        writeln!(code,"    digest_{b} = StackBuf(2)\n    blake2s(packed[{}:{}], packed[{}:{}], digest_{b}, counter={counter}, final={}{} )",4*b,4*b+2,4*b+2,4*b+4,usize::from(b+1==blocks),if b==0 {String::new()}else{format!(", cv=digest_{}",b-1)}).unwrap();
    }
    let iv = hash_to_scalars(&hash(b"flock-quotient-opening"));
    writeln!(code,"    pub_ptr = GEN ** 0\n    assert pub_ptr[1] == digest_{}[0]\n    assert pub_ptr[GEN] == digest_{}[1]\n    fs = StackBuf(2)\n    blake2s([{}, {}], digest_{}, fs)\n    fs, lam = squeeze(fs)\n    target = 0\n    power = 1",blocks-1,blocks-1,literal(iv[0]),literal(iv[1]),blocks-1).unwrap();
    code.push_str("    for k in unroll(0, CLAIM_COUNT):\n        target += power * data[2+k*(CLAIM_VARS+1)+CLAIM_VARS]\n        power *= lam\n");
    writeln!(code,"    stream = StackBuf({stream_len})\n    hint_witness(stream, \"opening_stream\")\n    target, point, residual, tail = open_stacked(0, fs[0], fs[1], target, data[0], data[1], addr(stream))").unwrap();
    code.push_str("    weight = 0\n    power = 1\n    for c in unroll(0, CLAIM_COUNT):\n        low = 1\n        for j in unroll(0, LOG_LANE):\n            low *= 1 + data[2+c*(CLAIM_VARS+1)+j] + point[GEN ** j]\n        lanes = 0\n        for lane in unroll(0, len(LANE_MAP)):\n            term = 1\n            for j in unroll(LOG_LANE, CLAIM_VARS):\n                if const((LANE_MAP[lane] // (2 ** (j-LOG_LANE))) % 2 == 1):\n                    term *= data[2+c*(CLAIM_VARS+1)+j]\n                else:\n                    term *= 1 + data[2+c*(CLAIM_VARS+1)+j]\n            for j in unroll(0, ");
    writeln!(code, "{}):", layout.fold).unwrap();
    code.push_str("                if const((lane // (2 ** j)) % 2 == 1):\n                    term *= point[GEN ** (LOG_LANE+j)]\n                else:\n                    term *= 1 + point[GEN ** (LOG_LANE+j)]\n            lanes += term\n        weight += power * low * lanes\n        power *= lam\n    assert target == tail * (weight + residual)\n    return\n");
    let mut replacements: Vec<_> = replacements.into_iter().collect();
    replacements.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));
    for (name, value) in replacements {
        code = code.replace(&name, &value);
    }
    code
}
fn guest(layout: &Layout, nclaims: usize, stream_len: usize) -> Program {
    lean_compiler::compile(
        &lean_compiler::parse(&guest_source(layout, nclaims, stream_len)).expect("opening guest parses"),
    )
}
pub fn bind(root: &[u8; 32], claims: &[Claim]) -> (Vec<F192>, [F192; 2]) {
    let mut data = hash_to_scalars(root).to_vec();
    let mut bytes = root.to_vec();
    for claim in claims {
        for x in claim.point.iter().chain([&claim.value]) {
            data.push(*x);
            for limb in [x.c0, x.c1, x.c2] {
                bytes.extend(limb.to_le_bytes());
            }
        }
    }
    (data, hash_to_scalars(&hash(&bytes)))
}
fn wrap(layout: &Layout, root: &[u8; 32], claims: &[Claim], proof: &fiat_shamir::transcript::Proof, name: &str) {
    let raw = opening::verification_trace(layout, root, claims, proof).unwrap();
    let mut program = guest(layout, claims.len(), raw.stream.len());
    let (data, public) = bind(root, claims);
    program.set_witness("claim", vec![data]);
    hints_named(&mut program, &raw, layout, "");
    eprintln!(
        "{name}: compiled code={} raw_scalars={}",
        program.code_len(),
        raw.stream.len()
    );
    let (proof, stats) = cpu::prove(&program, public, 2).expect("standalone opening recursive proof");
    cpu::verify(&program, &public, &proof).expect("standalone opening recursive verification");
    for i in 0..claims.len() {
        for change_point in [false, true] {
            let mut bad = claims.to_vec();
            if change_point {
                bad[i].point[0] += F192::ONE;
            } else {
                bad[i].value += F192::ONE;
            }
            let (data, pi) = bind(root, &bad);
            let mut altered = program.clone();
            altered.set_witness("claim", vec![data]);
            assert!(
                altered.execute(pi).is_err(),
                "mutated claim accepted by recursive guest"
            );
        }
    }
    let mut badroot = *root;
    badroot[0] ^= 1;
    let (data, pi) = bind(&badroot, claims);
    let mut altered = program.clone();
    altered.set_witness("claim", vec![data]);
    assert!(altered.execute(pi).is_err(), "mutated root accepted");
    let mut bad = raw.stream.clone();
    bad[0] += F192::ONE;
    let mut altered = program.clone();
    altered.set_witness("opening_stream", vec![bad]);
    assert!(altered.execute(public).is_err(), "mutated sumcheck message accepted");
    let mut pi = public;
    pi[0] += F192::ONE;
    assert!(
        cpu::verify(&program, &pi, &proof).is_err(),
        "outer statement substitution accepted"
    );
    println!(
        "{name}: recursive proof and {} negative checks passed {}",
        2 * claims.len() + 3,
        stats.details()
    );
}
pub fn run() {
    use flock::{
        membership::Secret,
        quotient::{self, Index, circuit},
    };
    let mut rng = StdRng::seed_from_u64(37);
    let mut bytes = || {
        let mut b = [0; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let secret = Secret {
        x: bytes(),
        siblings: std::array::from_fn(|_| bytes()),
        directions: 0x12564789,
    };
    let circuit = circuit::membership();
    let index = Index::new(&circuit);
    let wiring = opening::commit(index.table());
    let statement = secret.statement();
    let cells = circuit.cells(&circuit::membership_inputs(&secret));
    let masks = std::array::from_fn(|_| std::array::from_fn(|_| F64(rng.next_u64())));
    let mut committed = Vec::new();
    let mut commit = |table: &Table| {
        let c = opening::commit(table);
        let root = c.root;
        committed.push(c);
        root
    };
    let proved = quotient::prove(&circuit, &index, &wiring.root, &statement, &cells, &masks, &mut commit);
    let (roots, claims) = quotient::verify(&wiring.root, &statement, &proved.proof, circuit.log_rows).unwrap();
    assert_eq!(claims, proved.claims);
    assert_eq!(roots, [committed[0].root, committed[1].root]);
    for (name, table, commitment, claims) in [
        ("witness", &proved.witness, &committed[0], vec![claims.witness]),
        ("wiring", index.table(), &wiring, vec![claims.wiring]),
        (
            "quotient",
            &proved.quotient,
            &committed[1],
            vec![claims.quotient, claims.sum],
        ),
    ] {
        let proof = opening::open(table, commitment, &claims);
        wrap(&table.layout, &commitment.root, &claims, &proof, name);
    }
}
