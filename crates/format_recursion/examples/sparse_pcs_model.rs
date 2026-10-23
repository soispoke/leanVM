use fiat_shamir::transcript::{Challenger, ProverState, Receiver, Transmitter, VerifierState};
use pcs::whir;
use primitives::{
    field::{F64, F192},
    multilinear::{eq_eval, eq_table},
};
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    parallel::init();
    assert_eq!(parallel::num_threads(), 12);
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let part = &args[2];
    let (nlog, mlog) = match case.as_str() {
        "shielded" => (18, 16),
        "merge" => (21, 20),
        _ => panic!("unknown circuit"),
    };
    let columns: Vec<usize> = if part == "fixed" {
        std::iter::repeat_n(nlog, 21).chain([mlog, mlog]).collect()
    } else {
        assert_eq!(part, "derefs");
        vec![nlog; 18]
    };
    let words: usize = columns.iter().map(|&l| 1usize << l).sum();
    let log_n = words.next_power_of_two().trailing_zeros() as usize;
    let stack: Vec<F64> = parallel::map_collect(words, |i| {
        let mut v = (i as u64).wrapping_add(0x0123456789abcdef);
        v ^= v >> 12;
        v ^= v << 25;
        v ^= v >> 27;
        F64(v.wrapping_mul(0x2545f4914f6cdd1d))
    });
    let start = Instant::now();
    let (cm, data) = whir::commit(&stack, log_n, whir::INITIAL_FOLDING_FACTOR, 2);
    let commit_s = start.elapsed().as_secs_f64();
    let mut ps = ProverState::from_label(b"conditional-sparse-pcs-components-v1");
    ps.add_root(&cm.root);
    let point = ps.sample_vec(nlog);
    let beta = ps.sample();
    let start = Instant::now();
    let weights_n = eq_table(&point);
    let weights_m = eq_table(&point[..mlog]);
    let mut basis = vec![F192::ZERO; words];
    let mut at = 0;
    let mut power = F192::ONE;
    for &l in &columns {
        let w = if l == nlog { &weights_n } else { &weights_m };
        let end = at + (1usize << l);
        parallel::chunks_mut(&mut basis[at..end], 4096, |c, out| {
            for (j, v) in out.iter_mut().enumerate() {
                *v = power * w[c * 4096 + j];
            }
        });
        at = end;
        power *= beta;
    }
    let target = whir::inner_product_base_ext(&stack, &basis);
    ps.add_scalar(target);
    let config = whir::config_for_rate(log_n, 2).unwrap();
    whir::recursive_prover_with_basis(
        &config,
        log_n,
        &stack,
        basis,
        target,
        &data.codeword,
        &data.merkle_tree,
        &mut ps,
    );
    let proof = ps.into_proof();
    let bytes = bincode::serialize(&proof).unwrap();
    let opening_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let mut vs = VerifierState::from_label(b"conditional-sparse-pcs-components-v1", &proof);
    let root = vs.next_root().unwrap();
    let vpoint = vs.sample_vec(nlog);
    let vbeta = vs.sample();
    let target = vs.next_scalar().unwrap();
    let lanes = words >> (log_n - whir::INITIAL_FOLDING_FACTOR);
    whir::recursive_verifier_with_basis_succinct(
        &config,
        log_n,
        lanes,
        target,
        &root,
        |x| {
            let mut result = F192::ZERO;
            let mut at = 0;
            let mut power = F192::ONE;
            for &l in &columns {
                let selector = x[l..].iter().enumerate().fold(F192::ONE, |s, (j, &v)| {
                    s * if (at >> (j + l)) & 1 == 1 { v } else { F192::ONE + v }
                });
                result += power * selector * eq_eval(&vpoint[..l], &x[..l]);
                at += 1usize << l;
                power *= vbeta;
            }
            result
        },
        &mut vs,
    )
    .unwrap();
    vs.finish().unwrap();
    let verify_ms = start.elapsed().as_secs_f64() * 1000.;
    let recursive_census = format_recursion::row_format::record_sparse_pcs_component(&proof, &columns, nlog, words);
    println!(
        "{}",
        serde_json::json!({"case":case,"component":part,"words":words,"log_n":log_n,"commit_s":commit_s,"opening_s":opening_s,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"recursive_census":recursive_census,"kind":"synthetic WHIR component, not SPARK or a complete proof"})
    );
}
