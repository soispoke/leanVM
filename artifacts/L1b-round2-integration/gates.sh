#!/bin/bash
set -euo pipefail
export PATH=/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin
export CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=../target-ht-L1b LEANVM_NUM_THREADS=12 RAYON_NUM_THREADS=12
cargo fmt --all -- --check > ../artifacts/L1b-round2-fmt-final.log 2>&1
cargo test --release -p format_recursion -p rec_aggregation --lib > ../artifacts/L1b-round2-release.log 2>&1
cargo test --release -p format_recursion -p rec_aggregation --doc > ../artifacts/L1b-round2-doc.log 2>&1
cargo test --release -p circuit_suite --lib > ../artifacts/L1b-round2-circuit-suite.log 2>&1
cargo test --release -p flock keccak > ../artifacts/L1b-round2-flock-keccak.log 2>&1
for app in falcon sha256 shielded; do
 L3C_REJECTION_APP="$app" cargo test --release -p format_recursion --lib falcon_word_verifier_rejections_without_prechecks -- --ignored --nocapture > ../artifacts/L1b-round2-rejections-$app.log 2>&1
done
cargo build --release -p format_recursion --example automatic_lowering_check --example sparse_tree > ../artifacts/L1b-round2-build.log 2>&1
: > ../artifacts/L1b-round2-reconciliation.jsonl
for workload in blake2s-64b blake2s-1kib sha256-1kib keccak256-1KiB mpt-storage-proof shielded-transfer falcon512; do
 ../target-ht-L1b/release/examples/automatic_lowering_check experiments/pcs-r1cs/evidence/2026-10-23-automatic-trimming/reference.json "$workload" >> ../artifacts/L1b-round2-reconciliation.jsonl
done
../target-ht-L1b/release/examples/sparse_tree mixed reuse > ../artifacts/L1b-round2-sparse-tree.log 2>&1
cargo test --release -p format_recursion --features experimental-log26 --lib row_cap_requires_explicit_experimental_feature > ../artifacts/L1b-round2-log26.log 2>&1
cargo clippy --release -p format_recursion --features experimental-log26 --all-targets -- -D warnings > ../artifacts/L1b-round2-log26-clippy.log 2>&1
