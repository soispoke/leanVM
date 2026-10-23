#!/bin/bash
set -euo pipefail
export CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=../target-ht-L1b LEANVM_NUM_THREADS=12 RAYON_NUM_THREADS=12
# Run this script with taskset -c 48-63 and Rust 1.99.1 on PATH.
cargo build --release -p format_recursion --features experimental-log26 --example mldsa_workloads
../target-ht-L1b/release/examples/mldsa_workloads mldsa rows reject unused
