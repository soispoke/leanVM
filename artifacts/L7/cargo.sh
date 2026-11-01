#!/bin/bash
exec taskset -c 48-63 env PATH=/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/target-L7 LEANVM_NUM_THREADS=12 RAYON_NUM_THREADS=12 cargo "$@"
