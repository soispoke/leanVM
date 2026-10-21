#!/bin/sh
# Static aarch64 build of the benchmark examples for Android (Pixel 7: Tensor G2, Cortex-X1/A78/A55).
# A static PIE needs no Android libc, so it runs from /data/local/tmp under `adb shell`.
# Needs: rustup target aarch64-unknown-linux-gnu, aarch64-linux-gnu-gcc (Debian/Ubuntu gcc-aarch64-linux-gnu).
set -eu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export JEMALLOC_SYS_WITH_LG_PAGE=16   # correct on both 4 KiB and 16 KiB page kernels
# RUSTFLAGS replaces the workspace's target-cpu=native, which would describe the build host.
export RUSTFLAGS="-C target-cpu=cortex-a78 -C target-feature=+aes,+neon,+crt-static"
cargo build --locked --release --target aarch64-unknown-linux-gnu -p rec_aggregation --example challenge --example comparison --example batch
echo "${CARGO_TARGET_DIR:-target}/aarch64-unknown-linux-gnu/release/examples/challenge"
