#!/bin/sh
set -eu
cd "$(dirname "$0")/guest"
if [ "${1:-}" = "sdk-keccak" ]; then
  cargo --config 'patch.crates-io.shake.path="../vendor/shake"' build --release --target-dir ../../target-sdk
  cp ../../target-sdk/riscv64im-unknown-none-elf/release/mldsa ../mldsa-sdk.elf
else
  cargo build --release --target-dir ../../target
  cp ../../target/riscv64im-unknown-none-elf/release/mldsa ../mldsa.elf
fi
