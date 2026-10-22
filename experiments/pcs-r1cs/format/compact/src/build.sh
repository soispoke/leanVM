#!/bin/bash
# Compile every ported generator to progs/<circuit>.desc (the descriptions).
set -euo pipefail
cd "$(dirname "$0")"
C="python3 compile.py"
$C ../progs/membership.desc 20 membership.py
$C ../progs/blake2s-1kib.desc 19 ckt.py blake2s.py
$C ../progs/sha256-1kib.desc 20 ckt.py sha256.py sha256_lib.py sha256_main.py
$C ../progs/keccak256-1kib.desc 20 ckt.py keccak_tables.py keccak.py keccak_main.py
$C ../progs/shielded-transfer.desc 22 ckt.py sha256.py sha256_lib.py shielded.py
$C ../progs/falcon512.desc 22 ckt.py falcon.py
$C ../progs/mpt-storage-proof.desc 23 ckt.py keccak_tables.py keccak.py mpt_tables.py mpt.py
$C ../progs/ecdsa-secp256k1.desc 26 ckt.py nonnative.py ecdsa.py
$C ../progs/poseidon-bn254.desc 29 ckt.py nonnative.py poseidon.py
