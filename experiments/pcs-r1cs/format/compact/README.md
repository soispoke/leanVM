# Compact circuit descriptions

A benchmark generator program describes each application's circuit. The shared reference decoder has **83 logical Python statements** under the scorer's AST counting rule. This is the description layer alone; it excludes the PIOP, PCS, recursive verifier, registration rules and application semantics. Comparing 83 directly with a complete ISA/verifier's line count does not compare complete protocol specifications.

| Application | Full-adder rows, used | Program bytes | Code-deposit gas at 200/byte |
| --- | ---: | ---: | ---: |
| membership | 921,377 | 913 | 182,600 |
| blake2s-1kib | 503,072 | 1,641 | 328,200 |
| sha256-1kib | 615,478 | 4,157 | 831,400 |
| keccak256-1kib | 1,003,920 | 6,268 | 1,253,600 |
| shielded-transfer | 3,700,928 | 5,509 | 1,101,800 |
| falcon512 | 4,020,165 | 7,967 | 1,593,400 |
| mpt-storage-proof | 8,379,661 | 16,022 | 3,204,400 |
| ecdsa-secp256k1 | 42,790,747 | 8,391 | 1,678,200 |
| poseidon-bn254 | 365,998,911 | 8,660 | 1,732,000 |

Program sizes are **0.9-16.1 kB per application** (decimal kB). Code-deposit gas excludes deployment overhead, initcode, transaction data and registry costs. It is an illustration, not an implemented on-chain registration benchmark.

## What was checked

Each program reproduces the reference circuit's row connections and public sources. [`results.json`](results.json) records individual byte counts, SHA-256 hashes and whether the check is historical or fresh. The [historical scorer log](historical-score.jsonl) retains the completed large-circuit runs. Falcon was regenerated after the carry-cache bug fix and [rechecked](falcon-recheck.json) against a fresh Rust export. The rebuilt Keccak and MPT programs are smaller than the previously reported files and were also freshly compared byte for byte. A fresh membership run through `decode.py` anchors the unchanged interpreter.

Exact row reproduction establishes that these descriptions recover these circuits. It does not prove that a circuit implements Falcon, ECDSA or another application correctly; those checks are separate. It also does not formally verify the decoder, compiler or proof-system upgrade process.

The programs use bounded loops, integer/list operations, parameters and functions. They are hand-ported generators for these benchmark circuits. `encode` selects the corresponding precompiled program by filename; it is not an automatic compressor for arbitrary circuits. `decode_fast` compiles trusted benchmark programs to Python and omits the reference interpreter's resource guards. Neither is ready to process hostile consensus inputs without further specification and review.

Keeping descriptions durably available can support rebuilding an index after a proof-system upgrade. This branch demonstrates compact descriptions; it does not implement an on-chain publication registry or formally prove upgrade compatibility.

## Reproduce

Rebuild all nine descriptions with `src/build.sh`. Export the current Rust circuits with the `circuit_suite` `export_rows` example (release mode). `keccak256-1KiB` is the Rust workload name; rename its exported file to `keccak256-1kib.rows` for the scorer. The exporter includes membership from the quotient membership builder. The multi-gigabyte `.rows` files are not committed.

```sh
cargo run --locked --release -p circuit_suite --example export_rows -- /tmp/reference-rows falcon512
python3 experiments/pcs-r1cs/format/compact/score.py \
  experiments/pcs-r1cs/format/compact --rows-dir /tmp/reference-rows --only falcon512 --py-limit 0
```

For an independent interpreter/fast-decoder comparison, omit `--py-limit 0` on a smaller circuit. Large Python decodes can take minutes; the historical Poseidon decode took about 47 minutes. This reconstructs a circuit; it is not a proving-time measurement.
