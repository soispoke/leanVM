# Succinct Flock adapted to BLAKE2s

The complete baseline and its timing definitions are in [FLOCK_BASELINE.md](../../recursion/FLOCK_BASELINE.md). All three 8-segment, 256-step trials completed, with 15 proofs and nine malformed-root rejections per trial. Every endpoint agrees with Python's independent BLAKE2s implementation.

## Start here

| Artifact | Contents |
| --- | --- |
| [summary.json](summary.json) | Independently validated trial timings and medians |
| [Final receipt](flock-b2s-repeated-final/result.json) | Source/binary hashes, command, affinity, memory guard and process result |
| [Raw stdout](flock-b2s-repeated-final/run-00/stdout.log) | Every trial's stages, statement and verification result |
| [Second analysis](flock-b2s-repeated-final/analysis.json) | Separate stage, endpoint and byte-accounting checks |
| [Source patch](flock-blake2s.patch) | Full adaptation against pinned upstream |
| [Source freeze](source-freeze.json) | Upstream/adaptation revisions and changed-file hashes |
| [All source hashes](source-sha256.json) | Complete 396-file tracked source manifest |
| [Patch reconstruction](patch-reconstruction.json) | All source files reproduced from upstream plus patch |
| [Parameter audit](flock-blake2s-parameter-audit.json) | Unchanged embedded query/grinding schedules and their limits |
| [Final component audit](flock-b2s-final-audit.json) | Build, test and lint records |

Proof bundles are serialized and verified in memory. This archive retains sizes and verification results, not proof files or executables. The 414,354-byte bundle includes public inputs and commitment data; the 321,150-byte core proof alone is incomplete consumer input.

## Workload and measurement policy

The chain starts at 64 zero bytes. For 2,048 steps, set `state = hashlib.blake2s(state).digest() + bytes(32)`. The root's low digest is `1338c8d72146285481ade63df6c749daa633494c2f794ea5e98b678657f96561`; its remaining 32 bytes are zero. Eight sequential segments feed Flock's recursive tower. This differs from the tagged balanced tree in the native/leanVM comparison.

One process generates a separate immutable verification key, then proves three complete towers. All trials are retained. The key, immutable tables and allocator can remain warm. The generic runner has one process repetition; its fresh-process wording does not describe the three internal application trials. `shared_vk_setup` and `metadata.json` state their policy explicitly.

`online_wall_ms` times the prepared recursive shape through child-tape recording, witness preparation, inline replica/accumulator checks and proof generation. `prove_ms` times only the proving component. `consumer_verify_ms` checks the serialized root and discharges its residuals. `full_prove_ms_including_setup` covers the entire tower, including its shape setup and builder checks, but excludes the later root-discharge diagnostic and consumer verification. The external process timer includes the shared key generation, all three towers, all consumer checks and cleanup.

The runtime used Yukon `85e81e09fac36f6b69c1bdb5c0a74c2f4047414b` and runner SHA-256 `47c306c9564f159c56aab5a871e95d889f98f74e4025c07d45ac2cff34164ab6`. The shared checkout advanced during execution; [bench-research-used.py](bench-research-used.py) preserves the exact script loaded by the running process, recovered from its pinned Git blob and checked against the receipt. This is measurement tooling, not a Rust prover acceleration.

## Reproduce

Start from a fresh checkout and apply the saved patch:

```bash
git clone https://github.com/succinctlabs/flock.git flock-blake2s
cd flock-blake2s
git checkout b684b1258e4b1f202bec24afd660ace851b09e5e
git apply /absolute/path/to/flock-blake2s.patch
export RUSTUP_TOOLCHAIN=1.99.1
export RUSTFLAGS='-C target-cpu=native'
cargo build --locked --release -p flock-prover --features blake2s-tower --example tower_blake2s
export RAYON_NUM_THREADS=16
python3 /absolute/path/to/bench-research-used.py \
  --cwd "$PWD" --out /absolute/path/to/new-receipt \
  --budget-gib 32 --reserve-gib 40 --timeout-seconds 2400 \
  --cpus 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 \
  -- "$PWD/target/release/examples/tower_blake2s" 8 256 3
python3 /absolute/path/to/leanVM/experiments/pcs-r1cs/recursion/summarize_flock.py /absolute/path/to/new-receipt
```

Before running, compare the patched files to `source-sha256.json`. The concise command above hashes the executable; the original measurement additionally passed all tracked source paths and freeze inputs as `--source` arguments. Those 399 hashes are retained in the receipt. For a modified candidate, supply its complete source manifest and record the new hashes rather than relabeling this result.

## Retained earlier attempts

`flock-b2s-smoke-01` failed because upstream has no production m18 Fast profile for 16-step leaves. `smoke-02` exceeded the original 31-lane envelope. `smoke-03` produced a root but failed independent key generation at the old 2^14 slot capacity. `smoke-04` passed full verification at the enlarged envelope, before the final telemetry and nine-mutation harness. It is development evidence, not a final measured warmup.

The component directories retain native vectors, Merkle tests, transcript/physical-trace checks, builds and lint attempts. Earlier failures and interrupted attempts remain visible. `flock-default-regression-final` selected zero tests and is not counted as validation; `flock-default-tests-final` contains the full passing default library suite. The final feature/default tests retain their actual source revisions; subsequent telemetry and CLI edits are covered by the final build, lint and full repeated run.

The mathematical and implementation scope is stated in the [baseline report](../../recursion/FLOCK_BASELINE.md). This port retains BLAKE3 circuit/registry identifiers, supports RS only, and has no new formal composition theorem or official challenge score.
