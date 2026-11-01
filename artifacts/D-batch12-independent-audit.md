# D-batch12 independent artifact audit

Audited UTC: 2026-10-23T11:21:11.636630+00:00. Parent: `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022`.

**Conclusion: batch12 already completed three alternating paired repeats per workload and all requested release/doctest/clippy gates. Batch12 is REJECTED for performance, not correctness. Do not integrate provisional commit `0a137ef5`.** The later accepted owned-column optimization is separate and outside this decision.

Only existing evidence was read. No builds, benchmarks, contacts, worktree edits, commits or pushes were performed. This report is the only workspace output. No Lean files were edited; no edit-check time applies. The required `/root/yukon-autoresearch/bin/turbo-check.py` already exists and was preserved.

## Integrity and coverage

Inspected 48 receipt directories: all D-batch12-*, D-base-* and matching D-abab-* directories, plus three original full-application controls. Recomputed every recorded run stdout/stderr SHA-256 and checked receipt ok/returncode, files_unchanged and equality of complete before/after manifests. Errors: []. Historical manifests were compared to each other, not to current lane-D source (which has subsequently changed). Exact per-receipt hashes and commands appear in the appendix.

## Alternating paired repeats and timing

A = frozen `artifacts/D-base-control`; B = frozen `artifacts/D-base-batch12`. Three fresh processes per variant per workload completed. Each workload follows A1 B1 B2 A2 A3 B3 (paired order AB, BA, AB; not a strict ABABAB sequence) by receipt start/finish timestamps (listed below). All 18 receipts are ok=true/files_unchanged=true. All record CPUs 36–47, LEANVM_NUM_THREADS=12 and RAYON_NUM_THREADS=12.

The `base_only.proving_s` field is prover-only. **Time to mempool-ready proof (witness plus the one wallet proof)** is computed as `proving_s + native_trace_creation_ms/1000`; setup and native verification are excluded. These are development measurements with noisy host conditions, not an official performance claim.

### blake2s-64b

| Variant | Repeat | Proving s | Witness ms | Time to mempool-ready proof s | Raw proof bytes | Certificate bytes | Peak client RAM (wait4 KiB) | Sampled process-group bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| control | 1 | 0.135666550 | 11.887411000 | 0.147553961 | 247920 | 247956 | 339740 | 333959168 |
| control | 2 | 0.105498105 | 7.702009000 | 0.113200114 | 247920 | 247956 | 340268 | 207945728 |
| control | 3 | 0.120354002 | 7.612353000 | 0.127966355 | 247920 | 247956 | 340336 | 348823552 |
| batch12 | 1 | 0.132520185 | 8.423679000 | 0.140943864 | 247920 | 247956 | 340236 | 338198528 |
| batch12 | 2 | 0.111243974 | 8.722315000 | 0.119966289 | 247920 | 247956 | 340300 | 348749824 |
| batch12 | 3 | 0.118030283 | 10.174882000 | 0.128205165 | 247920 | 247956 | 340280 | 348622848 |

Prover-only: min-of-three A=0.105498105 s, B=0.111243974 s, delta=+5.446419%; medians A=0.120354002 s, B=0.118030283 s, delta=-1.930737%.

Time to mempool-ready proof: min-of-three A=0.113200114 s, B=0.119966289 s, delta=+5.977180%; medians A=0.127966355 s, B=0.128205165 s, delta=+0.186619%.

Order (start → finish UTC):
- control t1: 2026-10-23T10:30:05.578310+00:00 → 2026-10-23T10:30:06.118707+00:00
- batch12 t1: 2026-10-23T10:30:06.437922+00:00 → 2026-10-23T10:30:06.942307+00:00
- batch12 t2: 2026-10-23T10:30:26.123970+00:00 → 2026-10-23T10:30:26.620741+00:00
- control t2: 2026-10-23T10:30:26.882975+00:00 → 2026-10-23T10:30:27.376782+00:00
- control t3: 2026-10-23T10:30:46.662620+00:00 → 2026-10-23T10:30:47.164612+00:00
- batch12 t3: 2026-10-23T10:30:47.423985+00:00 → 2026-10-23T10:30:47.925625+00:00

Exact identical base-only shape/index record on all six runs:
```json
{"columns": 4, "index": [136188, 120960, 162], "kind": "shape", "shape": "PrivateShape { index: ArithmeticShape { log_rows: 17, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 120448, q_offset: 1572864, stack_log: 21 }"}
```
### blake2s-1kib

| Variant | Repeat | Proving s | Witness ms | Time to mempool-ready proof s | Raw proof bytes | Certificate bytes | Peak client RAM (wait4 KiB) | Sampled process-group bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| control | 1 | 1.126199570 | 131.087687000 | 1.257287257 | 323320 | 323356 | 4320268 | 4424372224 |
| control | 2 | 1.361735683 | 134.638749000 | 1.496374432 | 323320 | 323356 | 4320936 | 4425003008 |
| control | 3 | 1.357244046 | 133.934504000 | 1.491178550 | 323320 | 323356 | 4323996 | 4428935168 |
| batch12 | 1 | 1.158472855 | 129.849996000 | 1.288322851 | 323320 | 323356 | 4321072 | 4425084928 |
| batch12 | 2 | 1.258024858 | 134.689929000 | 1.392714787 | 323320 | 323356 | 4319664 | 4379222016 |
| batch12 | 3 | 1.126901203 | 132.627139000 | 1.259528342 | 323320 | 323356 | 4329012 | 4357152768 |

Prover-only: min-of-three A=1.126199570 s, B=1.126901203 s, delta=+0.062301%; medians A=1.357244046 s, B=1.158472855 s, delta=-14.645206%.

Time to mempool-ready proof: min-of-three A=1.257287257 s, B=1.259528342 s, delta=+0.178248%; medians A=1.491178550 s, B=1.288322851 s, delta=-13.603716%.

Order (start → finish UTC):
- control t1: 2026-10-23T10:30:07.190570+00:00 → 2026-10-23T10:30:10.166172+00:00
- batch12 t1: 2026-10-23T10:30:10.410125+00:00 → 2026-10-23T10:30:13.409816+00:00
- batch12 t2: 2026-10-23T10:30:27.615680+00:00 → 2026-10-23T10:30:30.741632+00:00
- control t2: 2026-10-23T10:30:30.995390+00:00 → 2026-10-23T10:30:34.258051+00:00
- control t3: 2026-10-23T10:30:48.178567+00:00 → 2026-10-23T10:30:51.395807+00:00
- batch12 t3: 2026-10-23T10:30:51.668240+00:00 → 2026-10-23T10:30:54.692626+00:00

Exact identical base-only shape/index record on all six runs:
```json
{"columns": 4, "index": [1678835, 1437312, 162], "kind": "shape", "shape": "PrivateShape { index: ArithmeticShape { log_rows: 21, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 1436800, q_offset: 25165824, stack_log: 25 }"}
```
### sha256-1kib

| Variant | Repeat | Proving s | Witness ms | Time to mempool-ready proof s | Raw proof bytes | Certificate bytes | Peak client RAM (wait4 KiB) | Sampled process-group bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| control | 1 | 2.438985395 | 314.995744000 | 2.753981139 | 347000 | 347036 | 8340872 | 8541540352 |
| control | 2 | 2.414828335 | 321.798931000 | 2.736627266 | 347000 | 347036 | 8347672 | 8548159488 |
| control | 3 | 2.265422212 | 339.346894000 | 2.604769106 | 347000 | 347036 | 8338068 | 8538419200 |
| batch12 | 1 | 2.318586582 | 359.321478000 | 2.677908060 | 347000 | 347036 | 8331764 | 8532168704 |
| batch12 | 2 | 2.425915000 | 302.698518000 | 2.728613518 | 347000 | 347036 | 8343244 | 8543784960 |
| batch12 | 3 | 2.540903379 | 314.794016000 | 2.855697395 | 347000 | 347036 | 8340060 | 8540696576 |

Prover-only: min-of-three A=2.265422212 s, B=2.318586582 s, delta=+2.346775%; medians A=2.414828335 s, B=2.425915000 s, delta=+0.459108%.

Time to mempool-ready proof: min-of-three A=2.604769106 s, B=2.677908060 s, delta=+2.807886%; medians A=2.736627266 s, B=2.728613518 s, delta=-0.292833%.

Order (start → finish UTC):
- control t1: 2026-10-23T10:30:13.657971+00:00 → 2026-10-23T10:30:19.878175+00:00
- batch12 t1: 2026-10-23T10:30:20.120858+00:00 → 2026-10-23T10:30:25.869132+00:00
- batch12 t2: 2026-10-23T10:30:34.516010+00:00 → 2026-10-23T10:30:40.338166+00:00
- control t2: 2026-10-23T10:30:40.609377+00:00 → 2026-10-23T10:30:46.407633+00:00
- control t3: 2026-10-23T10:30:54.947986+00:00 → 2026-10-23T10:31:00.600366+00:00
- batch12 t3: 2026-10-23T10:31:00.847815+00:00 → 2026-10-23T10:31:07.006080+00:00

Exact identical base-only shape/index record on all six runs:
```json
{"columns": 4, "index": [2584283, 2114176, 162], "kind": "shape", "shape": "PrivateShape { index: ArithmeticShape { log_rows: 22, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 2113664, q_offset: 50331648, stack_log: 26 }"}
```

Peak client RAM above is wait4 child high water; sampled process-group RAM is also retained. Sampling may miss short peaks; neither is a cgroup peak or a pure proof-stage allocation measurement. Base-only receipts record successful native verification but **do not time it separately**; full-application native verification timings are below.

## Full application certificate/shape checks

Certificate **sizes** and statements/keys/shapes can be compared from these JSON logs. These receipts do not emit certificate-content hashes or archive the actual certificate blobs, so byte-for-byte certificate identity is **not independently established** by these logs. Do not equate equal byte counts with equal serialized contents. The targeted test separately checks exact serialized transcript/claim equality for the batched dispatch.

### blake2s-64b

Base/node keys and shapes compare exactly equal:
```json
{"base_key": [181, 204, 251, 160, 210, 14, 88, 183, 206, 31, 97, 48, 223, 163, 66, 125, 220, 56, 207, 243, 58, 183, 73, 251, 218, 78, 84, 107, 102, 52, 251, 29], "base_shape": "PrivateShape { index: ArithmeticShape { log_rows: 17, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 120448, q_offset: 1572864, stack_log: 21 }", "node_key": [36, 52, 96, 174, 130, 17, 164, 57, 42, 156, 75, 213, 218, 86, 121, 59, 65, 154, 131, 3, 17, 78, 211, 199, 105, 120, 213, 37, 83, 114, 184, 244], "node_shape": "PrivateShape { index: ArithmeticShape { log_rows: 22, public_log: 10, public_len: 1024, index_log_inv_rate: 4 }, n_blocks: 65536, block_log: 16, connector_start: 2097152, q_offset: 50331648, stack_log: 26 }"}
```

| Entry | Certificate bytes A=B | Prove/merge ms A | Prove/merge ms B | Native verify ms A | Native verify ms B |
|---|---:|---:|---:|---:|---:|
| leaf 0 | 247956 | 296.017842000 | 159.467983000 | 8.701712000 | 4.961767000 |
| leaf 1 | 250308 | 355.055385000 | 139.084434000 | 6.248887000 | 4.971968000 |
| merge height 1 | 361196 | 10127.189524000 | 4462.486046000 | 11.179174000 | 6.496427000 |
| merge height 2 | 360524 | 8618.432449000 | 7817.519756000 | 11.000973000 | 8.331409000 |
| merge height 3 | 360716 | 8319.633008000 | 8384.496178000 | 8.104032000 | 11.787302000 |

Both leaves have identical statements; all three merge shapes and keys match. Both final complete events report status=verified. laneD-results.md reports final malformed-certificate rejection checks passed; the JSON completion event does not individually enumerate those checks, so this audit attributes that detail to the narrative rather than independently proving each mutation check.
### blake2s-1kib

Base/node keys and shapes compare exactly equal:
```json
{"base_key": [210, 188, 33, 62, 57, 20, 241, 124, 122, 57, 247, 70, 134, 229, 139, 56, 212, 60, 189, 3, 127, 213, 25, 53, 86, 44, 255, 211, 246, 47, 91, 102], "base_shape": "PrivateShape { index: ArithmeticShape { log_rows: 21, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 1436800, q_offset: 25165824, stack_log: 25 }", "node_key": [1, 152, 18, 48, 227, 7, 253, 105, 138, 73, 107, 74, 121, 4, 93, 120, 153, 240, 122, 116, 241, 39, 205, 67, 8, 58, 234, 156, 146, 70, 169, 142], "node_shape": "PrivateShape { index: ArithmeticShape { log_rows: 22, public_log: 10, public_len: 1024, index_log_inv_rate: 4 }, n_blocks: 131072, block_log: 17, connector_start: 2228224, q_offset: 67108864, stack_log: 27 }"}
```

| Entry | Certificate bytes A=B | Prove/merge ms A | Prove/merge ms B | Native verify ms A | Native verify ms B |
|---|---:|---:|---:|---:|---:|
| leaf 0 | 323356 | 2548.662333000 | 1712.588927000 | 6.223197000 | 5.800008000 |
| leaf 1 | 325148 | 2508.412717000 | 1492.674655000 | 7.972487000 | 7.016561000 |
| merge height 1 | 355980 | 11855.136348000 | 5942.500951000 | 12.319357000 | 7.159954000 |
| merge height 2 | 354732 | 11840.600383000 | 6600.272403000 | 9.499548000 | 7.918401000 |
| merge height 3 | 353580 | 10982.916065000 | 6389.179691000 | 7.715405000 | 6.908493000 |

Both leaves have identical statements; all three merge shapes and keys match. Both final complete events report status=verified. laneD-results.md reports final malformed-certificate rejection checks passed; the JSON completion event does not individually enumerate those checks, so this audit attributes that detail to the narrative rather than independently proving each mutation check.
### sha256-1kib

Base/node keys and shapes compare exactly equal:
```json
{"base_key": [142, 127, 216, 230, 134, 78, 160, 13, 91, 124, 130, 90, 103, 234, 117, 51, 169, 231, 20, 82, 70, 194, 21, 127, 37, 115, 153, 224, 50, 182, 251, 133], "base_shape": "PrivateShape { index: ArithmeticShape { log_rows: 22, public_log: 8, public_len: 162, index_log_inv_rate: 4 }, n_blocks: 39, block_log: 7, connector_start: 2113664, q_offset: 50331648, stack_log: 26 }", "node_key": [128, 99, 131, 48, 155, 254, 213, 133, 17, 142, 66, 16, 150, 115, 1, 77, 230, 64, 205, 132, 154, 121, 161, 80, 100, 79, 243, 57, 239, 158, 44, 123], "node_shape": "PrivateShape { index: ArithmeticShape { log_rows: 22, public_log: 10, public_len: 1024, index_log_inv_rate: 4 }, n_blocks: 131072, block_log: 17, connector_start: 2359296, q_offset: 67108864, stack_log: 27 }"}
```

| Entry | Certificate bytes A=B | Prove/merge ms A | Prove/merge ms B | Native verify ms A | Native verify ms B |
|---|---:|---:|---:|---:|---:|
| leaf 0 | 347036 | 6389.773119000 | 2740.625921000 | 10.343505000 | 9.297963000 |
| leaf 1 | 348028 | 6012.263605000 | 3259.306134000 | 9.299499000 | 6.029816000 |
| merge height 1 | 354668 | 12321.259762000 | 6845.758608000 | 12.716564000 | 5.888581000 |
| merge height 2 | 354796 | 9403.094012000 | 6000.725033000 | 6.608532000 | 7.012808000 |
| merge height 3 | 354060 | 9134.872776000 | 6191.234067000 | 7.271622000 | 6.699438000 |

Both leaves have identical statements; all three merge shapes and keys match. Both final complete events report status=verified. laneD-results.md reports final malformed-certificate rejection checks passed; the JSON completion event does not individually enumerate those checks, so this audit attributes that detail to the narrative rather than independently proving each mutation check.

## Gates

- `D-batch12-targeted-t1`: ok=True, files_unchanged=True, wall=32.824858551 s; command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion --lib batched_field_evaluations_preserve_transcript_and_claim_order`.
  - test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 79 filtered out; finished in 0.02s
- `D-batch12-release-gates-t1`: ok=True, files_unchanged=True, wall=207.642816890 s; command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion -p rec_aggregation --lib`.
  - test result: ok. 80 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 55.03s
  - test result: ok. 43 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 88.99s
- `D-batch12-doc-tests-t1`: ok=True, files_unchanged=True, wall=11.799422594 s; command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo test --locked --release -p format_recursion -p rec_aggregation --doc`.
  - test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
  - test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `D-batch12-clippy-t1`: ok=True, files_unchanged=True, wall=22.369747570 s; command: `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo clippy --locked --release -p format_recursion -p rec_aggregation --all-targets -- -D warnings`.
  - Successful returncode 0 with all-targets and warnings denied; no test count applies.

Release totals: **123 passed, 0 failed, 5 ignored** (80 format_recursion; 43 rec_aggregation plus 5 ignored). Doctests ran **0 tests in each package**, successfully. Targeted transcript test: **1 passed**, 79 filtered; execution 0.02 s. The targeted test covers l=1 and 13, strides 3 and 4, random extension points and stack values, claim offset/point/value order, challenge equality and exact bincode proof serialization equality. No claim of six targeted tests applies to batch12.

## Patch, binaries and acceptance status

Patch changes only native_arithmetic.rs: shared twelve-limb basis evaluation via send_fields replaces four send_field dispatches at gate and copy evaluations, preserving scalar/claim emission order, plus the transcript equivalence test. It does not change PCS configuration or verifier code.

`laneD-results.md` explicitly rejects batch12: the SHA median regressed and the small-workload effects were noisy. The prover-only minimum regresses for all three workloads. Earlier blocked-order medians and full application comparisons are retained as context, not accepted speedups. The provisional local commit 0a137ef5 was removed; the patch and frozen binary remain evidence. Later owned-column acceptance does not accept batch12.

- `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-batch12.patch`: 4628 bytes, SHA-256 `923dbaa2d0e406f9436911be6c3cfff8fb732d1aabaa6978b5bc392f27f70d97`.
- `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control`: 3573152 bytes, SHA-256 `083c0d1ba005eabecd5b5f03d664f61af5b69cc165a50027179571232409112c`.
- `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12`: 3591264 bytes, SHA-256 `3dc2c0e60948c2b3c5f56741d7f5e0cff17c4ba7f26d48f216f0009e2547b8d4`.
- `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/laneD-results.md`: 48674 bytes, SHA-256 `3c7c9bb951fb4b5415e8400f8e1b789f00ebbbc893f056fa7d48c37cd0cbf5fa`.
- `/root/yukon-autoresearch/bin/turbo-check.py`: 11738 bytes, SHA-256 `c8da08cef9040049246cf267536d7b0ebb3f9fa28838e1d9e80f9f5be62d4a76`.

## Exact receipt/hash appendix

Log hashes below were recomputed from files and matched the recorded run and outer receipt entries. Complete before/after manifest maps compare equal; current source was not substituted for historical evidence.
```json
[
  {
    "receipt": "D-abab-batch12-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:30:10.410125+00:00",
    "finished_utc": "2026-10-23T10:30:13.409816+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.8355656630010344,
        "stdout_sha256": "ac69f7e2a8a25fb99e1e023d3e95b3771713fbd656d4f1d31482082eec8a1eb3",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-blake2s-1kib-t2",
    "started_utc": "2026-10-23T10:30:27.615680+00:00",
    "finished_utc": "2026-10-23T10:30:30.741632+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.99332445699838,
        "stdout_sha256": "e6e9234f11bd5d9a5db06c5513066c2675ebac8b31954607ae543a4eef75b968",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-blake2s-1kib-t3",
    "started_utc": "2026-10-23T10:30:51.668240+00:00",
    "finished_utc": "2026-10-23T10:30:54.692626+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.8737936899997294,
        "stdout_sha256": "547fe7a685e91750479cf9f0b1bc5f4843d5d71bac29e2107a96e728926a3362",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:30:06.437922+00:00",
    "finished_utc": "2026-10-23T10:30:06.942307+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.36205081900698133,
        "stdout_sha256": "75feaf6dfbe2e064f6775222ef1f8e0bafbf4b80d91137b41c3011c21e966807",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-blake2s-64b-t2",
    "started_utc": "2026-10-23T10:30:26.123970+00:00",
    "finished_utc": "2026-10-23T10:30:26.620741+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3610490410064813,
        "stdout_sha256": "9f676c70e74993256866213176208f86a486aa3b0450ce7a704fa9a755b4dcbb",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-blake2s-64b-t3",
    "started_utc": "2026-10-23T10:30:47.423985+00:00",
    "finished_utc": "2026-10-23T10:30:47.925625+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3619812419929076,
        "stdout_sha256": "171fa91e9dd0e7c9ac25238e5838d408207c02f453c2156439b5510ecf015cad",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:30:20.120858+00:00",
    "finished_utc": "2026-10-23T10:30:25.869132+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.598787251015892,
        "stdout_sha256": "d9e19baec98a84c0a93098aca56a0e549d7c703d9a523c169cb2cb382dffc4cd",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-sha256-1kib-t2",
    "started_utc": "2026-10-23T10:30:34.516010+00:00",
    "finished_utc": "2026-10-23T10:30:40.338166+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.679367842996726,
        "stdout_sha256": "f0ee4f509bcb521fad2a644aa064265afeb73841c37a88773baa52fa2c518693",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-batch12-sha256-1kib-t3",
    "started_utc": "2026-10-23T10:31:00.847815+00:00",
    "finished_utc": "2026-10-23T10:31:07.006080+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-batch12",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 6.010832742991624,
        "stdout_sha256": "016d8b5480c606295ea3fd1b7d46015f83adbb9e45b26e614f37462e4dca7170",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:30:07.190570+00:00",
    "finished_utc": "2026-10-23T10:30:10.166172+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.835395542002516,
        "stdout_sha256": "1a6ca155093cc5ecfe586f636bc49c0dc7090d8e51b52f23c421affc00f87f84",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-1kib-t2",
    "started_utc": "2026-10-23T10:30:30.995390+00:00",
    "finished_utc": "2026-10-23T10:30:34.258051+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 3.122369399992749,
        "stdout_sha256": "96cc4dabd36f2ccaa3810ad24cc48042abcc269bc18809a8c7337df2ad03e0f3",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-1kib-t3",
    "started_utc": "2026-10-23T10:30:48.178567+00:00",
    "finished_utc": "2026-10-23T10:30:51.395807+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 3.061888750991784,
        "stdout_sha256": "9f3ce8ead7a1480a6119b3caa13b05b0363b52000ff002172b7c6cfb329ac2e0",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:30:05.578310+00:00",
    "finished_utc": "2026-10-23T10:30:06.118707+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3704878310090862,
        "stdout_sha256": "4a5499d363012a9781544f2e6066dc150eb3a5a546285962a962f68e51ae9dce",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-64b-t2",
    "started_utc": "2026-10-23T10:30:26.882975+00:00",
    "finished_utc": "2026-10-23T10:30:27.376782+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3543349569954444,
        "stdout_sha256": "7f61b882c28f5cc4ee8a366fb84376360e1a69ccfd604b7644883d971d5d3a10",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-blake2s-64b-t3",
    "started_utc": "2026-10-23T10:30:46.662620+00:00",
    "finished_utc": "2026-10-23T10:30:47.164612+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3609363629948348,
        "stdout_sha256": "128885c87d0bc67c632a54c07509662eecb2987ed8cba74e4915f77c4522ddb0",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:30:13.657971+00:00",
    "finished_utc": "2026-10-23T10:30:19.878175+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 6.068032923009014,
        "stdout_sha256": "230a0867d101a1b70110c34d8ff7f57e264d2d4bd528cb84cc05385cc396ab8e",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-sha256-1kib-t2",
    "started_utc": "2026-10-23T10:30:40.609377+00:00",
    "finished_utc": "2026-10-23T10:30:46.407633+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.646973002003506,
        "stdout_sha256": "73312c2cfcdff0b9d6cadb68a6fe011cb8cd249d0e7fc1ff8e4d9cfd1b465f03",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-abab-control-sha256-1kib-t3",
    "started_utc": "2026-10-23T10:30:54.947986+00:00",
    "finished_utc": "2026-10-23T10:31:00.600366+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.507466595998267,
        "stdout_sha256": "7dfe85a33c99efd192090a1b2c01ee6c078001548dc30571473bfaaa6a6e88ea",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:19:17.930765+00:00",
    "finished_utc": "2026-10-23T10:19:20.994302+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.9251177849946544,
        "stdout_sha256": "10bac62e0ddf5bdb0665f59a3d797c961a34fedb4e560cfe64cf3a35b859a317",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-1kib-t2",
    "started_utc": "2026-10-23T10:21:45.029837+00:00",
    "finished_utc": "2026-10-23T10:21:49.399449+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 4.1888957360060886,
        "stdout_sha256": "19b88000811d10dd35bc4120968f36c89581bdc0add85a7584ddfb27a5eadcb3",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-1kib-t3",
    "started_utc": "2026-10-23T10:21:56.647386+00:00",
    "finished_utc": "2026-10-23T10:21:59.946656+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 3.148116040014429,
        "stdout_sha256": "8e2881bacfe3d5a6e22345146bd93e3ded35d895a443827e989a025e292c045a",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:19:17.176982+00:00",
    "finished_utc": "2026-10-23T10:19:17.690768+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.35292209501494654,
        "stdout_sha256": "090d57ad3eae266ee929bf305db26b27154c02f7dafb32a4dadfb7669eaa6e70",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-64b-t2",
    "started_utc": "2026-10-23T10:21:43.901828+00:00",
    "finished_utc": "2026-10-23T10:21:44.727336+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.6123211509839166,
        "stdout_sha256": "0c53cc7834c739eb140e4519caf5387fb620243be27d8e87890915efbadba84b",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-blake2s-64b-t3",
    "started_utc": "2026-10-23T10:21:55.850957+00:00",
    "finished_utc": "2026-10-23T10:21:56.393591+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3821387529897038,
        "stdout_sha256": "6eb7bd1fc8e1d08d34341eded4d4ff9f58ba52a866d61665aa82e220303ae36d",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:19:21.237718+00:00",
    "finished_utc": "2026-10-23T10:19:26.949918+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.54058995100786,
        "stdout_sha256": "98eaaeea3c7a157cd4d05548bd437d02c1b5d63eadf300fa2f702d7af75c0450",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-sha256-1kib-t2",
    "started_utc": "2026-10-23T10:21:49.655982+00:00",
    "finished_utc": "2026-10-23T10:21:55.564565+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.754811176011572,
        "stdout_sha256": "9a825c937d624c57e2ef52b37571b365cc8cd5c8dcfada873c475b0dbfa11fe3",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-base-control-sha256-1kib-t3",
    "started_utc": "2026-10-23T10:22:00.238141+00:00",
    "finished_utc": "2026-10-23T10:22:06.651317+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/D-base-control",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 6.266626578988507,
        "stdout_sha256": "604b637ea13bbdd8c205a821165126eab51fc251331d89750657e9182e5d1a6f",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-app-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:28:39.592491+00:00",
    "finished_utc": "2026-10-23T10:29:14.123571+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "blake2s-1kib",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 34.260915916995145,
        "stdout_sha256": "8cd5efb03246f3e208161140feaac62cfd7ebf503de7f1fd5c5ff8e653ab190c",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-app-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:28:11.317631+00:00",
    "finished_utc": "2026-10-23T10:28:39.142169+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "blake2s-64b",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 27.66673186799744,
        "stdout_sha256": "949ccb88306f362c981d2aa7a7f44627810e2b6e1c9fe3c5415a646dc3b1f61a",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-app-build-t1",
    "started_utc": "2026-10-23T10:27:45.244377+00:00",
    "finished_utc": "2026-10-23T10:28:11.083002+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "build",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "--example",
      "application_tree"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 25.541997190011898,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stderr_sha256": "55a2a37b49efa19660c28bc65a3fcea114fe2202573086aba718d0cdfe790116",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-app-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:29:14.371630+00:00",
    "finished_utc": "2026-10-23T10:29:53.677761+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "sha256-1kib",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 39.153731291007716,
        "stdout_sha256": "dc441beac26edf682f21e90ff45d1675232bc240bb18bd835e7208ee48560542",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:20:36.848324+00:00",
    "finished_utc": "2026-10-23T10:20:39.911793+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 2.919671414012555,
        "stdout_sha256": "6e61532413835acbb345d0c26b992f1149459525722f1c6d6ff9125d897ef18d",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-1kib-t2",
    "started_utc": "2026-10-23T10:21:15.035448+00:00",
    "finished_utc": "2026-10-23T10:21:18.190450+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 3.0103189049987122,
        "stdout_sha256": "63ada6d90fb5ce286787c678958846a588f6a5d5be4f9974e472c37cb170cfc7",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-1kib-t3",
    "started_utc": "2026-10-23T10:21:25.207616+00:00",
    "finished_utc": "2026-10-23T10:21:28.516604+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 3.159103612008039,
        "stdout_sha256": "59c686ec722e5e2e74492a2fc24684fe4cfe5f495cd037b41d556847c44d0c2f",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:20:36.226420+00:00",
    "finished_utc": "2026-10-23T10:20:36.599547+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.24511374800931662,
        "stdout_sha256": "5d1c6e2ba744261c196dd11a34e247700b0de51d1684a413bbfad8c4bc65d73f",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-64b-t2",
    "started_utc": "2026-10-23T10:21:14.185022+00:00",
    "finished_utc": "2026-10-23T10:21:14.733811+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.38493047800147906,
        "stdout_sha256": "3dab9de749a7eed0530d1ff5b72515400e4135c0bf966ea39c706551a4c3c970",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-blake2s-64b-t3",
    "started_utc": "2026-10-23T10:21:24.444376+00:00",
    "finished_utc": "2026-10-23T10:21:24.949243+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "blake2s-64b"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 0.3630089040088933,
        "stdout_sha256": "de03e7bfe8011318ef52457b3a92f467d1ec6cae4cf4ca03821cf235d79771b7",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-build-t1",
    "started_utc": "2026-10-23T10:19:55.027219+00:00",
    "finished_utc": "2026-10-23T10:20:13.723468+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "build",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "--example",
      "d_native_profile"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 18.45729713299079,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stderr_sha256": "71c217495f72f02ec3a439159e1fb3472f6471fdf2a307d937d6ba6553ad7b58",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-clippy-t1",
    "started_utc": "2026-10-23T10:27:22.304071+00:00",
    "finished_utc": "2026-10-23T10:27:44.896649+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "clippy",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "-p",
      "rec_aggregation",
      "--all-targets",
      "--",
      "-D",
      "warnings"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 22.36974756998825,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stderr_sha256": "d1e23a203aec176647105ef9b4c8f5ffe7b8042a01a6ab1f3a1b0c4a534f2eba",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-doc-tests-t1",
    "started_utc": "2026-10-23T10:27:09.912920+00:00",
    "finished_utc": "2026-10-23T10:27:21.952012+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "test",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "-p",
      "rec_aggregation",
      "--doc"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 11.79942259399104,
        "stdout_sha256": "d38e6ea6d69ddb377e4a4380b22926f3864806998a850d5e28c8459dfc09f014",
        "stderr_sha256": "11c24f8b56769198f4802b97229c53377f88c3f91422e1a449185dbede5426ec",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-release-gates-t1",
    "started_utc": "2026-10-23T10:23:31.674000+00:00",
    "finished_utc": "2026-10-23T10:26:59.700873+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "test",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "-p",
      "rec_aggregation",
      "--lib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 207.642816890002,
        "stdout_sha256": "4df87132efb11dbb3417fd3976b78eeaf71ff25282ad40886eca61a7d24fa8bb",
        "stderr_sha256": "f3fa5e9e6a147cbc5bf882c7d23f669b6636dc931a4ee8a2ef5989ff1db8edfb",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:20:40.157643+00:00",
    "finished_utc": "2026-10-23T10:20:45.590736+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.283645554998657,
        "stdout_sha256": "3f671e9289e81de01c75564ecaa5041b30432b7376799ea1f64020c3d726565a",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-sha256-1kib-t2",
    "started_utc": "2026-10-23T10:21:18.447244+00:00",
    "finished_utc": "2026-10-23T10:21:24.178440+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 5.601573074993212,
        "stdout_sha256": "e098997394cbcd6d19c88a54847f3e11d6f738198e71edfa48b555e10ea0d38b",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-sha256-1kib-t3",
    "started_utc": "2026-10-23T10:21:28.800442+00:00",
    "finished_utc": "2026-10-23T10:21:38.049229+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/d_native_profile",
      "sha256-1kib"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 9.07043396201334,
        "stdout_sha256": "a5744463adc890385944b682feba72e448720a99d86f74f38d31c0c416ed377c",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-batch12-targeted-t1",
    "started_utc": "2026-10-23T10:22:38.442672+00:00",
    "finished_utc": "2026-10-23T10:23:11.524947+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 382,
    "command": [
      "/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin/cargo",
      "test",
      "--locked",
      "--release",
      "-p",
      "format_recursion",
      "--lib",
      "batched_field_evaluations_preserve_transcript_and_claim_order"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 32.82485855100094,
        "stdout_sha256": "377a4c08070fd2e6606090174a607ffee02c9c244ef5f63fd4d7d6d8b790b86b",
        "stderr_sha256": "f061d992c2ad1ade76d68f83fe20cfd5c4b6886f746d36f0b26de9719a8c0dd6",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-control-blake2s-64b-t1",
    "started_utc": "2026-10-23T10:14:16.630043+00:00",
    "finished_utc": "2026-10-23T10:14:53.741594+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "blake2s-64b",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 36.94539246999193,
        "stdout_sha256": "c0722e472ac76015919d90022358fc482496528dd2d2a48152594e7cfb18692e",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-control-blake2s-1kib-t1",
    "started_utc": "2026-10-23T10:14:54.048940+00:00",
    "finished_utc": "2026-10-23T10:15:55.088649+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "blake2s-1kib",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 60.840021993994014,
        "stdout_sha256": "56fa6403285f815807d4bebb8ac90bc6f40ed10bd492598beca564d0738945d3",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  },
  {
    "receipt": "D-control-sha256-1kib-t1",
    "started_utc": "2026-10-23T10:15:55.387642+00:00",
    "finished_utc": "2026-10-23T10:17:03.531815+00:00",
    "ok": true,
    "files_unchanged": true,
    "before_after_manifests_equal": true,
    "manifest_entries": 381,
    "command": [
      "/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/lane-D/target/release/examples/application_tree",
      "--workload",
      "sha256-1kib",
      "--samples",
      "1",
      "--seed",
      "20261023"
    ],
    "runs": [
      {
        "run": "run-00",
        "ok": true,
        "returncode": 0,
        "wall_seconds": 67.95470863999799,
        "stdout_sha256": "f0595af8acbd03ce14a7eac1a5569d46cadfdb7302246cde1910e9b07dfaefca",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hashes_match": true
      }
    ]
  }
]
```

VERDICT: CLEAN
