# Split native application closure: quick matrix

Resource label: the earlier quick matrix ran unpinned across all 64 available logical CPUs, with the prior 32-thread prover environment. These historical measurements were not rerun for the resource-policy change. New lane A timed runs use CPUs 0 through 15 with 16 prover threads; builds and gates use CPUs 32 through 47. The later application-role screens used their separately documented 12-thread CPU slice.

Single-run development observations, sample 0 leaf 0; not matched trials or medians; no new security or Ethereum acceptance claim. Native client total adds trace construction and proof creation. Each independent verifier reconstructs setup and checks two base plus three successive mixed-height node certificates. Later heights reuse one leaf. Historical and native base proof systems and identity namespaces differ.

All receipt directories below are relative to `/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/`. Their result JSON and gzip-compressed stdout/stderr are archived under `receipts/` (decompressed log bytes retain their original receipt hashes); `matrix.json` records original paths and SHA256 values. Each row selects sample 0, leaf 0, and its first (height-1) merge. The second leaf and later mixed-height merges are functional exercises, not repeats used for a median.

| Workload | Historical proof s | Historical adaptation s | Native trace s | Native proof s | Native client total s | First merge s | Base bytes | Root bytes | Root verify ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| blake2s-64b | 0.088 | 5.959 | 0.005 | 0.125 | 0.130 | 4.086 | 247956 | 361196 | 6.526 |
| blake2s-1kib | 1.050 | 6.344 | 0.124 | 1.520 | 1.645 | 6.010 | 323356 | 355980 | 7.385 |
| sha256-1kib | 1.955 | 7.694 | 0.259 | 2.991 | 3.250 | 5.760 | 347036 | 354668 | 6.671 |
| keccak256-1kib | 1.855 | 5.248 | 0.313 | 2.690 | 3.003 | 5.396 | 346652 | 354316 | 6.489 |
| mpt | 14.932 | 5.742 | 1.346 | 12.425 | 13.772 | 5.926 | 386356 | 353740 | 6.763 |
| shielded | 6.709 | 5.548 | 1.028 | 12.171 | 13.200 | 6.003 | 385204 | 356012 | 6.989 |
| falcon512 | 6.607 | 5.261 | 1.064 | 10.925 | 11.988 | 6.158 | 384756 | 353612 | 7.121 |

Native base adaptation is zero in every row. No quotient application proof is created in the new harness. Setup contains a canonical base proof and is separately reported. The historical baseline uses a different proof system and application-identity namespace; this is an architecture comparison, not a matched compiler optimization trial. Shielded transfer is slower in this quick sample; Falcon is approximately level.

The historical direct leanVM BLAKE2s client measurements are 73.290 ms (64 B) and 48.354 ms (1 KiB), seed 20261024, from the already completed direct-VM receipts referenced in the handoff. No rerun was made. Direct VM execution uses a hash opcode; the native application harness here expands full-adder computations. A complete direct leanVM matrix and Ethereum-ready comparison are not established by this experiment.

MPT initially failed native setup. The capacity diagnostic established 26,639,333 arithmetic rows above the unchanged 2^24 cap. The final MPT harness uses static output liveness for circuits with at least 2^23 Boolean rows; its base has native log_rows=24, public_len=162 and 39 compression blocks. Other matrix graphs are unchanged by that specialization. See `CLOSED.md` for transcript acceptance-check and compression-cap changes affecting existing symbolic-verifier circuit keys.

Examples (always assign a fresh receipt and certificate directory):

```sh
python3 ../run-application-command.py application-closure NEW_RECEIPT cargo run --locked --release -p format_recursion --example application_tree -- --workload blake2s-64b --samples 1 --out ../artifacts/NEW_CERTIFICATES
python3 ../run-application-command.py application-closure NEW_VERIFY_RECEIPT cargo run --locked --release -p format_recursion --example application_tree -- --workload blake2s-64b --samples 1 --verify ../artifacts/NEW_CERTIFICATES
```

Do not rerun the completed receipt names in this archive. These commands document the interface, not a request to repeat this matrix.

No formal composition proof, zero knowledge property, Ethereum verifier acceptance or production wallet readiness is claimed.

Final gates: `application-split-fmt-check-gate-t1`, `application-split-clippy-gate-t1`, `application-split-release-gates-t2`, and `application-native-adder-check-t3` all passed with unchanged sources. The release suite ran 79 format_recursion and 43 rec_aggregation tests (5 ignored), plus doc tests. `git diff --check` passed. Raw gate receipts are archived alongside the measurements.
