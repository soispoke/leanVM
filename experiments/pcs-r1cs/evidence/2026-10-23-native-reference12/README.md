# Native recursion reference at 12 pinned threads

Measured pushed commit `8715195359dee5cc52a54bd8ef72580d45286581`. Every timed executable ran on CPUs 0-11 with `LEANVM_NUM_THREADS=12`, `RAYON_NUM_THREADS=12` and `CARGO_BUILD_JOBS=12`. All 24 receipts report unchanged sources and a clean measured commit. This is one quick run per workload/role under shared-host contention, with no medians or stable speedup claim. Historical unpinned matrix commands were not rerun.

Wallet, mempool verification and each merge run in separate processes. Wallet time to mempool-ready proof is native witness trace construction plus native proof creation plus certificate encoding. Fixtures and independent reference evaluation, trusted setup and explicit proof verification are outside this total. All certificates include the 36-byte height/statement header. Peak RAM is the entire role process high-water mark, including trusted setup; it is not an isolated proof-stage allocation measurement. Setup should be precomputed for deployment and is reported separately here.

|Workload|Wallet total, s|Certificate bytes|Wallet peak, GiB|Mempool decode + verify, ms|
|---|---:|---:|---:|---:|
|blake2s-64b|0.106|247,956|0.33|5.209|
|blake2s-1kib|1.307|323,356|3.89|6.969|
|sha256-1kib|2.620|347,036|8.17|6.829|
|keccak256-1KiB|2.703|346,652|7.84|6.852|
|shielded-transfer|12.428|385,204|30.00|8.378|
|falcon512|15.104|384,756|33.06|12.522|

Aggregator leaf merge combines two height-zero certificates. The height-two node measurement combines a height-one node with a height-zero leaf, matching the existing mixed-height application_tree workload. It reuses the historical second leaf and previous root; it is not a batch of fresh clients or a measurement of two height-one children. Merge timing retains child admission, node recording, witness lowering and complete proving. Verification and encoding are separate. These per-relation split keys do not establish heterogeneous application merging.

|Workload|Leaf merge, s|Mixed-height node merge, s|Leaf root bytes|Node root bytes|Leaf root verify, ms|Merge peak, GiB|
|---|---:|---:|---:|---:|---:|---:|
|blake2s-64b|3.387|3.401|361,196|360,524|6.318|8.98|
|blake2s-1kib|4.884|5.019|355,980|354,732|6.795|14.33|
|sha256-1kib|5.150|4.909|354,668|354,796|6.799|16.43|
|keccak256-1KiB|4.854|5.413|354,316|355,564|8.186|16.29|
|shielded-transfer|5.873|6.467|356,012|354,668|6.823|34.36|
|falcon512|4.236|4.322|353,612|356,044|7.414|34.18|

Setup timings include application construction, the canonical reference trace and key preprocessing. Split setup includes its real base bootstrap proof and node-key preprocessing. Each merge process reconstructs that setup outside the merge timer. These are cold process observations, not costs to charge to every transaction.

|Workload|Native wallet setup, s|Split setup in first-merge process, s|
|---|---:|---:|
|blake2s-64b|0.090|5.305|
|blake2s-1kib|1.408|8.225|
|sha256-1kib|2.768|10.816|
|keccak256-1KiB|12.451|21.061|
|shielded-transfer|13.896|40.637|
|falcon512|17.222|35.255|

All six wallet certificates were decoded and natively verified in separate processes with independently reconstructed trusted application keys/claims. All twelve merge outputs verify. All eighteen newly encoded certificates match the exact already-verified historical certificate bytes, not only their lengths or digests. The retained default graphs and shapes therefore remain compatible for these workloads. `invariants.json` records the byte lengths and BLAKE2s digests. Historical proof files were read, not regenerated.

Every JSON measurement printed by the profiler includes the actual pool size and Linux CPU mask. The supervisor also checked every observed binary thread's affinity mask. One-second process CPU samples peaked at 1210.1% over 388 intervals, slightly above the nominal 1200% observation threshold. Every observed binary thread had the required 0-11 affinity and the pool reported 12 threads. Accounting quantization and the offset between scanning process statistics and sampling the clock can affect this short-interval estimate. The raw observation is preserved; no strict sampled peak below 1200% is claimed. Tiny roles can complete without a CPU sample. `cpu-observations.jsonl` preserves the sample counts and scope.

`matched.jsonl` contains the lane A records also atomically appended under a file lock to the shared parent `artifacts/matched-12t.jsonl`. `measurements.json` retains source role events, shapes and keys. Raw receipts and compressed logs are preserved under `receipts/`; compressed-log contents were checked against raw receipt hashes. `archive-manifest.json` records stored-file hashes. The exact matrix driver is preserved as text. No proof-system optimization, circuit-policy default or verifier check changes as part of these measurements.
