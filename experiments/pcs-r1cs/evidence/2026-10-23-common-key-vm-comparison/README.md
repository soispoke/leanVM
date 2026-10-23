# Matched common-key native and leanVM comparison

One setup/program/key per backend, reused for all leaves, internal nodes and measured depths. The keys belong to different proof systems; they are not literally the same cryptographic key. Both backends prove the same ordered tagged hash-chain statements and bounded 32-bit height relation. These chain16 fixtures are not application proofs, shielded transfers or EIP-8288 dependency-list aggregates.

Three alternating fresh-process pairs at each of 2, 4 and 8 leaves, with 32 workers and CPUs 0-63. Each process creates and explicitly verifies every certificate, then rejects a changed root statement and height. Native is the accepted hybrid-opening implementation with the unchanged native circuit; no new native optimization is retained here. VM uses its canonical recursive verifier and fresh-plus-carried deferred-claim batching, rather than forwarding an increasing list of older keys.

## Complete measurements

Each cell is an independent median over three trials. Do not add independently computed medians to reconstruct another column. Creation includes child prechecks, recording/hints, witness preparation and proving. Process total includes setup, all creation, explicit checks and serialization/reporting. Timed tree construction is sequential across nodes, with parallelism inside each proof. This is not an optimized tree scheduler.

| Leaves | Backend | Process total (s) | Setup (s) | All creation (s) | Leaf creation (s) | Internal-node creation (s) | Root creation (s) |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | leanR1CS native | 7.574 | 2.745 | 4.586 | 3.293 | 1.308 | 1.308 |
| 2 | leanVM | 2.584 | 0.863 | 1.515 | 0.276 | 1.236 | 1.236 |
| 4 | leanR1CS native | 12.760 | 2.732 | 9.766 | 5.828 | 3.950 | 1.310 |
| 4 | leanVM | 4.735 | 0.876 | 3.546 | 0.535 | 2.997 | 0.966 |
| 8 | leanR1CS native | 23.109 | 2.838 | 19.890 | 11.075 | 8.815 | 1.266 |
| 8 | leanVM | 8.493 | 0.842 | 7.284 | 0.942 | 6.332 | 0.860 |

| Leaves | Backend | Complete root verification (ms) | Root bytes | All certificate bytes | Sampled peak RSS (GiB) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 2 | leanR1CS native | 6.215 | 329,852 | 992,564 | 6.883 |
| 2 | leanVM | 12.618 | 297,164 | 736,004 | 2.181 |
| 4 | leanR1CS native | 6.558 | 329,564 | 2,312,868 | 6.918 |
| 4 | leanVM | 13.057 | 317,276 | 1,790,532 | 2.822 |
| 8 | leanR1CS native | 6.219 | 330,044 | 4,957,604 | 6.891 |
| 8 | leanVM | 13.129 | 317,020 | 3,898,436 | 2.736 |

## Who pays, and relevance to EIP-8288

The benchmark starts from raw hash-chain inputs. A leaf is the base computation together with the proof produced for it; it is not an already available client proof. In an application flow, the client normally produces the original application proof before submission. An aggregator verifies or wraps direct proof dependencies and merges existing aggregates. The current hash-chain leaf does not measure that wrapping operation.

Consequently, leaf creation and setup-inclusive tree total are useful end-to-end engineering measurements, not a charge the builder necessarily repeats. Internal-node creation measures the seven merges of an eight-leaf tree. Root creation measures its final two-to-one merge and is included in that seven-merge sum. Those are more relevant proxies when child proofs already exist, although they still omit real dependency-list merging, deduplication and discards. Root verification is complete Rust consumer verification, including VM deferred polynomial discharge; it is not the compiled Lean verifier used by the recursion.fast design.

At eight leaves, native spends about 11.075 s creating the eight base proofs and 8.815 s on the seven merges; VM spends 0.942 s and 6.332 s respectively. The final merge is 1.266 s native and 0.860 s VM. Native verifies the root more quickly, but its complete root certificate is larger. These observations establish an engineering gap for this fixture, not a universal ranking for real application workloads.

EIP-8288 specifies body-level dependency triples and a fixed aggregate verification key. A proposed circuit-claim lane additionally needs authenticated circuit identity/availability and a specified claim interface. This benchmark does not implement those links. The current EIP draft reserves generic leanSTARK dependencies until their digest is defined. Its 1,000 ms aggregation interval motivates incremental aggregation latency; the setup-inclusive synthetic tree total is not that operating measurement.

The pinned recursion.fast design scores 256 leaves of 16,384 steps plus 255 aggregation nodes, with build/setup excluded and a separate fresh-process root-step column. These local chain16 trees use in-process root timings and are not an official score. The Flock tower remains a different workload and is not mixed into this paired table.

## Adapter and validation

The VM adapter extracts the existing canonical verifier and aggregate_claims implementation without changing their logic, adds exact tagged chain/node hashing, and compiles the resulting program to a fixed point on its bytecode size. The seed naming that program is authenticated through each public statement and pinned by the consumer. A runtime leaf branch skips child verification. Each parent verifies two proofs of this same program and batches both fresh and carried claims into one claim per fixed polynomial; only points are transmitted and the consumer recomputes their values.

The guest constrains height = 1 + max(child heights), binds all heights to 32 bits, and rejects overflow. Its independent integer-reference test covers both child orders, carries, 32-bit boundaries, overflow, changed successors and values outside 32 bits. Actual proofs cover leaf, node, repeated composition and mixed-height composition through height three. Consumer and guest-witness tests reject malformed wire, trailing/truncated/oversized bytes, changed height, statement, stream, deferred points, foreign keys, child metadata and carried-claim hints.

The full rec_aggregation release library suite passes: 43 passed and 5 pre-existing ignored tests. Clippy with library/tests/examples and warnings denied, strict rustdoc, formatting and release example build pass. No Lean source changed; these checks do not prove knowledge soundness. The native/Flock/PCS composition, recursive extractor/security loss, real application wrapping and official recursion.fast integration remain open.

The independent audit checks 18 serial timed processes and 150 locally verified certificates, recomputes all statements with Python hashlib, checks stable keys and per-position certificate digests/geometry within each backend across repeated runs, verifies exact source/build/binary identity, and rejects overlapping admitted timing intervals. Keys and program shapes remain stable across depths. VM runtime layouts vary with execution, while the native R1CS shape is fixed. The native source under crates/ is unchanged between control-v6's base and the publication base.

## Provenance and reproduction

Yukon was checked against upstream and pinned clean at ca11688397f1a44d4d55f7fd4f4eeec092ea4a93. Runner SHA256: ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. Rust 1.99.1, native CPU plus pclmulqdq, four Cargo jobs, 32 prover workers, CPUs 0-63. VM witness WHIR rate is 1/2; native retains its accepted rate-1/2 witness and rate-1/16 fixed-index settings. Both retain their existing production security parameters and distinct protocol assumptions.

Build/test budget 96 GiB; timed jobs 16 GiB; host reserve 40 GiB. The shared Xeon Gold 6230R is not a dedicated machine; an unrelated single-process generator search was observed during part of the run. RSS is sampled process-group memory, not cgroup isolation. Three pairs provide descriptive medians; no official ranking or isolated-machine record is claimed.

The archive preserves exact commands, all 18 raw timed receipts/stdout/stderr, final gates, earlier successful targeted/build checks, format-mutation receipts, source and binary hashes, measured sources, the predeclared plan and the Yukon runner bytes. The initial format receipts have ok=false because formatting intentionally changed bound source. No timed observation was excluded. Executables and compiler caches are excluded.

Reproduce through current Yukon: build common_chain_tree_vm with the recorded flags in an isolated target directory, freeze the executable, and run --depth 1/2/3 --chain 16 against the accepted native closed_tree in the recorded alternating order. common-comparison.py documents the original absolute paths and audit. Each backend must reuse its own one setup/key at every level. Run verify-archive.py to independently check archive member hashes without extraction.

The performance goal remains active. This comparison supplies a matched baseline and does not mark the native construction or EIP-8288 integration complete.
