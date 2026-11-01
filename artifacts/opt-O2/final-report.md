# O2: fewer Keccak calls and committed words

Started 2026-10-23 23:34 UTC; stop deadline 2026-10-24 02:34 UTC. Worktree `opt-O2`, branch `opt/O2`, control `9e5f41c4`. No push. O4 integrates. This is a bounded optimization experiment, not an eligible Challenge score or a demonstrated one-arrival-per-second cadence.

Timed runs use cores 24–35 and `RAYON_NUM_THREADS=12 LEANVM_NUM_THREADS=12`; builds/tests use 48–63 and four Cargo jobs. Each ABAB3 is six samples per variant, against immutable original control binaries. Raw stdout/stderr, per-process receipts, SHA-256 provenance and medians are under the named receipt directory in `artifacts/opt-O2/`. Measurements are appended to `artifacts/hometurf-12t.jsonl`. Prior trial numbers are context, not matched controls.

## Best measured profiles

Best observed first median: **1.415160 s**, compact profile `aa1d59a1` (8,388,608 words). Best observed node median: **2.674808 s**, q-first profile `cb891af8` (14,680,064 words). These were measured in separate original-control ABAB3 runs; no incremental latency comparison is claimed. Q-first has the smallest measured first commitment: 7,340,032 words at 1.707962 s. The <=1 s and sustained-cadence goals remain unmet.

## Hash census

| Purpose | First control | Node control |
|---|---:|---:|
| WHIR Merkle paths | 5608 | 8868 |
| WHIR leaves | 1394 | 1556 |
| Opening remainder / transcript | 306 | 668 |
| Flock reduction | 560 | 630 |
| Final limb-range bridge | 1562 | 2156 |
| Other transcript / claim / identity / fold | 378 | 411 |
| Total | 9808 | 14289 |

The control expands pruned native multiproofs into full paths and recursively hashes each query separately: 390 query paths first, 444 node. Detailed per-phase, depth, query-count and word-count labels are in `census-first.json` and `census-node.json`; compact summaries and the soundness notes are also committed under `opt-O2/artifacts/opt-O2/`. Path hashing dominates. Native wire deduplication alone does not reduce recursive hashes.

## Locally committed candidates

- `e9164faa`: binary upper cap, explicit binding of every upper sibling, fixed-shape occupancy, purpose census, constrained subfield inference. Accepted for first-level latency; rejected for node latency/words.
- `41e98b89`: tighter first-wrapper dimensions; inactive mismatched routes are constrained inactive, active mismatches reject. Measured mixed depth-two layout only.
- `28387d02`: actual four-child WHIR commitments, native octopus encoding, raw paths, recursive routing, and setup-key arity domain together. This is the integrated implementation, beyond the old isolated hash-call screen.
- `aa1d59a1`: smaller cap and 20/20 first wrapper. Accepted first/node ABAB3: 1.415160/2.837498 s; 8,388,608/16,777,216 committed words. Best observed first latency profile is `keccak-route-compact`.
- `3c3ae330`: deterministic source-ID aliases for native hash port columns; 65/65 tests and Clippy pass. Its original-control ABAB3 is complete below; no incremental speedup over compact is claimed.
- `cb891af8`: q-first dense joint stack; 65/65 tests and Clippy pass. Physical offsets are checked by direct verifier mutation tests.
- `3fabb9c2`: canonicality checks after the Boolean sibling-routing permutation, removing redundant fallback limb-typing permutations. Matched wins at both levels; all tables below are complete. Soundness note: `canonical-route-soundness.md`.
- `ba49591f`: shared quaternary cap, tighter 21/21 first/node wrappers, and optional `keccak-quad-cap-fast` occupancy kernel / canonical sibling aliases. Formatting is `27bdc7b3`; soundness note is `909e6ae3`.

All variants are opt-in features. Use `format_recursion/keccak-route-compact` for the current committed best latency profile. Bare canonical routing has fewer calls but a larger first commitment. Source-ID aliases and q-first are separately selectable committed profiles; their tables below use their own matched controls. Do not infer an incremental win from tables measured at different times. Quaternary native trees change wallet proofs, so wallet timings and byte growth must be considered.

## Matched measurements

Each table shows medians, A = original control, B = named candidate. Calls count Keccak permutations, words count committed words. Core verification excludes external decoding; it is not by itself proof of the full admission gate.

### Binary cap: first (`cap4-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.295200 | 2.379045 |
| Calls | 9,808 | 7,706 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 999,496 | 1,133,098 |
| Proof bytes | 206,192 | 198,752 |
| Core verify ms | 10.139606 | 8.947597 |
| Complete root ms | 30.128066 | 26.111317 |

Matched latency reduction: 44.6%.

### Binary cap: node (`cap4-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.273276 | 5.540751 |
| Calls | 14,289 | 11,941 |
| Committed words | 33,554,432 | 33,554,432 |
| Rows | 1,139,668 | 1,295,124 |
| Proof bytes | 205,552 | 206,320 |
| Core verify ms | 9.596514 | 11.866993 |
| Complete root ms | 50.571151 | 51.558075 |

Matched latency reduction: -5.1%.

### Tighter first wrapper: node (`tight-fixed-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 6.251393 | 5.367997 |
| Calls | 14,289 | 11,388 |
| Committed words | 33,554,432 | 33,554,432 |
| Rows | 1,139,668 | 1,274,973 |
| Proof bytes | 205,552 | 206,416 |
| Core verify ms | 10.174126 | 11.931539 |
| Complete root ms | 56.482794 | 60.700506 |

Matched latency reduction: 14.1%.

### Actual arity four: first (`quad2-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.119516 | 2.498041 |
| Calls | 9,808 | 6,835 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 999,496 | 1,076,468 |
| Proof bytes | 206,192 | 241,504 |
| Core verify ms | 9.490010 | 9.032397 |
| Complete root ms | 28.226872 | 27.362327 |

Matched latency reduction: 39.4%.

Wallet medians (shielded / Merkle child): A 0.248428 s (151472 bytes) / 0.079354 s (134536 bytes); B 0.213964 s (178872 bytes) / 0.075720 s (150816 bytes); 

### Actual arity four: node (`quad2-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.328834 | 5.110171 |
| Calls | 14,289 | 9,950 |
| Committed words | 33,554,432 | 33,554,432 |
| Rows | 1,139,668 | 1,262,064 |
| Proof bytes | 205,552 | 250,992 |
| Core verify ms | 9.788447 | 9.652353 |
| Complete root ms | 48.360173 | 46.019307 |

Matched latency reduction: 4.1%.

### Shared quaternary cap: first (`quadcap-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.212402 | 2.422531 |
| Calls | 9,808 | 5,073 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 999,496 | 1,593,080 |
| Proof bytes | 206,192 | 242,224 |
| Core verify ms | 9.737081 | 8.992786 |
| Complete root ms | 27.978853 | 28.765331 |

Matched latency reduction: 42.5%.

### Shared quaternary cap: node (`quadcap-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.763412 | 3.268442 |
| Calls | 14,289 | 7,521 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,783,481 |
| Proof bytes | 205,552 | 240,688 |
| Core verify ms | 9.709269 | 10.213448 |
| Complete root ms | 50.667759 | 51.801328 |

Matched latency reduction: 43.3%.

### Fast shared quaternary cap: first (`quadcap-fast-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 3.874456 | 2.281856 |
| Calls | 9,808 | 4,574 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 999,496 | 1,277,222 |
| Proof bytes | 206,192 | 238,952 |
| Core verify ms | 10.095149 | 8.392049 |
| Complete root ms | 27.238944 | 24.515489 |

Matched latency reduction: 41.1%.

Wallet medians (shielded / Merkle child): A 0.224060 s (151472 bytes) / 0.074636 s (134536 bytes); B 0.216190 s (176568 bytes) / 0.072005 s (150720 bytes); 

### Fast shared quaternary cap: node (`quadcap-fast-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.500950 | 3.148392 |
| Calls | 14,289 | 6,966 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,451,237 |
| Proof bytes | 205,552 | 239,728 |
| Core verify ms | 10.498805 | 10.983411 |
| Complete root ms | 50.270855 | 48.660899 |

Matched latency reduction: 42.8%.

### Source-ID port aliases: first (`route-alias-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.336800 | 1.539672 |
| Calls | 9,808 | 3,923 |
| Committed words | 33,554,432 | 8,388,608 |
| Rows | 999,496 | 1,148,228 |
| Proof bytes | 206,192 | 216,256 |
| Core verify ms | 9.953352 | 8.028159 |
| Complete root ms | 30.871122 | 24.322560 |

Matched latency reduction: 64.5%.

Wallet medians (shielded / Merkle child): A 0.236449 s (151472 bytes) / 0.079340 s (134536 bytes); B 0.241250 s (178008 bytes) / 0.065546 s (150440 bytes); 

### Source-ID port aliases: node (`route-alias-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.469977 | 2.862938 |
| Calls | 14,289 | 5,074 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,292,613 |
| Proof bytes | 205,552 | 241,360 |
| Core verify ms | 10.497554 | 8.884483 |
| Complete root ms | 55.859291 | 38.109241 |

Matched latency reduction: 47.7%.

### Dense joint stack: first (`route-qfirst-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.462881 | 1.707962 |
| Calls | 9,808 | 3,811 |
| Committed words | 33,554,432 | 7,340,032 |
| Rows | 999,496 | 1,150,027 |
| Proof bytes | 206,192 | 209,184 |
| Core verify ms | 9.760647 | 9.423997 |
| Complete root ms | 31.806355 | 26.881195 |

Matched latency reduction: 61.7%.

Wallet medians (shielded / Merkle child): A 0.252511 s (151472 bytes) / 0.076521 s (134536 bytes); B 0.239820 s (178008 bytes) / 0.067032 s (128112 bytes); 

### Dense joint stack: node (`route-qfirst-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.941840 | 2.674808 |
| Calls | 14,289 | 5,074 |
| Committed words | 33,554,432 | 14,680,064 |
| Rows | 1,139,668 | 1,294,195 |
| Proof bytes | 205,552 | 234,192 |
| Core verify ms | 9.336030 | 9.329467 |
| Complete root ms | 49.241630 | 37.792919 |

Matched latency reduction: 45.9%.

### Canonical sibling routing: first (`canonical-route-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 3.951469 | 1.919764 |
| Calls | 9,808 | 3,736 |
| Committed words | 33,554,432 | 12,582,912 |
| Rows | 999,496 | 1,273,732 |
| Proof bytes | 206,192 | 226,544 |
| Core verify ms | 8.904117 | 8.773664 |
| Complete root ms | 28.572392 | 25.114308 |

Matched latency reduction: 51.4%.

Wallet medians (shielded / Merkle child): A 0.249356 s (151472 bytes) / 0.085751 s (134536 bytes); B 0.224779 s (176568 bytes) / 0.074849 s (150720 bytes); 

### Canonical sibling routing: node (`canonical-route-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.918154 | 2.989907 |
| Calls | 14,289 | 5,503 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,447,797 |
| Proof bytes | 205,552 | 240,784 |
| Core verify ms | 9.078512 | 8.387846 |
| Complete root ms | 47.874395 | 48.266247 |

Matched latency reduction: 39.2%.

### Canonical routing with compact cap: first (`route-compact-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 3.965698 | 1.415160 |
| Calls | 9,808 | 3,923 |
| Committed words | 33,554,432 | 8,388,608 |
| Rows | 999,496 | 1,148,228 |
| Proof bytes | 206,192 | 215,200 |
| Core verify ms | 9.186859 | 11.444031 |
| Complete root ms | 27.375426 | 23.232416 |

Matched latency reduction: 64.3%.

Wallet medians (shielded / Merkle child): A 0.232694 s (151472 bytes) / 0.078989 s (134536 bytes); B 0.214927 s (176568 bytes) / 0.070341 s (150720 bytes); 

### Canonical routing with compact cap: node (`route-compact-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.366619 | 2.837498 |
| Calls | 14,289 | 5,074 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,292,613 |
| Proof bytes | 205,552 | 240,304 |
| Core verify ms | 11.740093 | 8.441968 |
| Complete root ms | 53.137747 | 43.143585 |

Matched latency reduction: 47.1%.

### Native skipped intermediate levels (not adopted): first (`quad-native-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 4.299449 | 2.377206 |
| Calls | 9,808 | 4,574 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 999,496 | 1,277,222 |
| Proof bytes | 206,192 | 238,952 |
| Core verify ms | 9.834673 | 8.828941 |
| Complete root ms | 27.549506 | 26.139271 |

Matched latency reduction: 44.7%.

### Native skipped intermediate levels (not adopted): node (`quad-native-abab`)

| Metric | A | B |
|---|---:|---:|
| Merge s | 5.294959 | 3.091358 |
| Calls | 14,289 | 6,966 |
| Committed words | 33,554,432 | 16,777,216 |
| Rows | 1,139,668 | 1,451,237 |
| Proof bytes | 205,552 | 239,728 |
| Core verify ms | 9.070617 | 9.564552 |
| Complete root ms | 48.107692 | 56.490519 |

Matched latency reduction: 41.6%.

## Rejected and superseded screens

F64 inference: first control/candidate 4.501586/4.550159 s, calls 9808/9145, words unchanged 33,554,432. Node 5.168737/5.443371 s, calls 14289/13553, words unchanged. Rejected on matched latency and no commitment reduction.

Binary node cap: control/candidate 5.273276/5.540751 s, calls 14289/11941, words unchanged 33,554,432; rejected. The first failed cap prototype was rejected before timing because a raw verifier sibling mutation could be ignored; it was reverted. The corrected implementation explicitly binds every sibling. The initial tight-padding prototype failed a route-dimension assertion and has no valid timing claim. Its repaired variant is the `41e98b89` table above.

Plain arity four improves node latency modestly but keeps 33,554,432 words and increases proof bytes; it is a building block, not the preferred final node layout. The combined cap crosses the node commitment boundary. Old contaminated control samples that overlapped interrupted runs are retained only as history, never used by these matched tables.

Compact-cap single screens (not matched acceptance): first 2.743544 s, 4868 calls, 16,777,216 words, 1,152,166 rows, 240208 B, 8.724 ms verify, 25.534 ms root; node 3.593446 s, 7260 calls, 16,777,216 words, 1,326,181 rows, 240496 B, 10.913 ms verify, 45.138 ms root. The smaller cap reduces arithmetic but adds 294 calls per workload and crosses no new commitment boundary. Not accepted; source patch and binary hashes are in `quadcap-compact.patch` and `quadcap-compact.sha256`.

Query-selection screen (`query-select.patch`): first 2.690759 s, 4574 calls, 16,777,216 words, 1,253,674 rows, 239440 B, 8.920 ms verify, 38.417 ms root. It saved about 24,000 rows but no calls or words; not accepted without a matched win. Its package suite passed 63/63 (`query-select-full-tests.log`).

Native skipped-level ABAB completed against the original control: first 4.299449/2.377206 s and node 5.294959/3.091358 s. Recursive shape and calls equal fast cap; this comparison does not isolate its incremental effect, so it is not adopted separately. Its PCS suite passed 6/6, full format package 63/63, and Clippy passed. Raw patch and binary hashes are retained in `quad-native.patch` and `quad-native.sha256`.

The wider affine-cap single screen also fits first-level 20/20 without reducing the cap: first 1.596227 s, 3736 calls, 8,388,608 words, 1,273,732 rows, 215584 B, 8.339 ms verify, 33.399 ms root; node 3.122177 s, 4924 calls, 16,777,216 words, 1,540,485 rows, 241168 B, 8.894 ms verify, 64.454 ms root. It is not accepted without a matched win; larger matrix forms increase root cost. Source patch and hashes: `route-wide.patch`, `route-wide.sha256`.

The tight 20/20 node experiment failed setup construction (`route-tight-node.stderr`, exit 101), so it has no valid timing or proof claim. Its 65-test package and Clippy passed, but do not establish that the measured node fits. Source was reverted; patch and binary hashes remain in `route-tight.patch` and `route-tight.sha256`.

A further cap-height-2 screen (`route-cap2.patch`, `route-cap2.sha256`) verified at 2.735185 s, 5842 calls, 14,680,064 words, 1,239,525 rows, 232080 B, 9.568 ms core verify and 39.368 ms root. Natural node dimensions were 899,863 rows / 1,088,307 columns, still above the 20-bit column bound. The first wrapper grew to 11,534,336 committed words. Rejected before matched acceptance: no word boundary crossed and calls increased.

Affine-limit-16 with aliases (`route-affine16.patch`, `.sha256`) also failed to cross the column boundary: natural node 945,293 rows / 1,104,569 columns. Verified single screen: 2.689042 s, 5074 calls, 14,680,064 words, 1,294,195 rows, 232464 B, 9.711 ms core verify, 40.346 ms root. No calls or words saved; rejected without matched acceptance.

## Validation and soundness scope

Source-ID alias and q-first release packages each pass 65/65 tests and Clippy (`route-alias-full-tests.log`, `route-qfirst-full-tests-final.log`, respective Clippy logs). See `joint-stack-soundness.md` and `qfirst-soundness.md`. Compact routing release package: 64/64 tests pass (`route-compact-full-tests.log`). Canonical routing release package: 64/64 tests pass (`canonical-route-full-tests-final.log`), including coherent high-limb replay attacks against raw native rows. The earlier test log failed only a fixture assertion expecting checks to remain on input nodes; the updated test asserts the new layout and adds the coherent attack. Compact-profile Clippy lib/examples passes with warnings denied (`route-compact-clippy.log`). Binary-cap release package: 61/61 tests and Clippy passed. Quaternary/shared-cap and fast-cap release package: 63/63 tests passed (`quadcap-full-tests.log`, `quadcap-fast-full-tests.log`). Fast-cap Clippy lib/examples with warnings denied passed (`quadcap-fast-clippy.log`). Native PCS / Fiat–Shamir Merkle tests are recorded in `quad2-native-tests.log`. The targeted raw recursive tests mutate every sibling at depths 1–6, duplicate and distributed query positions, wrong leaves, query challenges and leaf widths. Full-size cap occupancy tests compare sparse/distributed fixed programs and directly mutate a supplied sibling's high F192 limb. Full package and mixed-tree examples reject false carried claims, substituted keys, omitted/duplicated claims, wrong child kinds, reordered children, and tampered child/root proofs, bypassing prover prechecks. See source tests and raw logs for exact coverage; no coordinator rejection corpus exists here.

Rates (including leaf rate 1/4), query counts, OOD schedule, grinding, extension field, leaf packing and application statements are unchanged. Four 32-byte child digests fit the same 136-byte Keccak rate; capacity remains 512. Odd tree depths retain a binary top. Security assumes the unchanged WHIR proximity argument for the same sampled leaf positions and collision resistance of 256-bit Keccak digests (128-bit generic collision security). This is not a new formal security proof or a coordinator-calculator result. Cap occupancy is derived from constrained query bits, not private host branching. Every supplied sibling is bound, including aliases of reconstructed regions. Fast aliases use full-field equality to canonical digests; high limbs are not silently truncated.

The smaller wrappers prove only the measured mixed depth-two configuration; arbitrary repeated node-on-node closure is not established. Native builder memory still retains unused binary intermediate levels. Proof size remains below 300,000 B for accepted measured merges. Core verification medians remain below 20 ms, but occasional samples exceed it (quad-cap node 24.816 ms), and external decoding/admission is not measured by this lane. Root time and proof growth are explicit tradeoffs, not hidden gates. No sustained cadence or <=1 s result is established. O1 owns cost per permutation; this lane does not change its Keccak reduction.
