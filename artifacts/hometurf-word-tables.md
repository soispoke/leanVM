# Word-table integer workload screen: L3b

## Stage 0: Falcon census

2026-10-23. Branch `hometurf/L3`, worktree `ht-L3`; no push authorized.
Raw receipts: `ht-L3b-bit-stages.txt`, `ht-L3b-nibble-stages.txt`.
Census executions: CPUs 24-35, `RAYON_NUM_THREADS=12 LEANVM_NUM_THREADS=12`.
Builds: CPUs 48-63, `CARGO_BUILD_JOBS=4`, lane-owned `target-ht-L3`.
These are row counts, not timed wallet measurements.

| Part | Bit-level Boolean rows | Nibble lowering native arithmetic rows |
|---|---:|---:|
| Inputs (decoded coefficients, message, nonce) | 21,056 | 21,056 |
| Statement digest SHAKE256(pk || message) | 865,426 | 2,130,480 |
| HashToPoint SHAKE256 | 1,114,399 | 2,762,418 |
| HashToPoint sample range/rejection tests | 9,180 | 27,540 |
| Sample compaction | 254,794 | 602,020 |
| Public key/s1 bounds and conversion to modular values | 47,104 | included in frontend/packing below |
| c − s1 modular subtraction | included in preceding row | 40,960 |
| NTT(s2) | 394,109 | 682,177 |
| NTT(h) | 398,801 | 682,177 |
| NTT(c − s1) | 387,974 | 682,177 |
| Pointwise products / quotient checks | 342,939 | 315,392 |
| Modular validity reduction | 19,595 | included in equality checks |
| Norm (nibble frontend also includes public key/s1 bounds) | 161,008 | 532,578 |
| Encoding length and final validity | 3,009 | 10,580 |
| Port packing, sign conversions and sample reduction; frontend remainder | n/a | 112,903 |
| Public reserved rows and final native output/anchor bookkeeping | 512 | 64 |
| **Total before query binding** | **4,019,906 Boolean** | **8,602,458 native arithmetic** |

Quotient hint inputs occur within the bit-level modular stages, not the initial input stage.
The bit-level modular subtotal is 1,590,522 Boolean rows; its nested rows above
are not counted twice. Boolean and native rows are different units: the existing
trimmed native bit-level benchmark has 8,798,175 arithmetic rows. The table does
not claim a direct row-for-row comparison between these representations.
The nibble frontend subtotal (including port packing/conversions) is 6,199,575
native rows. SHAKE accounts for 4,892,898 native rows (56.88% of core total).
Three NTTs plus pointwise checks account for 2,361,923 (27.46%).

Signature/public-key decoding scope: inputs are already decoded coefficients,
not compressed signature/public-key byte strings. Public-key serialization into
the statement digest is wire routing. Coefficient bounds, centered-s1 bounds,
norm and the compressed-signature encoding *budget* are checked. The in-circuit
compressed-byte parser has zero rows because it is absent; this is a disclosed
statement limitation, not a free implementation of full byte decoding.

Nibble lookup queries: LOGIC=153,088; ADD=884,201; RANGE=0. Queries pad to
1,048,576. Six coordinates add 6,291,456 copy rows; alignment brings the bound
circuit to 15,728,512 rows, padded to 16,777,216. Prior wallet evidence is
16.0942 s mean nibble versus 13.4127 s mean bit-level (see
`hometurf-integer-lookups.md`). No new word-table wallet measurement exists yet.

Interpretation: optimizing only the modular NTT/product relation leaves most
native rows. Even deleting all 2,402,883 modular rows following the frontend
leaves approximately 6.20M core rows. Proportional scaling from the prior
13.4127 s / 8,798,175-row bit-level baseline estimates 9.45 s; this is a
rough conditional projection, not a measured lower bound. It assumes the
Boolean frontend remains unchanged. Word-sized LOGIC can also target SHAKE,
so this estimate alone does **not** trigger the requested final stop rule.

## Step 1 status

The candidate shared relation is now defined in `word_tables.rs`, with exact
fixed concatenation order and six-coordinate canonical tuples:

| Tag / domain | Rows | Tuple (unused coordinate is zero) |
|---|---:|---|
| 1 / LOGIC8 | 65,536 | `(1,a,b,a XOR b,a AND b,0)` |
| 2 / ADD8 | 131,072 | `(2,a,b,carry,(a+b+carry) mod 256,floor((a+b+carry)/256))` |
| 3 / MUL8 | 65,536 | `(3,a,b,(a*b) mod 256,floor((a*b)/256),0)` |
| **Total** | **262,144 = 2^18** | |

`a,b` range over bytes, ADD carry over `{0,1}`. Range checks can use
LOGIC8 `(x,0,x,0)` without another table. Wider integers decompose into bytes;
there is no Falcon/mod-12289-specific table. MUL returns two bytes, avoiding
confusion between integer and characteristic-two multiplication. The relation
is fixed for this candidate; proof layout/performance are not frozen.

Sparse host counters store sorted `(fixed-row-index, integer-count)` entries.
They are **not yet committed or proven by a sparse lookup argument**.
Exhaustive release tests cover all 262,144 rows, integer semantics, malformed
coordinates/tags/padding, and even multiplicity preservation. These are host
relation tests, **not verifier rejection tests**. Receipt:
`ht-L3b-word-table-tests.log` (2/2 passed, 0.02s).

The sparse reduction prototype is now implemented in `word_lookup_reduction.rs`.
It commits sorted `(table-row, integer-count)` advice into the transcript before
sampling six-coordinate fingerprints, proves the query product with the existing
GKR product bus, and checks fixed-table products using integer exponentiation.
It never uses additive LogUp counts. Its standalone verifier test bypasses host
membership checks and rejects wrong carry/sum/product, wrong tag, out-of-range
operands, duplicate-row ordering, and altered multiplicity distribution.
Receipt: `ht-L3b-sparse-reduction-tests.log` (1/1 passed).
The reduction returns unbound query evaluations; application PCS openings still
must bind each coordinate directly to witness cells before this can be a sound
application proof.

The direct-gather binding prototype is implemented in `word_query_binding.rs`.
A frozen schedule maps each of the six tuple coordinates to existing three-limb
witness cells or constants; it adds no query-copy rows. The schedule digest is
transcript-bound, and a degree-two folding reduction returns one stack claim
that still requires the existing PCS opening. Its test forges a coordinate
claim and verifier rejection succeeds. Combined release receipt:
`ht-L3b-word-reductions-tests.log` (5/5 passed).

No direct witness-query argument or sparse multiplicity argument has been
validated, and no word-table rejection/ABAB/fresh-input results are claimed.
Existing nibble verifier tests do not establish soundness of the word design.
`cargo check -p circuit_suite -p format_recursion` passed for the census edits;
release table tests also compile the latest census instrumentation. Formatting
used the installed Rust 1.99.1 `rustfmt` directly (Cargo's fmt subcommand is
not installed); `git diff --check` passed.

## Retained-frontend stop screen and verdict

The retained-frontend candidate fails the requested approximately 3-second
stop gate even under an optimistic relaxation. The screen removes all NTTs,
pointwise products, query-copy rows, lookup products, sparse-count verification,
and direct-gather openings. It retains the existing Boolean frontend and its
port conversion arithmetic. This is an **incomplete Falcon relation**, used
only to screen performance; accepting its proof is not Falcon verification.

| Metric | Fixture 0 retained-frontend relaxation |
|---|---:|
| Wallet (witness + proof + encoding; setup excluded) | 7.741669403 s |
| Whole-process peak RSS (setup included; no HWM reset) | 13,806,324 KiB (13.17 GiB) |
| Proof bytes | 361,464 |
| Separate-process verify (including decode) | 6.840737 ms |
| Core arithmetic rows | 6,199,575 |
| Committed F64 words | 102,760,448 |
| Process wall time including setup | 11.598558184 s |

Timing uses CPUs 24-35 and both thread knobs set to 12. Builds use 48-63 and
four Cargo jobs. The witness is rebuilt inside the wallet interval. Setup and
initial fixture evaluation are outside it. RSS is Linux child `ru_maxrss` from
a fresh Python subprocess runner because `/usr/bin/time` is not installed.
Receipts: `ht-L3b-frontend-0.jsonl`, `.resources`, `.verify.jsonl`, and
`ht-L3b-frontend-build.log`. Metrics were appended to `hometurf-12t.jsonl`.

Even assigning zero cost to every removed modular/lookup operation leaves the
measured retained frontend at 2.58 times the gate and 7.59 times the supplied
1.02-second leanVM Falcon reference. This is a credible negative projection for
this candidate architecture, not a mathematical lower bound for all word-table
circuits. In particular, a word-level SHAKE rewrite could change the result;
that rewrite was not implemented or measured here.

**Stop decision:** stop the retained-Boolean-frontend word-table candidate.
Per the early stop rule, do not spend additional runs on ABAB, independent fresh
Falcon signatures or SHA-256 word-table timings for this failed candidate.
No complete word-table application proof, application-level verifier rejection
suite, or recursive integration is claimed. Standalone reduction rejection tests
and table tests are the evidence for the prototype pieces only.

**Verdict:** parity with leanVM on integer-heavy applications is **not
established**. Freeze no production lowering or application configuration.
The exact 262,144-row shared relation above is the experimental candidate list;
only its contents and prototype reductions are committed. The useful result is
that eliminating copy rows and making modular arithmetic free is insufficient
while retaining this Boolean SHAKE frontend. Any subsequent attempt at parity
must include a different SHAKE lowering and a new measured end-to-end screen.
