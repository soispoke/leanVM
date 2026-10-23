# L4 merge investigation (in progress)

Fresh 12-thread BLAKE64 first merge on CPUs 36-47: 3.483816 s, 361,196 bytes, 9,393,676 KiB peak process RSS. Same-process diagnostic verification passed in 6.516 ms. Tracing enabled, so use as a stage diagnostic. Existing target-vm-common reference binary, source tip 0830fb9a; independent L4 rebuild underway. Raw log: `hometurf-L4/merge-profile.log`.

Archived shape and fresh setup agree: node arithmetic log_rows=22, block_log=16, n_blocks=65536, connector_start=2097152, q_offset=50331648, stack_log=26. Twelve arithmetic F64 limb columns contain 50,331,648 words. Hash packed witness adds 2^(14-6+16)=16,777,216 words. Total joint witness is exactly 67,108,864 words, before rate expansion and fixed index commitment. The 361 KB certificate size is not the committed prover data size.

Remaining: row census by kind, full stage extraction, leanVM table comparison, one-proof recursion-machine estimate, safe lever screen, analytic lookup model and local commit.

## Stage breakdown and causal diagnosis

The trace tree for the fresh run reports: record node witness 139 ms, compile witness 123 ms, arithmetic witness 262 ms, hash witness 54.9 ms, joint commitment 747 ms, arithmetic reduction 608 ms, hash reduction 392 ms, joint opening 581 ms, and index opening 288 ms. These sum to approximately 3.19 s; the remainder is parallel scheduling, transcript, child admission, and tracing overhead. The archived independent run is 3.387 s, so tracing is a small perturbation, not the explanation for the multi-second result.

The node shape is `log_rows=22`, hence 4,194,304 padded arithmetic rows. The fixed native circuit has 12 populated F64 limbs per row (four F192 values represented by three F64 limbs), or 50,331,648 committed F64 words. The 65,536 BLAKE2s compression slots each use `2^14` packed z slots and six-bit packing, adding 16,777,216 words. Thus the joint witness is 67,108,864 F64 words before opening-rate expansion and the separately committed index. The two child Merkle paths and transcript are represented by the 65,536 scheduled compression blocks; their hash rows are therefore 65,536 compression rows at the block level, with 16,384 packed field slots per block. Copy/connector rows are included in the padded arithmetic circuit; the exact unpadded count is not exported by the current profiler, so it would be unsound to claim a finer row census.

This makes the dominant cause clear. It is not the 361 KB transported proof: proving commits and opens tens of millions of field words. It is not simply the 112 L0 queries at rate 1/4: those queries affect opening work, but the commitment, arithmetic reduction, hash reduction, and two openings already account for 2.33 s. The node's 2^22 padding and 65,536 hash schedule force a large fixed witness even when the children are only 64-byte applications. The two-proof structure (joint private witness plus index opening) adds the 581 ms joint and 288 ms index openings. LeanVM's first-level node is reported at 0.52–0.59 s at 12 threads, with approximately 9.57M committed words for the wrapped leaf and 5.08M for wrap-only; its lower table size and RISC-V cycle execution explain the 6–7x gap. Proof-byte size is not predictive.

## One-proof cost inside recursion

A single native R1CS base certificate is 247,956 bytes for BLAKE2s-64B and standalone decode plus verification is 5.2–7.0 ms in the separate-process matrix. The verifier's trusted shape is the base shape (`log_rows=17`, 131,072 rows, 39 compression blocks), while a recursive node uses the padded 2^22 shape above. A recursion machine that verifies one R1CS proof must execute the transcript and Merkle checks over the certificate, then the arithmetic and opening verifier. A conservative accounting is one hash row per committed Merkle/transcript compression plus one F192 multiplication for each recorded extension-field product in the verifier. The current native verifier does not export an operation counter, so exact counts are unavailable; the shape implies at least O(log rows) Fiat-Shamir rounds and O(112) L0 query paths. This is qualitatively much smaller than proving the node, but materially larger than verifying one leanVM proof, whose wrapping benchmark is about 9.57M committed words per leaf (5.08M wrap-only) and whose verifier is already expressed as VM execution.

## Levers

* Reduce node padding by admitting a smaller trusted node shape. At fixed workload this removes roughly 4,194,304-row arithmetic work and 50.3M words, potentially saving the 0.61 s arithmetic reduction and part of commitment/opening. This requires a new fixed key and rejection tests; it is the highest-value safe lever.
* Batch child Merkle/transcript queries before hashing. This can reduce repeated hash witness and hash reduction work (392 ms observed), with no soundness change if every original query remains bound. Expected saving is bounded by that 392 ms stage.
* Raise the leaf opening rate (lower inverse rate) only after re-deriving PCS soundness parameters. It can reduce query/opening volume, but changes proof length and security accounting; no safe numeric saving is claimed here.
* Remove neither child nor transcript checks. The two-proof structure could be fused only with a new soundness proof; it is not a safe quick optimization.

## Analytic row model

The following is a planning model, not a measured circuit claim. Let `W` be committed words per completed leanVM proof (9.57M for the wrapped leaf, 5.08M wrap-only), and let `C(op)` be guest cycles. For a workload with `C` total cycles, leanVM committed-word rows are approximately `W`; if allocating by operation, use `W*C(op)/C` rather than multiplying every operation by the full proof size. lookup-R1CS rows use one row per word operation plus table/range-check rows.

| operation | today's bit-level circuit | lookup/R1CS word-level | leanVM estimate |
|---|---:|---:|---:|
| 32-bit add | 32 full-adder rows | 1 lookup/range row (2–4 with carries) | 1–3 cycles × W/C |
| XOR | 32 boolean rows | 1 lookup row | 1 cycle × W/C |
| rotate | 32 copy/permutation rows | 0 arithmetic rows, wiring only | 1 cycle × W/C |
| mod-q multiply | 32×32 partial-product/carry rows, roughly 1,000–2,000 | 1 word multiply plus 2–8 reduction/range rows | 1–4 cycles × W/C |
| Keccak-f | 24 rounds × (1600 bit lanes plus theta/chi wiring), roughly 50k–100k rows | about 24×(25 lane lookups + word XOR/rotate), roughly 600–2,000 rows | measured cycles × W/C |
| SHA-256 compression | 64 rounds × 32-bit Boolean arithmetic, roughly 20k–40k rows | 64×(word add/σ/choice lookups), roughly 300–1,000 rows | measured cycles × W/C |

For SHA256 1 KiB (16 compressions), the model is 320k–640k bit rows, 4.8k–16k lookup-R1CS rows, or 16 times the measured compression cycle count times W. For Keccak 1 KiB (8 absorb blocks plus final padding, then 8 or 9 permutations depending on the exact sponge framing), it is about 0.85M–1.7M bit rows, 10k–34k lookup-R1CS rows, or 17 times measured permutation cycles times W. MPT is dominated by its number of hash calls and path copies, so lookup-R1CS becomes competitive only when the hash is word-native and the table is reused across paths. Falcon is dominated by modular arithmetic and large-vector transforms; lookup-R1CS can reduce Boolean overhead but remains larger than leanVM unless modular multiplication and range checks are custom word gates. R1CS can match leanVM on integer-heavy SHA/MPT only if hash compression is a native/lookup gadget, node padding is removed, and committed words fall near the 5–10M leanVM range. With today's bit-level BLAKE2s and 2^22 padding, it cannot match on merge cost.

These ranges intentionally separate architectural estimates from measured receipts. They should not be used as security or Ethereum-client compatibility claims.

## Exact verifier census and right-sizing screen

A release census of the fixed BLAKE64 split-node program reports 63,426 BLAKE2s compression calls, 2,034,321 pre-bridge arithmetic rows, and 133,479 arithmetic checks. The operation census is: Add 708,413; Mul 589,175; Select 101,977; Slice 154,235; Hash 32,661; HashHigh 32,661; Pack 12,729; Input 131,251; Constant 989. The 65,536 hash slots are therefore the exact next power of two above the real compression need, with only 2,110 unused slots.

The requested query expression (112+45+28+21+16) is 222 L0 queries per child family before path depth and transcript openings. The measured 63,426 compression calls include both children, all Merkle path and transcript compression work, verifier opening reductions, and the fixed bridge schedule. The source records both base and node verifier shapes for each child, then gates the relevant checks by child height, so the first merge still carries the universal either-kind verifier circuit. This is why simply counting application Merkle queries underestimates the circuit.

The bridge connector schedule adds `6 * 65,536 = 393,216` rows. Together with the 2,034,321 pre-bridge rows and alignment, this crosses the 2^21 boundary and forces `log_rows=22` (2^22 rows). A right-sized node would need fewer than 32,768 compression slots, or a different connector representation, to reach 2^21 rows. The current exact 63,426-call universal verifier cannot meet that bound by changing a constant: 65,536 is already minimal under the current fixed-point program. Shrinking below it requires reducing verifier work (native child proof hash rows, query batching, or a redesigned shared base/node verifier) while retaining both child-kind checks.

No shape-changing candidate was screened because the available branch has the old bit-level base verifier and its measured lower bound is 63,426 compressions. Applying a smaller `n_blocks` would reject valid witnesses or truncate compression commitments, so it would weaken soundness and was not attempted. The safe screen result is therefore a negative result: current constants are already right-sized for the measured program, while the 2^22 padding follows from the universal verifier's connector schedule.
