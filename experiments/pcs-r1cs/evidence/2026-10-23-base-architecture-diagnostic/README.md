# Specialized base circuit diagnostic

Removing the recursive verifier makes the tiny base fixture much cheaper, but gives only a small difference between medians at the defined chain length. This is an architecture diagnostic, with different keys and proof geometry. No proving change is promoted and no integrated tree speedup is established.

| Hash steps per base proof | Current closure circuit | Specialized base circuit | Reduction between medians |
| ---: | ---: | ---: | ---: |
| 16 | 1.657642 s | 0.034691 s | 97.91% |
| 16,384 | 7.147426 s | 6.855200 s | 4.09% |

Each cell is the median of three process totals for creating two original proofs, divided by two. It is an average cost per proof, not an isolated proof latency. Creation includes expected statement computation, trace recording, witness preparation and proving. Setup, explicit verification and serialization reporting are outside this measurement. Both variants prove the same tagged chain and final leaf statement. The specialized example rejects changed statements and truncated encodings after verifying the original proof.

The 16 step processes alternate control and specialized order. The continuation at 16,384 steps uses the opposite alternating order. These descriptive medians do not establish a robust retained speedup at full length. Control processes also create and verify one parent after the two leaves. Specialized processes stop after their two original proofs. Their process totals must not be compared as equivalent complete trees.

## Why full length differs

The current closure circuit contains the hash chain and two child verifier branches, even when making an original proof. Disabling a branch's checks does not remove its rows from the fixed circuit. Removing those branches matters enormously for a tiny chain. At full length, repeated hash input connections already generate millions of rows without any recursive verifier.

Each chain step hashes the one byte tag 0x43 followed by the previous 32 byte digest. In private_trace.rs, Compiler::hash uses the direct word path only when every part has a length divisible by eight. The tag forces the generic bit path. Compiler::range_bits decomposes digest words into Boolean bits and reconstructs the source words, then Compiler::hash reconstructs the shifted message words. This is proving circuit overhead, not evidence that the compiler's wall time dominates creation.

A new source bound census, without commitments or proof timings, counts 774 additional arithmetic rows per extra chain step: 256 Boolean checks, 256 source reconstruction rows, four equalities, 256 message reconstruction rows, and two rows combining output words. The observed row count is 781 + 774 times the step count at 0, 1, 2, 16 and 256 steps. Extrapolating to 16,384 gives 12,681,997 rows before bridge connections and padding. That agrees with the connector boundary independently reported by the completed full length specialized proof runs.

| Steps | Circuit | Padded arithmetic rows | Hash blocks | Connector start | Stack log |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16 | Current closure | 2,097,152 | 65,536 | 1,114,112 | 26 |
| 16 | Specialized base | 16,384 | 17 | 13,312 | 18 |
| 16,384 | Current closure | 16,777,216 | 65,536 | 13,893,632 | 28 |
| 16,384 | Specialized base | 16,777,216 | 16,385 | 12,713,984 | 28 |

Both full length variants round up to the same arithmetic table size. This motivates reducing the cost of connecting successive hash inputs while preserving the exact tagged statement and all private chain equalities. It does not authorize changing the hash input layout or omitting range constraints. In the F192 tower, multiplication by a field constant is not generally an integer bit shift.

Splitting base and node circuits still deserves integration testing. The current common circuit computes the full chain even during a merge; three full length control runs have a median merge cost of 5.368763 s. A separate node circuit could avoid that chain work. No specialized node or base acceptance integration has been built in this diagnostic, so that benefit is unmeasured.

## Proof geometry, memory and failed attempts

At 16,384 steps the specialized backend proofs are 386,192 and 385,328 bytes. The control complete certificates are 388,708 and 389,060 bytes, including a 36 byte height and statement header. These are different serialization boundaries, not unchanged proof sizes. Keys, per position certificate digests, geometry and statements stay stable within each variant and length across three trials. Median sampled process peak memory is about 31.53 GiB for control and 32.55 GiB for specialized. The extra parent proof in control also prevents an isolated allocation comparison.

All attempts are retained. The original full length control used a 16 GiB process budget and was stopped by Yukon's sampled RSS guard before creating its first proof. The six successful full length processes use 96 GiB. An earlier scaffolding command invoked the wrong worktree and failed because the requested example target did not exist; its unused initial source is retained.

The previously unpolled leanVM full length attempt is terminal. It created and locally verified two original proofs, then panicked before its merge with ChildOutOfRange { log_committed: 30 }. It did not hit the memory guard. No complete tree or three trial comparison exists, and the command was not rerun. The VM adapter's dispatch range needs a checked extension before a fresh comparison. Partial proof times are excluded from this table.

## Validation and provenance

The proving implementation is unchanged from accepted native code at 906015c1. The specialized example starts at f7efa52a. Twelve successful measurement processes produced 30 locally verified certificates. The publication audit independently recomputes all tagged statements with Python hashlib, checks raw log hashes, exact measured source and executable identities, stable keys and certificate digests, and nonoverlapping measurement intervals. Both diagnostic examples pass release compilation and Clippy with warnings denied. No native proving source was edited.

Original builds and timings used clean Yukon 42e046241e0fe55ba34476c9d5310b5d2590843a. The new census, release build and Clippy checks use upstream 18344306f0e215ee621ac3a8cafb6530d9d0c300, checked on this continuation. Both revisions have runner SHA256 ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. Rust is 1.99.1, native CPU plus PCLMUL, four Cargo jobs, 32 prover workers, CPUs 0 through 63 and a 40 GiB global memory reserve. The shared host is a Xeon Gold 6230R. These are local research measurements, not official recursion.fast scores.

The archive retains commands, raw receipts and logs, failed attempts, build and binary manifests, scripts, the initial scaffold, deduplicated observed source bytes and the Yukon runner. Source maps translate original absolute paths to source blobs. Executables are omitted with hashes preserved. Run verify-archive.py through Yukon to validate the archive and independently recompute medians and chain statements without extraction. The complete defined tree, formal native composition and official verifier integration remain open. The performance goal remains active.
