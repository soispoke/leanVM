# Application roles and first-merge profile, 2026-10-23

These quick development observations use the `eda5a0c9` prover with the new `application_role_profile` example and two extra tracing spans around split-node child admission and recording. Each role runs in its own process. No verifier, transcript, application graph, key or proof shape is changed by the profiling harness. This does not establish security, zero knowledge or Ethereum acceptance.

## Resources and timing boundaries

The runner is an Intel Xeon Gold 6230R VM. Commands use the pinned Yukon wrapper, a 96 GiB process-group budget, 40 GiB available-memory reserve and 1,800 s timeout. The five role profiles explicitly restrict process affinity to CPUs 0 through 11 and override `LEANVM_NUM_THREADS=12` in the child command. The wrapper's parent environment still records 32; the command's explicit `env LEANVM_NUM_THREADS=12` is the effective prover setting. Other missions may compete for host resources. These are single observations, without medians or a stable speedup estimate.

`native-client` constructs only the native base setup, then prepares and proves one application instance. Its proof timer includes the same host satisfaction check used by `prove_base`. `native_trace_creation_ms` is reported separately and is required client work. Independent application reference generation/evaluation, trusted setup, explicit verification and serialization are outside these timers. Peak process RSS includes setup within that role, and is not incremental proof memory. `quotient-client` runs the historical application-only proof without the wrap proof or recursive setup; its reported `create_ms` sums witness, PIOP and opening times and excludes reference checking and verification. Its enclosing trace span includes those checks, so that root span must not be substituted for `create_ms`.

`merge` reconstructs trusted split setup outside the merge timer and reads the previously completed BLAKE1K certificates. The measured call retains child admission and all active child-verifier equations. It does not create new client proofs in the measured role. Setup reconstruction currently includes a canonical base proof as preprocessing; it is reported separately. The merge outputs the same statement, keys and certificate bytes as the historical receipt. These measurements do not include a deployment mechanism for distributing setup keys.

## Client-required work

| Application | Native trace ms | Native proof ms | Native total ms | Quotient application-only ms | Native certificate bytes | Native verify ms |
|---|---:|---:|---:|---:|---:|---:|
| BLAKE2s 64 B | 8.187 | 113.513 | 121.699 | 125.698 | 247956 | 4.827 |
| BLAKE2s 1 KiB | 138.944 | 1272.100 | 1411.045 | 1171.262 | 323356 | 5.966 |

These current, role-separated observations differ from the earlier all-core, 32-thread quick matrix. They must not be combined to infer a thread-scaling improvement or a stable regression ratio. BLAKE64 does not reproduce the old proof-only regression in this screen, while BLAKE1K still costs more once native trace creation is counted.

The native BLAKE1K base has arithmetic log_rows=21, 1,437,312 stored rows, 1,678,835 variables, 39 actual proof-system hash compressions padded to 128, and a joint stack log=25. The corresponding Boolean application has log_rows=19. Full-adder expansion into the native field and the three-limb arithmetic representation create substantial commitment and reduction work. Native proof tracing attributes 56.4 ms to witness compilation, 147 ms to arithmetic witness construction, 343 ms to joint commitment, 325 ms to arithmetic reduction, 249 ms to joint opening and 124 ms to index opening. Hash witness/reduction together are under 5 ms. The native client slowdown is therefore not explained by an additional wrap proof or by recursive node verification in the client process. The quotient client's own profile spends 850 ms in its quotient stage, 41.5 ms in witness construction and 57.2 ms in the sum stage; its reported openings take 182.3 ms.

## Aggregator-side work

The first BLAKE1K merge takes 4,950.083 ms, produces 355,980 certificate bytes and verifies in 6.657 ms. Peak role-process RSS is 16,170,188,800 bytes. Its node shape has arithmetic log_rows=22, 131,072 padded compression blocks and stack log=27. Child admission takes 11.3 ms and witness recording 154 ms. Witness compilation takes 117 ms, arithmetic witness construction 195 ms, hash witness construction 92.6 ms, joint commitment 1.23 s, arithmetic reduction 564 ms, hash reduction 812 ms, joint opening 1.10 s and index opening 293 ms. Commitment, reductions and openings dominate the first-merge cost.

## Capacity reconciliation

MPT already has completed native base and mixed-height merge certificates, independently verified under `application-native-mpt-{out,verify}-quick-t2`. The smaller existing workload graphs and shapes remain unchanged. A new Poseidon capacity diagnostic was stopped with SIGTERM to the bounded runner after reading the circuit's documented size: the 1 KiB nonnative application has about 366 million Boolean rows before native lowering. No capacity result or support claim follows from the interrupted receipt. Its result records `KeyboardInterrupt: signal 15` and unchanged sources. The secp256k1 source documents about 42.8 million Boolean rows. Merely raising the native row bound does not establish feasible proof creation within the existing 96 GiB budget. The later shared orchestrator handoff defers these two benchmarks; their native support remains unfinished.

## Receipt interpretation

`application-role-profile-check-t1` compiles the new example. `application-role-profile-format-t1` runs the formatter successfully but its receipt is unsuccessful because formatting deliberately changes source hashes; it is not a gate. The later formatting check uses unchanged sources. `receipts/` preserves raw wrapper results and gzip-compressed logs, including unsuccessful attempts. Successful profile receipts report unchanged sources. The wrapper names retain historical terminology in older application metrics; this report separates application proof creation, wrap proof creation and aggregator merges by role.

## Matched lifetime screen

The candidate releases the native value buffer after compact arithmetic preparation, the arithmetic witness after arithmetic reduction, and the BLAKE witness tables after hash reduction. This preserves transcript order and does not change any verifier equations. It was screened against a byte-identical control with `LEANVM_NUM_THREADS=12`, CPUs 0 through 11, in opposite order for two trials. BLAKE1K native proof times were candidate 1,063.045 and 1,063.294 ms versus controls 1,162.496 and 1,120.167 ms. First-merge times were candidate 4,585.862 and 4,588.522 ms versus controls 4,928.667 and 4,735.597 ms. Candidate peak RSS was 4,179,910,656 and 4,181,073,920 bytes for native proving, versus 4,430,237,696 and 4,427,563,008; merge RSS was 15,392,169,984 and 15,393,779,712 versus 16,183,869,440 and 16,171,327,488. BLAKE64 was mixed: candidate 101.378 and 107.256 ms versus controls 94.088 and 114.382 ms. The candidate is retained for BLAKE1K and merge resource lifetime behavior, with no BLAKE64 speedup claim. Every matched pair has identical key, shape, statement, certificate size and certificate digest, and verification succeeds. The control and candidate receipts are archived under `receipts/`. The unsuccessful formatting receipt is retained separately; it changed sources by design and is not gate evidence.

The candidate BLAKE64/BLAKE1K native certificates and first-merge certificate also match the exact BLAKE2s digest of the already completed historical certificate files. Those historical proofs were read, not rerun.

Final frozen-tree gates are `application-role-lifetime-final-{fmt,clippy,release}-t1`: formatting, all-target release Clippy with `-D warnings`, 79 format_recursion tests and 43 rec_aggregation tests (5 ignored), plus doc tests. Every receipt reports unchanged sources, and the recorded source hashes were rechecked against the final working tree before committing. The targeted seven bridge tests also pass, including rejection after bypassing prover prechecks.
