# Native recursive prover profile

A Yukon source-bound diagnostic on the accepted common-key closure implementation, using `ca3f535` and a fresh depth-1 chain-16 process. It adds only tracing fields, then restores the source; it is not a performance comparison.

| Quantity | Value |
|---|---:|
| Allocated native rows | 2,097,152 |
| Actual arithmetic gates | 1,506,304 |
| Real hash blocks | 34,979 |
| Padded hash slots | 65,536 |
| Root creation | 1.247 s |

| Root stage | Time |
|---|---:|
| Joint opening | 317 ms |
| Joint commitment | 193 ms |
| Arithmetic reduction | 147 ms |
| Hash reduction | 173 ms |
| Native copy product | 77.9 ms |
| Arithmetic witness | 55.7 ms |
| Hash witness | 15.3 ms |
| Index opening | 74.5 ms |

The first proof is colder than later proofs; the rows above are the final node in the one-process diagnostic and are descriptive only. The process locally verified every certificate and the independent closure validator passed. `RUST_LOG` alone produced no spans and is recorded as excluded; the replacement used `BENCH_TRACING=1` with the frozen diagnostic binary. The temporary tracing source was restored before publication. No proof bytes, keys or circuit shapes changed. This diagnostic explains why padding-template reuse was screened out: the stage is small relative to opening and reduction costs.

Run `python3 verify-archive.py` after the evidence archive is created. This is local profiling evidence, not official `recursion.fast` certification or a formal recursive-composition proof.
