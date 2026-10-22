# Matched outer aggregation

Same child proofs and public claim, BLAKE2s, 16 workers, one warmup per job. These are single-level outer aggregations of independent proofs of one small application, not repeated self-recursion.

| Children | Native prove (s) | leanVM prove (s) | Native verify (ms) | leanVM verify (ms) | Native certificate (MB) | leanVM certificate (MB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.039 | 0.889 | 155.4 | 6.3 | 2.582 | 0.199 |
| 2 | 1.902 | 1.764 | 294.0 | 6.4 | 4.432 | 0.208 |
| 4 | 3.316 | 3.550 | 586.6 | 6.5 | 8.283 | 0.216 |
| 8 | 6.629 | 7.259 | 1185.5 | 7.0 | 15.788 | 0.236 |

| Children | Native setup (s) | leanVM setup (s) | Native peak RSS (GiB) | leanVM peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.516 | 0.097 | 1.69 | 2.43 |
| 2 | 1.041 | 0.096 | 3.27 | 5.22 |
| 4 | 2.047 | 0.099 | 4.61 | 9.72 |
| 8 | 4.057 | 0.098 | 8.09 | 19.35 |

Each timing is the median of 5 fresh measured samples. Sizes use decimal MB and include all public requests, chaining advice and serialization framing. Peak RSS covers each complete process, including setup, warmup and negative checks. Raw timing ranges, preparation times and totals are in summary.json. Shared-host measurements are indicative, not an architectural ranking.

Child proving is shared and excluded. Preparation and one-time setup are reported separately. Native proving includes arithmetic prechecks, both arguments and their binding. Verification covers the complete certificate. The native verifier still processes a linear public hash table and walks public projections; it does not replay field arithmetic. The native backend uses a new field gate and an unproved composition of existing primitives; it is not the original Boolean full-adder backend or covered by its Lean theorem.
