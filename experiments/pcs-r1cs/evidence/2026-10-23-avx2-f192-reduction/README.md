# AVX2 F192 reduction candidate

Rejected after the predeclared three-pair tree screen. The candidate reduces three F192 coefficients together with AVX2 shifts and XORs on PCLMUL-only x86 hosts. It was tested against the accepted hybrid-opening baseline. All complete certificate bytes, keys, statements, circuit shape fields and proof geometry matched.

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.709 | 7.745 | -0.82% | 1/3 |
| All proof creation | 4.549 | 4.693 | -3.13% | 1/3 |
| Root creation | 1.212 | 1.256 | -3.99% | 1/3 |
| Setup | 2.911 | 2.834 | +2.66% | 3/3 |

The isolated microbenchmark was positive, with median reduction gains of 10.81% for reduction alone and 13.76% for multiply plus reduction across three alternating pairs. That gain did not survive the complete two-leaf recursive tree: proof creation regressed 3.13% and total time regressed 0.82%. The candidate therefore fails the retention rule and is not promoted.

The interrupted trial was inspected before continuation. Its setup-only directory is retained in the raw archive as `reduction-screen-reduction-02-interrupted`; it had no receipt and no live process. Only the missing trial 2 and trial 3 observations were rerun. All three completed pairs passed independent statement reconstruction, source-bound Yukon receipts, and certificate digest equality.

Validation used Yukon ca3f535, Rust 1.99.1, native x86 with PCLMUL and AVX2, 32 workers, and serial non-overlapping measurements. The accepted Rust source was restored after the rejection. The raw archive contains the candidate patch, all receipts, logs, scripts, microbenchmark output and the interrupted directory.

Formal composition and official recursion.fast integration remain open.
