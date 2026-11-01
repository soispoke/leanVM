# Streaming Keccak matrix evaluation

This changes only the native evaluation of the already fixed Keccak R1CS matrix form. It accumulates `u_i (A_i w + alpha B_i w)` as the structured rounds produce each nonzero row, applying the same simultaneous VM row/column relabeling. Zero rows contribute exactly zero. No reduction, witness relation, transcript, commitment, proof encoding, rate, query count, grinding parameter, or verifier equation changes.

Dense forward evaluation remains available as an independent reference. Focused Flock tests compare the streaming value to dense evaluation and the transposed form, preserve permutation equivalence, and reject false Keccak outputs in all 25 output lanes without relying on a prover precheck. Seven focused tests passed in opt-O3/streaming-tests.log. Matched ABAB x3 against frozen 979226d1 completed all five workloads; all proof sizes and table rows remain identical. This is implementation evidence, not a new general security claim.
