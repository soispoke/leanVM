# Sparse hybrid opening screens

Neither candidate is retained. Both start from the accepted common key native implementation at 906015c1. The first skips individual zero words and substitutes the field identity for one words. The second skips an entire zero tile or window while keeping dense multiplication free of per word branches. Both change prover computation only.

Three alternating pairs per candidate use two leaves with 16 hash steps each, 32 workers and separate frozen executables. Each cell is a median; paired percentage changes are computed within each pair. Positive percentages mean faster. Root creation is the one merge in this fixture.

| Candidate | Measure | Control (s) | Candidate (s) | Paired reduction | Wins |
| :--- | :--- | ---: | ---: | ---: | ---: |
| Individual words | Complete process | 7.473 | 7.697 | -4.17% | 1/3 |
| Individual words | All proof creation | 4.536 | 4.705 | -3.74% | 0/3 |
| Individual words | Base proof creation | 3.278 | 3.454 | -5.37% | 0/3 |
| Individual words | Recursive merge | 1.266 | 1.252 | +0.52% | 2/3 |
| Whole zero blocks | Complete process | 7.511 | 7.477 | +0.94% | 2/3 |
| Whole zero blocks | All proof creation | 4.593 | 4.547 | +1.04% | 2/3 |
| Whole zero blocks | Base proof creation | 3.321 | 3.287 | +1.00% | 2/3 |
| Whole zero blocks | Recursive merge | 1.272 | 1.246 | +1.14% | 2/3 |

The individual word candidate slows all proof creation in all three pairs. The whole zero block candidate has a small positive median but its observed range includes regressions, and neither total nor creation reaches the predeclared threshold. Neither warrants the seven independent eight leaf confirmation pairs. The source patches are archived for reproducibility and are not installed in the accepted implementation.

Each candidate first passed a separate complete certificate byte comparison. The three screen pairs also match every complete certificate digest, verification key, circuit shape, statement and proof geometry. Across both experiments, 16 serial timed processes produced 48 locally verified certificates. Python hashlib independently recomputed every statement. Source manifests match the corresponding isolated build, and admitted timing intervals do not overlap within either experiment.

The individual word implementation passed all 77 native library tests and 44 PCS library tests, with one existing PCS test ignored. Those checks ran on the earlier candidate checkpoint; all relevant PCS, native, primitive, parallel and transcript Rust source hashes are checked against the matched candidate. The whole zero block variant separately passed the complete proof differential against dense reference openings. That differential includes zero, one and random witness words, a contiguous zero tail, overlapping supports and missing lanes at two rates.

Yukon upstream was checked and pinned clean at 42e046241e0fe55ba34476c9d5310b5d2590843a. The runner hash is ccfa389f297eba6f0adcac80a41c15302ac6a749019f464f371e6be990970c9e. Measurements use Rust 1.99.1, native CPU plus PCLMUL, CPUs 0 through 63, 32 workers, a 16 GiB sampled process budget and 40 GiB global reserve. Builds and tests use a 96 GiB budget and run outside timed series. The host is shared; these are local screens, not isolated machine records.

Recursion.fast remains the primary performance target: base proof creation plus recursive merges, excluding setup and build. These small fixtures screen implementation ideas. The complete defined workload and formal native PCS/Flock composition remain open.
