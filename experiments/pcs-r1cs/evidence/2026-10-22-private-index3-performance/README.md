# Preceding profile: private recursion, index rate 1/8

Source and executable hashes, CPU affinity, tooling revision and schedule are in [config.json](config.json), [source-sha256.json](source-sha256.json) and [measure.py](measure.py). All 26 planned processes completed: one smoke run, three alternating baseline/candidate pairs, three rotated trials of each of three implementations at depths one and three, and one full-length native tree. All 226 proof records verify; independent statement recomputation and record validation passed. The same deterministic fixture is repeated; there are no warmups.

[Optimization](optimization.json), [paired gains](paired-gains.json), [two-child comparison](matched-depth1.json), [deeper diagnostic comparison](matched-depth3.json), and [full-length tree](full-summary.json) retain per-run values and ranges. Every process keeps raw output and an execution receipt. The root of each tree is independently recomputed with Python BLAKE2s. Recorded source/binary hashes were checked before changing source profiles.

Process elapsed time includes setup, leaf proofs, verification, negative checks and up to about 0.5 s polling delay. Use parent preparation plus proving for precise parent latency. The deeper VM wrapper carries and verifies deferred records; it is not an optimal fixed-point VM construction. Separate keys remain trusted at each level. These are implementation measurements, with no new formal composition proof or official challenge score.

See [the comparison and profile tradeoff](../../recursion/PRIVATE.md) for the current interpretation. Earlier evidence is preserved rather than relabeled.
