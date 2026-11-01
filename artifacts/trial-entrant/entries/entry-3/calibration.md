# Encoded Falcon calibration

This is partial/ineligible evidence, not full A/B composition or a scalar score. Source81a17dc6 adds a raw-byte canonical encoding relation for fixed padded Round-3 Falcon512: pk897 bytes, signature666 bytes (header,40-byte nonce,625-byte compressed body). Decoded coefficients are witness hints constrained by canonical re-encoding, including header, public-key encoding, nonce, unary magnitude, negative zero and zero tail. Existing SHAKE, sampler completion, modular relation, range, norm and encoding budget remain. Validity is constrained to one by the driver.

The raw signature interface accepts only this fixed padded format, not arbitrary variable-length signatures. Samples consume known-answer fixture0; fresh coordinator raw-input consumption is unavailable. The native mixed bridge does not compose with the uniform sparse aggregate envelope. Protocol hash is BLAKE2s; application SHAKE uses native Keccak. ZK=false. Setup is reconstructed in each process and excluded from the internal wallet timer; whole-process wall and RSS are separately retained. No wallet-memory/byte gate success is claimed.

Five ABAB/BABA rounds,10 fresh processes per variant, cores0–11,12 threads:

| Boundary | Reduced | Full padded |
|---|---:|---:|
| Internal wallet median seconds |5.958877|12.733585|
| Whole-process median seconds |13.140787|26.279915|
| Median peak RSS KiB |14051658|28003642|
| Serialized bridge proof bytes |367064|389456|
| Native arithmetic rows |6077056|10400603|
| Committed F64 words |102760448|205520896|

Full/reduced internal ratio2.13691. Proof bytes above omit a standalone statement/setup forwarding adapter, which is unavailable. Full proof independently verified in12.14089ms (resident setup boundary). Six forged-proof probes bypass prover prechecks and reject: key header/payload, signature header, nonce, compressed payload, trailing padding. Parser-only tests additionally cover negative zero. Raw logs, exact executable and provenance are under falcon-encoded/. Security calculator and composed budget remain missing. These measurements do not establish arbitrary signature parser completeness or recursive Falcon admission.
