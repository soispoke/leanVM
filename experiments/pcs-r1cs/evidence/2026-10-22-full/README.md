# Full Linux run, 22 October 2026

Hardware: Intel(R) Xeon(R) Gold 6230R CPU @ 2.10GHz; 16 pinned threads (CPUs 0-15); 251.7 GiB RAM. Fresh binaries explicitly enable pclmulqdq.

PCS uses a Keccak application transcript; R1CS uses the VM-native BLAKE2s transcript. Each cell is a median of three measured proofs on the same 16 pinned logical CPUs. Raw samples retain every stage. These are shared-host measurements, not a dedicated-machine performance limit.

## One application

| Statement | Rows, padded | Client proof, PCS / R1CS (s) | Aggregate proof, PCS / R1CS (s) | Execution gas, PCS / R1CS |
| --- | ---: | ---: | ---: | ---: |
| membership | 2^20 | 1.573 / 1.566 | 1.207 / 1.170 | 10,971 / 61 |
| blake2s-1kib | 2^19 | 0.912 / 0.887 | 1.256 / 1.221 | 10,709 / 61 |
| sha256-1kib | 2^20 | 1.596 / 1.662 | 1.159 / 1.170 | 10,971 / 61 |
| keccak256-1KiB | 2^20 | 1.615 / 1.668 | 1.253 / 1.209 | 10,971 / 61 |
| shielded-transfer | 2^22 | 6.513 / 6.602 | 1.249 / 1.204 | 11,495 / 61 |
| falcon512 | 2^22 | 6.560 / 6.621 | 1.214 / 1.239 | 11,495 / 61 |
| mpt-storage-proof | 2^23 | 14.268 / 14.346 | 1.168 / 1.150 | 11,758 / 61 |

Client proof includes witness generation, quotient PIOP and PCS openings. Aggregate proof is the recursive VM prover alone. The circuits and inputs match across interfaces; the client proof bytes differ because the transcript hashes differ.

## Batching and recursion

| Applications in one aggregate | PCS aggregate proof (s) | R1CS aggregate proof (s) | PCS / R1CS base VM cycles |
| --- | ---: | ---: | ---: |
| 1 | 1.207 | 1.170 | 797,296 / 798,165 |
| 2 | 2.466 | 2.356 | 1,594,317 / 1,596,686 |
| 4 | 4.770 | 4.971 | 3,189,147 / 3,193,079 |
| 8 | 10.351 | 10.413 | 6,377,862 / 6,385,676 |

Batches use independent membership instances. Trees below use matching membership leaf aggregates; tree times have no explicit warmup.

| Tree (leaf aggregates x applications per leaf) | All leaf proofs, PCS / R1CS (s) | Root proof, PCS / R1CS (s) | Root cycles, PCS / R1CS |
| --- | ---: | ---: | ---: |
| 2x2 | 5.326 / 5.351 | 0.883 / 0.905 | 509,032 / 509,039 |
| 4x4 | 21.800 / 21.754 | 1.774 / 1.707 | 1,040,169 / 1,040,185 |

## Separate packed-backend experiment

This proves the same Boolean circuit relation with a different proof system. It is not either interface's recursive aggregate, is not zero knowledge, and has no Lean soundness proof.

| Statement | Prove median (s) | Measured range (s) | Verify (ms) | Proof bytes | Process peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: |
| membership | 0.241 | 0.240-0.253 | 7.80 | 447,488 | 0.59 |
| blake2s-1kib | 0.147 | 0.145-0.163 | 7.22 | 408,656 | 0.34 |
| sha256-1kib | 0.254 | 0.249-0.255 | 7.54 | 444,608 | 0.60 |
| keccak256-1KiB | 0.266 | 0.261-0.279 | 8.09 | 449,848 | 0.61 |
| shielded-transfer | 0.765 | 0.742-0.767 | 8.55 | 497,856 | 2.06 |
| falcon512 | 0.747 | 0.726-0.784 | 8.26 | 501,848 | 2.21 |
| mpt-storage-proof | 1.581 | 1.564-1.708 | 10.02 | 550,472 | 4.45 |
| ecdsa-secp256k1 | 10.834 | 10.749-10.928 | 10.31 | 646,856 | 34.70 |

## Limits and accounting

- ECDSA (2^26 padded rows) and Poseidon (2^29) exceed the quotient implementation's 2^23-row domain. No paired interface time is measured for them.
- Packed Poseidon was not admitted: retained GKR and index allocations alone need about 218 GiB, before the circuit and temporary memory. See `packed-poseidon-capacity.json`.
- Gas is application-contract execution in the prototype. It excludes transaction/calldata charges, ordinary application state, registry/publication and native claim coverage. PCS assumes the proposed 10-gas FIELD_MUL opcode.
- Setup is excluded from the main proof tables. Raw `serial_cold_us` adds shared setup and guest compilation to the timed serial stages; it is a stage-sum model, not a process-start measurement.
- 82 jobs completed; reported tampering rejections: 1,095. Minimum sampled system memory available: 159.3 GiB. Maximum job RSS: 42.8 GiB.
- Timings are measurements of these implementations and hashes. They do not prove equal performance, protocol optimality or architectural dominance.

Reproduce with `full_run.py`; regenerate these tables with `summarize_full.py`. `manifest.json` pins the commands, CPU, binary hashes and source hashes. Each `.jsonl` has raw protocol results; its `.result.json` has process status, peak RSS and the memory guard record.
