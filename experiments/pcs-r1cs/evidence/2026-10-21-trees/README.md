# Two-level trees, the Keccak circuit and the device kits

Same Arch host and rules as the [optimization round](../2026-10-20-arch/README.md): exact counts, wall times not representative (no `pclmulqdq`), total memory kept at least 30 GiB below capacity. Trees ran from `22397fec` (the `tree` example and `aggregation::tree`), with leaves of two or four applications.

| Tree | Applications | Each leaf | Root | Root cycles per leaf | Root proof |
| --- | ---: | --- | --- | ---: | ---: |
| BLAKE2s R1CS, 2 × 2 | 4 | 1.60M cycles, 2^25.88 | 509,019 cycles, 2^24.09 | 254,510 | 194,896 B |
| BLAKE2s R1CS, 4 × 4 | 16 | 3.19M cycles, 2^26.88 | 1,040,081 cycles, 2^25.08 | 260,020 | 204,360 B |
| PCS, 4 × 4 | 16 | 3.19M cycles, 2^26.88 | 1,039,892 cycles, 2^25.08 | 259,973 | 204,008 B |
| Keccak R1CS, 2 × 2 | 4 | 4.38M cycles, 2^27.24 | 554,947 cycles, 2^24.09 | 277,474 | 194,736 B |

Each run verified its root natively against the leaf bytecode and rejected six cases: reordered leaves, a changed leaf, a dropped leaf, a moved deferred claim, another leaf program, and a leaf proof for another statement. Peak memory was 8.3 GiB (2 × 2) to 18.1 GiB (Keccak 2 × 2). The root verifies a leaf in about 260,000 cycles, a third of one application's aggregate work, so at four applications a leaf the root adds about 8% per application. The Keccak leaf costs a little more to verify because its bytecode is larger.

`regressions/` reruns upstream after the deferred-claim refactor: the whole `rec_aggregation` library suite passes (37 tests, 5 ignored upstream), including `aggregate_two_to_one` and `leaf_claim_matches_the_general_path`.

`devices/` holds the device kits' tests on this host: `pixel7.py --local` with the x86 binary (client peak 3.2 GiB, which fits a Pixel 7's 8 GB), and the static aarch64 binary producing and admitting a BLAKE2s client proof under QEMU (3.3 GiB). Neither is a phone or Mac timing.
