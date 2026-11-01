# L2 RISC-V leanVM home-turf results

Canonical direct-compression guest ELF built with pinned nightly-2026-10-03 at source 0b3d2269; unchanged signature and shielded fixtures remain the checked-in upstream ELFs. All wallet/verify/merge timings: CPUs 12-23, 12 total pool threads, both thread environment variables 12. Builds and diagnostic tests: CPUs 48-63, CARGO_BUILD_JOBS=4. Earlier streaming-hasher guest results are superseded and retained in hometurf-L2-streaming-first; the first direct-instruction samples built on September nightly are archived in hometurf-L2-direct-unpinned. Original JSONL entries pointing at overwritten raw receipt paths should be read from that archive; canonical records appended by this summary point at current direct-instruction receipts. Raw receipt commit field is the original leanVM base a40a7fa6; outer normalized metadata identifies local source. No pushes.

Wallet includes witness generation, proving and proof encoding. Signature generation and fixture preparation, ELF decoding, and recursion setup are excluded. RSS is process high-water and includes resident setup. Independent verification includes proof decode; merged verifier setup is excluded. Leaves use log inverse rate 2 and recursion uses 1. Single development samples, not confidence intervals.

## leanxmss

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.102988 | 124,592 | 187,974 | 12.537 | 2,178 | 146 | 624,584 |

| Merge level | Merge s | RSS KiB | Bytes | Verify ms | Committed words |
|---|---:|---:|---:|---:|---:|
| leaf | 0.353720 | 513,572 | 258,611 | 13.242 | 5,948,416 |
| node | 0.392196 | 529,860 | 259,179 | 15.455 | 5,948,416 |

Verdict: same-program 2-to-1 proof construction and independent verification succeed within the measured times shown here. Both slots repeat one proof; distinct-leaf preparation is not measured. Higher-node proof represents four copies of the leaf claim.

One-leaf recursion verifier: 54,610 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## leansphincs

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.142990 | 160,328 | 211,158 | 11.828 | 9,489 | 532 | 1,033,416 |

Verdict: the native guest proof and independent verifier succeed. This is a leanVM measurement; a cross-system winner requires an identical R1CS relation and comparable soundness/commitment settings.

One-leaf recursion verifier: 59,155 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## hashchain-16

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.075921 | 98,372 | 170,358 | 12.717 | 651 | 18 | 328,872 |

Amortized per application compression: 40.6875 cycles and 20554.5000 committed words. Denominator is 16, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.

| Merge level | Merge s | RSS KiB | Bytes | Verify ms | Committed words |
|---|---:|---:|---:|---:|---:|
| leaf | 0.392821 | 504,368 | 259,915 | 16.472 | 5,948,416 |
| node | 0.426688 | 524,036 | 260,267 | 17.393 | 5,948,416 |

Verdict: same-program 2-to-1 proof construction and independent verification succeed within the measured times shown here. Both slots repeat one proof; distinct-leaf preparation is not measured. Higher-node proof represents four copies of the leaf claim.

One-leaf recursion verifier: 51,764 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## hashchain-256

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.129748 | 124,644 | 188,990 | 13.130 | 6,891 | 258 | 665,128 |

Amortized per application compression: 26.9180 cycles and 2598.1562 committed words. Denominator is 256, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.

| Merge level | Merge s | RSS KiB | Bytes | Verify ms | Committed words |
|---|---:|---:|---:|---:|---:|
| leaf | 0.346030 | 515,236 | 260,107 | 13.733 | 5,948,416 |
| node | 0.397150 | 522,416 | 259,115 | 15.667 | 5,948,416 |

Verdict: same-program 2-to-1 proof construction and independent verification succeed within the measured times shown here. Both slots repeat one proof; distinct-leaf preparation is not measured. Higher-node proof represents four copies of the leaf claim.

One-leaf recursion verifier: 55,629 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## hashchain-4096

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.495015 | 568,064 | 219,894 | 13.097 | 106,731 | 4,098 | 6,164,008 |

Amortized per application compression: 26.0574 cycles and 1504.8848 committed words. Denominator is 4096, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.

| Merge level | Merge s | RSS KiB | Bytes | Verify ms | Committed words |
|---|---:|---:|---:|---:|---:|
| leaf | 0.367518 | 508,828 | 260,171 | 13.383 | 5,948,416 |
| node | 0.396968 | 529,020 | 258,795 | 15.048 | 5,948,416 |

Verdict: same-program 2-to-1 proof construction and independent verification succeed within the measured times shown here. Both slots repeat one proof; distinct-leaf preparation is not measured. Higher-node proof represents four copies of the leaf claim.

One-leaf recursion verifier: 62,870 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## merkle-20

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.073789 | 101,608 | 170,838 | 16.769 | 1,065 | 22 | 336,248 |

Amortized per application compression: 53.2500 cycles and 16812.4000 committed words. Denominator is 20, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.

Verdict: the native guest proof and independent verifier succeed. This is a leanVM measurement; a cross-system winner requires an identical R1CS relation and comparable soundness/commitment settings.

One-leaf recursion verifier: 51,944 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## merkle-32

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.079915 | 105,132 | 174,110 | 13.450 | 1,563 | 34 | 366,200 |

Amortized per application compression: 48.8438 cycles and 11443.7500 committed words. Denominator is 32, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.

Verdict: the native guest proof and independent verifier succeed. This is a leanVM measurement; a cross-system winner requires an identical R1CS relation and comparable soundness/commitment settings.

One-leaf recursion verifier: 52,758 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## shielded

| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |
|---:|---:|---:|---:|---:|---:|---:|
| 0.150847 | 194,484 | 197,990 | 12.788 | 5,957 | 106 | 1,330,872 |

Verdict: the native guest proof and independent verifier succeed. This is a leanVM measurement; a cross-system winner requires an identical R1CS relation and comparable soundness/commitment settings.

One-leaf recursion verifier: 56,938 rows and 5,358,592 committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.

## Verifier stage accounting

The complete machine has EMUL, EXK, HASH, SPLIT, CAST and PUB tables. Unpadded witness words per row are 9, 7, 257, 65, 4 and 0 respectively. A hash row owns a 256-word packed BLAKE2s witness plus one selector; its 18 ports are views into that witness and must not be counted a second time. These differ from the 18 input/output ports alone. Padded totals additionally include power-of-two table heights and the hash/Flock floor; padding has no unique stage owner. Merkle numbers include opening leaf hashing and shared upper nodes. WHIR includes stack-opening target and ring-switch reductions, with Merkle authentication subtracted. Program claim includes bus/table checks plus deferred program binding. All checks remain enabled.

| Workload | Stage | Rows | Unpadded committed words |
|---|---|---:|---:|
| leanxmss | program claim and bus | 4,932 | 148,288 |
| leanxmss | Flock | 3,874 | 223,194 |
| leanxmss | WHIR opening excluding Merkle | 39,359 | 364,771 |
| leanxmss | Merkle paths and leaf hashing | 3,527 | 872,497 |
| leanxmss | announcement, reduction and other | 2,918 | 45,677 |
| leanxmss | Padding and floors |  | 3,704,165 |
| leansphincs | program claim and bus | 5,032 | 149,253 |
| leansphincs | Flock | 3,888 | 224,302 |
| leansphincs | WHIR opening excluding Merkle | 43,383 | 395,387 |
| leansphincs | Merkle paths and leaf hashing | 3,862 | 958,849 |
| leansphincs | announcement, reduction and other | 2,990 | 46,550 |
| leansphincs | Padding and floors |  | 3,584,251 |
| hashchain-16 | program claim and bus | 4,689 | 140,394 |
| hashchain-16 | Flock | 3,854 | 221,536 |
| hashchain-16 | WHIR opening excluding Merkle | 37,248 | 344,605 |
| hashchain-16 | Merkle paths and leaf hashing | 3,116 | 770,665 |
| hashchain-16 | announcement, reduction and other | 2,857 | 44,619 |
| hashchain-16 | Padding and floors |  | 3,836,773 |
| hashchain-256 | program claim and bus | 4,778 | 141,420 |
| hashchain-256 | Flock | 3,881 | 223,748 |
| hashchain-256 | WHIR opening excluding Merkle | 40,376 | 373,485 |
| hashchain-256 | Merkle paths and leaf hashing | 3,639 | 901,281 |
| hashchain-256 | announcement, reduction and other | 2,955 | 46,001 |
| hashchain-256 | Padding and floors |  | 3,672,657 |
| hashchain-4096 | program claim and bus | 5,404 | 164,966 |
| hashchain-4096 | Flock | 3,909 | 225,964 |
| hashchain-4096 | WHIR opening excluding Merkle | 46,194 | 430,588 |
| hashchain-4096 | Merkle paths and leaf hashing | 4,276 | 1,064,990 |
| hashchain-4096 | announcement, reduction and other | 3,087 | 47,675 |
| hashchain-4096 | Padding and floors |  | 3,424,409 |
| merkle-20 | program claim and bus | 4,687 | 140,376 |
| merkle-20 | Flock | 3,854 | 221,536 |
| merkle-20 | WHIR opening excluding Merkle | 37,430 | 346,019 |
| merkle-20 | Merkle paths and leaf hashing | 3,116 | 770,665 |
| merkle-20 | announcement, reduction and other | 2,857 | 44,619 |
| merkle-20 | Padding and floors |  | 3,835,377 |
| merkle-32 | program claim and bus | 4,734 | 140,955 |
| merkle-32 | Flock | 3,860 | 222,086 |
| merkle-32 | WHIR opening excluding Merkle | 38,158 | 351,899 |
| merkle-32 | Merkle paths and leaf hashing | 3,116 | 770,665 |
| merkle-32 | announcement, reduction and other | 2,890 | 45,164 |
| merkle-32 | Padding and floors |  | 3,827,823 |
| shielded | program claim and bus | 5,175 | 155,644 |
| shielded | Flock | 3,874 | 223,194 |
| shielded | WHIR opening excluding Merkle | 41,054 | 381,044 |
| shielded | Merkle paths and leaf hashing | 3,844 | 953,966 |
| shielded | announcement, reduction and other | 2,991 | 46,550 |
| shielded | Padding and floors |  | 3,598,194 |
| sha256-1kib | program claim and bus | 5,319 | 158,399 |
| sha256-1kib | Flock | 3,903 | 225,414 |
| sha256-1kib | WHIR opening excluding Merkle | 43,621 | 404,378 |
| sha256-1kib | Merkle paths and leaf hashing | 4,182 | 1,040,832 |
| sha256-1kib | announcement, reduction and other | 3,094 | 47,733 |
| sha256-1kib | Padding and floors |  | 3,481,836 |
| keccak256-1kib | program claim and bus | 5,037 | 150,401 |
| keccak256-1kib | Flock | 3,895 | 224,856 |
| keccak256-1kib | WHIR opening excluding Merkle | 43,612 | 400,249 |
| keccak256-1kib | Merkle paths and leaf hashing | 4,067 | 1,011,534 |
| keccak256-1kib | announcement, reduction and other | 3,022 | 46,838 |
| keccak256-1kib | Padding and floors |  | 3,524,714 |

## Remaining parity differences

VM commits an extra BLAKE2s digest of public values and binds program identity. Raw-digest R1CS must explicitly account for this. Chain uses reset-IV final compression at each step, not streaming BLAKE2s state; initial value, N and mode are public through the output digest. Merkle sibling witnesses are private and index is public. Shielded has a tagged 65-byte Merkle hash (two compressions), unlike the untagged 64-byte standalone Merkle benchmark. Shielded VM includes one output-wrapper compression: 106 total versus 105 inner-relation compressions. Signature hash digests are 128-bit truncations of BLAKE2s-256 and use the source-defined tweaks/admissibility rules. Signing is not included in signature verification wallet time. Do not interpret these proof-of-execution measurements as zero knowledge or a production security claim.

Rejection evidence: all three chains reject wrong output and tampered proof; both Merkle depths additionally reject a changed sibling against the original root. Shielded host reference/guest tests pass (3 tests); raw 1680-byte fixtures and 32-byte inner digests for shapes 0,1,2 are exported beside the receipts. The existing historical shielded 0.275508294 s receipt is confirmed at 12 threads and retained; current timing variation is not a statement change.
