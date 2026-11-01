# L3 shielded lookup prototype — partial implementation, not a lookup proof

Baseline local commits: 11276e8f, 168ea19e, 7b49025a, 36e634b1. No push.
Baseline matched native result: 106 BLAKE2s compressions; 148,272 arithmetic rows; 3,211,264 committed F64 words; wallet min-of-3 0.237856497 s (runs 0.237856497, 0.292819994, 0.258052319), peak 560,140 KiB for the min run, 274,272 bytes; separate-process decode+verify 5.173608 ms. Fresh leanVM: 0.150847462 s / 194,484 KiB / 197,990 bytes / 12.787562 ms. First-level merge of distinct spends 0 and 1: 1.631148891 s / 317,064 bytes, 21,990 hash requests, log_rows 20, hash block_log 15. This is not arbitrary-height closure.

## Concrete prototype

`shielded_lookup_prototype.rs` builds the full same spend with byte wires, native compressions, native-field zero/equality gadgets, and table reads. The builder is private and only a census API is exposed: callers cannot accidentally create a proof without the missing lookup argument.

All three spend shapes reproduce the independent BLAKE2s byte reference and the recorded leanVM output for spend 0. Every existing invalid-rule generator is rejected by arithmetic equations or the host table-membership oracle. Tables enumerate canonical tuples and exhaustively test byte arithmetic/logic including wrong sums and out-of-range operands.

Measured source census for every shape:
- Arithmetic rows: 16,890 (88.6% below 148,272).
- Native compressions: 106, unchanged.
- RANGE16 reads: 48.
- BYTE_LOGIC reads: 3,472. Byte range reads use `(a,0,a,0)`; fixed BYTE_LOGIC domain forces a<256.
- BYTE_ADD reads: 68, with 17-byte sums so integer conservation cannot wrap at 128 bits.
- Total reads: 3,588.
- Native arithmetic/hash stack only: 425,984 committed F64 words, excluding lookup argument. This is not a final proof word count or timing.

Fixed index table storage, uncompressed:
- RANGE16: 65,536 rows x 1 column.
- BYTE_LOGIC: 65,536 rows x 4 columns.
- BYTE_ADD: 131,072 rows x 5 columns.
- 983,040 fixed F64 words total (7.5 MiB), plus table tag/layout metadata.
- One u64 multiplicity per fixed row: 262,144 witness words (2 MiB). At most 3,588 reads means 12 multiplicity bits suffice.
- Query tuples padded to 4,096 rows x up to 6 coordinates including a table tag: at most 24,576 F64 words before layout/PCS padding. They must be linked to the same arithmetic witness variables; an independent commitment alone is unsound.
- Naive multiplicity-bit product producer has 262,144 x 12 = 3,145,728 leaves (next power of two 4,194,304). Much of it is identity, but this may dominate. No latency claim is made.

## Reuse and integration

This branch already provides `leanvm_core::gkr::{prove_product_triple,verify_product_triple}` and `leanvm_core::leaf::{prove_balance,verify_balance}`. The newer RISC-V branch provides `leaf::layout::Producer` with committed integer multiplicity columns and bit-expanded product leaves. These are product/GKR buses, not additive LogUp. Plain additive LogUp over GF(2^192) loses even multiplicities, so use the product argument.

Remaining integration work: fixed table commitment/index identity; commitment to multiplicities before fingerprint challenges; table-tagged query coordinates linked to native witness positions; multiplicity bit-range constraint; one shared product/GKR relation; terminal leaf sumcheck and openings; base verifier invocation and transcript/domain binding; malicious multiplicity proof rejection without host prechecks. The current host `same_multiset` test is not cryptographic rejection evidence.

Extend the joint stack/opening rather than disclosing query lists. `PrivateBridge::prove_unchecked` currently commits native+hash stack, then arithmetic reduction, hash reduction and connector openings. Add multiplicity/query regions to the committed stack before sampling challenges, add the bus reduction, and append its terminal claims to the existing mixed WHIR opening. Bind layout/table version in `PrivateBridge::label`. Query columns must be index-wired to native variables or proved with a copy relation; exposing an unconstrained extra query commitment would not suffice.

## End-to-end shared-root lookup prototype (measured)

Source commit follows after this run. `shielded_lookup_native` extends the native bridge with six query-coordinate columns, table-tagged fixed-table digest, and 13 multiplicity bits per table row. The table bus uses the existing batched GKR product reduction and zerocheck Booleanity; all returned query/multiplicity claims are opened through the same WHIR commitment.

12-thread run on CPUs 24-35: setup 0.110454363 s (separate); wallet witness+proof+encoding **1.037028611 s**, peak RSS **973192 KiB**, proof **267080 bytes**, committed words **5111808**, padded arithmetic rows **65536**, 106 BLAKE2s compressions. Separate process verification **63.899263 ms**; wrong digest and tampered proof rejected. The lookup proof itself is soundness-tested against malformed multiplicities/query tuples in `lookup_reduction` unit tests.

This is slower than the 148272-row native bridge (0.238 s / 560 MiB / 274272 B / 5.17 ms) because the first implementation commits an uncompressed multiplicity/table bus and pads it into a 65,536-row arithmetic index. It demonstrates binding and rejection, not the final performance direction.

Prototype census remains 16890 arithmetic rows before query copies; 44992 rows after 4096 query rows x 6 copy coordinates. Fixed table columns total 983040 F64 words, and direct multiplicity bits total 3416064 bits/words before PCS packing.
