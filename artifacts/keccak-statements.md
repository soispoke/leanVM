# Shared Keccak application statements (L6 / L7)

Keccak means Keccak-256 with Keccak-f[1600], 24 rounds, 136-byte rate, Ethereum suffix 0x01 followed by final 0x80, and 32 output bytes. It does not mean SHA3-256. No security parameters change.

## Shielded spend

Use the existing `circuit_suite::shielded_blake2s` two-input/two-output, depth-20 statement and its exact 1,680-byte private input layout. Replace every BLAKE2s invocation by Keccak-256. Tag bytes, field widths, big-endian integer encoding, sibling order, zero-output sinks, validity checks and public amount/fee rules are identical. Public output is the 32-byte statement digest followed by one validity byte, then zero padding to the existing public width. Hash preimages are tag || fields: PK=1 || spend_key32; INNER=5 || owner32 || rho32; COMMIT=2 || inner32 || value16; OCC=7 || commitment32 || index4; NK=6 || domain32 || spend_key32; NULL=3 || nk32 || occurrence32; NODE=4 || left32 || right32. STATEMENT=8 with the exact existing field concatenation in `build_with_breakdown` / `reference::statement_digest`. The deterministic fixture stream also uses Keccak on 0xff || "shielded" || spend_u64_le || counter_u64_le. Fixture generation is outside the proved statement.

## Merkle membership

Use the existing `row_format::merkle_source(seed)` depth-16 statement. Hash the private 32-byte leaf once, then hash left32 || right32 at each of 16 levels. Each private path bit is Boolean; bit zero places the current node left, bit one places it right. No domain tags are added. Words serialize as u64 little-endian. The root is four little-endian u64 public words. Fixture leaf word i = seed*0x10001+i+17 (i=0..3); sibling word i at level l = (seed+3)*0x1000001+4*l+i; path bit l=(seed+l)&1. Replace both leaf and node BLAKE2s by Keccak-256.

## Unchanged statements

Falcon-512, Keccak-256 1 KiB and MPT retain their existing application inputs and predicates. Their protocol envelopes change separately. Falcon SHAKE remains SHAKE with its existing suffix and output lengths, using the same Keccak-f[1600] permutation.

## Vectors

Primitive Keccak-256(empty) = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
Primitive Keccak-256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45.
Application fixture digests will be appended after independent reference evaluation; no wallet result is claimed yet.

Shielded fixture seed `20261024`: statement digest `599943d4ea06d97bbd20b602add63200e167a17a72d9775d91d33fa3eb72e4d3`, validity 1. Independent RustCrypto reference agrees with the Boolean circuit and native-row lowering.

Depth-16 Merkle seed 1 root: `8d1c538daaf507f9783e9cd7a2875ae611664056ac8d05b30bad55d0359dc2a9`. Native sponge agrees at every level with RustCrypto reference; 17 permutations including the leaf.
