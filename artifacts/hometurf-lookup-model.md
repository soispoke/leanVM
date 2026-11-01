# R1CS with a frozen small lookup set: row and witness model

Status: analysis, no lookup prover or new lookup circuit implemented. Operation counts below are modeled schedules; all quantities labeled measured come from inspected receipts. This supersedes the initial scratch estimate in this file. In particular, proof bytes are not committed words; software BLAKE2s guest cycles are not SHA cycles; 1 KiB SHA-256 has 17 compressions, and 1 KiB Keccak-256 has 8 permutations. The final model uses those distinctions throughout.

## Frozen set and a binary-field qualification

| Frozen table | Inputs and outputs | Entries | Public columns if materialized |
|---|---|---:|---:|
| RANGE16 | x in [0,65535] | 65,536 | 1 |
| BYTE_ADD | a,b in [0,255], cin in {0,1}; sum=(a+b+cin) mod 256, cout=floor((a+b+cin)/256) | 131,072 | 5 |
| BYTE_LOGIC | a,b in [0,255]; xor=a XOR b, and=a AND b | 65,536 | 4 |
| SMALL_MUL | a,b in [0,255]; product=a*b in [0,65535] | 65,536 | 3 |
| BLAKE2s | standard compression h,m,t,final -> out; same native circuit as measured | circuit, not a finite enumerated table | 256 packed F64 witness words/compression plus interface/connector columns |

There are 327,680 enumerated table entries. The uncompressed public table columns occupy 1,179,648 scalar entries, before tags or alignment. They are deterministic verifier-known columns, not fresh per-wallet witness commitments; their evaluations still cost verifier work or a preprocessing key. A packed tagged lookup tuple fits in one F64 word for all four tables, but that does not make checking membership free. The native hash is a circuit/Flock class, not another 65K-entry table: calling its 18 ports the whole committed witness would undercount it by about 14x.

A plain characteristic-p LogUp multiplicity identity cannot be copied blindly into characteristic two: integer multiplicities collapse to parity in GF(2^192), and even repetitions can cancel. The model assumes a sound characteristic-two-compatible GKR membership/function evaluation or equivalent weighted lookup argument that binds every query and its address. Integer count reconstruction or any parity workaround must be proved, not asserted. One shared transcript/argument is a design goal; it does not make different table relations share their witness for free. No soundness claim for a new argument is made here.

## Commitment model, explicit lower and upper cases

Let Q be populated query tuples, A residual ordinary arithmetic rows, T=327680 table entries, and H native hash compression slots. An optimistic query layout commits one packed tuple word, three F64 limbs of an extension-field denominator/inverse, three limbs of a running identity or GKR accumulator, and one selector/address word: 8Q words. A less compact implementation uses 12Q. A includes ordinary binding rows and the six native-hash bridge rows per slot when H is nonzero. The ordinary native R1CS witness costs approximately 12A words before its power-of-two padding. One F64 multiplicity/address-accounting word per fixed table entry costs T; if three inverse limbs for table-side denominators are also committed it costs 4T. Thus raw modeled words are:

`Wlow = 8Q + 12A + T + 256H`, `Whigh = 12Q + 12A + 4T + 256H`.

This is an accounting envelope, not a derived optimal GKR protocol. A protocol with verifier-computed fixed-table inverses avoids the 3T commitment but pays their evaluation cost elsewhere. A sparse table argument might avoid unused table entries but requires a different, fully specified layout. The table multiplicity commitment cannot be silently omitted merely because the values column is fixed. At present there is no implementation proving that 8 words/query is attainable with every required lookup consistency check; use the upper case for planning until that is established.

For rows, count one logical query row plus 1 to 3 argument/wiring rows, so 2Q+A to 4Q+A arithmetic-equivalent rows. These are not RISC-V instruction rows. Fixed table rows are listed separately; a dense table reduction additionally touches T entries. A BLAKE2s compression is one logical native-hash row but 256 packed witness words, plus its interface and connectors (current native R1CS uses six arithmetic bridge rows per slot). Padding/placement can add up to about 2x to these raw totals, and small proofs retain fixed setup/floor costs. A joint stack layout can add further holes; actual committed words must be read from that layout before benchmarking.

## Operation schedule with this table set

Known-byte XOR is native addition in the binary field and needs no BYTE_LOGIC query; AND is not native. Linear constraints binding bytes and outputs remain necessary. RANGE16 does not prove a byte is <256 by itself: use a high-zero constraint, a narrower projection with a proved range bound, or SMALL_MUL(x,1) plus an output-high-zero constraint. Carry outputs from BYTE_ADD are already Boolean by membership.

| Operation | Query tuples | Logical query rows | Arithmetic-equivalent rows | Construction and limit |
|---|---:|---:|---:|---|
| 32-bit add | 4 BYTE_ADD | 4 | 8-16 | ripple four bytes; fix cin=0 and bind all carries; extra output carry proves overflow when needed |
| 32-bit XOR | 0 if inputs are known bytes; 4 BYTE_LOGIC fallback | 0 or 4 | 0 linear rows, or 8-16 | binary-field addition of byte encodings is XOR; range checks for fresh unconstrained inputs are extra |
| 32-bit AND | 4 BYTE_LOGIC | 4 | 8-16 | bind AND outputs; XOR output may be reused |
| 32-bit fixed rotate | 0 if byte-aligned, otherwise at most 8 SMALL_MUL/range queries | 0-8 | 0-32 | split each byte into low/high parts, constrain bounds using power-of-two constant products, reassemble with linear XOR; not an unproved bit-slicing primitive |
| 64-bit add | 8 BYTE_ADD | 8 | 16-32 | same carry chain, eight bytes |
| mod-12289 multiply | 24-40 | 24-40 | 48-160 plus binding rows | 14-bit residues represented as two bytes; 4 byte products for ab, up to 4 for quotient*12289, carry equalities and range checks; prove a*b=q*12289+r and 0<=r<12289 with integer carries, not GF multiplication; quotient bounds and signed normalization required |
| Keccak-f[1600] | 15,168 | 15,168 | 30,336-60,672 | per round 5 one-bit theta rotates*16 + 22 non-byte-aligned rho rotates*16 + 25 chi ANDs*8 =632 queries; 24 rounds; pi, XOR and NOT are linear on established byte/bit encodings |
| SHA-256 compression | 8,544 | 8,544 | 17,088-34,176 | 64 rounds*(6 rotates*8 + Ch4 + Maj8 + 7 adds*4)=5632; 48 schedule words*(6 rotate/shift operations*8 + 3 adds*4)=2880; feed-forward 8 adds*4=32. Zero-fill shifts need proved dropped-bit bounds; the quoted 8-query split includes these checks |
| BLAKE2s compression | 0 generic lookups; one native circuit call | 1 hash row | current bridge 6 rows/slot, plus Flock | 256 packed words/slot, ports alias existing witness; counters, IV, final flag and state dependency must be bound |
| RLP byte parsing | 2-8 per byte, plus fixed header/length comparisons | 2-8 | 4-32 per byte plus comparisons | prefix classes, canonical lengths, bounds and nibble decisions; worst-case bounded arrays and variable-length selection may cost more; this set has no RLP opcode/table |

The fixed-rotate upper schedule uses existing tables, not an extra shift table. If a compiler keeps a full bit decomposition across many rotates it can reduce repeated splits at the cost of more committed wires; that is a compiler tradeoff, not a change to the frozen lookup relations. The operation model does not count host witness computation as zero time.

## Workload counts and parity

SHA-256 1024-byte message requires 17 compressions including padding, giving Q=145248 before 512 input range queries. Keccak-256 rate is 136 bytes, so 1024 bytes requires 8 permutations, Q=121344 before input checks. Both benchmark messages have byte i = i mod 251 and private message words with public digest. A VM output wrapper adds one BLAKE2s compression when committing the 32-byte digest.

The inspected leanVM MPT fixture is `programs/stateproof/host/fixture/mainnet.json`, first account and first storage proof. Header length 649 bytes; account node lengths [532,532,532,532,532,532,372,115,115]; storage node lengths [532,532,532,532,532,211,67]. Header plus nodes total 7381 bytes. Hashing those and the address/slot keys takes 59 Keccak permutations under the source's hash-per-node convention (embedded-node/path details must still be matched by a circuit port). Its modeled Q is about 0.910M-0.954M: 59*15168 plus 2-8 parsing queries per byte. Allow A=10K-50K for trie linking, canonical RLP, comparisons and claim binding. The old 15.0M-row R1CS fixture is an MPT storage-proof workload, not demonstrated byte-identical to this mainnet account-plus-storage fixture. Do not call this a matched-statement speedup.

Falcon-512 source has N=512, not 1024. Three transforms have 3*(512/2)*9=6912 butterflies; allowing another 1024 pointwise/normalization products gives 7936 modular products. HashToPoint uses nine Keccak permutations in the inspected VM source. Model Q=0.402M-0.625M including 24-40 queries/modular product, butterfly add/sub reductions and 20K-60K codec/range/norm queries; A=20K-80K. An algebraic NTT circuit may normalize each residue rather than imitate the VM's lazy signed 64-bit Plantard/Montgomery schedule. That is the same modular relation only when range, exact norm, codec rejection and HashToPoint sampling rules are retained. The old Falcon fixture's message/signature identity also needs confirmation before claiming exact parity.

## Application rows and committed words

Today's bit-level numbers are exact inspected `C-mempool-*-trim-t1/run-00/events.jsonl` rows. Their words are inferred from the committed stack layout: q_offset=12*2^log_rows and 128 hash slots*256 words, not proof bytes. This gives 25,198,592 words for SHA/Keccak and 201,359,360 for MPT/Falcon. Pre-padding residual row estimates are not a promise to keep today's padding boundaries.

| Application | Current bit-level R1CS rows / committed F64 words | Lookup Q; modeled arithmetic-equivalent rows | Lookup raw words low-high; with up-to-2x padding | leanVM RISC-V measured cycles / committed words / words per cycle |
|---|---|---|---|---|
| SHA256 1 KiB | 1,761,212 / 25,198,592 | 145,760; 0.294M-0.585M (A=2000) | 1.518M-3.084M; 1.52M-6.17M | 70,435 / 3,232,336 / 45.8910 |
| Keccak256 1 KiB | 1,897,195 / 25,198,592 | 121,856; 0.246M-0.489M (A=2000) | 1.327M-2.797M; 1.33M-5.59M | 47,956 / 1,885,616 / 39.32 |
| MPT account + storage | 15,001,840 / 201,359,360 (old storage fixture) | 0.910M-0.954M; 1.83M-3.87M | 7.73M-13.36M; 7.73M-26.72M | 396,788 / 13,400,864 / 33.7734 |
| Falcon-512 verify | 8,798,175 / 201,359,360 | 0.402M-0.625M; 0.825M-2.58M | 3.79M-9.77M; 3.79M-19.54M | 147,758 / 7,916,072 / 53.5746 |

RISC-V cycles are not multiplied by a universal words/cycle constant. The displayed ratios come from each measured proof's actual total words and include padding, VM tables and native hashes. Sources for the last two rows are `leanvm-riscv-mpt-wallet-t1/run-00/events.jsonl` and `leanvm-riscv-falcon512-wallet-t1/run-00/events.jsonl`, commit a40a7fa6, CPUs 12-23 and 12 threads.

## Wallet estimates calibrated to actual receipts

The old bit-level native R1CS wallet times (witness+proof, key setup excluded) are SHA 2.06419915 s, Keccak 1.885488521 s, MPT 13.704729783 s, Falcon 13.153263136 s. Dividing the inferred committed words by those times gives 12.21M, 13.36M, 14.69M and 15.31M words/s respectively. These are measured prover+workload throughput calibrations, not a measured throughput of a lookup argument. L2 native-hash R1CS and leanVM have different fixed overheads; a small-query proof need not sustain the large-stack rate.

At the same per-application R1CS words/s, the padded modeled ranges translate to SHA 0.12-0.51 s, Keccak 0.10-0.42 s, MPT 0.53-1.82 s and Falcon 0.25-1.28 s. They exclude any extra lookup-specific CPU work beyond the committed-word calibration. If the new argument halves throughput, double each range. Small proofs also need a fixed overhead allowance; do not quote the low endpoint as an achieved wallet time.

Measured VM SHA/Keccak baselines from new L2 guests: SHA 70,435 cycles, 3,232,336 words, 0.303272 s; Keccak 47,956 cycles, 1,885,616 words, 0.216070 s. These guests commit only the raw digest and read 1 KiB of deterministic private advice; they are direct application baselines, not the older static-circuit receipts.

Measured VM MPT: 13,400,864 words / 1.298550002 s = 10.32M words/s. Falcon: 7,916,072 / 1.022909148 s = 7.74M words/s. The direct BLAKE2s chain at N=4096 gives 6,164,008 / 0.495014896 =12.45M words/s; at N=16 only 4.37M because of floors and fixed costs. These explain why a single universal words/s conversion is too strong. SHA baseline throughput is 10.66M words/s and Keccak is 8.73M words/s, from the separate-process receipts above.

## Verdicts and exactly what is frozen

SHA-256: the set plausibly removes most carry and bit-slicing rows and could reduce witness words by 4x-16x. The modeled 1.52M-6.17M words straddle the measured VM's 3.23M words, and the modeled 0.12-0.51 s straddles its 0.303 s wallet. The compact case reaches parity, while the padded/table-heavy case loses. No native SHA instruction is assumed.

Keccak: XOR is already native binary arithmetic; lookups primarily help AND and efficient representation/range wiring, while fixed rotates are linear if bits remain exposed. A byte-table design is not automatically better than bit-level Keccak. The model predicts a 4.5x-19x witness reduction over the current R1CS layout, subject to table and padding costs. The modeled 1.33M-5.59M words straddle the measured VM's 1.89M; its 0.216 s wallet lies inside the 0.10-0.42 s modeled range. Parity requires the compact table/argument case, and is lost if lookup throughput halves.

MPT: modeled words straddle the measured VM's 13.40M. The low case can reach parity; the high/padded case cannot. Exact RLP/trie operation census, fixture parity and lookup throughput are required. This is a credible parity target, not an established win.

Falcon: modeled words straddle the VM's 7.92M; even the fast predicted wall-time range overlaps 1.02 s. Three NTTs, modular range checks, exact norm and sampler/codec constraints dominate uncertainty. Parity is plausible at the compact end and fails at the padded/high-overhead end. Wider modular multiplication or Keccak-native tables would change the frozen set and cannot be credited here.

Freeze: the four table relations and all domains shown above; polynomial-basis byte encoding, endianness and word packing; table tags, tuple packing and collision domain separation; integer carry/quotient/range semantics; constant-rotation lowering and dropped-bit checks; characteristic-two-safe GKR/lookup consistency protocol, transcript, challenges and soundness analysis; query/table committed columns, multiplicity representation and fixed-column preprocessing; BLAKE2s gate circuit, 256-word packed witness, ports, bridge schedule, IV/counters/final flag; SHA/Keccak padding and exact application fixtures; canonical RLP/trie rules and variable-length bounds; Falcon parameters, codec, sampler, NTT, integer norm and rejection rules; public-value binding and output digest wrapper; proof-of-execution versus zero-knowledge scope; WHIR rate/security and padding/layout; 12 threads on the prescribed CPU slice and timing boundaries. Freeze the relations, not one witness's lookup multiplicities. A proof-system native instruction/interface is an additional protocol commitment, even when its table is not enumerated.

## Final baseline receipt scope

SHA/Keccak source and pinned ELFs are local commit 0b3d2269, checked against host outputs; SHA output additionally matches Python hashlib.sha256 followed by hashlib.blake2s for the VM public wrapper. Both verify in independent processes. Timed CPUs 12-23; exact 12-thread pool; host build CPUs 48-63 with 4 Cargo jobs; guest nightly-2026-10-03. Source be86e5fa adds these small software guests solely to fill the missing measured baseline, not to implement the modeled lookup argument. Files are artifacts/hometurf-L2/{sha256-1kib,keccak256-1kib}-{wallet,verify}.jsonl. All analysis metrics remain in this Markdown; no modeled number is inserted into the measured JSONL as if it were a benchmark.

The low-case row model assumes linear byte expressions are folded into lookup arguments rather than materialized as a fresh arithmetic row for every XOR. If each XOR/rotate output is materialized, its linear binding row and witness words must be added. The 2-4 arithmetic-equivalent rows/query range is a planning allowance for that wiring and the global argument, not a demonstrated compiler lowering. A full GKR circuit may trade these commitments for more evaluation work; measure that tradeoff before making a product or consensus decision. Falcon's nine Keccak calls are a typical-fixture/source estimate: rejection sampling is variable-length and must have the same bound and failure behavior on both sides.
