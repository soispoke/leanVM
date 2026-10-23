# Hometurf statement contract

The native bridge proves application compressions, not just claim hashing. `native_hash::Builder` creates packed u64 words, arithmetic constraints and compression connectors. `compress(h, m, counter, flags)` accepts four packed CV words, eight packed message words, the byte counter and packed f0/f1 flags. The final block uses f0=0xffffffff, f1=0. All eighteen input/output packed words are wired into the bridge; outputs can be reused directly by later compressions. `hash_words` applies the standard BLAKE2s-256 IV, streaming counters and final padding to an aligned word string. It does not substitute a software-hash witness for a constraint.

`constant` creates verifier-supplied public anchors, deduplicated by value. A verifier must use the trusted expected anchors, not accept arbitrary prover-supplied constants. `expose` marks statement outputs. Boolean gates, bounded decomposition, packing and selection retain their constraints. The bridge's commitment and fixed index bind all copy links and compression I/O. This implementation is experimental and is not a new formal security certificate.

For BLAKE64/1KiB, the message byte at position i is i modulo251, fixed as in the VM `programs/hash` guest. Hash with standard BLAKE2s-256, counter equal to bytes consumed and final on the last block. Commit little-endian u64 length followed by the full32-byte digest; the public output is BLAKE2s-256 of those40 bytes. The extra output hash is included in wallet timing and compression counts. Earlier raw-digest/private-message screens in the shared JSONL are superseded by final matched entries.

The native Merkle circuit decomposes the full64-bit index, using only the low depth bits for directions, matching the VM guest's treatment of high bits. Length, depth and count are specialized into the R1CS key; the VM reads them at runtime and binds its program identity. Both systems include the same final output hash. The chain and Merkle definitions and exact signature parameters below are L2's agreed contract.

# Home-turf statements, L2 leanVM

Source base a40a7fa6, local branch hometurf/L2. Leaf WHIR log inverse rate 2; recursion log inverse rate 1. All timed runs use 12 total pool threads and CPUs 12-23. Proofs are not zero knowledge. No soundness settings were changed.

## Signature verification

Exact source specification is programs/leanxmss/guest/src/lib.rs and programs/leansphincs/guest/src/lib.rs in leanvm-riscv. Deterministic fixtures are host::batch(1), seed = 32 zero bytes, message = four little-endian u64 words 0x4242424242424242. XMSS leaf index = 1234. Guests verify the full signature and publicly commit the key (root then public parameter), index (XMSS only), then message. Public output is BLAKE2s-256 of these serialized little-endian words, represented as four little-endian u64s. Signatures are advice, not public outputs. Exact advice and output JSON receipts live in artifacts/hometurf-L2 after refreshed wallet runs.

leanXMSS parameters: 128-bit digest, public parameter 128 bits, V=42 chains, W=3 bits (Winternitz radix 8), chain length 8, 99 remaining verification chain hashes, target sum 195, Merkle height 32, public key 32 bytes, signature 1208 bytes. Tweak hash = first 16 bytes of BLAKE2s-256(tweak[16] || public_parameter[16] || payload), protocol domain 0; tweak byte layout is domain, type, layer=0, zero, position u32 LE, tree=0 u32 LE, index u32 LE. WOTS endpoint aggregation and encoding follow the source exactly; do not replace this with ordinary XMSS.

leanSPHINCS parameters: 128-bit digest, W=3 bits (radix 8), V=42, chain length 8, target sum 191, D=3 layers with heights [12,7,7], total H=26; FTS A=10, K=15 with 14 FTS trees; public key 32 bytes, signature 4924 bytes. Protocol domain 1. Tweak hashing truncates BLAKE2s-256 to the first 16 bytes, over tweak || public_parameter || message. Admissibility and encoding checks are required. VERIFY_HASHES=497 is a logical hash count, not the VM compression instruction count (532 including public-output hashing).

## Hash chain

N = 16, 256, 4096. Let x0 = 32 zero bytes and x(i+1) = BLAKE2s-256(x(i) || 32 zero bytes). Each step is exactly one full, final BLAKE2s compression with standard BLAKE2s-256 IV/parameter block, byte counter 64 and final flag set. This is sequential dependency between independent one-block hashes, implemented as one direct BLAKE2s compression instruction per step with h=the fixed BLAKE2s-256 IV, message=x(i)||32 zero bytes, counter=64, final flag set. The seed is public; the intermediate values need not be public. VM guest is programs/hometurf/guest and uses the bare compression instruction (not the streaming SDK hasher). Public serialized words: x0 (4 u64), mode=0, N, index=0, xN (4 u64), all little-endian. VM output is BLAKE2s-256 of those 88 bytes (2 additional compressions). Input N is public via commitment, rather than specialized into the program.

## Merkle path

Depth d = 20, 32. Leaf = 32 zero bytes, index = 0x55555555 masked to d bits. At level l from leaf upward sibling consists of four little-endian u64 words each equal to l+1. If bit l of index is zero, parent = BLAKE2s-256(current || sibling); otherwise parent = BLAKE2s-256(sibling || current). Full 32-byte digests, no domain prefix; exactly one final compression per node at byte counter 64. Siblings are private advice; leaf, depth, index and root are public. Guest commits leaf (4 u64), mode=1, d, index, root (4 u64); output is BLAKE2s-256 of those 88 bytes. The benchmark uses this deterministic path, but the proven relation permits any sibling witnesses yielding the same public root.

## Parity notes

The VM additionally hashes public committed values to a four-word output, binds its program identity, and proves RISC-V execution. R1CS must record whether it binds those same public values directly or reproduces this final hash. Timings exclude deterministic signing/key generation: the wallet starts with a signature to verify. They include proof witness generation and proof encoding. Separate-process verification includes proof decoding. Setup is separate. Recursion currently repeats the same valid child proof in both slots; this establishes same-program aggregation cost and does not measure preparation of two distinct leaves.


## Shielded relation

The complete BLAKE2s-edition spend is ported in `circuit_suite::shielded_blake2s`, with native compression calls in `shielded_application::application_vm`. Deterministic `leanvm_input(0)` matches the VM host's first spend byte for byte. The circuit retains all rule checks and Boolean input/range checks, hashes105 application compressions and one final public-output compression. Its public output words are [8148722794000879574,12273388761951158148,13463691297944637417,5783332347444188522]. The lookup census and the experimental shared-root LookupBridge are excluded from the wallet comparison. The latter supplies a separate proving API and binds query copies and Boolean multiplicity bits to the joint root.

## Measurement and artifacts

`experiments/pcs-r1cs/measure_hometurf.py` runs native wallets on CPUs0-11 with twelve threads, then verifies each proof in a new process. It checks VM output parity and appends the required schema to P/artifacts/hometurf-12t.jsonl. Wallet timings include witness, proof and encoding; verify timings include decoding. Process RSS includes fixture/setup. Deterministic signing and index setup are excluded from wallet time. Source commits and comparison-binary SHA values are in note fields. Current final summaries are in P/artifacts/hometurf-L1-final; proof transport bytes and committed witness words are separate metrics.

## Baseline push

L1 native hash benchmark evidence and frozen release gates were archived and pushed fast-forward to `publish/research/r1cs-recursive-verifier` at commit `ed65df0f`. The committed L3 shared-root lookup prototype and corrected L4 census/report commits were subsequently integrated and gated. The rejected shared-parent patch is archived only and is not enabled. Lane worktree edits were not imported.
