# Compact private stack experiment

22 October 2026. Local engineering evidence; no formal security certificate or numerical soundness claim. Yukon tooling: `86b1153b747d3ae442901dbc97ae475801c3e28e` (local and upstream master matched). No Lean sources changed.

## Construction

The standalone arithmetic argument retains its original four F64 slots per F192 column. Only the private joint commitment packs each column's three used limbs consecutively: 12n native words instead of 16n. Native witness openings are mapped to the new offsets; index openings and permutation addresses remain unchanged. All 18 connector words still receive low-limb and two zero-high-limb openings. The Flock region starts at the next multiple of its length after 12n. Both concrete and symbolic bridge transcript domains are version 2 and retain all layout metadata. A non-power-of-two offset is valid because it remains aligned to the Flock region length.

Two layouts were measured:

- **Natural:** smallest power-of-two logical joint domain.
- **Padded:** keep at least 32n logical words, retaining a zero suffix that
narrows initial Merkle leaves. This is a separate candidate, not a winner.

For Flock length 4n, the old layout stores 20n words in a 32n domain. Natural packing stores 16n in a 16n domain, with 64 initial lanes instead of 40. Padded packing stores 16n in a 32n domain, with 32 lanes. Domain size and leaf width therefore trade off; reducing the domain does not guarantee faster recursion.

## Commits

- `b6f093913a30329c33a8ec5be7f89524bc029f5b`: natural compact mapping, labels,
and direct layout controls. Based on `e972e0ce`.
- `38557bfcc1f1fbd8dd3dca4f67695c16e03836c4`: root's fixed-input hash
precomputation (`30f62587`) cherry-picked for the matched comparison.
- `de5cb28ce8749e06cd7d57d4864fa1fc68533681`: padded alternative only.

Root integrated natural mapping separately as `56d7b50e`. Do not cherry-pick `38557bfc` if the root's original precomputation commit is already present.

## Measured local smoke runs

Two leaves of chain length 16, one parent, four workers on CPUs 56-59. Same Xeon Gold 6230R, native/PCLMUL release build. Each is one trial; no warmup or statistical performance claim. All proofs and parent statement checks passed.

| Candidate | Parent prove | Rust verify | Total root proof | Node compressions after lowering | Whole process | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Natural + fixed hashes | 7.291 s | 8.600 ms | 619,880 B | 32,856 | 9.025 s | 8.443 GiB |
| Padded + fixed hashes | 9.948 s | 9.998 ms | 575,984 B | 34,058 | 12.040 s | 8.620 GiB |

Both parents use 2^22 native rows. Padding reduced proof size by 7.1% while increasing observed proving time by 36%. Its larger verifier trace also failed to cross the hoped-for 32,768-compression threshold. These are alternatives to compare further, not evidence of superiority over the unmodified stack or VM.

The earlier `natural/` run predates fixed-input hash precomputation and overlapped Clippy on the same CPUs. It passed, but use `natural-fixed/` and `padded-fixed/` for the comparison above. Prove timing excludes preprocessing and symbolic child-verifier recording; whole-process timing includes them.

## Validation and receipts

- Natural mapping: 56 release library tests passed, 8.43 s test execution.
- Final padded/fixed combination: 58 release library tests passed, 8.61 s.
- Both include 54 actual malformed bridge proofs rejected (18 slots × 3 limbs),
bypassing prover prechecks, and standalone/symbolic verifier regressions.
- New controls check every copied limb, mapping boundaries, unchanged connector
offsets, invalid fourth-slot/out-of-range/unaligned claims, and aligned, disjoint Flock placement throughout supported row/block sizes.
- Release Clippy for library and tests passed with warnings denied; fmt clean.
- Each run used memguard admission, 24 GiB process budget and the shared 40 GiB
reserve. No resource stop occurred. `result.json` records source/binary hashes, exact command, host, affinity, thread count, Rust flags and measured resources.

Receipts: `natural-fixed/{started.json,result.json,stdout.jsonl,stderr.log}` and `padded-fixed/{started.json,result.json,stdout.jsonl,stderr.log}`. Test receipts: `library.log`, `library-padded.log`, `clippy.log`, `clippy-padded.log`. Consolidated machine-readable results: `summary.json`. Preserved binaries are beside them.

This remains a family of separately preprocessed recursion levels, with no closed fixed-shape key and no new Lean composition proof, zero-knowledge claim, challenge score or matched VM performance claim.
