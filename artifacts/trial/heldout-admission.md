# Held-out admission record

The referee exported the actual baseline sparse node key (32 bytes) from `merge-controls/node-r1cs-session/setup.json`, recorded its hash and the two adapter binary hashes, then drew `keccak1k` and `mpt`. The timestamped freeze and draw are in `freezes/referee-r1cs-control/freeze.json` and `heldout-referee-r1cs-control.json`. This is a key-freeze integrity exercise, not a successful entry.

The first-level matrix key differs from the node key. Freezing the node key alone therefore does not satisfy the rule requiring one key for both levels. No full retained setup or deterministic public-generator registry export is established. The key hash must not be interpreted as a hash of all setup dependencies.

Neither selected application has a baseline sparse-child adapter in this worktree: `row_format::source` admits shielded and a merge application, while the first-level example separately adds the BLAKE2s Merkle source. The native Keccak bridge certificates are not sparse child certificates. Fresh standalone inputs can be generated, but merging them under this frozen key is not measurable. No key was rebuilt after the draw and no admission pass is claimed.

The VM Tree is built from a fixed pair of `Program` objects and their leaf shapes (`Tree::new_mixed`). Its public API does not expose a retained aggregate-key artifact. No VM held-out draw has been made under a fabricated key. Source evidence establishes pair-specific construction; an entry-level frozen key/admission test remains unavailable.

## Entrant revisions

Entry 1 was snapshotted with eleven declared objects before its separate Keccak-1KiB/MPT draw. A read-only check at 19:08 UTC found all eleven objects unchanged. Its command interface remains incomplete, so no held-out admission is measured.

Entry 2 changes the executable and claim finalization, so it was independently snapshotted at 19:08 UTC before a new draw, rather than inheriting entry 1's draw. The snapshot includes aggregate setup/cache/trace, local generators and every declared application-retained artifact, including the approximately 275 MiB of application caches in addition to approximately 366 MiB of aggregate retention. `heldout-entry-2.json` selected MPT and Keccak-1KiB. Its manifest explicitly states no decoder for either held-out application and no Falcon composition. Local shielded/Merkle/hash3 composition is useful structural evidence, but is not A+B or held-out admission. A freeze/draw pass is not an admission pass.

Entry 3 is a wallet-only encoded-Falcon diagnostic with no aggregate key or composition adapter. No held-out draw is performed for it.

Entry 4 was independently frozen at 19:20 UTC with its Keccak binary, 1.075 GiB aggregate retained surface and interface notes. The draw selected MPT and Keccak-1KiB. Its finite decoder registry includes both selected cases, but this is a finite known pool, not arbitrary generator universality. Full Falcon remains outside the declared sparse envelope. Held-out run receipts are in `entry-4-referee/`; the complete A+B score remains unavailable.

Entry 4's referee run completed 90 successful tree requests plus three public setup commands. All eight frozen objects remained unchanged. The actual tree was `((A+MPT)+(A+Keccak-1KiB))`, with independent seeded leaves and finalized roots. This demonstrates the selected finite-pool held-out cases with A under one key, but not admission with B, because Falcon remains unsupported. No full challenge admission pass or scalar score is claimed. Per-application caches separately exceed 64 MiB.

Entry 5 changes the bounded envelope and key again. Its new frozen snapshot and separate draw are in `freezes/entry-5/` and `heldout-entry-5.json`; MPT and Keccak-1KiB were selected. Its referee run is queued independently, without retrofitting the earlier entries.

Entry 5 completed its independently frozen MPT/Keccak-1KiB draw with ten complete trees and unchanged tight-key snapshot. It demonstrates selected held-out composition only; Falcon, full admission semantics and the required A/B/held-out tree remain unavailable.

Entry 6 separately froze a canonical native graph parser and passed one novel post-freeze graph: four independent witnesses, two first merges, node and complete root. Six malformed generator descriptions were rejected. Witness construction was upstream and excluded from wallet timing; this is structural parser evidence, not full challenge admission or score eligibility.

Entry 7 completed its compact-retention MPT/Merkle-Keccak draw. Aggregate retained state was approximately 53 MiB and each application retained file was below 64 MiB; public caches were regenerated on cold startup. The run demonstrates the declared compact boundary and selected held-outs, not Falcon or the full score tree.

Entry 8 was independently frozen with grouped/packed public-matrix evaluation and the compact retention policy, then drawn for MPT/Keccak-1KiB. Its held-out receipts are retained separately. As with entries 4, 5 and 7, this is selected held-out composition and does not supply Falcon, security certification or an eligible scalar.

Entry 8 completed all ten independent trees (five cold and five warm), with 93 successful requests and no recorded failures. All six frozen objects remained unchanged. Per-application compact files fit below 64 MiB; complete timing and process RSS remain in `entry-8-referee/summary.json`. No full challenge admission pass is claimed.
