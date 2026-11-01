# Entry 7 results supplement

The unchanged frozen binary passed all 90 cold/warm requests. External medians and maximum process HWM are in `universal-compact-v2/summary.json`; all raw requests are in `samples.jsonl`. Public derivation is included in each cold invocation, and warm startup before ready is recorded separately. OS page cache was uncontrolled.

Exact referee seed 4324567479184108561 drew MPT and Merkle-Keccak. Four independent seeded leaves (shielded, MPT, published depth-16 Merkle, shielded), two first merges, node, root, profile and outer admission passed in `entry7-heldout/`. This is finite-pool held-out support without Falcon; it does not satisfy the required A+B+held-out gate. The failed earlier `universal-compact-v1` smoke used the prior binary and is not cryptographic rejection evidence.

Aggregate retained trace+key totals 55,649,192 bytes. Shielded, Keccak1KiB and MPT retain 11,155,468 / 1,747,596 / 39,195,260 bytes. Runtime RAM still exceeds 1 GiB; cold regeneration is substantially slower. No eligible score. Depth two is tested, not authenticated by a height bound. The security correction supplement and census supersede inherited inverse-rate16 wording: sparse backend has a joint inverse-rate4 WHIR stack, no separate index commitment. No independently certified composition budget or upgrade backend exists.
