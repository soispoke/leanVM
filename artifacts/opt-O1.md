
## Rejected candidate: field/q table offset repacking

I tested placing the Keccak q table at offset zero and the three F64 arithmetic limbs after it, updating all native and deferred claim offsets. The relation tests passed, including false permutation output, swapped connector wiring and tampered proof rejection. The candidate was rejected before ABAB because it cannot lower the power-of-two boundary: 16,777,216 q words plus 5,242,880 field words still requires a 2^25 committed stack, versus the control’s 16,777,216 q words plus a 16,777,216 aligned field region. It would increase the logical occupied range, and therefore cannot approach the 2^24 target. Source changes were discarded.

## Stage census

Tracing diagnostic binaries show, on a first-level mixed merge, approximately 0.56 s hash witness, 0.85 s joint commitment, 0.35 s Keccak reduction and 0.79 s joint opening in one representative run. Node shows approximately 0.44 s hash witness, 0.78 s commitment, 0.34 s reduction and 0.79 s opening. The release JSON stage census remains authoritative for row counts: first 999,496 rows and 33,554,432 words; node 1,139,668 rows and 33,554,432 words.
