# Shared small-table integer workload screen (L3)

Both applications use exactly the shielded table set with `LOOKUP_SMALL=1`: RANGE8 (256 rows), NIBBLE_LOGIC `(a,b,a xor b,a and b)` (256 rows), and NIBBLE_ADD `(a,b,carry,sum,carry_out)` (512 rows). There are no per-application tables. The same canonical six-column concatenation and table digest are trusted setup metadata and transcript-bound; fixed table columns are not committed per proof. The product/GKR bus, multiplicity Booleanity, query-to-native-copy binding and joint PCS openings are retained. This is research, opt-in code.

All measurements use CPUs 24-35 and 12 threads. Builds/tests use CPUs 48-63 with four Cargo jobs. Wallet includes witness preparation, proving and encoding, with setup excluded and the base key resident. Lookup verification runs in a separate process. The fresh bit-level verification figures below are same-process diagnostics; the leanVM reference is the orchestrator's supplied result.

| workload/backend | core arithmetic rows | rows after query copies | padded rows | committed F64 words | wallet seconds | peak GiB | bytes | verify ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SHA256 1KiB, lookup | 360,290 | 2,097,088 | 4,194,304 | 55,574,528 | 3.1405 | 6.74 | 361,992 | 6.98 |
| SHA256 1KiB, bit-level, fresh matched seed | 1,761,212 | included | 2,097,152 | 25,690,112 | 1.7249 | 3.68 | 322,940 | 5.89 diagnostic |
| SHA256 1KiB, leanVM reference | | | | 3,232,336 | 0.3083 | 0.3525 | 213,470 | 16.83 |
| Falcon512, lookup modular relation | 8,602,458 | 15,728,512 | 16,777,216 | 222,298,112 | 16.0942 mean | 27.44 | 402,112 | 9.10 / 10.44 |
| Falcon512, bit-level, fresh matched fixture | 8,798,175 | included | 16,777,216 | 205,520,896 | 13.4127 mean | 27.48 | 385,044 | 6.48-6.66 diagnostic |
| Falcon512, leanVM reference | | | | | 1.02 | 0.68 | | |

The historical R1CS references supplied by the orchestrator are SHA256 1.81s and Falcon 13.7s/33GiB. Fresh baseline processes above retain only the base key, reset the transaction RSS high-water mark and omit the aggregator key. Thus the fresh 27.48GiB Falcon baseline supersedes the historical 33GiB for this comparison. An earlier L3 progress message incorrectly called 5.36M words the SHA bit-level R1CS size; that was a VM recursion figure. The correct fresh R1CS size is 25,690,112 words.

SHA256 performs 17 padded compressions in lookup/arithmetic rows. Words have eight 4-bit limbs; additions use NIBBLE_ADD with carry, logic uses NIBBLE_LOGIC, and rotations use bounded nibble splits plus field-linear recombination. XOR of already bounded nibbles uses native characteristic-two addition. Three seeded inputs agree with circuit_suite's independent SHA256 reference. Query counts are RANGE8=1,024, LOGIC=117,172, ADD=80,416, padded to 262,144 queries. Materializing six coordinates adds 1,572,864 copy rows and alignment. The connector suffix then pushes the circuit past 2^21 rows, causing the 2^22 commitment. The lookup bus itself is only 84ms in the profiled run; arithmetic reduction and commitment/openings dominate. Its 55,574,528 words comprise 50,331,648 native arithmetic words, 262,144 multiplicity words, 3,932,160 alignment words, 32,768 packed hash words, and 1,015,808 final PCS padding words.

Falcon keeps the existing Boolean SHAKE256, nine-block HashToPoint cap, sample compaction, norm and compressed-encoding-budget frontend. It replaces the modular relation with canonical residues modulo 12,289, three 512-point forward negacyclic NTTs and 512 pointwise product checks. Integer products use bit products and exact base-16 carry additions, not characteristic-two multiplication as an integer substitute. Operands and quotients are bounded below q; remainders are bounded below q; the seven-nibble product relation is `a*b = q*k + r`. Its 28-bit width is sufficient because q^2 < 2^28. Comparisons are bounded carry checks against constants through the same ADD table. Public-key and centred-s1 bounds are retained in the frontend. No modular-product or q-specific table was added. The frontend API explicitly returns incomplete modular ports, and the lookup adapter supplies all missing NTT/product constraints.

Falcon queries are RANGE8=0, LOGIC=153,088, ADD=884,201, padded to 1,048,576. Its 222,298,112 committed words comprise 201,326,592 arithmetic words, 1,048,576 multiplicity words, 15,728,640 alignment words, 32,768 packed hash words, and 4,161,536 final PCS padding words. The profiled initial wallet was 14.8136s with a 354ms lookup bus; the close comparison was then rerun ABAB:

| round | lookup seconds | bit-level seconds |
|---|---:|---:|
| 1 | 15.534978 | 13.362314 |
| 2 | 16.301693 | 13.996780 |
| 3 | 16.445996 | 12.879046 |

Both Falcon variants use fixture 0. Both accept its SHAKE256(pk||message) digest and valid signature predicate. SHA uses seed 20261023 in both matched runs. There are explicit envelope differences: the old native compiler publishes an application-id-bound BLAKE2s hash of the 64-byte statement; these lookup screens publish the raw 32-byte digest, with Falcon validity constrained to one. They use raw bincode proof encoding rather than the old Certificate envelope. The current bridge rejects zero native compression schedules, so each new screen includes one fixed, unused BLAKE2s anchor compression (128 padded slots). It does not replace SHA256 or SHAKE and imposes disclosed overhead. The first SHA wallet JSON's `compressions:0` is a reporting error in that early executable; the census and final executable correctly report the one anchor. These results do not establish recursive merge support for the lookup applications.

Validation: format_recursion release library suite 90/90; circuit_suite Falcon release tests 18/18; all-target format_recursion clippy with -D warnings. Strict base-verifier rejection tests construct malformed proofs after bypassing host checks: SHA bad carry, sum, table tag and query-copy row; Falcon wrong quotient, remainder=q and an out-of-range operand. The shared shielded wrong-multiplicity and malformed-query tests remain passing. Separate-process SHA/Falcon verification rejects wrong digests and tampered proofs. Artifacts: ht-L3-integer-lookup-tests.log, ht-L3-integer-full-tests.log, ht-L3-falcon-suite-tests.log, ht-L3-integer-clippy.log, ht-L3-sha-lookup-*, ht-L3-falcon-lookup-*, falcon-small-{1,2,3}.*, falcon-bits-{1,2,3}.*, sha-bits-matched.jsonl.

Verdict: the frozen shared set is sufficient to express these integer operations, but this implementation loses on both workloads. The shielded improvement does not generalize to SHA256 or Falcon with the current six-column query-copy layout. Keep the lowering opt-in; do not add a per-application table or adopt it as the default based on this screen.
