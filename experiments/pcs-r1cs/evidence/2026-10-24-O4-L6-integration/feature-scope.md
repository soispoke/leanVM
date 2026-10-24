# Keccak feature gate scope

The required default release suites passed: circuit_suite 79, format_recursion 112, rec_aggregation 43 (ignored tests retain their original status). Keccak format_recursion passed 67 with one ignored; primitives passed 30, fiat_shamir passed 9, and Keccak circuit_suite passed 79 in the preceding attempt. Default and Keccak Clippy passed.

The additional rec_aggregation run with the format_recursion Keccak feature failed 15 of 43 executed tests (28 passed, 5 ignored), preserved in test-keccak.log. This package contains the legacy BLAKE VM guest and hard-coded primitives::hash calls; enabling the shared protocol transcript/PCS hash changes native messages without converting that guest. Failures include its explicit blake2s_hash_chain and VM guest write-once conflicts. This configuration is unsupported by L6's format-recursion feature and is not a claim of Keccak VM support. The independently measured VM implementation is separate. No tests were disabled or verifier checks removed.

Push gating uses all requested default package suites plus the supported Keccak format, circuit, primitive, transcript and Flock suites, followed by reconciliation and exact default certificate compatibility. The failed broader diagnostic remains a published limitation.
