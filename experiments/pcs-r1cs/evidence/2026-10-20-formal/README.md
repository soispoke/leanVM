# Structured R1CS formal validation

On 2026-10-20, `LEAN_NUM_THREADS=8 lake build` in `formal/quotient` completed successfully with the pinned Lean 4.34.0 toolchain and dependency manifest. The [manifest](manifest.json) records the checked source hashes; the [compressed build log](lake-build.log.gz) retains the full output. The mathlib cache was obtained through its official Azure fallback (`MATHLIB_CACHE_DEBUG_USE_LEGACY=1 lake exe cache get`) after the default endpoint was slow.

The new module proves auxiliary uniqueness, exact gate elimination, full relation equivalence and `Instance.r1cs_soundness`. The root module imports it and checks the exact transitive axioms of all seven new theorems. The soundness theorem uses only `propext`, `Classical.choice` and `Quot.sound`; no `sorryAx` or additional cryptographic axiom is present in its proof dependencies. The assumptions are parameters of the same upstream ideal-model experiment.

The log contains existing upstream deprecation/linter warnings and unfinished declarations in dependencies. The axiom guards verify that the reported theorems do not depend on those unfinished declarations. No upstream theorem or protocol definition was changed. No Rust runtime code was changed or benchmark rerun for this formal-only addition.

The [formal scope](../../../../formal/quotient/README.md#structured-r1cs-comparison) remains essential: the formal public constraints are packed word equations, not a verified identification with the Rust checker's individual bit anchors. Concrete circuit semantics, Rust refinement, PCS implementation, recursive execution, registration and hashing remain outside this result.
