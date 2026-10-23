# Common-key AVX2 round-one zerocheck

Rejected packed AVX2 multiplication under the frozen retention rule; accepted Rust sources restored.

The control is the accepted hybrid opener at f23eddd9. These are chain16 local fixtures. Both variants use the same verifier, keys, circuit shapes, security settings, statements, transcript order and certificate encoding.

Eight carryless bit steps multiply 32 independent AES-field bytes in parallel, followed by the same widened shift/reduction. AVX2 is selected only for x86 builds without GFNI. NEON, GFNI and scalar paths remain available.

Every one of the 65,536 byte products matches the scalar field oracle. Kernel checks cover edge values, random data, unaligned offsets and medium positions; complete zerocheck Proof objects, claims and the next transcript challenge match the scalar kernel. The full run passes 72 Flock, 77 native and 44 PCS tests (one pre-existing PCS ignore), Clippy, formatting and PCS/native rustdoc. Explicit RUSTFLAGS checks cover wide GFNI/AVX-512 workspace, AVX2-only and scalar configurations.

Broader Flock rustdoc has a pre-existing broken Keccak-f[1600] link. It fails identically on both variants with identical keccak.rs bytes; it is recorded rather than reported as passing.

## Three-pair two-leaf screen

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 7.478 | 7.318 | +2.97% | 3/3 |
| All proof creation | 4.438 | 4.378 | +2.80% | 3/3 |
| Root creation | 1.249 | 1.223 | +4.23% | 3/3 |

## Seven independent eight-leaf confirmation pairs

| Measure | Control median (s) | Candidate median (s) | Paired reduction | Wins |
| --- | ---: | ---: | ---: | ---: |
| Whole process | 22.895 | 22.725 | +0.74% | 5/7 |
| All proof creation | 19.732 | 19.647 | +0.74% | 5/7 |
| Root creation | 1.277 | 1.261 | +0.60% | 6/7 |

The predeclared retention bar is at least3% paired median improvement in total or creation, at least6/7 target wins, a positive bootstrap95 lower bound, no companion total/creation regression over1%, and exact keys/shapes/statements/proof geometry. The 2.97% total screen was treated as promising, not a retention pass; confirmation uses seven new pairs.

Every process is fresh, locally verifies every certificate, and is checked against independently recomputed statements plus the published common-key geometry. Timed jobs alternate order and have no overlapping recorded intervals. Positive paired reductions mean faster; median ratios need not equal the ratio of medians. No timed observations are removed.

Yukon upstream was checked and pinned at1ffa172. Rust1.99.1, native CPU plus pclmulqdq, 32 workers, CPUs0-63, four Cargo jobs. Build/test budget96GiB, timed budget16GiB, reserve40GiB. The Xeon Gold6230R host is shared. Memory is sampled process-group RSS, not cgroup isolation. No new matched leanVM or original Flock speedup is claimed.

The archive records failed drafts, formatting mutation, interrupted checks, corrected gates and the architecture flag-precedence correction. Initial per-target flag checks were shadowed by the runner RUSTFLAGS; only the later explicit-env checks establish the feature matrix. Early compile failures and interrupted gates were excluded before timing. The interrupted old PGO command was not restarted; its resumed build and use-build receipts were already present.

The source patch, predeclared plan, exact commands, raw logs, source/binary hashes, frozen-control build reuse receipts, exclusions and all timed receipts are preserved. Run python3 verify-archive.py for archive integrity without extraction. Formal composition/security proof and official recursion.fast integration remain open. The optimization goal remains active.
