# Entrant report — leanR1CS Challenge v2 trial

Trial window: 2026-10-23 18:01:45–21:01:45 UTC. Local branch `trial/entrant`; no pushes. Timed entrant requests use cores 0–11 and 12 threads; builds/checks use cores 48–63 and four Cargo jobs. All nine entries (0–8) remain partial/ineligible; no scalar score is claimed.

## Submitted entries and referee results

| Entry | Change and source | Result and limitation |
|---|---|---|
| 0 | Baseline, `65745ca1` | Two apps and different first/node keys; incomplete adapter. Merge 0.937 s, root 20.74 ms, own wrapper 7.93 ms. No common-key held-out pass. |
| 1 | Uniform six-slot BLAKE aggregate, `79c337ee` | Three local apps at depth two; frozen referee MPT/Keccak1KiB draw unsupported. Failed admission coverage, not a cryptographic rejection pass. |
| 2 | Complete file/warm BLAKE adapter and root finalization, `cea0251a` | 90 entrant requests and 90 independent referee requests passed for local apps. Referee held-outs unsupported. |
| 3 | Encoded Falcon calibration, `81a17dc6` | Full fixed-padded encoding relation measured; no variable-length support, no sparse composition, fixture setup. Calibration only. Later raw-byte adapter `050dc4f3` accepts explicit pk/message/padded signature. |
| 4 | Uniform Keccak block15, `753e34e6` | 90 entrant + 90 independent referee requests passed; exact referee MPT/Keccak1KiB draw passed under frozen binary. No Falcon. Retained application and aggregate setup, memory and merge gates fail. |
| 5 | Tight Keccak block14, `050dc4f3` | 90 entrant requests passed; exact referee MPT/Keccak1KiB draw passed. Same missing Falcon/upgrade/security gates. |
| 6 | External canonical generator importer, `bc7de4ca` | Three imported graphs and exact referee Keccak1KiB/Merkle draw passed; external witness construction excluded from wallet timer, unscored. |
| 7 | Compact retained public setup, `a131e876` | 90 entrant requests and exact referee MPT/Merkle draw passed. Aggregate/application retained files below 64 MiB; cold regeneration and runtime RAM remain expensive. |
| 8 | Packed/grouped public matrix evaluator, `a8b6f70f` (cross-block validation `480c078e`) | New referee freeze/draw recorded; exact MPT/Keccak1KiB seeded tree passed under frozen binary. Matched root-only improvement; referee90-request cold/warm run passed. No Falcon composition. |

Referee evidence is `referee-report.md`, immutable `freeze-entry-*-result.json` and `heldout-entry-*.json`. Separate `entry-*-entrant-response.md` files record entrant exact-draw results; they are not independent referee measurements. Entry5 independently passed 93 receipts (90 requests plus three public setups); referee warm first/node/root/admission medians4.658s/6.710s/45.14ms/14.35ms. Referee Entry6 independently encoded a novel graph after freeze, admitting four fresh witnesses,two firsts,node androot; six malformed generators reject. External witness construction is upstream/unscored. Entry7 independently passed93receipts (90requests plus3setups),zero failures,10trees and unchanged frozenobjects. Referee cold/warm medians: wallet5.493/3.655s,first18.105/4.541s,node19.950/6.477s,root13.891s/44.591ms,admission5.627s/15.438ms. This confirms the compact setup cost and finite-pool MPT/Merkle support, not Falcon eligibility. Never infer eligibility from a successful finite-pool draw. Every tree lacks the required composed Falcon workload.

## External timing observations

All values below are seconds, cold/warm medians. Each complete entrant series contains 90 requests in five alternating rounds: four independent wallets, two first merges, node, root, admission per mode/round. Warm is one persistent process with public preprocessing; cold is a fresh process with declared retained files. OS page cache is uncontrolled. Cold Entry7 regenerates public matrices and evaluation plans inside the timer; warm startup does so before ready and records that time separately. Warm HWM includes previously executed wallet and merge work.

| Entry | Wallet | First merge | Node merge | Complete root | Outer admission |
|---|---:|---:|---:|---:|---:|
| 2 | .887698/.642456 | 2.341142/1.055478 | 2.880513/1.672611 | 1.367984/.027729 | .794490/.005262 |
| 4 | 6.742923/6.271974 | 11.581585/7.317193 | 13.732532/9.531972 | 4.879147/.079723 | 2.140866/.010333 |
| 5 | 4.390940/3.867849 | 8.719523/5.013506 | 10.630945/7.253891 | 4.147188/.060103 | 2.067824/.012545 |
| 7 | 5.671726/3.698240 | 18.563998/4.499602 | 20.289481/6.244731 | 14.122580/.056246 | 5.693537/.009717 |

Raw samples, serialized certificate directories and boundary labels are in `universal-v3`, `universal-keccak-v3`, `universal-keccak-tight-v1`, and `universal-compact-v2`. Proof transport includes inherited claims, metadata and root-finalization sidecars. Admission verifies the outer proof with deferred matrix claims; complete root acceptance is a separate operation. Warm isolated root-only runs differ from roots after wallet/merge service because allocator retention and public-cache working sets differ.

The independent referee Entry2 medians were wallet .863/.688 s, first 2.299/1.046 s, node 2.936/1.685 s, root 1.432/.0355 s and admission .803/.0158 s. Referee Entry4 warm first/node/root/admission were 7.620 s/9.942 s/75.1 ms/17.7 ms. These are separate observations, not replacements for entrant samples.

## Improvements and limits

The six-slot uniform envelope admits five application identities plus the aggregate identity under one key, including three real applications and two merge levels. Frozen Entry4/5 draws use shielded, Keccak1KiB and MPT; Entry6 adds published depth16 Merkle; Entry7 exact seed `4324567479184108561` uses shielded/MPT/Merkle/shielded independent leaves. The aggregate key is unchanged across tight entries: SHA-256 `65d74ef5bae806e327050dd092de55cf2829e63103d98b6c4d25632ae0d4dd00`. Application setup is publicly derived after freeze, before witness files for external tests. Imported graph structural bounds are explicit and strict fixed-int decoding rejects trailing bytes. External witness generation is upstream, excluded, and never treated as an eligible wallet measurement.

Tight block14 halves committed words versus block15, from 67,108,864 to 33,554,432. Entry5 aggregate setup took 16.593 s, peak 5,600,952 KiB and retained 987,006,975 bytes. Compact Entry7 retains only trace55,649,160 + key32 = 55,649,192 bytes. Shielded/Keccak1KiB/MPT retained bytes are 11,155,468/1,747,596/39,195,260. Public setup took 15.642 s and peak5,434,364 KiB; full-series maximum HWM6,607,072 KiB. Disk retention fits the stated cap; runtime memory fails the wallet cap and cold regeneration worsens latency. `entrant-compact-retained.json` gives every retained-file hash/size.

Structured padding sums the exact same matrix entries with carry/borrow dynamic programming, without dropping constraints. A block15 matched root-only comparison improved 61.399→36.359 ms over ten warm roots/variant. Linear-row batching was neutral/slower (42.17 versus41.69 ms) and was reverted. Packed public addressing improved matched tight roots38.930→36.177 ms (ten each). Extra profile checks, outside the internal root timer, measured aggregate-own settlement14.816 ms median; the individual10 ms target remains unmet. Changed evaluators are separate local builds and never retrofitted into frozen entries.

Falcon parses raw897-byte public key, message and fixed padded666-byte signature through coefficient hints constrained by canonical in-circuit re-encoding. Header/nonce/key, unary magnitude, negative zero and zero tail are checked; original SHAKE, sampler, modular and norm constraints remain, and validity is constrained1. Reduced/full-padded ten-process medians: internal5.959/12.734 s, whole process13.141/26.280 s, RSS14,051,658/28,003,642 KiB, bridge-only proof367064/389456 bytes, native rows6,077,056/10,400,603 and committed words102,760,448/205,520,896. The2.137× internal ratio is calibration, not an eligible fresh workload score. Six unchecked forged proofs reject under each tested encoded/raw-byte binary; honest independent verification succeeds. Variable-length signatures and sparse composition remain absent. See `falcon-encoded-report.md`.

## Exact claim and root invariant

Six slots each carry active Boolean,32-byte key,rowpointF192[22],colpointF192[22],three matrix evaluations; public statement has kind,digest and canonical slots (304 fields including one). F192 is a degree-three extension of F64. Each32-byte digest/key is packed as two128-bit halves in the first two64-bit limbs of twoF192 elements (thirdlimbzero). Public order:one,kind,digest[2],then6slots each(active,key[2],row[22],column[22],values[3]);1+1+2+6×50=304fields. Wallet inherited claims are zero. Child proof/native Keccak validity, ordered child digest, dimensions, key and full workload statement are bound. Same-slot identities agree, distinct active identities differ, and one-hot routing has Booleanity, prefix exclusivity and totalone. Active selectors bind before theta.

Same-identity claims fold with22-round row and column sumchecks. Every merge adds a fresh aggregate claim. Root checks expected digest, outer proof, complete transcript, canonical inactive slots and all active application claims. A transcript-bound native sidecar combines inherited and fresh aggregate claims for one aggregate matrix settlement; all generation time and sidecar bytes are counted. Root uses locally trusted deterministic public derivation, not arbitrary unauthenticated application caches. Conditional accepted-root invariant: every covered wallet predicate, application matrix claim and merge-circuit claim is valid under the underlying proof assumptions and a composition budget still requiring certification. Tested depth2 is not an authenticated depth bound; no height counter exists. Frozen schema wording is corrected only in separate supplements.

## Frozen census and security boundary

Actual aggregate source rows1,150,370;variables1,847,193;native compressions14,419;linear rows882,181;A/B/C nnz2,688,114/2,170,937/1,011,042;maximum row width12. Padded constraints/witness are2^22,hashslots2^14,public304,committedF64words33,554,432. Shielded/Keccak1KiB/MPT source rows347,814/54,430/1,223,981 and variables347,904/54,521/1,224,071. Exact per-application census and actual WHIR query/grinding/OOD vectors are `entrant-frozen-surface-census.json`.

The sparse backend has no separate WHIR index commitment: matrix authentication uses the public matrix hash, and a joint witness/hash stack starts at inverse rate4. Inherited inverse-rate16 index wording belongs to the separate Falcon mixed bridge and is corrected in `entrant-security-boundary-correction.md`. Production parameter derivation targets128-bit per-opening/round Johnson-list/OOD soundness; no certified overall128-bit recursion/composition claim is made. Falcon's bounded sampler has original approximate2^-60.2 honest completeness failure, not a soundness relaxation. ZK=false. Independent security calculator, bit-level upgrade backend and complete coordinator rejection corpus remain missing gates.

## Validation, immutability and failed attempts

Final grouped implementation: default full library117passed/1ignored; tight Keccak72passed/1ignored; parser2passed; packed/column row-format10passed; tight scoped clippy-Dwarnings passed. Direct native fold mutations reject altered inputs/keys/dimensions/digest/output/omissions/transcript; root tests reject missing sidecar,false final value,trailing scalar,omitted aggregate claim. Falcon rejection tests bypass prover prechecks. Five strict decoder rejects are parser evidence, not forged-proof evidence. No Lean proof edits occurred.

All76 checks pass:74 referee-frozen binary/key/setup/interface/manifest hashes across entries1/2/4/5/6/7/8,plus manifest/binary self-consistency forcalibrationentries0/3. Failed block16 overflow, obsolete-binary compact smoke, and initial missing-Merkle-setup attempt are retained and labelled; they are not cryptographic rejection successes. Full proof/generator caches remain outside git; small provenance, responses, summaries and logs are committed locally. No pushes.

## Feedback ranked by impact

`entrant-feedback.md` contains27 tagged gameable/ambiguous/unworkable/too-strict findings and proposed fixes. Priority order:

1. Publish executable independent upgrade backend and exact security/composition calculator (#12,#15,#19).
2. Resolve the two-real-app bound versus required three-app tree and freeze held-out grammar/shape before the draw (#1,#6,#23).
3. Specify complete root identity accounting, inherited/fresh wrapper claims, all sidecars and generator authentication (#2,#10,#14,#16,#17).
4. Enforce fresh independent witnesses and public-only setup/cache accounting; charge cold regeneration and complete runtime memory (#4,#9,#11,#21).
5. Distinguish full raw Falcon parsing, ZK status, protocol Keccak and application SHAKE in every comparison (#3,#5,#13,#20,#22).
6. Standardize cores, open-loop arrivals, ordered multiplicities, p95 latency and unfinished backlog (#7,#18,#24).
7. Require strict decoder consumption, explicit public evaluation-plan classification and authenticated depth bounds (#25–27).
8. Enforce characteristic-two one-hot exclusivity, not parity alone (#8; implementation fixed).

No red-team shortcut is submitted as successful eligibility evidence.

Entry8 grouped affine addressing comparison: ten warm roots each, packed40.858ms versusgrouped38.361ms. Extra profile median aggregate14.204ms (targetunmet), shielded.992ms,Keccak1KiB.332ms,MPT8.595ms. Public allocation/RSS increases are recorded in rawprofile receipts. Full-column table was slower77.008ms versus42.137ms and reverted. New cross-block test and tight clippy passed.

The final linear-run specialization was slower41.155ms versus39.019ms and reverted. Entry8 exact seed16058744104676432397 passed all10requests with fourindependentleaves. Independent referee Entry8 measurements completed successfully (details below).

Public evaluation-plan allocations forEntry8 (logical retained capacity,excluding originalgenerator/allocatoroverhead): shielded29,585,888bytes,Keccak1KiB16,497,552,MPT127,363,344,aggregate104,324,704. Isolatedprofile processHWM2,863,704KiB. These public caches are charged to runtime RAM,not hidden in32-bytekeysize.

Final Entry8 warm service roots forone/two/three applicationidentities: 1 apps 44.922ms external/29.304ms internal, 2 apps 44.177ms external/29.312ms internal, 3 apps 57.685ms external/40.721ms internal. Fivefresh trees each,150requests total; allpass. These include complete root work after wallet/merge service and differ from isolated root-only comparisons. Seeentry8-root-counts/summary.json forperidentityprofiles.

Entry8 independent referee completed93receipts (90requests +3publicsetups),10trees,zerofailures,unchangedfrozenobjects. Cold/warm medians:wallet6.050683/3.680595s,first19.433732/4.573764s,node21.934467/6.472624s,root15.098369/.044551s,admission6.120476/.013272s. This isfinite-poolMPT/Keccakcontrol,noFalconcomposition.

## Trial close

Stopped at2026-10-23 21:01:45UTC afterthefullthree-hourwindow. Allentrantjobsfinishedbeforethedeadline;noongoingresearchprocesses. Ninepartialentries0–8submitted,noneeligible,noscore. FinalrefereereportconfirmsEntry8’s93receiptsandunchangedfreeze. Finaldefault117pass/1ignored,tight72pass/1ignored,scopedclippyclean,76immutabilitycheckspass. Allworkcommittedlocally;no pushes. Stopreceipt:entrant-stop-receipt.json.
