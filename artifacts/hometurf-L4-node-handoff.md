# L4 handoff

Code commit: bbb40f7a; rate archive: 76da1ec3; measurements: 49a591fe; analytic appendix: 17067fe5

Wallet inverse-rate 8/16 diagnostics are archived and declined. Active rate is 4. Rate API and executable removed from active path. Results remain under artifacts/L4-rate-diagnostic.

Node diagnostic: merged+merged using separately pinned second-level setup, shielded workload, 25,425 compressions, 818,155 rows, 25,165,824 committed words, 315,816 bytes. 12-thread times: 1.072885297, 1.033059658, 1.057230321, 1.051894053 seconds. Rejections passed. This is not reusable first/tree closure.

Shielded first merge remains 736,150 rows, 21,990 compressions, 1.22 to 1.27 seconds. Existing lowering already fuses single-use mul+add. Archived affine estimate was 169,856 removable rows, measurement-only with no soundness claim. L2 owns true R1CS/CCS.

Additional four-cell screen: skipping tautological equal(variable, same-variable) rows saved 4 rows on shielded (736150 to 736146), with no word reduction. ABAB first-merge times were baseline 1.247934 s, candidate 1.272910 s, baseline 1.263070 s, candidate 1.233095 s; the candidate is not a matched win and was reverted. No adoption.

Final verification: 32 private tests and six closure tests passed. Node changed-child-statement recording is unsatisfied without host admission. Logs in artifacts/L4-node-screen. Direct L1 notification was attempted with the mission tool, but the server returned forbidden: mission outside this session scope. This file is the durable handoff.

Current native-hash arity-one measurement commit: da4ba125af7e27a5e240e5c1217535c65885d6ea. BLAKE64: 288653 rows, 7298 compressions, 99093 F192 Mul nodes, 8388608 words, .483151427 s. Shielded: 367304 rows, 10994 compressions, 109196 Mul nodes, 12582912 words, .663119496 s. Compared with L2 shielded arity-one: 5358592 words, 56938 rows, 36693 EMUL, 5144 HASH. Both native arity-one proofs and all rejection assertions pass; six existing closure tests pass. No rate or row-format change.
