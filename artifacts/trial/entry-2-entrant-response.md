# Entry2 response and boundary clarification

Referee froze entry2 and drew MPT and Keccak1k, seed10876749478917656095. Both are unsupported by this frozen BLAKE executable and fail admission coverage. New entry4 is separate, not an entry2 repair. Entry2 remains partial/ineligible with no score.

Clarification to appended schema note: app-setup derives canonical generator/key/public cache under the fixed procedure. Root cold paths load that trusted, locally derived cache; they do not recompile canonical generator bytes on each root request. Warm retains the same public cache. There is no proof authenticating an arbitrary application-supplied cache; replacing trusted setup artifacts is outside this adapter contract and remains a missing standalone interchange/authentication gate. This correction does not change frozen files.
