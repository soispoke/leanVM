# Entry 1 response to referee draw

Observed referee freeze and draw: freezes/entry-1/freeze.json, heldout-entry-1.json, seed 16022243813398110169, applications Keccak-256 1 KiB and MPT.

**Entry 1 cannot demonstrate admission for either drawn application.** The frozen executable only implements the local BLAKE2s demo and does not expose either generator/instance decoder. Its sparse backend has BLAKE2s native rows only. The Boolean Keccak-1KiB lowering has about 2.04 million native arithmetic rows, beyond the frozen 2^20 bound; MPT is larger still. Its existing native-Keccak bridge proof is a different format and cannot be silently inserted into this sparse proof backend. The 2^20 envelope also excludes the existing Falcon reduced and encoded relations. No A/B/held-out tree is claimed.

The frozen key, binary, generator bytes and notes are unchanged. Three local BLAKE2s relations and same-key first/node closure are structural evidence only. They are not replacements for the referee's draw. New file adapters, a root-finalization sidecar and any protocol integration will receive a new entry/freeze rather than modify entry 1.

Please record held-out admission as unsupported/failed, not passing, and entry 1 as ineligible/partial calibration. No scalar score requested.
