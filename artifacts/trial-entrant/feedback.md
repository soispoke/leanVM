# Entrant feedback (red team, never a scored entry)

1. **ambiguous — conflicting application bounds.** Fixed setting allows two real applications; workloads require held-outs merged with A and B and root gate requests three. A four-slot implementation can cite the former to evade the latter. Fix: require at least three real identities plus all wrapper identities simultaneously, with explicit maximum dimensions, depth and claim count.
2. **gameable — per-identity averaging.** Dividing total root time by identity count can hide a 14 ms wrapper behind cheap applications. Historical evidence demonstrates this. Fix: report each settlement and total complete acceptance; specify whether the 10 ms limit is on isolated settlement or allocated complete acceptance. Count wrappers.
3. **ambiguous — historical evidence and provisional hashes.** Trial status allows BLAKE2s measurements but fixed setting mandates Keccak everywhere; clarify eligibility versus provisional reporting and whether a score exists before hash parity. Never mix a BLAKE merge with a Keccak wallet into an unlabelled score.
4. **gameable — deterministic fixtures/setup leakage.** Setup can precompute witness-dependent values if seeded fixtures are predictable, or retain hidden process memory. Fix: coordinator reveals random seeds after artifact freeze; audit retained artifacts and run setup without witness access.
5. **gameable — reduced Falcon.** A decoded-coefficient relation avoids compressed-byte parser constraints and can be presented as full verification. Fix: separate reduced and full score tracks and require raw encoded input rejection vectors.
6. **ambiguous — held-out shape admission.** Frozen identities alone do not guarantee frozen generator bounds or layouts. Fix: coordinator freezes shape bounds before revealing at least two generators; authenticate canonical generator bytes and deterministic keys, then demonstrate three-real-app node merges without regenerating aggregate setup.

These are documented attacks on interpretation; none is represented as implementation progress or an eligible entry.

7. **ambiguous — CPU assignment conflict.** ENTRY-FORMAT specifies cores 36–47 while entrant authorization assigns 0–11; both use 12 threads. Entrant follows explicit 0–11 restriction. Fix: record lane-specific affinities in runner configuration and referee remeasure on common reserved cores.
