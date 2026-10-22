#!/usr/bin/env python3
"""Independently check the complete deterministic closed-tree benchmark output."""
import hashlib
import json
import math
import sys
from pathlib import Path


def digest(data):
    return hashlib.blake2s(data).digest()


def check(path):
    receipt = json.loads((path.parent.parent / 'result.json').read_text())
    assert receipt['ok'] and receipt['files_unchanged'] and len(receipt['runs']) == 1
    run = receipt['runs'][0]
    assert run['ok'] and run['returncode'] == 0 and run['stop_reason'] is None
    assert hashlib.sha256(path.read_bytes()).hexdigest() == run['stdout_sha256']
    events = [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]
    setups = [e for e in events if e.get('kind') == 'setup']
    completes = [e for e in events if e.get('kind') == 'complete']
    assert len(setups) == len(completes) == 1, 'missing or duplicate boundaries'
    setup, complete = setups[0], completes[0]
    depth, chain = setup['depth'], setup['chain']
    assert 1 <= depth <= 8 and 0 <= chain <= 65536
    assert complete['depth'] == depth and complete['chain'] == chain
    assert complete['status'] == 'locally_verified'
    assert setup['official_score'] is False
    assert len(setup['key']) == 32 and setup['key'] == complete['key']
    proofs = [e for e in events if e.get('kind') == 'proof']
    assert len(events) == len(proofs) + 2
    assert len(proofs) == (1 << (depth + 1)) - 1
    found = {}
    totals = {'creation_s': 0.0, 'verification_s': 0.0}
    for e in proofs:
        level, index = e['level'], e['index']
        assert 0 <= level <= depth and 0 <= index < (1 << (depth - level))
        assert (level, index) not in found, 'duplicate proof'
        assert e['height'] == level and e['verified'] is True
        if level == 0:
            start = digest((index + 20261022).to_bytes(8, 'little'))
            assert bytes(e['start']) == start
            for _ in range(chain):
                start = digest(b'\x43' + start)
            expected = digest(b'\x4c' + start + chain.to_bytes(8, 'little'))
        else:
            expected = digest(b'\x4e' + found[level - 1, 2 * index] + found[level - 1, 2 * index + 1])
        assert bytes(e['statement']) == expected, 'independent statement mismatch'
        found[level, index] = expected
        for name in totals:
            assert isinstance(e[name], (float, int)) and math.isfinite(e[name]) and e[name] >= 0
            totals[name] += e[name]
        assert e['certificate_bytes'] > 36 and e['stream_scalars'] > 0 and e['merkle_phases'] > 0
    assert complete['height'] == depth and bytes(complete['root']) == found[depth, 0]
    root = next(e for e in proofs if e['level'] == depth)
    return {'path': str(path), 'leaves': 1 << depth, 'chain': chain, 'proofs': len(proofs),
            'setup_s': setup['setup_s'], **totals,
            'total_s': run['wall_seconds'],
            'measured_stages_s': setup['setup_s'] + sum(totals.values()),
            'cpu_s': run['user_seconds'] + run['system_seconds'],
            'peak_rss_bytes': run['sampled_group_peak_rss_bytes'],
            'root_creation_s': root['creation_s'], 'root_verification_s': root['verification_s'],
            'root_certificate_bytes': root['certificate_bytes'],
            'shape': {k: setup[k] for k in ('native_rows', 'public_len', 'blocks', 'block_log', 'connector_start', 'q_offset', 'stack_log')},
            'key': setup['key'],
            'proof_geometry': [{k: p[k] for k in ('level', 'index', 'statement', 'certificate_bytes', 'stream_scalars', 'merkle_phases')} for p in proofs]}


if __name__ == '__main__':
    print(json.dumps([check(Path(arg)) for arg in sys.argv[1:]], indent=2))
