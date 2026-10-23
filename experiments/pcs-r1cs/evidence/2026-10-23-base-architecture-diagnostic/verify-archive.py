#!/usr/bin/env python3
"""Validate archived observations independently without extracting executables."""
from datetime import datetime
from pathlib import Path
import hashlib
import json
import statistics
import tarfile

root = Path(__file__).resolve().parent
archive = root / 'raw-evidence.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == (root / 'archive.sha256').read_text().split()[0]
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    assert len({m.name for m in members}) == len(members)
    assert all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
    expected = json.load(tar.extractfile('archive-manifest.json'))
    assert set(expected) == {m.name for m in members} - {'archive-manifest.json'}
    data = {name: tar.extractfile(name).read() for name in expected}
    assert all(hashlib.sha256(data[name]).hexdigest() == h for name, h in expected.items())
assert (root / 'results.json').read_bytes() == data['results.json']
r = json.loads(data['results.json'])
assert r['ok'] and not r['integrated_recursive_closure']
assert not r['whole_tree_speedup_established'] and not r['retained_proving_change']
intervals, geometry, certificates = [], {}, 0
for row in r['rows']:
    prefix = 'raw/' + row['label'] + '/'
    receipt = json.loads(data[prefix + 'result.json'])
    assert receipt['ok'] and receipt['files_unchanged'] and len(receipt['runs']) == 1
    assert receipt['runs'][0]['ok']
    for kind in ['stdout', 'stderr']:
        assert hashlib.sha256(data[prefix + 'run-00/' + kind + '.log']).hexdigest() == receipt['runs'][0][kind + '_sha256']
    events = [json.loads(line) for line in data[prefix + 'run-00/stdout.log'].splitlines() if line.startswith(b'{')]
    setup, complete = events[0], events[-1]
    proofs = events[1:-1]
    leaves = [p for p in proofs if p.get('level', 0) == 0]
    assert len(leaves) == 2 and complete['status'] == 'locally_verified'
    statements = {}
    for p in leaves:
        initial = hashlib.blake2s((p['index'] + 20261022).to_bytes(8, 'little')).digest()
        assert initial == bytes(p['start'])
        state = initial
        for _ in range(row['chain']):
            state = hashlib.blake2s(b'\x43' + state).digest()
        statement = hashlib.blake2s(b'\x4c' + state + row['chain'].to_bytes(8, 'little')).digest()
        assert statement == bytes(p['statement']) and p['verified'] is True
        statements[p['index']] = statement
    if row['variant'] == 'control':
        assert len(proofs) == 3 and proofs[-1]['verified'] is True
        assert bytes(proofs[-1]['statement']) == hashlib.blake2s(b'\x4e' + statements[0] + statements[1]).digest()
        assert proofs[-1]['statement'] == complete['root']
    else:
        assert len(proofs) == 2
    assert row['base_creation_s'] == sum(p['creation_s'] for p in leaves)
    assert row['all_creation_s'] == sum(p['creation_s'] for p in proofs)
    assert row['base_proof_bytes'] == [p['certificate_bytes'] for p in leaves]
    assert row['shape'] == {key: setup[key] for key in row['shape']}
    signature = (setup['key'], [{key: p[key] for key in ['index', 'statement', 'certificate_bytes',
                                                       'certificate_digest', 'stream_scalars', 'merkle_phases']} for p in proofs])
    key = row['chain'], row['variant']
    assert key not in geometry or geometry[key] == signature
    geometry[key] = signature
    intervals.append((datetime.fromisoformat(receipt['started_utc']), datetime.fromisoformat(receipt['finished_utc'])))
    certificates += len(proofs)
intervals.sort()
assert all(end <= start for (_, end), (start, _) in zip(intervals, intervals[1:]))
assert certificates == r['audited_certificates'] == 30 and len(intervals) == 12
for s in r['summary']:
    rows = [x for x in r['rows'] if (x['chain'], x['variant']) == (s['chain'], s['variant'])]
    assert len(rows) == s['trials'] == 3
    assert statistics.median(x['base_creation_s'] for x in rows) == s['two_base_creation_s']
    assert statistics.median(x['base_creation_s'] / 2 for x in rows) == s['mean_per_base_s']
for row in r['census']:
    assert row['arithmetic_rows'] == 781 + 774 * row['chain']
    assert row['boolean_rows'] == 256 * (row['chain'] + 1)
    assert row['witness_satisfied']
for label, sources in json.loads(data['source-maps.json']).items():
    receipt = json.loads(data['raw/' + label + '/result.json'])
    for path, name in sources.items():
        assert hashlib.sha256(data[name]).hexdigest() == receipt['file_sha256_before'][path]
failed = json.loads(data['raw/cheap-base-probe-control-c16384-t1/result.json'])
assert not failed['ok'] and failed['runs'][0]['stop_reason'] == 'sampled process-group RSS budget'
failed = json.loads(data['raw/vm-common-full-length-c16384-t1/result.json'])
assert not failed['ok'] and failed['runs'][0]['returncode'] == 101
assert b'ChildOutOfRange { log_committed: 30 }' in data['raw/vm-common-full-length-c16384-t1/run-00/stderr.log']
assert r['vm_comparison']['complete_trees'] == 0
print(json.dumps({'ok': True, 'archive_files': len(expected), 'complete_processes': 12,
                  'certificates': certificates, 'extra_rows_per_hash': 774, 'vm_failure_reconciled': True}))
