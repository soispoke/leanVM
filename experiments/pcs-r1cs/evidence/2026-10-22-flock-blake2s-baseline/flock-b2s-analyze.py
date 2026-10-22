#!/usr/bin/env python3
"""Postprocess the complete source-bound baseline; does not replace verification."""
import collections
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'flock-b2s-repeated-final'
receipt = json.loads((OUT / 'result.json').read_text())
assert receipt['ok'] and receipt['files_unchanged']
assert len(receipt['runs']) == 1 and receipt['runs'][0]['ok']
events = []
for line in (OUT / 'run-00/stdout.log').read_text().splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(event, dict) and 'record' in event:
        events.append(event)
setup = [e for e in events if e['record'] == 'shared_vk_setup']
assert len(setup) == 1 and setup[0]['trials'] == 3
assert setup[0]['same_process'] and setup[0]['excluded_warmups'] == 0
chain = bytes(64)
for _ in range(2048):
    chain = hashlib.blake2s(chain).digest() + bytes(32)
expected_end = [int.from_bytes(chain[i:i+4], 'little') for i in range(0, 64, 4)]
trials = []
for trial in range(3):
    stages = [e for e in events if e['record'] == 'stage' and e['trial'] == trial]
    assert len(stages) == 15
    assert [e['ordinal'] for e in stages] == list(range(15))
    assert collections.Counter(e['kind'] for e in stages) == {
        'leaf': 8, 'first_level': 4, 'base': 1, 'spine': 2}
    for stage in stages:
        for name, value in stage.items():
            if name.endswith('_ms'):
                assert math.isfinite(value) and value >= 0, (trial, name, value)
        assert stage['accumulator_self_discharge_ms'] <= stage['replica_checks_ms']
        assert stage['online_wall_ms'] <= stage['builder_call_ms_including_setup_and_self_checks']
    summaries = [e for e in events if e['record'] == 'summary' and e['trial'] == trial]
    statements = [e for e in events if e['record'] == 'statement' and e['trial'] == trial]
    assert len(summaries) == len(statements) == 1
    summary, statement = summaries[0], statements[0]
    assert summary['verified'] and summary['mutation_rejections'] == 9
    assert (summary['leaves'], summary['blocks_per_leaf'], summary['total_compressions']) == (8, 256, 2048)
    assert statement['h_start'] == [0] * 16 and statement['h_end'] == expected_end
    assert statement['total_compressions'] == 2048
    assert summary['proof_bytes'] == stages[-1]['proof_bytes']
    assert summary['bundle_bytes'] > summary['proof_bytes'] > 0
    row = dict(summary, root=stages[-1])
    row['all_stage_call_ms'] = sum(s['builder_call_ms_including_setup_and_self_checks'] for s in stages)
    row['all_stage_online_ms'] = sum(s['online_wall_ms'] for s in stages)
    assert row['all_stage_call_ms'] <= row['full_prove_ms_including_setup']
    trials.append(row)

def stats(values):
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'all': values}

metrics = {}
for name in ('full_prove_ms_including_setup', 'root_discharge_ms', 'consumer_verify_ms', 'proof_bytes', 'bundle_bytes', 'all_stage_online_ms'):
    metrics[name] = stats([t[name] for t in trials])
for name in ('online_wall_ms', 'prove_ms', 'setup_ms', 'replica_checks_ms', 'accumulator_self_discharge_ms', 'builder_call_ms_including_setup_and_self_checks'):
    metrics['root_' + name] = stats([t['root'][name] for t in trials])
report = {
    'schema': 1, 'validated': True, 'scope': 'three repeated warm-in-process complete Flock BLAKE2s adapted towers; independent consumer verified each root and rejected nine mutations per trial',
    'shared_vk_setup': setup[0], 'metrics': metrics,
    'process_wall_seconds': receipt['runs'][0]['wall_seconds'],
    'wait4_max_rss_kib': receipt['runs'][0]['wait4_max_rss_kib'],
    'sampled_group_peak_rss_bytes': receipt['runs'][0]['sampled_group_peak_rss_bytes'],
    'source_git': receipt['source_git'], 'tooling_git': receipt['tooling_git'],
    'harness_sha256': receipt['harness_sha256'], 'expected_h_end': expected_end,
    'trials': trials,
}
(OUT / 'analysis.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'trials'}, indent=2))
