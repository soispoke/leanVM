#!/usr/bin/env python3
"""Check the retained profile criteria, exact baseline source and batch coverage."""
from pathlib import Path
import hashlib
import json

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

freeze = json.loads((BASE / 'baseline-freeze.json').read_text())
for name, expected in freeze['files'].items():
    assert digest(ROOT / name) == expected, name
assert digest(Path(freeze['binary'])) == freeze['binary_sha256']
workers = json.loads((BASE / 'workers-audit.json').read_text())
primary = workers['workers-wide-validation-depth3-chain256']
assert primary['all_shapes_and_lengths_identical']
assert primary['workers']['16']['trials'] == primary['workers']['32']['trials'] == 9
for metric in ('root_s', 'total_s'):
    result = primary['paired'][metric]
    assert result['median_paired_reduction'] >= .03
    assert result['positive_pairs'] >= 8
    assert result['bootstrap_median_95pct'][0] > 0
assert workers['workers-wide-validation-depth1-chain256']['paired']['total_s']['median_paired_reduction'] < 0
runner = digest(BASE / 'bench-research-used.py')
processes = proofs = 0
for pattern in ('trace-depth*', 'stack-depth*', 'workers-*-depth*'):
    for folder in sorted(BASE.glob(pattern)):
        if not folder.is_dir():
            continue
        for path in folder.glob('*/result.json'):
            if path.parent.name.endswith('-guard'):
                continue
            guard = json.loads(path.parent.with_name(path.parent.name + '-guard').joinpath('result.json').read_text())
            assert guard['ok'] and guard['files_unchanged'] and guard['harness_sha256'] == runner
            rows = [json.loads(line) for line in (path.parent / 'stdout.jsonl').read_text().splitlines()]
            processes += 1
            proofs += sum(row['kind'] == 'proof' for row in rows)
assert (processes, proofs) == (96, 960), (processes, proofs)
original = (BASE / 'run-original.py').read_text()
expected = original.replace('ROOT = Path(__file__).resolve().parents[3]',
                            "ROOT = Path('/root/workspaces/mission-9abcee72/leanvm-opt')")
expected = expected.replace('time.sleep(0.5)', 'time.sleep(0.01)')
assert (BASE / 'run-precise.py').read_text() == expected
print(json.dumps(dict(status='retained_profile_validated', tree_processes=processes, proof_records=proofs,
                      source_files=len(freeze['files']), baseline_binary_unchanged=True,
                      scope='32 workers for measured four/eight-leaf cases on this host; retain 16 for two leaves')))
