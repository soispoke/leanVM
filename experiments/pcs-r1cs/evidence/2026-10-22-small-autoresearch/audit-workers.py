#!/usr/bin/env python3
"""Validate worker-count screens, including every proof and raw log hash."""
from pathlib import Path
import importlib.util
import json
import statistics

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('series', BASE / 'audit-series.py')
series = importlib.util.module_from_spec(spec)
spec.loader.exec_module(series)
output = {}
for folder in sorted(BASE.glob('workers-*-depth*-chain*')):
    plan = json.loads((folder / 'plan.json').read_text())
    result = {}
    reference = None
    environment = None
    for worker in plan['workers']:
        runs = []
        for trial in ['warmup', *(f'trial-{i}' for i in range(plan['repeats']))]:
            values, shape = series.metrics(folder / f'w{worker}-{trial}')
            checked = series.audit.trees.load(folder / f'w{worker}-{trial}')
            assert checked['environment']['worker_count'] == str(worker)
            current = {k:v for k,v in checked['environment'].items() if k != 'worker_count'}
            if environment is None:
                environment = current
            assert current == environment
            assert checked['binary_sha256'] == plan['binary']['sha256']
            assert checked['source_commit'] == plan['binary']['revision']
            if reference is None:
                reference = shape
            assert shape == reference, 'worker count changed shape or proof length'
            if trial != 'warmup':
                runs.append(values)
        result[str(worker)] = dict(trials=len(runs), medians={key:statistics.median(r[key] for r in runs) for key in runs[0]}, runs=runs)
    paired = {}
    if len(plan['workers']) == 2:
        left, right = (result[str(w)]['runs'] for w in plan['workers'])
        paired = {key:series.paired([(a[key],b[key]) for a,b in zip(left,right)]) for key in left[0]}
    output[folder.name] = dict(all_shapes_and_lengths_identical=True, workers=result, paired=paired)
(BASE / 'workers-audit.json').write_text(json.dumps(output, indent=2) + '\n')
print(json.dumps({name:{w:r['medians'] for w,r in row['workers'].items()} for name,row in output.items()}, indent=2))
