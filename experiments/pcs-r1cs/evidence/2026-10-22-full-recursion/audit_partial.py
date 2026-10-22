#!/usr/bin/env python3
"""Validate completed full-length trials without treating missing runs as data."""
from pathlib import Path
import importlib.util
import json
import statistics

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('full', BASE / 'audit.py')
full = importlib.util.module_from_spec(spec)
spec.loader.exec_module(full)
result = {}
for depth in (1, 2, 3):
    folder = BASE / f'depth{depth}-chain16384'
    groups = {}
    for backend in ('native', 'leanvm-mu30'):
        runs = []
        for receipt in sorted(folder.glob(f'{backend}-trial-*/result.json')):
            if receipt.parent.name.endswith('-guard'):
                continue
            record = json.loads(receipt.read_text())
            if record['returncode'] == 0 and record['stop_reason'] is None:
                runs.append(full.run_values(receipt.parent))
        assert len(runs) <= 3
        if runs:
            assert all(run['shapes'] == runs[0]['shapes'] for run in runs)
            numeric = [k for k,v in runs[0].items() if isinstance(v, (int,float))]
            groups[backend] = dict(trials=len(runs), medians={k:statistics.median(r[k] for r in runs) for k in numeric},
                                   max_rss_gib=max(r['rss_gib'] for r in runs), runs=runs)
        else:
            groups[backend] = dict(trials=0, medians=None, runs=[])
    result[str(1 << depth)] = groups
(BASE / 'partial-summary.json').write_text(json.dumps(dict(status='incomplete', chain=16384, workloads=result), indent=2) + '\n')
print(json.dumps({leaves:{name:dict(trials=g['trials'], medians=g['medians']) for name,g in groups.items()} for leaves,groups in result.items()}, indent=2))
