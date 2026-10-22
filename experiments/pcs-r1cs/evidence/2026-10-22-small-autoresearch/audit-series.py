#!/usr/bin/env python3
"""Audit every retained proof and calculate paired improvements by timer scope."""
from pathlib import Path
import importlib.util
import json
import random
import statistics
import sys

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('trace_audit', BASE / 'audit-trace.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

def metrics(path):
    checked, shapes, sizes = audit.read(path)
    rows = [json.loads(line) for line in (path / 'stdout.jsonl').read_text().splitlines()]
    root = [row for row in rows if row['kind'] == 'proof'][-1]
    return dict(total_s=checked['elapsed_s'], root_s=root['preparation_s'] + root['proving_s'],
                root_proving_s=root['proving_s'], root_preparation_s=root['preparation_s'],
                setup_s=sum(row['setup_s'] for row in rows if row['kind'] == 'setup'),
                rss_gib=checked['peak_rss_gib']), (shapes, sizes)

def paired(values):
    changes = [1 - b / a for a, b in values]
    rng = random.Random(20261022)
    draws = sorted(statistics.median(rng.choices(changes, k=len(changes))) for _ in range(20000))
    return dict(baseline_median=statistics.median(a for a, b in values),
                candidate_median=statistics.median(b for a, b in values),
                median_paired_reduction=statistics.median(changes),
                positive_pairs=sum(v > 0 for v in changes),
                bootstrap_median_95pct=[draws[500], draws[19499]], pairs=values)

def main():
    prefix = sys.argv[1]
    output = {}
    for folder in sorted(BASE.glob(prefix + '-depth*-chain*')):
        plan = json.loads((folder / 'plan.json').read_text())
        trials = plan['trials']
        runs = []
        reference = None
        for trial in ['warmup', *(f'trial-{i}' for i in range(trials))]:
            left, ls = metrics(folder / f'baseline-{trial}')
            right, rs = metrics(folder / f'candidate-{trial}')
            assert ls == rs, 'changed proof length or circuit geometry'
            if reference is None:
                reference = ls
            assert ls == reference, 'geometry/proof length changed across repeats'
            if trial != 'warmup':
                runs.append((left, right))
        output[folder.name] = dict(trials=trials, all_shapes_and_lengths_identical=True,
            metrics={key:paired([(a[key], b[key]) for a,b in runs]) for key in runs[0][0]})
    assert output
    (BASE / (prefix + '-audit-expanded.json')).write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({name:{k:{s:v for s,v in m.items() if s != 'pairs'} for k,m in r['metrics'].items()} for name,r in output.items()}, indent=2))

if __name__ == '__main__':
    main()
