#!/usr/bin/env python3
"""Compare every proof length and circuit shape, then report paired root times."""
from pathlib import Path
import hashlib
import importlib.util
import json
import random
import statistics

BASE=Path(__file__).resolve().parent
ROOT=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
spec=importlib.util.spec_from_file_location('trees',ROOT/'experiments/pcs-r1cs/recursion/summarize_trees.py')
trees=importlib.util.module_from_spec(spec);spec.loader.exec_module(trees)

def read(path):
    value=trees.load(path)
    guard=json.loads(path.with_name(path.name+'-guard').joinpath('result.json').read_text())
    assert guard['ok'] and guard['files_unchanged']
    for i,run in enumerate(guard['runs']):
        folder=path.with_name(path.name+'-guard')/f'run-{i:02d}'
        for name in ['stdout','stderr']:
            assert hashlib.sha256((folder/f'{name}.log').read_bytes()).hexdigest()==run[f'{name}_sha256']
    rows=[json.loads(line) for line in (path/'stdout.jsonl').read_text().splitlines()]
    shapes=[];lengths={}
    for row in rows:
        if row['kind'] in ('setup','leaf_trace','node_trace'):
            shapes.append({k:v for k,v in row.items() if k not in ('setup_s',)})
        if row['kind']=='proof':lengths[(row['level'],row['index'])]=row['proof_bytes']
    return value,shapes,lengths

def main():
    result={}
    for folder in sorted(BASE.glob('trace-depth*-chain*')):
        plan=json.loads((folder/'plan.json').read_text());trials=plan['trials']
        paired=[];all_values=[]
        for i in range(trials):
            left=read(folder/f'baseline-trial-{i}');right=read(folder/f'candidate-trial-{i}')
            assert left[1:]==right[1:], 'circuit shape or proof length changed'
            a=left[0]['levels'][-1]['preparation_plus_proving_s'];b=right[0]['levels'][-1]['preparation_plus_proving_s']
            paired.append(1-b/a);all_values.append({'baseline':a,'candidate':b,'reduction':1-b/a})
        warmups=[read(folder/f'{name}-warmup') for name in ('baseline','candidate')]
        assert warmups[0][1:]==warmups[1][1:]
        rng=random.Random(20261022)
        bootstrap=sorted(statistics.median(rng.choices(paired,k=trials)) for _ in range(20000))
        result[folder.name]={'trials':trials,'all_shapes_and_lengths_identical':True,'baseline_root_median_s':statistics.median(v['baseline'] for v in all_values),'candidate_root_median_s':statistics.median(v['candidate'] for v in all_values),'median_paired_reduction':statistics.median(paired),'positive_pairs':sum(x>0 for x in paired),'paired_median_bootstrap_95pct':[bootstrap[500],bootstrap[19499]],'pairs':all_values}
    (BASE/'trace-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
