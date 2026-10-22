#!/usr/bin/env python3
"""Repeat frozen binaries with alternating order and immutable provenance."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

phase = Path(__file__).resolve().parent
root = Path('/root/workspaces/mission-9abcee72/leanvm-opt')
out = phase / 'matched-compact-plan-depth2'
out.mkdir(exist_ok=False)
specs = {
    'candidate': (phase / 'private_tree-compact-plan', 'f1b6626fc546956085f4512d8210f715e6dd256b',
                  '61aa7593645c0a7838f3a40e61bb0826b0dd78b77826413335178a29ae474713'),
    'leanvm': (Path('/root/workspaces/mission-9abcee72/scratch/perf-20261022/frozen/chain_tree_vm-final'),
               'bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47',
               '54c05b65a9594d44ca297238eae9c69d8dc05a164b88360bbb0a61e9644b58af'),
}
for binary, revision, digest in specs.values():
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
env = os.environ.copy()
env.pop('BENCH_TRACING', None)
env.update(LEANVM_NUM_THREADS='16', RUSTUP_TOOLCHAIN='1.99.1',
           RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
plan = [('warmup', ['candidate', 'leanvm'])]
plan += [(f'trial-{i}', ['candidate', 'leanvm'] if i % 2 == 0 else ['leanvm', 'candidate'])
         for i in range(3)]
(out / 'plan.json').write_text(json.dumps(dict(specs={k: [str(x) for x in v] for k,v in specs.items()},
    plan=plan, scope='4 leaves, 16 hash steps each, 2 levels; 16 workers CPUs0-15. Warmup excluded.'), indent=2)+'\n')
for trial, order in plan:
    for name in order:
        binary, revision, _ = specs[name]
        record = out / f'{name}-{trial}'
        command = ['python3', str(root / 'experiments/pcs-r1cs/recursion/run.py'),
                   '--out', str(record), '--budget-gib', '32', '--binary-source-commit', revision,
                   '--', str(binary), '--depth', '2', '--chain', '16']
        if name == 'leanvm':
            command += ['--log-inv-rate', '1']
        print(f'{name} {trial}', flush=True)
        subprocess.run(['python3', str(phase / 'main16-lane.py'),
                        str(out / f'{name}-{trial}-guard'), *command], env=env, check=True,
                       stdout=subprocess.DEVNULL)
groups = []
for name in specs:
    groups += ['--group', name, *[str(out / f'{name}-trial-{i}') for i in range(3)]]
subprocess.run(['python3', str(root / 'experiments/pcs-r1cs/recursion/summarize_trees.py'),
                *groups, '--out', str(out / 'summary.json')], check=True)
summary = json.loads((out / 'summary.json').read_text())
for name, group in summary['groups'].items():
    print(name, json.dumps(group['levels'][-1]), flush=True)
