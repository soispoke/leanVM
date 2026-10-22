#!/usr/bin/env python3
"""Frozen local measurement schedule, binary/source provenance is in config.json."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent
CONFIG = json.loads((OUT / 'config.json').read_text())
FROZEN = Path('/root/workspaces/mission-9abcee72/scratch/perf-20261022/frozen')
ENV = os.environ.copy()
ENV.update(LEANVM_NUM_THREADS='16', RUSTUP_TOOLCHAIN='1.99.1',
           RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
(OUT / 'driver-state.json').write_text(json.dumps(dict(status='running', pid=os.getpid(), started=time.time())) + '\n')

def run(name, sample, depth, binary, revision, extra=()):
    print('START', name, sample, flush=True)
    args = ['taskset', '-c', '0-15', sys.executable, 'experiments/pcs-r1cs/recursion/run.py',
            '--out', str(OUT / f'{name}-{sample}'), '--budget-gib', '32',
            '--binary-source-commit', revision, '--', str(binary), '--depth', str(depth), '--chain', '16', *extra]
    subprocess.run(args, cwd=ROOT, env=ENV, check=True)
    print('DONE', name, sample, flush=True)

for sample in range(CONFIG['samples']):
    pair = [('baseline', Path(CONFIG['baseline_binary']), CONFIG['baseline_source']),
            ('optimized', FROZEN / 'private_tree-final', CONFIG['source_commit'])]
    if sample % 2:
        pair.reverse()
    for name, binary, revision in pair:
        run(name, sample, 2, binary, revision)

for sample in range(CONFIG['samples']):
    comparison = [('native', FROZEN / 'private_tree-final', ()),
                  ('vm1', FROZEN / 'chain_tree_vm-final', ('--log-inv-rate', '1')),
                  ('vm2', FROZEN / 'chain_tree_vm-final', ('--log-inv-rate', '2'))]
    comparison = comparison[sample:] + comparison[:sample]
    for name, binary, extra in comparison:
        run(name, sample, 1, binary, CONFIG['source_commit'], extra)

(OUT / 'driver-state.json').write_text(json.dumps(dict(status='complete', pid=os.getpid(), finished=time.time())) + '\n')
