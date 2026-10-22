#!/usr/bin/env python3
"""Full-length matched trees, serial and resumable without overwriting receipts."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
INPUTS = json.loads((BASE / 'inputs.json').read_text())
RUNNER = Path('/root/yukon-autoresearch/bin/bench-research.py')
assert RUNNER.read_bytes() == (BASE / 'bench-research-used.py').read_bytes()
ENV = dict(os.environ, LEANVM_NUM_THREADS='16', RUSTUP_TOOLCHAIN='1.99.1',
           RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
SOURCES = [ROOT / name for name in INPUTS['source_freeze']['files']]
for path in SOURCES:
    assert hashlib.sha256(path.read_bytes()).hexdigest() == INPUTS['source_freeze']['files'][str(path.relative_to(ROOT))]
for spec in INPUTS['specs'].values():
    assert hashlib.sha256(Path(spec['binary']).read_bytes()).hexdigest() == spec['sha256']
for depth in (1, 2, 3):
    work = BASE / f'depth{depth}-chain16384'
    work.mkdir(exist_ok=True)
    plan = [('warmup', ['native', 'leanvm-mu30'])] + [
        (f'trial-{i}', ['native', 'leanvm-mu30'] if i % 2 == 0 else ['leanvm-mu30', 'native']) for i in range(3)]
    for trial, order in plan:
        for name in order:
            if os.environ.get('FULL_BACKEND') and name != os.environ['FULL_BACKEND']:
                continue
            original = f'{name}-{trial}'
            label = original
            attempt = 0
            while (work / (label + '-guard') / 'result.json').exists():
                guard = work / (label + '-guard')
                receipt = json.loads((guard / 'result.json').read_text())
                if receipt['ok']:
                    break
                # Retry only failures before the benchmark executable launched.
                started = work / label / 'pid'
                assert not started.exists(), f'inspect failed benchmark: {label}'
                attempt += 1
                label = original + f'-retry{attempt}'
            else:
                receipt = None
            if receipt and receipt['ok']:
                continue
            guard = work / (label + '-guard')
            budget = '42' if name == 'native' else '66'
            wait_started = time.monotonic()
            while subprocess.run([str(ROOT / 'experiments/pcs-r1cs/memguard'), 'admit', str(int(budget) + 1)], capture_output=True).returncode:
                assert time.monotonic() - wait_started < 1800, 'admission wait exceeded 30 minutes'
                print(f'waiting for admission: depth={depth} {label}', flush=True)
                time.sleep(5)
            spec = INPUTS['specs'][name]
            args = ['python3', str(RUNNER), '--cwd', str(ROOT), '--out', str(guard),
                    '--budget-gib', budget, '--reserve-gib', '40', '--timeout-seconds', '1800',
                    '--cpus', ','.join(map(str, range(16)))]
            extra = [Path(spec['binary'])]
            if name == 'leanvm-mu30':
                extra += [Path('/root/yukon-autoresearch/workspaces/leanr1cs-full-hunt-20261022/vm-full') / name for name in INPUTS['vm_source_files']]
            for source in [*SOURCES, *extra, Path(__file__).resolve(), BASE / 'inputs.json', ROOT / 'experiments/pcs-r1cs/recursion/run.py']:
                args += ['--source', str(source)]
            args += ['--', 'python3', str(ROOT / 'experiments/pcs-r1cs/recursion/run.py'),
                     '--out', str(work / label), '--budget-gib', budget,
                     '--binary-source-commit', spec['revision'], '--', spec['binary'],
                     '--depth', str(depth), '--chain', '16384']
            if name == 'leanvm-mu30':
                args += ['--log-inv-rate', '1']
            print(f'depth={depth} {label}', flush=True)
            subprocess.run(args, env=ENV, check=True)
    if os.environ.get('FULL_BACKEND'):
        continue
    groups = []
    for name in INPUTS['specs']:
        paths = []
        for i in range(3):
            matches = [p.parent for p in work.glob(f'{name}-trial-{i}*/result.json')
                       if not p.parent.name.endswith('-guard') and json.loads(p.read_text()).get('returncode') == 0]
            assert len(matches) == 1, matches
            paths.append(str(matches[0]))
        groups += ['--group', name, *paths]
    subprocess.run(['python3', str(ROOT / 'experiments/pcs-r1cs/recursion/summarize_trees.py'),
                    *groups, '--out', str(work / 'summary.json')], check=True)
