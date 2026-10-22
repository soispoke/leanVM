#!/usr/bin/env python3
"""Small, serial worker-count experiments with exact source-bound receipts."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

BASE = Path(__file__).resolve().parent
ROOT = Path('/root/workspaces/mission-9abcee72/leanvm-opt')
CONFIG = json.loads((BASE / 'trace-freeze.json').read_text())
SPEC = CONFIG['specs']['baseline']
MODE = sys.argv[1]
if MODE == 'screen':
    depth, chain, repeats, workers = 2, 256, 3, [16, 8, 4]
elif MODE == 'wide':
    depth, chain, repeats, workers = 2, 256, 3, [16, 32, 64]
else:
    depth, chain, repeats, workers = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), [16, int(sys.argv[5])]
OUT = BASE / f'workers-{MODE}-depth{depth}-chain{chain}'
OUT.mkdir(exist_ok=True)
assert hashlib.sha256(Path(SPEC['binary']).read_bytes()).hexdigest() == SPEC['sha256']
sources = subprocess.check_output(['git', 'ls-files', '*.rs', '*.toml', 'Cargo.lock'], cwd=ROOT, text=True).splitlines()
plan = [('warmup', workers)]
for i in range(repeats):
    order = workers[i % len(workers):] + workers[:i % len(workers)] if len(workers) > 2 else workers[::1 if i % 2 == 0 else -1]
    plan.append((f'trial-{i}', order))
(OUT / 'plan.json').write_text(json.dumps(dict(depth=depth, chain=chain, repeats=repeats, workers=workers, plan=plan, binary=SPEC), indent=2) + '\n')
for trial, order in plan:
    for worker in order:
        label = f'w{worker}-{trial}'
        guard = OUT / (label + '-guard')
        if (guard / 'result.json').exists():
            assert json.loads((guard / 'result.json').read_text())['ok']
            continue
        subprocess.run([str(ROOT / 'experiments/pcs-r1cs/memguard'), 'admit', '9'], check=True)
        env = dict(os.environ, LEANVM_NUM_THREADS=str(worker), RUSTUP_TOOLCHAIN='1.99.1', RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
        cpu_count = 64 if MODE in ('wide', 'wide-validation') else 16
        args = ['python3', '/root/yukon-autoresearch/bin/bench-research.py', '--cwd', str(ROOT), '--out', str(guard), '--budget-gib', '8', '--reserve-gib', '40', '--timeout-seconds', '300', '--cpus', ','.join(map(str, range(cpu_count)))]
        for source in [*(ROOT / p for p in sources), Path(SPEC['binary']), Path(__file__).resolve(), BASE / 'trace-freeze.json', BASE / 'run-precise.py']:
            args += ['--source', str(source)]
        args += ['--', 'python3', str(BASE / 'run-precise.py'), '--out', str(OUT / label), '--budget-gib', '8', '--binary-source-commit', SPEC['revision'], '--', SPEC['binary'], '--depth', str(depth), '--chain', str(chain)]
        print(label, flush=True)
        subprocess.run(args, env=env, check=True)
print('WORKER SERIES COMPLETE', flush=True)
