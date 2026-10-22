#!/usr/bin/env python3
"""Alternating fresh-process controls; admission waits precede all timed runs."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

BASE=Path(__file__).resolve().parent
ROOT=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
TREE=BASE/'stack'
CONFIG=json.loads((BASE/'stack-freeze.json').read_text())
DEPTH=int(sys.argv[1]); CHAIN=int(sys.argv[2]); TRIALS=int(sys.argv[3])
OUT=BASE/f'stack-depth{DEPTH}-chain{CHAIN}'
OUT.mkdir(exist_ok=True)
SPECS=CONFIG['specs']
for spec in SPECS.values():
    assert hashlib.sha256(Path(spec['binary']).read_bytes()).hexdigest()==spec['sha256']
for name,digest in CONFIG['source_files'].items():
    assert hashlib.sha256((TREE/name).read_bytes()).hexdigest()==digest
ENV=dict(os.environ, LEANVM_NUM_THREADS='16',RUSTUP_TOOLCHAIN='1.99.1',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
PLAN=[('warmup',['baseline','candidate'])]+[(f'trial-{i}',['baseline','candidate'] if i%2==0 else ['candidate','baseline']) for i in range(TRIALS)]
(OUT/'plan.json').write_text(json.dumps(dict(depth=DEPTH,chain=CHAIN,trials=TRIALS,plan=PLAN,policy='One excluded warmup per backend; alternating fresh processes; same deterministic statement; 16 workers, CPUs 0-15.'),indent=2)+'\n')
for trial,order in PLAN:
    for name in order:
        label=f'{name}-{trial}'; guard=OUT/(label+'-guard')
        if (guard/'result.json').exists():
            assert json.loads((guard/'result.json').read_text())['ok']
            continue
        budget=42 if CHAIN==16384 else 8
        while subprocess.run([str(ROOT/'experiments/pcs-r1cs/memguard'),'admit',str(budget+1)],capture_output=True).returncode:
            print('waiting for admission',label,flush=True);time.sleep(5)
        spec=SPECS[name]
        args=['python3','/root/yukon-autoresearch/bin/bench-research.py','--cwd',str(TREE),'--out',str(guard),'--budget-gib',str(budget),'--reserve-gib','40','--timeout-seconds','900','--cpus',','.join(map(str,range(16)))]
        for source in [*(TREE/n for n in CONFIG['source_files']),Path(spec['binary']),Path(__file__).resolve(),BASE/'stack-freeze.json',ROOT/'experiments/pcs-r1cs/recursion/run.py']:
            args+=['--source',str(source)]
        args+=['--','python3',str(ROOT/'experiments/pcs-r1cs/recursion/run.py'),'--out',str(OUT/label),'--budget-gib',str(budget),'--binary-source-commit',spec['revision'],'--',spec['binary'],'--depth',str(DEPTH),'--chain',str(CHAIN)]
        print(DEPTH,CHAIN,label,flush=True)
        subprocess.run(args,env=ENV,check=True)
groups=[]
for name in SPECS:
    groups+=['--group',name,*[str(OUT/f'{name}-trial-{i}') for i in range(TRIALS)]]
subprocess.run(['python3',str(ROOT/'experiments/pcs-r1cs/recursion/summarize_trees.py'),*groups,'--out',str(OUT/'summary.json')],check=True)
