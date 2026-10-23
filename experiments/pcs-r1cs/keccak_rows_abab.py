#!/usr/bin/env python3
"""Three ABAB rounds, fresh processes, frozen executable; no parallel timing."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

workload = sys.argv[1]
root = Path.cwd().parent
out = root / 'artifacts' / 'hometurf-L4k' / (workload + '-abab')
out.mkdir(exist_ok=True)
exe = out / 'keccak_row_workloads'
shutil.copy2(root / 'target-L4k/release/examples/keccak_row_workloads', exe)
source = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
metadata = {'source_commit':source,'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
            'cpus':'36-47','threads':12,'seed':20261024,'rounds':3,'order':'ABAB'}
(out/'metadata.json').write_text(json.dumps(metadata,indent=2))
env = dict(os.environ,RAYON_NUM_THREADS='12',LEANVM_NUM_THREADS='12')
for r in range(1,4):
    for slot, variant in enumerate(['bits','rows','bits','rows']):
        prefix = out/f'r{r}-s{slot}-{variant}'
        command = ['taskset','-c','36-47','python3','experiments/pcs-r1cs/measure_keccak_rows.py',str(prefix),str(exe),workload,variant,'prove',str(prefix)+'.cert','20261024']
        subprocess.run(command,env=env,check=True)
        print(prefix.with_suffix('.stdout').read_text(),flush=True)
for variant in ['bits','rows']:
    prefix = out/f'verify-{variant}'
    proof = out/f'r3-s{0 if variant == "bits" else 1}-{variant}.cert'
    subprocess.run(['taskset','-c','36-47','python3','experiments/pcs-r1cs/measure_keccak_rows.py',str(prefix),str(exe),workload,variant,'verify',str(proof),'20261024'],env=env,check=True)
    print(prefix.with_suffix('.stdout').read_text(),flush=True)
