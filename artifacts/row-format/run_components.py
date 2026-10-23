#!/usr/bin/env python3
"""Calibrate conditional SPARK table sizes with actual WHIR components."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
binary = root.parent / 'target-ht-L2r/release/examples/sparse_pcs_model'
env = dict(os.environ, LEANVM_NUM_THREADS='12', RAYON_NUM_THREADS='12')
meta = {'commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'cores':'12-23','threads':12,'build_cores':'48-63'}
(out/'components-provenance.json').write_text(json.dumps(meta,indent=2)+'\n')
with (out/'sparse-pcs-components.jsonl').open('w') as f:
    for case in ['shielded','merge']:
        for part in ['fixed','derefs']:
            for repetition in range(1,4):
                result = subprocess.run(['taskset','-c','12-23',str(binary),case,part],cwd=root,env=env,text=True,capture_output=True,check=True)
                record = json.loads(result.stdout.splitlines()[-1])
                record.update(repetition=repetition,cores='12-23',threads=12)
                f.write(json.dumps(record)+'\n')
                f.flush()
                print(json.dumps(record),flush=True)
