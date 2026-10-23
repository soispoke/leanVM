#!/usr/bin/env python3
"""Six fresh native proofs when the bit-level layout exceeds the memory budget.
This is not an ABAB comparison: the bit-level side is a census/projection only.
"""
from pathlib import Path
import os,subprocess,json
root=Path.cwd().parent
out=root/'artifacts/hometurf-L4k'
exe=out/'mldsa_workloads-frozen'
env=dict(os.environ,RAYON_NUM_THREADS='12',LEANVM_NUM_THREADS='12')
for index in range(1,7):
 prefix=out/f'mldsa-native-r{index}'
 subprocess.run(['taskset','-c','36-47','python3','experiments/pcs-r1cs/measure_keccak_rows.py',str(prefix),str(exe),'mldsa','rows','prove',str(prefix)+'.cert','20261024'],env=env,check=True)
 print(Path(str(prefix)+'.stdout').read_text(),flush=True)
