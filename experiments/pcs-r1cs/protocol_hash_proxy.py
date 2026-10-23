#!/usr/bin/env python3
"""Native-hash batch proxy, not a switched-protocol merge proof."""
from pathlib import Path
import hashlib,json,os,subprocess,statistics
root=Path.cwd().parent
out=root/'artifacts/hometurf-L4k'
exe=out/'native_hash_row_cost-frozen'
metadata={'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'source_commit':'4613ff77','cpus':'36-47','threads':12,'rounds':3,'order':'ABAB','scope':'hash-row batch proxy; not a native Keccak protocol wallet/merge'}
(out/'protocol-proxy-metadata.json').write_text(json.dumps(metadata,indent=2))
env=dict(os.environ,RAYON_NUM_THREADS='12',LEANVM_NUM_THREADS='12')
results={}
for count in [16384,32768]:
 samples={'blake':[],'keccak':[]}
 for r in range(1,4):
  for slot,kind in enumerate(['blake','keccak','blake','keccak']):
   prefix=out/f'protocol-proxy-{count}-r{r}-s{slot}-{kind}'
   subprocess.run(['taskset','-c','36-47','python3','experiments/pcs-r1cs/measure_keccak_rows.py',str(prefix),str(exe),kind,str(count)],env=env,check=True)
   value=json.loads(Path(str(prefix)+'.stdout').read_text())
   samples[kind].append(value)
   print(value,flush=True)
 results[count]={kind:{'median_s':statistics.median(v['wallet_prove_s'] for v in values),'committed_words':values[0]['committed_words'],'proof_bytes':values[0]['proof_bytes'],'samples_s':[v['wallet_prove_s'] for v in values]} for kind,values in samples.items()}
 (out/'protocol-proxy-summary.json').write_text(json.dumps({'metadata':metadata,'results':results},indent=2))
 print(json.dumps(results[count]),flush=True)
