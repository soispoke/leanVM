"""Summarize node measurements; append medians to the shared lane JSONL."""
import json
from pathlib import Path
import statistics
import subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SHARED=ROOT.parent/'artifacts'
summary={}
for group in ['node','node-digest','node-compact','node-final']:
 for case in ['same','mixed']:
  ds=[json.loads((HERE/f'{group}-{case}-{i}.json').read_text()) for i in range(1,4)]
  keys=['merge_s','fold_prover_s','outer_prover_s','rows','committed_words','proof_bytes','carried_bytes','complete_root_ms','own_settle_ms']
  if group=='node-final': keys+=['leaf_complete_root_ms','first_complete_root_ms']
  summary[f'{group}-{case}']={k:statistics.median(d[k] for d in ds) for k in keys}
  assert all(d['verified'] for d in ds)
  assert len({d['node_key'] for d in ds})==1
  if group=='node-final': assert all(len(d['verifier_rejections'])==8 for d in ds)
 assert json.loads((HERE/f'{group}-same-1.json').read_text())['node_key']==json.loads((HERE/f'{group}-mixed-1.json').read_text())['node_key']
(HERE/'node-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
rows=[]
for case in ['same','mixed']:
 d=summary['node-final-'+case]
 for key,metric,unit in [('merge_s','merge2to1_s','s'),('fold_prover_s','matrix_fold_prover_s','s'),('rows','merge_rows','rows'),('committed_words','merge_committed_words','words'),('proof_bytes','merge_proof_bytes','bytes'),('carried_bytes','merge_carried_bytes','bytes'),('complete_root_ms','complete_root_ms','ms')]:
  rows.append(dict(system='r1cs',workload='sparse-node-depth2-'+case,role='merge',metric=metric,value=d[key],unit=unit,threads=12,cpus='12-23',commit=commit,lane='L2b',note=f'node-final medians; binary provenance in ht-L2r/artifacts/sparse-tree/node-provenance.json'))
 for count,key in [(1,'leaf_complete_root_ms'),(3 if case=='mixed' else 2,'first_complete_root_ms'),(4 if case=='mixed' else 3,'complete_root_ms')]:
  rows.append(dict(system='r1cs',workload=f'sparse-root-{case}-{key}',role='mempool',metric='complete_root_ms',value=d[key],unit='ms',threads=12,cpus='12-23',commit=commit,lane='L2b',note=f'node-final median; {count} distinct matrix identities, including wrapper identities'))
with (SHARED/'hometurf-12t.jsonl').open('a') as f:
 for row in rows:f.write(json.dumps(row)+'\n')
print(json.dumps(summary,indent=2))
