"""Final settlement candidate; preserve raw groups and append selected medians."""
import hashlib,json,statistics,subprocess
from pathlib import Path
here=Path(__file__).resolve().parent
root=here.parents[1]
summary={}
for group in ['fastcoeff-node','constantb-node','ondemand-node','weightedcols-node']:
 for case in ['same','mixed']:
  ds=[json.loads((here/f'{group}-{case}-{i}.json').read_text()) for i in (1,2,3)]
  assert all(d['verified'] for d in ds)
  keys=['merge_s','fold_prover_s','outer_prover_s','rows','committed_words','proof_bytes','carried_bytes','complete_root_ms','own_settle_ms','leaf_complete_root_ms','first_complete_root_ms']
  summary[f'{group}-{case}']={k:statistics.median(d[k] for d in ds) for k in keys}
  summary[f'{group}-{case}']['settlements']={str(s['slot']):statistics.median(d['settlements'][j]['ms'] for d in ds) for j,s in enumerate(ds[0]['settlements'])}
for case in ['same','mixed']:
 for tag in ['baseline','candidate']:
  ds=[json.loads((here/f'weightedcols-paired-{tag}-{case}-{i}.json').read_text()) for i in (1,2,3)]
  summary[f'paired-{tag}-{case}']={k:statistics.median(d[k] for d in ds) for k in ['merge_s','fold_prover_s','outer_prover_s']}
provenance={'parent':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'cpus':'12-23','threads':12,'binaries':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/tmp/L2r-weightedcols-tree','/tmp/L2r-weightedcols-merge','/tmp/L2r-bc1f691a-merge']},'node_order':[f'{case}-{i}' for i,cases in enumerate([['same','mixed'],['mixed','same'],['same','mixed']],1) for case in cases],'paired_order':[f'{tag}-{case}-{i}' for i,cases in enumerate([['same','mixed'],['mixed','same'],['same','mixed']],1) for case in cases for tag in ['baseline','candidate']],'notes':['Earlier final-paired-weighted files used /tmp/L2r-weighted-merge, not the fastcoeff binary.','constantb was exploratory and reverted; weightedcols is selected.','Node schema supports shielded and Merkle plus two wrapper shapes.','Host latency variation is substantial; separate groups are not paired comparisons.']}
(here/'settlement-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
(here/'settlement-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
rows=[]
for case in ['same','mixed']:
 d=summary[f'weightedcols-node-{case}']
 for k,unit in [('merge_s','s'),('fold_prover_s','s'),('rows','rows'),('committed_words','F64 words'),('proof_bytes','bytes'),('carried_bytes','bytes'),('complete_root_ms','ms'),('own_settle_ms','ms')]:
  rows.append(dict(system='r1cs',lane='L2r',workload=f'sparse-node-depth2-{case}',role='merge',metric=k,value=d[k],unit=unit,threads=12,cpus='12-23',binary_sha256=provenance['binaries']['/tmp/L2r-weightedcols-tree'],receipt='ht-L2r/artifacts/sparse-tree/settlement-summary.json',note='weightedcols: median of three fresh processes, alternating same/mixed; own claim included in complete root'))
 for count,k in [(1,'leaf_complete_root_ms'),(3 if case=='mixed' else 2,'first_complete_root_ms'),(4 if case=='mixed' else 3,'complete_root_ms')]:
  rows.append(dict(system='r1cs',lane='L2r',workload=f'sparse-root-{case}-{count}-identities',role='mempool',metric='complete_root_ms',value=d[k],unit='ms',threads=12,cpus='12-23',note='weightedcols median, includes outer verification and own matrix claim',receipt='ht-L2r/artifacts/sparse-tree/settlement-summary.json'))
with (root.parent/'artifacts/hometurf-12t.jsonl').open('a') as f:
 for row in rows:f.write(json.dumps(row)+'\n')
