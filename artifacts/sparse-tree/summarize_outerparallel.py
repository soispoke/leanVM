"""Final outer-fold measurements, paired control and shared lane records."""
import hashlib,json,statistics,subprocess
from pathlib import Path
h=Path(__file__).resolve().parent
root=h.parents[1]
summary={}
for group in ['outerparallel-node','outerparallel-paired-baseline','outerparallel-paired-candidate']:
 for case in ['same','mixed']:
  ds=[json.loads((h/f'{group}-{case}-{i}.json').read_text()) for i in (1,2,3)]
  assert all(d['verified'] and len(d['verifier_rejections'])==8 for d in ds)
  assert len({d['node_key'] for d in ds})==1
  keys=['merge_s','fold_prover_s','outer_prover_s','rows','committed_words','proof_bytes','carried_bytes','leaf_complete_root_ms','first_complete_root_ms','complete_root_ms','own_settle_ms']
  summary[f'{group}-{case}']={k:statistics.median(d[k] for d in ds) for k in keys}
  summary[f'{group}-{case}']['settlements']={str(s['slot']):statistics.median(d['settlements'][j]['ms'] for d in ds) for j,s in enumerate(ds[0]['settlements'])}
 assert json.loads((h/f'{group}-same-1.json').read_text())['node_key']==json.loads((h/f'{group}-mixed-1.json').read_text())['node_key']
provenance={'parent':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'binaries':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/tmp/L2r-outerparallel-tree','/tmp/L2r-weightedcols-tree']},'cpus':'12-23','threads':12,'order':[f'{c}-{i}' for i,cs in enumerate([['same','mixed'],['mixed','same'],['same','mixed']],1) for c in cs],'paired_order':[f'{t}-{c}-{i}' for i,cs in enumerate([['same','mixed'],['mixed','same'],['same','mixed']],1) for c in cs for t in ['baseline','candidate']],'note':'All four fresh leaves proved independently per process. Same node key across same/mixed. Reuse run separately shares leaves and is not a fresh eight-leaf timing.'}
(h/'outerparallel-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
(h/'outerparallel-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
rows=[]
for group in ['outerparallel-node','outerparallel-paired-candidate']:
 for case in ['same','mixed']:
  d=summary[f'{group}-{case}']
  for k,u in [('merge_s','s'),('fold_prover_s','s'),('outer_prover_s','s'),('rows','rows'),('committed_words','F64 words'),('proof_bytes','bytes'),('carried_bytes','bytes'),('own_settle_ms','ms'),('complete_root_ms','ms')]:
   rows.append(dict(system='r1cs',lane='L2b',workload=f'sparse-node-depth2-{case}',role='merge',metric=k,value=d[k],unit=u,threads=12,cpus='12-23',binary_sha256=provenance['binaries']['/tmp/L2r-outerparallel-tree'],receipt='ht-L2r/artifacts/sparse-tree/outerparallel-summary.json',note=f'{group}: median of three fresh processes, alternating case order; own claim included in root'))
  for count,k in [(1,'leaf_complete_root_ms'),(3 if case=='mixed' else 2,'first_complete_root_ms'),(4 if case=='mixed' else 3,'complete_root_ms')]:
   rows.append(dict(system='r1cs',lane='L2b',workload=f'sparse-root-{case}-{count}-identities',role='mempool',metric='complete_root_ms',value=d[k],unit='ms',threads=12,cpus='12-23',receipt='ht-L2r/artifacts/sparse-tree/outerparallel-summary.json',note=f'{group}: outer verification, own matrix claim and all active carried claims; wrapper identities counted'))
with (root.parent/'artifacts/hometurf-12t.jsonl').open('a') as f:
 for r in rows:f.write(json.dumps(r)+'\n')
