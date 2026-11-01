"""Untimed, build-slice recursion accounting and negative checks."""
import subprocess,pathlib,json,re
out=pathlib.Path('../artifacts/hometurf-L2'); result={}
names=['leanxmss','leansphincs','hashchain-16','hashchain-256','hashchain-4096','merkle-20','merkle-32','shielded','sha256-1kib','keccak256-1kib']
for name in names:
 with (out/f'{name}-profile.log').open('w') as err:
  p=subprocess.run(['taskset','-c','48-63','env','LEANVM_ROW_PROFILE=1','LEANVM_NUM_THREADS=12','RAYON_NUM_THREADS=12','../target-leanvm-riscv/release/receipt','stats-one',name,str(out/name)],stdout=subprocess.PIPE,stderr=err,text=True)
 assert p.returncode==0,name
 (out/f'{name}-stats-one.jsonl').write_text(p.stdout)
 current={};last={};paths=[0]*6;program=[0]*6
 for line in (out/f'{name}-profile.log').read_text().splitlines():
  if not line.startswith('ROW_PROFILE|'):continue
  _,scope,arr=line.split('|');v=json.loads(arr)
  if scope=='leaf 0/announcement':current={};paths=[0]*6
  if scope.startswith('leaf 0/'):
   current[scope]=v
   if scope.endswith('/Merkle paths'):paths=[a+b for a,b in zip(paths,v)]
  if scope=='leaf 0':last=dict(current);last['core']=v;last['merkle']=paths.copy()
  if scope=='leaf 0 program':program=v
 row=json.loads(p.stdout.splitlines()[-1]);totals=[int(x) for x in re.findall(r'rows: (\d+)',row['recursion_stats'])]
 add=lambda a,b:[x+y for x,y in zip(a,b)]
 sub=lambda a,b:[x-y for x,y in zip(a,b)]
 groups={'program claim and bus':add(last['leaf 0/bus and tables'],program),'Flock':last['leaf 0/flock'],'WHIR opening excluding Merkle':sub(last['leaf 0/opening'],last['merkle']),'Merkle paths and leaf hashing':last['merkle']}
 groups['announcement, reduction and other']=sub(totals,[sum(v[i] for v in groups.values()) for i in range(6)])
 assert all(x>=0 for v in groups.values() for x in v),(name,groups)
 weights=[9,7,257,65,4,0]
 d={'total_rows':sum(totals),'committed_words':row['per_claim_committed_words'],'tables':totals,'groups':{k:{'rows':sum(v),'table_rows':v,'unpadded_committed_words':sum(a*b for a,b in zip(v,weights))} for k,v in groups.items()}}
 d['padding_and_floors_words']=d['committed_words']-sum(g['unpadded_committed_words'] for g in d['groups'].values());assert d['padding_and_floors_words']>=0
 result[name]=d
for name in ['hashchain-16','hashchain-256','hashchain-4096','merkle-20','merkle-32','sha256-1kib','keccak256-1kib']:
 p=subprocess.run(['taskset','-c','48-63','env','LEANVM_NUM_THREADS=12','RAYON_NUM_THREADS=12','../target-leanvm-riscv/release/receipt','reject',name,str(out/name)],capture_output=True,text=True)
 (out/f'{name}-reject.log').write_text(p.stdout+p.stderr);assert p.returncode==0,(name,p.stderr)
(out/'verifier-breakdown.json').write_text(json.dumps(result,indent=2)+'\n')
print('All 10 profiles and 7 rejection checks passed')
