from pathlib import Path
import json
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022');D=P/'artifacts/opt-O2';f=P/'artifacts/hometurf-12t.jsonl'
seen=set()
for line in f.read_text().splitlines():
 try:
  r=json.loads(line)
  if r.get('lane')=='O2':seen.add((r.get('note'),r.get('metric'),r.get('workload')))
 except json.JSONDecodeError:pass
n=0
with f.open('a') as out:
 for name in ['quad2-abab','quadcap-abab','quadcap-fast-abab','quadcap-compact-abab','quad-native-abab','canonical-route-abab','route-compact-abab','route-alias-abab','route-qfirst-abab']:
  for file in sorted((D/name).glob('first-*.stdout')):
   receipt=file.with_suffix('.receipt.json')
   if not receipt.exists() or json.loads(receipt.read_text())['exit_code']!=0:continue
   r=json.loads(file.read_text().splitlines()[-1]);assert r['verified']
   for i,workload in enumerate(['shielded','merkle']):
    for metric,unit in [('wallet_s','s'),('proof_bytes','bytes')]:
     note=f'O2 wallet from {name}/{file.name}; SHA256 in provenance.json'
     key=(note,metric,workload)
     if key in seen:continue
     commit='9e5f41c4' if '-A.' in file.name else '28387d02' if name=='quad2-abab' else 'uncommitted-quad-native' if name=='quad-native-abab' else 'uncommitted-canonical-route' if name=='canonical-route-abab' else 'ba49591f'
     out.write(json.dumps(dict(system='r1cs',workload=workload,role='wallet',metric=metric,value=r['wallets'][i][metric],unit=unit,threads=12,cpus='24-35',commit=commit,lane='O2',note=note))+'\n');seen.add(key);n+=1
print('appended',n,'wallet measurements')
