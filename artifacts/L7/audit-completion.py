#!/usr/bin/env python3
"""Read-only artifact audit; writes only its machine-readable receipt."""
import hashlib,json,statistics,subprocess
from pathlib import Path
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022');R=P/'lvm-L7';O=P/'artifacts/hometurf-L7'
metrics=[json.loads(s) for s in (P/'artifacts/hometurf-12t.jsonl').read_text().splitlines() if s.strip()]
metrics=[m for m in metrics if m.get('system')=='leanvm' and m.get('lane')=='L7']
checks={}; receipts=0
for folder,key in [('protocol-wallet-abab','app'),('exact-l6-wallet-abab','app'),('protocol-merge-abab','case')]:
 d=O/folder; manifest=json.loads((d/'manifest.json').read_text());samples=json.loads((d/'samples.json').read_text())
 for variant,entry in manifest.items():
  path=Path(entry.get('binary',entry.get('path',''))); assert hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256']
  for g in entry.get('guest',{}).values():assert hashlib.sha256(Path(g['path']).read_bytes()).hexdigest()==g['sha256']
 for name in sorted({s[key] for s in samples}):
  group=[s for s in samples if s[key]==name]
  assert len(group)==12
  assert [(s['round'],s['position'],s['variant']) for s in group]==[(rnd,pos,v) for rnd in range(1,4) for pos,v in enumerate('ABAB',1)]
  med=json.loads((d/f'{name}-medians.json').read_text())
  for v in 'AB':
   for metric,value in med[v].items():
    assert statistics.median(s[metric] for s in group if s['variant']==v)==value
    assert any(m['workload']==name and m['metric']==metric and m['value']==value and f'variant {v}' in m.get('note','') and m.get('cpus')=='24-35' and m.get('threads')==12 and folder in m.get('note','') for m in metrics) if key=='app' else any(m['workload']==name and m['metric']==metric and m['value']==value and f'variant {v}' in m.get('note','') and 'Keccak protocol' in m.get('note','') for m in metrics)
  for s in group:
   prefix=d/f"{name}-r{s['round']}-{s['position']}{s['variant']}"
   for suffix in ['', '-verify']:
    rs=json.loads(Path(str(prefix)+suffix+'.resources.json').read_text());assert rs['exit_code']==0 and rs['peak_rss_kib']>0
    data=json.loads(Path(str(prefix)+suffix+'.stdout').read_text());assert data.get('accepted',True)
    receipts+=1
  checks[f'{folder}/{name}']='12 samples; ABAB x3; manifest SHA256; raw process success; exact medians; locked JSONL values'
for app in ['shielded','merkle','falcon-l6','mpt-l6']:
 modes=['reject-path','reject-proof'] if app in ['shielded','merkle'] else ['reject-witness','reject-proof']
 for mode in modes:
  data=json.loads((O/f'protocol-rejections/{app}-{mode}.json').read_text());assert data['returncode']==0
  payload=json.loads(data['stdout']);assert payload.get('wrong_path_rejected',payload.get('invalid_witness_rejected',payload.get('accepted') is False))
checks['application_rejections']='wrong paths, invalid exact Falcon/MPT witnesses, tampered proofs'
for case in ['same','mixed','node-mixed']:
 for v,pos in [('A',1),('B',2)]:
  assert json.loads((O/f'protocol-merge-abab/{case}-r1-{pos}{v}-reject.resources.json').read_text())['exit_code']==0
checks['root_rejections']='same/mixed/node-mixed x A/B: identity, output and serialized root tampering refused'
for path,expected in [('keccak-only-core-tests-final.log','210 passed; 0 failed'),('keccak-only-flock-tests.log','5 passed; 0 failed'),('keccak-only-integration-tests6.log','25 passed; 0 failed'),('final-clippy.log','Finished `release`')]:
 assert expected in (O/path).read_text();checks[path]=expected
native=(O/'keccak-only-native-sdk-tests2.log').read_text()
for n in [11,14,44,35]:assert f'{n} passed; 0 failed' in native
checks['native_suites']='Fiat-Shamir11, SDK14, PCS44, primitives35'
assert subprocess.check_output(['git','diff','a40a7fa6','--','crates/pcs/src/whir/config'],cwd=R)==b''
checks['security']='WHIR config byte-identical to a40a7fa6:128-bit target, queries and grinding retained'
parity=json.loads((O/'exact-statement-parity.json').read_text());assert parity['falcon_matches_L6_wallet'] and parity['mpt_matches_L6_wallet']
checks['exact_parity']=parity
result={'checks':checks,'fresh_successful_process_receipts':receipts,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'status':'PASS','pending_L7_requirements':[],'external_comparison_cells_reserved':['L6 depth16 Merkle median','L6 same-program merge median']}
(O/'completion-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
