#!/usr/bin/env python3
"""ABAB x3 with fresh processes and per-process RSS; instruction-only migration stage."""
import fcntl,hashlib,json,shutil,statistics,subprocess,sys,time
from pathlib import Path
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022'); ROOT=P/'lvm-L7'; OUT=P/'artifacts/hometurf-L7/wallet-abab'; OUT.mkdir(exist_ok=True)
SNAP=OUT/'bin';SNAP.mkdir(exist_ok=True)
apps={'shielded':'shielded-keccak','merkle':'merkle-keccak','keccak1k':'keccak1k','falcon':'falcon','mpt':'stateproof'}
manifest={}
for var,target in [('A','target-L7-control'),('B','target-L7')]:
 binary=SNAP/f'harness-{var}'; shutil.copy2(P/target/'release/keccakapps-host',binary)
 manifest[var]={'binary':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'guest':{}}
 for app,elf in apps.items():
  path=SNAP/f'{app}-{var}.elf';shutil.copy2(P/(target+'-guest')/'riscv64im-unknown-none-elf/release'/elf,path)
  manifest[var]['guest'][app]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
samples=[]
for app in apps:
 for rnd in range(1,4):
  for pos,var in enumerate('ABAB',1):
   prefix=OUT/f'{app}-r{rnd}-{pos}{var}'
   common=[manifest[var]['binary'],app,None,manifest[var]['guest'][app]['path'],str(prefix)]
   for mode in ['prove','verify']:
    command=common.copy();command[2]=mode
    dest=str(prefix)+('-verify' if mode=='verify' else '')
    run=subprocess.run([sys.executable,str(ROOT/'artifacts/L7/run-one.py'),dest,*command],capture_output=True,text=True)
    if run.returncode: raise RuntimeError(run.stdout+'\n'+run.stderr)
   w=json.loads(Path(str(prefix)+'.stdout').read_text());r=json.loads(Path(str(prefix)+'.resources.json').read_text());v=json.loads(Path(str(prefix)+'-verify.stdout').read_text());vr=json.loads(Path(str(prefix)+'-verify.resources.json').read_text())
   sample={'app':app,'round':rnd,'position':pos,'variant':var,'wallet_prove_s':w['wallet_prove_s'],'wallet_peak_rss_kib':r['peak_rss_kib'],'wallet_proof_bytes':w['proof_bytes'],'cycles':w['cycles'],'committed_words':w['committed_words'],'mempool_verify_ms':v['verify_ms'],'mempool_peak_rss_kib':vr['peak_rss_kib']}
   samples.append(sample)
   (OUT/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
   print(json.dumps(sample),flush=True)
 summary={}
 for var in 'AB':
  group=[s for s in samples if s['app']==app and s['variant']==var]
  summary[var]={key:statistics.median(s[key] for s in group) for key in ['wallet_prove_s','wallet_peak_rss_kib','wallet_proof_bytes','cycles','committed_words','mempool_verify_ms','mempool_peak_rss_kib']}
 print('MEDIAN '+app+' '+json.dumps(summary),flush=True)
 (OUT/f'{app}-medians.json').write_text(json.dumps(summary,indent=2)+'\n')
 with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX)
  for var,metrics in summary.items():
   note=f'ABAB x3; median of six fresh processes; variant {var}; A unchanged a40a7fa6 VM core/software Keccak; B Keccak instruction/BLAKE2s protocol; leaf rate1/4; SHA256 {manifest[var]["sha256"]}; instruction-only stage, not full protocol migration; raw wallet-abab/{app}-*'
   for key,value in metrics.items():
    role='mempool' if key.startswith('mempool') else 'wallet'; unit='KiB' if key.endswith('kib') else 'bytes' if key.endswith('bytes') else 'ms' if key.endswith('ms') else 's' if key.endswith('_s') else 'cycles' if key=='cycles' else 'words'
    f.write(json.dumps(dict(system='leanvm',workload=app,role=role,metric=key,value=value,unit=unit,threads=12,cpus='24-35',commit='a40a7fa6de0f5ba75214aa53aceff49a5c61d7e2',lane='L7',note=note))+'\n')
