from pathlib import Path
import os,subprocess,json,time,hashlib,statistics
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022'); D=P/'artifacts/hometurf-L3c/abab'
bins={'A':P/'artifacts/hometurf-L4k/falcon-abab/keccak_row_workloads','B':D/'falcon_word_application'}
env={**os.environ,'RAYON_NUM_THREADS':'12','LEANVM_NUM_THREADS':'12'}
def run(cmd,name):
 t=time.monotonic()
 with (D/(name+'.stdout')).open('w') as out,(D/(name+'.stderr')).open('w') as err:
  p=subprocess.Popen([str(x) for x in cmd],stdout=out,stderr=err,env=env)
  _,status,usage=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
 if p.returncode:raise RuntimeError((name,p.returncode,(D/(name+'.stderr')).read_text()))
 process={'wall_s':time.monotonic()-t,'peak_rss_kib':usage.ru_maxrss,'pid':p.pid,'command':[str(x) for x in cmd]}
 (D/(name+'.process.json')).write_text(json.dumps(process))
 rows=[json.loads(x) for x in (D/(name+'.stdout')).read_text().splitlines() if x.startswith('{')]
 return rows[-1],process
metadata={'cpus':'24-35','threads':12,'binaries':{v:{'path':str(b),'sha256':hashlib.sha256(b.read_bytes()).hexdigest()} for v,b in bins.items()},'A':'Keccak rows only','B':'Keccak rows plus word tables','seed':0}
(D/'metadata.json').write_text(json.dumps(metadata,indent=2))
results=[]
for round in range(1,4):
 for slot,variant in enumerate('ABAB'):
  name=f'r{round}-s{slot}-{variant}'; cert=D/(name+'.cert')
  args=[bins[variant],'falcon','rows','prove',cert,'0'] if variant=='A' else [bins[variant],'prove',cert]
  wallet,process=run(args,name)
  args=[bins[variant],'falcon','rows','verify',cert,'0'] if variant=='A' else [bins[variant],'verify',cert]
  verify,_=run(args,name+'-verify')
  result={'round':round,'slot':slot,'variant':variant,'wallet':wallet,'verify':verify,'process':process}
  results.append(result)
  with (D/'samples.jsonl').open('a') as f:f.write(json.dumps(result)+'\n')
  print(json.dumps(result),flush=True)
summary={}
for variant in 'AB':
 samples=[x for x in results if x['variant']==variant]
 summary[variant]={'wallet_prove_s':statistics.median(x['wallet']['wallet_prove_s'] for x in samples),'peak_rss_kib':statistics.median(x['process']['peak_rss_kib'] for x in samples),'proof_bytes':statistics.median(x['wallet']['proof_bytes'] for x in samples),'verify_ms':statistics.median(x['verify']['verify_ms'] for x in samples),'rows':statistics.median(x['wallet'].get('rows',x['wallet'].get('arithmetic_rows')) for x in samples),'committed_words':statistics.median(x['wallet']['committed_words'] for x in samples)}
(D/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
