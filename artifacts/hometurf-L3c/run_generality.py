from pathlib import Path
import os,subprocess,json,time,hashlib,statistics,shutil
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022');T=P/'target-ht-L3c/release/examples';D=P/'artifacts/hometurf-L3c/generality';D.mkdir(exist_ok=True)
names=['sha256_word_application','keccak_row_workloads','shielded_word_application','shielded_native','shielded_lookup_native']
for name in names:shutil.copyfile(T/name,D/name);(D/name).chmod(0o755)
(D/'metadata.json').write_text(json.dumps({name:hashlib.sha256((D/name).read_bytes()).hexdigest() for name in names},indent=2))
def run(cmd,name,small=False):
 env={**os.environ,'RAYON_NUM_THREADS':'12','LEANVM_NUM_THREADS':'12','LOOKUP_SMALL':'1' if small else '0'};t=time.monotonic()
 with (D/(name+'.stdout')).open('w') as out,(D/(name+'.stderr')).open('w') as err:
  p=subprocess.Popen([str(x) for x in cmd],env=env,stdout=out,stderr=err);_,status,u=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
 if p.returncode:raise RuntimeError((name,p.returncode,(D/(name+'.stderr')).read_text()))
 rows=[json.loads(s) for s in (D/(name+'.stdout')).read_text().splitlines() if s.startswith('{')]
 process={'peak_rss_kib':u.ru_maxrss,'wall_s':time.monotonic()-t,'cmd':[str(x) for x in cmd]};(D/(name+'.process.json')).write_text(json.dumps(process));return rows[-1],process
pairs={'sha256':('sha256-bit','sha256-word'),'shielded-small':('shielded-small','shielded-word'),'shielded-native':('shielded-native','shielded-word')}
def cmd(variant,mode,cert):
 if variant=='sha256-bit':return [D/'keccak_row_workloads','sha256','bits',mode,cert,'0']
 if variant=='shielded-native':return [D/'shielded_native',mode,'0',cert]
 if variant=='shielded-small':return [D/'shielded_lookup_native',mode,cert]
 return [D/('sha256_word_application' if variant=='sha256-word' else 'shielded_word_application'),mode,cert]
results=[]
for pair,(a,b) in pairs.items():
 for r in range(1,4):
  for slot,variant in enumerate([a,b,a,b]):
   name=f'{pair}-r{r}-s{slot}';cert=D/(name+'.cert');wallet,process=run(cmd(variant,'prove',cert),name,variant=='shielded-small');verify,_=run(cmd(variant,'verify',cert),name+'-verify',variant=='shielded-small')
   result={'pair':pair,'round':r,'slot':slot,'variant':variant,'wallet':wallet,'verify':verify,'process':process};results.append(result)
   with (D/'samples.jsonl').open('a') as f:f.write(json.dumps(result)+'\n')
   print(json.dumps(result),flush=True)
 summary={}
 for variant in [a,b]:
  rs=[x for x in results if x['pair']==pair and x['variant']==variant]
  summary[variant]={'wallet_prove_s':statistics.median(x['wallet']['wallet_prove_s'] for x in rs),'peak_rss_kib':statistics.median(x['process']['peak_rss_kib'] for x in rs),'proof_bytes':statistics.median(x['wallet']['proof_bytes'] for x in rs),'verify_ms':statistics.median(x['verify'].get('verify_ms',x['verify'].get('mempool_verify_ms')) for x in rs),'rows':statistics.median(x['wallet'].get('rows',x['wallet'].get('arithmetic_rows',x['wallet'].get('gate_rows',x['wallet'].get('padded_arithmetic_rows')))) for x in rs),'committed_words':statistics.median(x['wallet']['committed_words'] for x in rs)}
 (D/(pair+'-summary.json')).write_text(json.dumps(summary,indent=2));print(json.dumps({'pair':pair,'summary':summary}),flush=True)
