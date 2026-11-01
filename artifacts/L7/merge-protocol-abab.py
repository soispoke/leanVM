#!/usr/bin/env python3
import fcntl,hashlib,json,shutil,statistics,subprocess,sys
from pathlib import Path
P=Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022'); ROOT=P/'lvm-L7'; OUT=P/'artifacts/hometurf-L7/protocol-merge-abab'; W=P/'artifacts/hometurf-L7/protocol-wallet-abab'
OUT.mkdir(exist_ok=True); SNAP=OUT/'bin'; SNAP.mkdir(exist_ok=True)
manifest={}
for v,t in [('A','target-L7-control'),('B','target-L7')]:
 dst=SNAP/f'merge-{v}'; shutil.copy2(P/t/'release/merge',dst)
 manifest[v]={'path':str(dst),'sha256':hashlib.sha256(dst.read_bytes()).hexdigest()}
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
samples=[]
def command(v,mode,case,prefix,child):
 pos='1A' if v=='A' else '2B'; other='merkle' if 'mixed' in case else 'shielded'
 return [manifest[v]['path'],mode,case,str(W/f'bin/shielded-{v}.elf'),str(W/f'shielded-r1-{pos}'),str(W/f'bin/{other}-{v}.elf'),str(W/f'{other}-r1-{pos}'),str(prefix),str(child)]
def run(v,mode,case,prefix,child):
 dest=str(prefix)+('-verify' if mode=='verify' else '-reject' if mode=='reject' else '')
 result=subprocess.run([sys.executable,str(ROOT/'artifacts/L7/run-one.py'),dest,*command(v,mode,case,prefix,child)],capture_output=True,text=True)
 if result.returncode: raise RuntimeError(result.stdout+'\n'+result.stderr)
 return json.loads(Path(dest+'.stdout').read_text()),json.loads(Path(dest+'.resources.json').read_text())
for case in ['same','mixed','node-mixed']:
 for rnd in range(1,4):
  for pos,v in enumerate('ABAB',1):
   prefix=OUT/f'{case}-r{rnd}-{pos}{v}'; child=OUT/f'mixed-r1-{1 if v=="A" else 2}{v}'
   w,r=run(v,'prove',case,prefix,child); q,qr=run(v,'verify',case,prefix,child)
   sample=dict(case=case,variant=v,round=rnd,position=pos,merge2to1_s=w['merge_s'],setup_s=w['setup_s'],merge_peak_rss_kib=r['peak_rss_kib'],merge_proof_bytes=w['proof_bytes'],merge_committed_words=w['committed_words'],merge_rows=w['rows'],merge_verify_ms=q['verify_ms'],merge_verify_peak_rss_kib=qr['peak_rss_kib'],whole_process_s=r['elapsed_s'])
   samples.append(sample); (OUT/'samples.json').write_text(json.dumps(samples,indent=2)+'\n'); print(json.dumps(sample),flush=True)
 summary={v:{k:statistics.median(s[k] for s in samples if s['case']==case and s['variant']==v) for k in samples[-1] if k not in ['case','variant','round','position']} for v in 'AB'}
 (OUT/f'{case}-medians.json').write_text(json.dumps(summary,indent=2)+'\n'); print('MEDIAN '+case+' '+json.dumps(summary),flush=True)
 for v in 'AB':
  prefix=OUT/f'{case}-r1-{1 if v=="A" else 2}{v}'; child=OUT/f'mixed-r1-{1 if v=="A" else 2}{v}'
  run(v,'reject',case,prefix,child)
 with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX)
  for v,metrics in summary.items():
   note=f'ABAB x3 median six fresh processes; variant {v}; A baseline a40a7fa6 plus fixed-pair extension 5eeb6207; B full Keccak protocol and instruction plus same extension; leaves rate1/4 recursion rate1/2; setup excluded merge timer, included process RSS; merge SHA256 {manifest[v]["sha256"]}; case {case}; cycles not applicable to direct recursive circuit; rows reported instead'
   for k,val in metrics.items():
    unit='KiB' if k.endswith('kib') else 'bytes' if k.endswith('bytes') else 'ms' if k.endswith('ms') else 's' if k.endswith('_s') else 'rows' if k.endswith('rows') else 'words'
    f.write(json.dumps(dict(system='leanvm',workload=case,role='setup' if k=='setup_s' else 'merge',metric=k,value=val,unit=unit,threads=12,cpus='24-35',commit='ef342ea4+full-keccak-dirty',lane='L7',note=note))+'\n')
