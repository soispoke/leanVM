#!/usr/bin/env python3
import subprocess,json,pathlib,fcntl,sys
base=pathlib.Path(__file__).resolve().parent
out=base.parent/'artifacts/hometurf-L2'
metrics=out.parent/'hometurf-12t.jsonl'
units={'wallet_prove_s':'s','wallet_peak_rss_kib':'KiB','wallet_proof_bytes':'bytes','mempool_verify_ms':'ms','riscv_cycles':'cycles','committed_words':'u64 words','blake2s_compressions':'compressions','merge2to1_leaf_s':'s','merge2to1_node_s':'s','merged_proof_bytes':'bytes','merge_peak_rss_kib':'KiB','merged_verify_ms':'ms','per_claim_committed_words':'u64 words','rows':'rows'}
commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
for name in sys.argv[1:] or ['leanxmss','leansphincs','hashchain-16','hashchain-256','hashchain-4096','merkle-20','merkle-32','shielded']:
 modes=['wallet','verify']
 if name in ['leanxmss','hashchain-16','hashchain-256','hashchain-4096']:modes+=['leaf','verify-leaf','node','verify-node','stats-one']
 elif name=='leansphincs':modes+=['stats-one']
 for mode in modes:
  p=subprocess.run(['taskset','-c','12-23','env','LEANVM_NUM_THREADS=12','RAYON_NUM_THREADS=12',str(base.parent/'target-leanvm-riscv/release/receipt'),mode,name,str(out/name)],capture_output=True,text=True)
  (out/f'{name}-{mode}.jsonl').write_text(p.stdout)
  if p.returncode: print(p.stdout,p.stderr,flush=True);sys.exit(p.returncode)
  for line in p.stdout.splitlines():
   row=json.loads(line)
   if row['role']=='setup':continue
   print(line,flush=True)
   with metrics.open('a') as f:
    fcntl.flock(f,fcntl.LOCK_EX)
    for key,unit in units.items():
     if key not in row:continue
     entry=dict(system='leanvm',workload=name,role='merge' if mode not in ['wallet','verify'] else row['role'],metric=key,value=row[key],unit=unit,threads=12,cpus='12-23',commit=commit,lane='L2',note=row.get('scope','')+'; '+mode+'; leaf log_inv_rate=2, tree log_inv_rate=1; fixture/signing excluded; raw receipt '+str(out/f'{name}-{mode}.jsonl'))
     f.write(json.dumps(entry)+'\n')
