import pathlib,subprocess,json,statistics,hashlib,time,os
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
out=P/'artifacts/opt-O2/quadcap-fast-abab';out.mkdir(exist_ok=True)
bins={'A':P/'bin-opt-O2-control','B':P/'bin-opt-O2-quadcap-fast'}
prefix=['taskset','-c','24-35','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']
(out/'provenance.json').write_text(json.dumps({v:{n:hashlib.sha256((d/n).read_bytes()).hexdigest() for n in ['deferred_merge','sparse_tree']} for v,d in bins.items()},indent=2))
for workload,exe,args in [('first','deferred_merge',['merkle','B','B','carried']),('node','sparse_tree',[])]:
 samples={'A':[],'B':[]}
 for i,v in enumerate('ABAB'*3):
  stem=out/f'{workload}-{i:02d}-{v}'
  if stem.with_suffix('.receipt.json').exists():
   r=json.loads(stem.with_suffix('.stdout').read_text().splitlines()[-1]);assert r['verified']
   samples[v].append({k:r[k] for k in ['merge_s','permutations','committed_words','rows','proof_bytes','core_verify_ms','complete_root_ms']})
   continue
  cmd=prefix+[str(bins[v]/exe)]+args
  start=time.monotonic()
  with stem.with_suffix('.stdout').open('w') as stdout,stem.with_suffix('.stderr').open('w') as stderr:
   proc=subprocess.Popen(cmd,stdout=stdout,stderr=stderr)
   _,status,usage=os.wait4(proc.pid,0)
  receipt=dict(command=cmd,exit_code=os.waitstatus_to_exitcode(status),whole_process_s=time.monotonic()-start,peak_rss_kib=usage.ru_maxrss)
  stem.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
  if receipt['exit_code']:raise RuntimeError(receipt)
  r=json.loads(stem.with_suffix('.stdout').read_text().splitlines()[-1]);assert r['verified']
  row={k:r[k] for k in ['merge_s','permutations','committed_words','rows','proof_bytes','core_verify_ms','complete_root_ms']}
  samples[v].append(row)
  with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
   for k,value in row.items():
    unit='s' if k.endswith('_s') else 'ms' if k.endswith('_ms') else 'bytes' if k=='proof_bytes' else 'count'
    f.write(json.dumps(dict(system='r1cs',workload=workload,role='merge',metric=k,value=value,unit=unit,threads=12,cpus='24-35',commit='9e5f41c4' if v=='A' else 'ba49591f',lane='O2',note=f'quadcap-fast ABAB3 {i} {v}; binary hashes in quadcap-fast-abab/provenance.json'))+'\n')
  print(json.dumps(dict(workload=workload,index=i,variant=v,**row)),flush=True)
 medians={v:{k:statistics.median(r[k] for r in rows) for k in rows[0]} for v,rows in samples.items()}
 (out/f'{workload}-medians.json').write_text(json.dumps(medians,indent=2))
 print(json.dumps(dict(workload=workload,medians=medians)),flush=True)
