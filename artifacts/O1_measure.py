import hashlib,json,os,pathlib,statistics,subprocess,sys,time
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
name=sys.argv[1]; dirs=[P/'artifacts/opt-O1/control',pathlib.Path(sys.argv[2])] if len(sys.argv)>2 else [P/'artifacts/opt-O1/control']
out=P/'artifacts/opt-O1'/name;out.mkdir(parents=True,exist_ok=True)
variants=dict(zip('AB',dirs)); prefix=['taskset','-c','12-23','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']
commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
(out/'provenance.json').write_text(json.dumps({'order':'ABAB'*3 if len(dirs)==2 else 'AAA','commit':commit,'sha256':{v:{x:hashlib.sha256((d/x).read_bytes()).hexdigest() for x in ['deferred_merge','sparse_tree']} for v,d in variants.items()}},indent=2))
for workload,exe,args in [('first','deferred_merge',['merkle','B','B','carried']),('node','sparse_tree',[])]:
 samples={v:[] for v in variants}
 for i,v in enumerate('ABAB'*3 if len(dirs)==2 else 'AAA'):
  stem=out/f'{workload}-{i:02d}-{v}';cmd=prefix+[str(variants[v]/exe)]+args; start=time.monotonic()
  with stem.with_suffix('.stdout').open('w') as stdout,stem.with_suffix('.stderr').open('w') as stderr:
   p=subprocess.Popen(cmd,stdout=stdout,stderr=stderr);_,status,usage=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
  receipt={'command':cmd,'exit_code':p.returncode,'peak_rss_kib':usage.ru_maxrss,'whole_process_s':time.monotonic()-start};stem.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
  if p.returncode:raise RuntimeError(str(stem))
  r=[json.loads(l) for l in stem.with_suffix('.stdout').read_text().splitlines() if l.startswith('{')][-1];assert r['verified']
  record={k:r[k] for k in ['merge_s','committed_words','rows','proof_bytes','core_verify_ms','complete_root_ms','permutations','outer_prover_s','fold_prover_s','record_s','native_child_checks_s']};samples[v].append(record)
  with (out/'samples.jsonl').open('a') as f:f.write(json.dumps({'workload':workload,'variant':v,'index':i,**record})+'\n')
  with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
   for metric,value in record.items():
    unit='s' if metric.endswith('_s') else 'ms' if metric.endswith('_ms') else 'bytes' if metric=='proof_bytes' else 'count'
    f.write(json.dumps(dict(system='r1cs',workload=workload+'-mixed',role='merge',metric=metric,value=value,unit=unit,threads=12,cpus='12-23',commit='9e5f41c4' if v=='A' else commit,lane='O1',note=f'{name}; variant {v}; sample {i}; binary hashes in provenance'))+'\n')
  print(json.dumps({'workload':workload,'variant':v,'index':i,**record}),flush=True)
 medians={v:{k:statistics.median(r[k] for r in rs) for k in rs[0]} for v,rs in samples.items()};(out/f'{workload}-medians.json').write_text(json.dumps(medians,indent=2));print(json.dumps({'workload':workload,'medians':medians}),flush=True)
