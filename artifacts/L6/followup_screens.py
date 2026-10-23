import hashlib,json,os,pathlib,statistics,subprocess,time
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
out=P/'artifacts/L6-followup';out.mkdir(exist_ok=True)
prefix=['taskset','-c','12-23','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']
def run(cmd,stem):
    start=time.monotonic()
    with stem.with_suffix('.stdout').open('w') as stdout,stem.with_suffix('.stderr').open('w') as stderr:
        proc=subprocess.Popen(prefix+cmd,stdout=stdout,stderr=stderr)
        _,status,usage=os.wait4(proc.pid,0);proc.returncode=os.waitstatus_to_exitcode(status)
    receipt={'command':prefix+cmd,'exit_code':proc.returncode,'peak_rss_kib':usage.ru_maxrss,'whole_process_s':time.monotonic()-start,'binary_sha256':hashlib.sha256(pathlib.Path(cmd[0]).read_bytes()).hexdigest()}
    stem.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
    if proc.returncode:raise RuntimeError(f'{stem}: {receipt}')
    return [json.loads(s) for s in stem.with_suffix('.stdout').read_text().splitlines() if s.startswith('{')][-1],receipt

def record(workload,r):
    with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
        for metric,value in r.items():
            if not isinstance(value,(int,float)) or isinstance(value,bool):continue
            unit='s' if metric.endswith('_s') else ('ms' if metric.endswith('_ms') else ('KiB' if metric=='peak_rss_kib' else 'count'))
            f.write(json.dumps(dict(system='r1cs',lane='L6',workload=workload,role='screen',metric=metric,value=value,unit=unit,threads=12,cpus='12-23',commit='see-L6-followup-receipts',note='screen or ABAB sample; immutable binary hash in receipt'))+'\n')
    print(json.dumps({'workload':workload,**r}),flush=True)
while not (P/'artifacts/L6-merge-abab/node-medians.json').exists():time.sleep(10)
samples={'A':[],'B':[]}
for i,v in enumerate('ABAB'*3):
    binary=P/('bin-L6-current-blake' if v=='A' else 'bin-L6-merkle-keccak')/'keccak_merkle_application'
    stem=out/f'merkle-{i:02d}-{v}';proof=str(stem)+'.proof'
    r,receipt=run([str(binary),'prove',proof,'1'],stem)
    vr,_=run([str(binary),'verify',proof,'1'],out/f'merkle-{i:02d}-{v}-verify')
    sample={k:r[k] for k in ['wallet_prove_s','proof_bytes','arithmetic_rows','committed_words','permutations']}
    sample.update(peak_rss_kib=receipt['peak_rss_kib'],verify_ms=vr['verify_ms']);samples[v].append(sample)
    record('merkle-wallet-'+v,sample)
medians={v:{k:statistics.median(s[k] for s in rs) for k in rs[0]} for v,rs in samples.items()}
(out/'merkle-medians.json').write_text(json.dumps(medians,indent=2));print(json.dumps({'merkle_medians':medians}),flush=True)
for workload,exe,args in [('first-batched','deferred_merge',['merkle','B','B','carried']),('node-batched','sparse_tree',[])]:
    r,receipt=run([str(P/'bin-L6-batched-transcript'/exe)]+args,out/workload)
    r['whole_process_peak_rss_kib']=receipt['peak_rss_kib'];record(workload,r)
