import hashlib,json,os,pathlib,subprocess,time
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022');out=P/'artifacts/L6-layout-screen';out.mkdir(exist_ok=True)
binary=P/'bin-L6-layout/keccak_layout_screen'
while not (P/'artifacts/L6-followup/node-batched.receipt.json').exists() or not binary.exists():time.sleep(10)
for arity,leaf in [(2,32),(4,32),(2,128),(4,128)]:
    stem=out/f'arity{arity}-leaf{leaf}';cmd=['taskset','-c','12-23','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12',str(binary),str(arity),str(leaf)]
    with stem.with_suffix('.stdout').open('w') as stdout,stem.with_suffix('.stderr').open('w') as stderr:
        proc=subprocess.Popen(cmd,stdout=stdout,stderr=stderr);_,status,usage=os.wait4(proc.pid,0);proc.returncode=os.waitstatus_to_exitcode(status)
    receipt={'command':cmd,'exit_code':proc.returncode,'peak_rss_kib':usage.ru_maxrss,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};stem.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
    assert proc.returncode==0,receipt
    r=json.loads(stem.with_suffix('.stdout').read_text().splitlines()[-1]);r['peak_rss_kib']=usage.ru_maxrss
    print(json.dumps(r),flush=True)
    with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
        for metric,value in r.items():
            if not isinstance(value,(int,float)) or isinstance(value,bool):continue
            f.write(json.dumps(dict(system='r1cs',lane='L6',workload=f'isolated-keccak-arity{arity}-leaf{leaf}',role='screen',metric=metric,value=value,unit='s' if metric.endswith('_s') else ('ms' if metric.endswith('_ms') else 'count'),threads=12,cpus='12-23',commit='see-L6-layout-screen-receipts',note='isolated native membership relation; not a changed PCS or merge'))+'\n')
