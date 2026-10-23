import hashlib,json,os,pathlib,statistics,subprocess,sys,time
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
out=P/'artifacts/L6-wallet-abab';out.mkdir(exist_ok=True)
bins={'A':P/'bin-L6-blake-control/keccak_row_workloads','B':P/'bin-L6-keccak-host/keccak_row_workloads'}
provenance={'order':'ABAB'*3,'A':'native Keccak application, BLAKE2s protocol','B':'native Keccak application, Keccak protocol with grinding','binary_sha256':{k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in bins.items()},'commands':[]}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2))
def run(cmd,path):
    start=time.monotonic()
    with path.with_suffix('.stdout').open('w') as stdout,path.with_suffix('.stderr').open('w') as stderr:
        p=subprocess.Popen(cmd,stdout=stdout,stderr=stderr)
        _,status,usage=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
    receipt={'command':cmd,'exit_code':p.returncode,'peak_rss_kib':usage.ru_maxrss,'whole_process_s':time.monotonic()-start}
    path.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
    if p.returncode:raise RuntimeError(f'failed {path}: {receipt}')
    return [json.loads(line) for line in path.with_suffix('.stdout').read_text().splitlines() if line.startswith('{')],receipt
for workload in sys.argv[1:]:
    samples={'A':[],'B':[]}
    for i,variant in enumerate('ABAB'*3):
        stem=out/f'{workload}-{i:02d}-{variant}'
        proof=str(stem)+'.proof'
        prefix=['taskset','-c','12-23','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12',str(bins[variant]),workload,'rows']
        rows,receipt=run(prefix+['prove',proof,'20261024'],stem)
        wallet=next(r for r in rows if r.get('kind')=='wallet')
        vr,vreceipt=run(prefix+['verify',proof,'20261024'],out/f'{workload}-{i:02d}-{variant}-verify')
        verify=next(r for r in vr if r.get('kind')=='verify')
        record={'variant':variant,'index':i,'wallet_prove_s':wallet['wallet_prove_s'],'peak_rss_kib':receipt['peak_rss_kib'],'proof_bytes':wallet['proof_bytes'],'verify_ms':verify['verify_ms'],'rows':wallet['arithmetic_rows'],'words':wallet['committed_words'],'application_permutations':wallet['permutations']}
        samples[variant].append(record)
        with (out/'samples.jsonl').open('a') as f:f.write(json.dumps({'workload':workload,**record})+'\n')
        with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
            for metric,value in record.items():
                if metric in ['variant','index']:continue
                unit='s' if metric.endswith('_s') else ('ms' if metric.endswith('_ms') else ('KiB' if metric=='peak_rss_kib' else ('bytes' if metric=='proof_bytes' else ('F64 words' if metric=='words' else ('rows' if metric=='rows' else 'permutations')))))
                f.write(json.dumps(dict(system='r1cs',lane='L6',workload=workload+'-keccak-app-'+variant,role='wallet',metric=metric,value=value,unit=unit,threads=12,cpus='12-23',commit='immutable-binaries-see-L6-wallet-abab-provenance',note=f'ABAB3 sample {i}; {provenance[variant]}; application_permutations excludes claim envelope; whole-process wait4 RSS.'))+'\n')
        print(json.dumps({'workload':workload,**record}),flush=True)
    medians={v:{k:statistics.median(r[k] for r in rs) for k in rs[0] if k not in ['variant','index']} for v,rs in samples.items()}
    (out/f'{workload}-medians.json').write_text(json.dumps(medians,indent=2))
    print(json.dumps({'workload':workload,'medians':medians}),flush=True)
