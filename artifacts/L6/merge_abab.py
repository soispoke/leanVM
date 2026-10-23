import hashlib,json,os,pathlib,statistics,subprocess,time
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
out=P/'artifacts/L6-merge-abab';out.mkdir(exist_ok=True)
prefix=['taskset','-c','12-23','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']
bins={'A':P/'bin-L6-current-blake','B':P/'bin-L6-fixed-prefix'}
provenance={'order':'ABAB'*3,'A':'BLAKE2s protocol and original BLAKE2s sparse shielded/Merkle applications','B':'Keccak protocol and Keccak sparse shielded/Merkle applications; fixed-prefix compiler optimization','binary_sha256':{v:{name:hashlib.sha256((d/name).read_bytes()).hexdigest() for name in ['deferred_merge','sparse_tree']} for v,d in bins.items()}}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2))
def run(cmd,stem):
    start=time.monotonic()
    with stem.with_suffix('.stdout').open('w') as stdout,stem.with_suffix('.stderr').open('w') as stderr:
        proc=subprocess.Popen(prefix+cmd,stdout=stdout,stderr=stderr)
        _,status,usage=os.wait4(proc.pid,0);proc.returncode=os.waitstatus_to_exitcode(status)
    receipt={'command':prefix+cmd,'exit_code':proc.returncode,'peak_rss_kib':usage.ru_maxrss,'whole_process_s':time.monotonic()-start}
    stem.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
    if proc.returncode:raise RuntimeError(f'{stem}: {receipt}')
    rows=[json.loads(line) for line in stem.with_suffix('.stdout').read_text().splitlines() if line.startswith('{')]
    return rows[-1],receipt
while pathlib.Path('/proc/366556').exists():time.sleep(10)
for workload,exe,args in [('first','deferred_merge',['merkle','B','B','carried']),('node','sparse_tree',[])]:
    samples={'A':[],'B':[]}
    for i,v in enumerate('ABAB'*3):
        r,receipt=run([str(bins[v]/exe)]+args,out/f'{workload}-{i:02d}-{v}')
        assert r['verified']
        record={'merge_s':r['merge_s'],'peak_rss_kib':receipt['peak_rss_kib'],'proof_bytes':r['proof_bytes'],'core_verify_ms':r['core_verify_ms'],'complete_root_ms':r['complete_root_ms'],'rows':r['rows'],'words':r['committed_words'],'permutations':r['permutations'],'compressions':r['compressions']}
        samples[v].append(record)
        with (out/'samples.jsonl').open('a') as f:f.write(json.dumps({'workload':workload,'variant':v,'index':i,**record})+'\n')
        with (P/'artifacts/hometurf-12t.jsonl').open('a') as f:
            for metric,value in record.items():
                unit='s' if metric.endswith('_s') else ('ms' if metric.endswith('_ms') else ('KiB' if metric=='peak_rss_kib' else ('bytes' if metric=='proof_bytes' else 'count')))
                f.write(json.dumps(dict(system='r1cs',lane='L6',workload=workload+'-mixed-'+v,role='merge',metric=metric,value=value,unit=unit,threads=12,cpus='12-23',commit='immutable-binaries-see-L6-merge-abab-provenance',note=f'ABAB3 sample {i}; {provenance[v]}; complete root verifier and direct rejection probes pass.'))+'\n')
        print(json.dumps({'workload':workload,'variant':v,'index':i,**record}),flush=True)
    medians={v:{k:statistics.median(r[k] for r in rs) for k in rs[0]} for v,rs in samples.items()}
    (out/f'{workload}-medians.json').write_text(json.dumps(medians,indent=2))
    print(json.dumps({'workload':workload,'medians':medians}),flush=True)
