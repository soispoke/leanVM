#!/usr/bin/env python3
"""Serial, single-operation RISC-V benchmark receipts. Never repeat successful stages."""
from pathlib import Path
import fcntl,json,subprocess,sys,os,hashlib
TREE=Path(__file__).resolve().parent
BASE=TREE.parent
BIN=BASE/'target-leanvm-riscv/release/receipt'
ART=TREE/'artifacts'
os.sched_setaffinity(0,range(12,24))
os.environ.update(CARGO_BUILD_JOBS='12',RAYON_NUM_THREADS='12',LEANVM_NUM_THREADS='12')
METRICS={'wallet_prove_s':'s','wallet_peak_rss_kib':'KiB','wallet_proof_bytes':'bytes','riscv_cycles':'cycles','mempool_verify_ms':'ms','merge2to1_leaf_s':'s','merge2to1_node_s':'s','merged_proof_bytes':'bytes','merged_verify_ms':'ms','merge_peak_rss_kib':'KiB','setup_s':'s'}
def stage(mode,workload):
 label=f'leanvm-riscv-{workload}-{mode}-t1'
 receipt=BASE/label
 prefix=ART/f'{workload}-t1'
 if not receipt.exists():
  code=subprocess.call([sys.executable,str(TREE/'run-application-command.py'),'leanvm-riscv',label,str(BIN),mode,workload,str(prefix)],cwd=TREE)
  if code:raise RuntimeError(f'{label} failed')
 result=json.loads((receipt/'result.json').read_text())
 assert result['ok'] and result['files_unchanged'],label
 assert result['machine']['command_affinity']==list(range(12,24))
 events=[json.loads(x) for x in (receipt/'run-00/stdout.log').read_text().splitlines() if x.startswith('{')]
 marker=ART/f'{label}.published'
 if marker.exists():return
 audit=json.loads((receipt/'concurrency-audit.json').read_text())
 records=[]
 for event in events:
  assert event['threads']==12
  event.update(receipt=str(receipt),noise_note={'load_average_start':audit['load_average_start'],'load_average_end':audit['load_average_end'],'other_lanes':audit['other_benchmark_processes_observed']})
  print(json.dumps(event),flush=True)
  for metric,unit in METRICS.items():
   if metric in event:
    row={k:event[k] for k in ('path','leanvm_version','commit','workload','role','threads','cpus','receipt','noise_note')}
    row.update(metric=metric,value=event[metric],unit=unit,lane='B',kind=event['kind'],measurement='single cold development run',merge_level=event.get('merge_level',mode),verified=mode.startswith('verify'))
    records.append(row)
 for file in [BASE/'artifacts/matched-12t.jsonl',ART/'riscv-metrics.jsonl']:
  with file.open('a') as f:
   fcntl.flock(f,fcntl.LOCK_EX);f.write(''.join(json.dumps(r,sort_keys=True)+'\n' for r in records));f.flush();os.fsync(f.fileno())
 marker.write_text(json.dumps({'receipt':str(receipt),'records':len(records)}))
if __name__=='__main__':
 workloads=sys.argv[1:] or ['mpt','shielded','falcon512','blake2s-1kib','blake2s-64b']
 for name in workloads:
  stage('wallet',name);stage('verify',name)
