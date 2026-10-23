#!/usr/bin/env python3
"""Validate six independent native proofs and publish final medians once."""
import fcntl,json,statistics
from pathlib import Path
root=Path.cwd().parent
out=root/'artifacts/hometurf-L4k'
values=[]
for i in range(1,7):
 stem=out/f'mldsa-native-r{i}'
 receipt=json.loads(Path(str(stem)+'.process.json').read_text())
 assert receipt['exit_code']==0
 records=[json.loads(s) for s in Path(str(stem)+'.stdout').read_text().splitlines()]
 wallet,=[r for r in records if r.get('kind')=='wallet']
 wallet['wallet_peak_rss_kib']=receipt['whole_process_peak_rss_kib']
 values.append(wallet)
assert all(v['statement']==values[0]['statement'] for v in values)
keys=['wallet_prove_s','wallet_peak_rss_kib','proof_bytes','arithmetic_rows','padded_arithmetic_rows','committed_words','permutations']
summary={k:statistics.median(v[k] for v in values) for k in keys}
summary['samples_s']=[v['wallet_prove_s'] for v in values]
summary['rss_samples_kib']=[v['wallet_peak_rss_kib'] for v in values]
summary['statement']=values[0]['statement']
verify=[json.loads(s) for s in (out/'mldsa-native-verify.stdout').read_text().splitlines()]
summary['verify_ms'],=[v['verify_ms'] for v in verify if v.get('kind')=='verify']
summary['sampling']='six native processes, no bit-level ABAB because memory projection exceeds 200 GiB'
summary['metadata']=json.loads((out/'mldsa-metadata.json').read_text())
(out/'mldsa-summary.json').write_text(json.dumps(summary,indent=2))
with (root/'artifacts/hometurf-12t.jsonl').open('a') as f:
 fcntl.flock(f,fcntl.LOCK_EX)
 for key,metric,unit in [('wallet_prove_s','wallet_prove_s','s'),('wallet_peak_rss_kib','wallet_peak_rss_kib','KiB'),('proof_bytes','wallet_proof_bytes','bytes'),('arithmetic_rows','arithmetic_rows','rows'),('padded_arithmetic_rows','padded_arithmetic_rows','rows'),('committed_words','committed_words','F64 words'),('permutations','native_keccak_rows','permutations'),('verify_ms','mempool_verify_ms','ms')]:
  f.write(json.dumps({'system':'r1cs','workload':'mldsa44-keccak-rows','role':'mempool' if key=='verify_ms' else 'wallet','metric':metric,'value':summary[key],'unit':unit,'threads':12,'cpus':'36-47','commit':summary['metadata']['source_commit'],'lane':'L4b','note':summary['sampling']+'; medians; pinned L5 sign(0), validity and digest; fixed rejection budgets'})+'\n')
print(json.dumps(summary,indent=2))
