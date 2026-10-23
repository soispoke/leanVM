#!/usr/bin/env python3
"""Validate complete ABAB receipts and publish measured role metrics."""
import fcntl
import json
from pathlib import Path
import statistics
import sys
workload = sys.argv[1]
root = Path.cwd().parent
out = root/'artifacts'/'hometurf-L4k'/(workload+'-abab')
meta = json.loads((out/'metadata.json').read_text())
all_statements = []
rows = []
summary = {}
for variant in ['bits','rows']:
    samples = []
    for r in range(1,4):
        for slot in ([0,2] if variant == 'bits' else [1,3]):
            stem = out/f'r{r}-s{slot}-{variant}'
            receipt = json.loads(Path(str(stem)+'.process.json').read_text())
            assert receipt['exit_code'] == 0
            records = [json.loads(line) for line in Path(str(stem)+'.stdout').read_text().splitlines()]
            wallet, = [rec for rec in records if rec.get('kind') == 'wallet']
            all_statements.append(wallet['statement'])
            wallet['wallet_peak_rss_kib'] = receipt['whole_process_peak_rss_kib']
            samples.append(wallet)
    verify = [json.loads(line) for line in (out/f'verify-{variant}.stdout').read_text().splitlines() if json.loads(line).get('kind') == 'verify'][0]
    assert json.loads((out/f'verify-{variant}.process.json').read_text())['exit_code'] == 0
    result = {key:statistics.median([sample[key] for sample in samples]) for key in ['wallet_prove_s','wallet_peak_rss_kib','proof_bytes','arithmetic_rows','padded_arithmetic_rows','committed_words','permutations']}
    result['verify_ms'] = verify['verify_ms']
    result['samples_s'] = [sample['wallet_prove_s'] for sample in samples]
    summary[variant] = result
    mapping = {'wallet_prove_s':('wallet_prove_s','s'), 'wallet_peak_rss_kib':('wallet_peak_rss_kib','KiB'),'proof_bytes':('wallet_proof_bytes','bytes'),'arithmetic_rows':('arithmetic_rows','rows'),'padded_arithmetic_rows':('padded_arithmetic_rows','rows'),'committed_words':('committed_words','F64 words'),'permutations':('native_keccak_rows','permutations'),'verify_ms':('mempool_verify_ms','ms')}
    for key,(metric,unit) in mapping.items():
        rows.append({'system':'r1cs','workload':samples[0]['workload']+('-keccak-rows' if variant=='rows' else '-bit-level'),'role':'mempool' if key=='verify_ms' else 'wallet','metric':metric,'value':result[key],'unit':unit,'threads':12,'cpus':'36-47','commit':meta['source_commit'],'lane':'L4b','note':'matched canonical BLAKE2s application claim; three ABAB rounds/six fresh processes per variant; medians; direct Boolean/native compiler; binary sha256 '+meta['binary_sha256']})
assert all(statement == all_statements[0] for statement in all_statements)
summary['metadata'] = meta
summary['statement'] = all_statements[0]
(out/'summary.json').write_text(json.dumps(summary,indent=2))
with (root/'artifacts'/'hometurf-12t.jsonl').open('a') as f:
    fcntl.flock(f,fcntl.LOCK_EX)
    for row in rows: f.write(json.dumps(row,separators=(',',':'))+'\n')
print(json.dumps(summary,indent=2))
