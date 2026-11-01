#!/usr/bin/env python3
"""Run from leanvm-riscv after building --release -p leanvm-cli --bin mixed."""
import datetime
import fcntl
import hashlib
import json
import pathlib
import subprocess

receipts = pathlib.Path('../artifacts/hometurf-L2')
binary = pathlib.Path('../target-leanvm-riscv/release/mixed')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
command = ['taskset', '-c', '12-23', 'env', 'LEANVM_NUM_THREADS=12',
           'RAYON_NUM_THREADS=12', str(binary)]
samples = []
for number, case in enumerate(['same', 'mixed', 'same', 'mixed']):
    prefix = receipts / f'mixed-abab-{number + 1}-{case}'
    sample = {'sample': number + 1, 'source_commit': commit,
              'binary_sha256': binary_sha256, 'cpus': '12-23',
              'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    for mode in ['merge', 'verify']:
        run = subprocess.run(command + [mode, case, str(prefix)],
                             text=True, capture_output=True, check=True)
        prefix.with_suffix(f'.{mode}.stdout.json').write_text(run.stdout)
        prefix.with_suffix(f'.{mode}.stderr.log').write_text(run.stderr)
        result = json.loads(run.stdout)
        result[f'{mode}_setup_s'] = result.pop('setup_s')
        sample.update(result)
    sample['receipt'] = str(prefix)
    samples.append(sample)
    print(json.dumps(sample), flush=True)

pathlib.Path('../artifacts/hometurf-mixed-measurements.json').write_text(
    json.dumps(samples, indent=2) + '\n')
with pathlib.Path('../artifacts/hometurf-12t.jsonl').open('a') as output:
    fcntl.flock(output, fcntl.LOCK_EX)
    for sample in samples:
        case = sample['case']
        for metric, key, unit in [
            ('merge2to1_mixed_s' if case == 'mixed' else 'merge2to1_leaf_s', 'merge_s', 's'),
            ('merge_committed_words', 'committed_words', 'u64 words'),
            ('merge_rows', 'rows', 'rows'),
            ('merge_verify_ms', 'verify_ms', 'ms'),
            ('merge_proof_bytes', 'proof_bytes', 'bytes'),
            ('merge_peak_rss_kib', 'rss_kib', 'KiB'),
        ]:
            output.write(json.dumps({
                'system': 'leanvm', 'lane': 'L2', 'workload': 'shielded+leanxmss' if case == 'mixed' else 'shielded+shielded',
                'role': 'first-level merge', 'metric': metric, 'value': sample[key],
                'unit': unit, 'threads': 12, 'cpus': '12-23', 'commit': commit,
                'sample': sample['sample'], 'receipt': sample['receipt'],
                'note': 'ABAB; fixed ordered program pair; all checks enabled; setup excluded; independent-process verify includes decode',
            }) + '\n')
    output.flush()
    fcntl.flock(output, fcntl.LOCK_UN)
