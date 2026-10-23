#!/usr/bin/env python3
"""Fresh-process, interleaved measurements for the standard row formats."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
binary = root.parent / 'target-ht-L2r/release/examples/row_prover'
env = dict(os.environ, LEANVM_NUM_THREADS='12', RAYON_NUM_THREADS='12')
provenance = {
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'cores': '12-23', 'threads': 12, 'build_cores': '48-63',
    'order': ['A', 'B', 'C', 'C', 'B', 'A', 'A', 'B', 'C'],
    'affine_cap': 8,
}
(out / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
with (out / 'pinned.jsonl').open('w') as combined:
    for case in ['shielded', 'merge']:
        counts = dict.fromkeys('ABC', 0)
        digests = set()
        for fmt in provenance['order']:
            counts[fmt] += 1
            stem = f'{case}-{fmt}-{counts[fmt]}'
            proof = out / (stem + '.proof')
            for mode in ['prove', 'verify']:
                result = subprocess.run(
                    ['taskset', '-c', '12-23', str(binary), case, fmt, mode, str(proof), '8'],
                    cwd=root, env=env, text=True, capture_output=True, check=True)
                (out / (stem + '.' + mode + '.log')).write_text(result.stdout + result.stderr)
                record = json.loads(result.stdout.splitlines()[-1])
                record.update(repetition=counts[fmt], mode=mode, cores='12-23', threads=12)
                digests.add(record['source_program_digest'])
                (out / (stem + '.' + mode + '.json')).write_text(json.dumps(record, indent=2) + '\n')
                combined.write(json.dumps(record) + '\n')
                combined.flush()
                print(json.dumps({k: record[k] for k in ['case', 'format', 'repetition', 'mode', 'wallet_s' if mode == 'prove' else 'verify_ms']}), flush=True)
            proof.unlink()
        assert len(digests) == 1, digests
