#!/usr/bin/env python3
"""Recheck full-run raw receipts, statements and independently derived totals."""
from pathlib import Path
import hashlib
import importlib.util
import json
import statistics

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
spec = importlib.util.spec_from_file_location('trees', ROOT / 'experiments/pcs-r1cs/recursion/summarize_trees.py')
trees = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trees)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def audit_guard(path):
    value = json.loads((path / 'result.json').read_text())
    assert value['ok'] and value['files_unchanged']
    assert value['file_sha256_before'] == value['file_sha256_after']
    for i, run in enumerate(value['runs']):
        folder = path / f'run-{i:02d}'
        assert run['ok'] and run['stop_reason'] is None
        assert digest(folder / 'stdout.log') == run['stdout_sha256']
        assert digest(folder / 'stderr.log') == run['stderr_sha256']
    return value

def run_values(path):
    checked = trees.load(path)
    audit_guard(path.with_name(path.name + '-guard'))
    rows = [json.loads(line) for line in (path / 'stdout.jsonl').read_text().splitlines()]
    proofs = [r for r in rows if r['kind'] == 'proof']
    setups = [r for r in rows if r['kind'] == 'setup']
    root = proofs[-1]
    return dict(directory=str(path.relative_to(BASE)),
                root_preparation_proving_s=root['proving_s'] + root.get('preparation_s', 0),
                root_proving_s=root['proving_s'], root_verification_ms=root['verification_ms'],
                root_proof_bytes=root['proof_bytes'],
                setup_s=sum(r['setup_s'] for r in setups),
                all_preparation_proving_s=sum(r['proving_s'] + r.get('preparation_s', 0) for r in proofs),
                leaf_proving_s=statistics.median(r['proving_s'] for r in proofs if r['level'] == 0),
                process_s=checked['elapsed_s'], rss_gib=checked['peak_rss_gib'],
                shapes=[{k:r[k] for k in ('level', 'rows', 'native_shape', 'compressions', 'code_len') if k in r} for r in setups])

def main():
    output = {'scope':'Local full-length benchmark; Flock baseline has a different statement and timing policy.', 'workloads':{}}
    for depth in (1, 2, 3):
        work = BASE / f'depth{depth}-chain16384'
        summary = json.loads((work / 'summary.json').read_text())
        result = {}
        for name, group in summary['groups'].items():
            runs = [run_values(Path(r['directory'])) for r in group['runs']]
            assert len(runs) == 3
            assert all(r['shapes'] == runs[0]['shapes'] for r in runs)
            warmups = [p.parent for p in work.glob(f'{name}-warmup*/result.json')
                       if not p.parent.name.endswith('-guard') and json.loads(p.read_text()).get('returncode') == 0]
            assert len(warmups) == 1, warmups
            run_values(warmups[0])
            medians = {key:statistics.median(r[key] for r in runs) for key in runs[0]
                       if isinstance(runs[0][key], (int, float))}
            ranges = {key:[min(r[key] for r in runs), max(r[key] for r in runs)] for key in medians}
            result[name] = dict(medians=medians, ranges=ranges, peak_rss_gib=max(r['rss_gib'] for r in runs), runs=runs)
        output['workloads'][str(1 << depth)] = result
    (BASE / 'audit.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({leaves:{name:r['medians'] for name,r in groups.items()} for leaves,groups in output['workloads'].items()}, indent=2))

if __name__ == '__main__':
    main()
