"""Collect fresh-process medians and append missing measurement rows."""
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHARED = ROOT.parent / 'artifacts'
GROUPS = {
    'generator': ['same', 'mixed'],
    'paired-fixed-baseline': ['same', 'mixed'],
    'paired-fixed-fixed': ['same', 'mixed'],
    'combined': ['same', 'mixed'],
    'simd': ['same', 'mixed'],
    'merkle-control': ['same', 'merkle'],
}
summary = {}
rows = []
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
for group, cases in GROUPS.items():
    for case in cases:
        files = [HERE / f'{group}-{case}-{i}.json' for i in range(1, 4)]
        data = [json.loads(p.read_text()) for p in files]
        assert all(d['verified'] for d in data)
        keys = ['merge_s', 'fold_prover_s', 'outer_prover_s', 'rows', 'committed_words', 'proof_bytes',
                'carried_claim_bytes', 'own_merge_matrix_settle_ms', 'core_verify_ms']
        result = {k: statistics.median(d[k] for d in data) for k in keys}
        result['root_ms'] = statistics.median(d['core_verify_ms'] + d['own_merge_matrix_settle_ms'] +
                                             sum(s['ms'] for s in d['root_settlements']) for d in data)
        result['raw'] = [p.name for p in files]
        summary[f'{group}-{case}'] = result
        for p, d in zip(files, data):
            for key, metric, unit in [('merge_s', 'merge2to1_s', 's'), ('fold_prover_s', 'matrix_fold_prover_s', 's'),
                                     ('rows', 'merge_rows', 'rows'), ('committed_words', 'merge_committed_words', 'words'),
                                     ('proof_bytes', 'merge_proof_bytes', 'bytes'),
                                     ('carried_claim_bytes', 'merge_carried_bytes', 'bytes')]:
                rows.append(dict(system='r1cs', workload='sparse-carried-' + case, role='merge', metric=metric,
                                 value=d[key], unit=unit, threads=12, cpus='12-23', commit=commit, lane='L2b',
                                 note=f'{p.relative_to(ROOT)}; candidate={group}; commit records evidence, candidate source differs by group'))
(HERE / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
log = SHARED / 'hometurf-12t.jsonl'
existing = set()
for line in log.read_text().splitlines():
    try:
        d = json.loads(line)
        existing.add((d.get('metric'), d.get('note')))
    except json.JSONDecodeError:
        pass
with log.open('a') as out:
    for row in rows:
        if (row['metric'], row['note']) not in existing:
            out.write(json.dumps(row) + '\n')

binaries = {}
for candidate in ['bc1f691a', 'generator', 'generator-fixed', 'generator-combined', 'generator-simd']:
    binary = Path('/tmp') / f'L2r-{candidate}-merge'
    binaries[candidate] = hashlib.sha256(binary.read_bytes()).hexdigest()
(HERE / 'generator-provenance.json').write_text(json.dumps(dict(
    evidence_commit=commit, binaries=binaries, cores='12-23', threads=12,
    order='For each group: same/mixed, mixed/same, same/mixed. merkle-control substitutes merkle for mixed. paired-fixed alternates baseline/candidate within each case.',
    build='Rust 1.99.1 release; cores 48-63; CARGO_BUILD_JOBS=4',
    note='All timings include fresh wallet proofs in each process; setup excluded from merge. Native matrix fold uses source walks; wallet and outer Spartan retain CSR.'), indent=2) + '\n')
print(json.dumps(summary, indent=2))
