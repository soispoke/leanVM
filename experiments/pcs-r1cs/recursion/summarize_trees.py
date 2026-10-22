#!/usr/bin/env python3
"""Validate retained tagged trees and compare repeated whole-process trials."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


def require(value, message):
    if not value:
        raise ValueError(message)


def statements(depth, chain):
    leaves = []
    for i in range(1 << depth):
        d = hashlib.blake2s((i + 20261022).to_bytes(8, 'little')).digest()
        for _ in range(chain):
            d = hashlib.blake2s(b'\x43' + d).digest()
        leaves.append(hashlib.blake2s(b'\x4c' + d + chain.to_bytes(8, 'little')).digest())
    levels = [leaves]
    for _ in range(depth):
        prior = levels[-1]
        levels.append([hashlib.blake2s(b'\x4e' + a + b).digest() for a, b in zip(prior[::2], prior[1::2])])
    return levels


def load(directory):
    directory = Path(directory)
    receipt = json.loads((directory / 'result.json').read_text())
    start = json.loads((directory / 'started.json').read_text())
    require(all(receipt.get(k) == v for k, v in start.items()), 'receipt changed')
    require(receipt['returncode'] == 0 and receipt['stop_reason'] is None, 'failed run')
    require(not receipt['harness_worktree_dirty'], 'dirty source')
    require(receipt['peak_rss_gib'] <= receipt['budget_gib'] and receipt['min_available_gib'] >= 40, 'resource limit')
    command = receipt['command']
    depth = int(command[command.index('--depth') + 1])
    chain = int(command[command.index('--chain') + 1])
    require(1 <= depth <= 3 and 0 <= chain <= 1 << 20, 'invalid workload')
    rows = [json.loads(line) for line in (directory / 'stdout.jsonl').read_text().splitlines()]
    require(all(r['kind'] in {'leaf_trace', 'setup', 'node_trace', 'proof', 'complete'} for r in rows), 'unknown record')
    completed = [r for r in rows if r['kind'] == 'complete']
    require(len(completed) == 1 and rows[-1] == completed[0], 'completion count')
    done = completed[0]
    require(done['chain'] == chain and done['levels'] == depth and done['status'] == 'locally_verified', 'wrong completed workload')
    require(all(done[k] is False for k in ['single_fixed_circuit', 'lean_certificate', 'official_score']), 'unexpected claim')
    expected = statements(depth, chain)
    require(done['root'] == list(expected[-1][0]), 'independent root mismatch')
    backend = done.get('backend', 'native')
    require(backend in {'native', 'vm'}, 'unknown backend')
    require(done.get('same_backend') is True if backend == 'native' else done.get('forwarded_deferred_claims') is True, 'wrong construction')
    setups = [r for r in rows if r['kind'] == 'setup']
    require(len(setups) == depth + 1 and {r['level'] for r in setups} == set(range(depth + 1)), 'setup coverage')
    proofs = [r for r in rows if r['kind'] == 'proof']
    require(len(proofs) == (1 << (depth + 1)) - 1, 'proof coverage')
    levels = []
    for level in range(depth + 1):
        group = [r for r in proofs if r['level'] == level]
        require(len(group) == len(expected[level]) and {r['index'] for r in group} == set(range(len(group))), 'proof indices')
        for r in group:
            require(r['verified'] is True and 0 < r['proof_bytes'] <= 1 << 20, 'proof status/cap')
            for key in ['proving_s', 'verification_ms']:
                require(math.isfinite(r[key]) and r[key] > 0, 'invalid timing')
            if 'preparation_s' in r:
                require(math.isfinite(r['preparation_s']) and r['preparation_s'] >= 0, 'invalid preparation')
            if backend == 'vm' or 'statement' in r:
                require(r['statement'] == list(expected[level][r['index']]), 'independent statement mismatch')
            if backend == 'vm':
                require(r['deferred_records'] == (1 << level) - 1, 'missing deferred records')
        levels.append(dict(level=level, proofs=len(group),
                           proving_s=statistics.median(r['proving_s'] for r in group),
                           verification_ms=statistics.median(r['verification_ms'] for r in group),
                           proof_bytes=statistics.median(r['proof_bytes'] for r in group),
                           preparation_plus_proving_s=statistics.median(r['preparation_s'] + r['proving_s'] for r in group)
                           if all('preparation_s' in r for r in group) else None))
    return dict(directory=str(directory), backend=backend, depth=depth, chain=chain, levels=levels,
                elapsed_s=receipt['elapsed_s'], peak_rss_gib=receipt['peak_rss_gib'],
                source_commit=receipt['source_commit'], binary_sha256=receipt['binary_sha256'],
                environment={k:receipt[k] for k in ['hostname', 'kernel', 'cpu_model', 'affinity', 'worker_count', 'rust_toolchain', 'rustflags']})


def group(paths):
    runs = [load(path) for path in paths]
    for key in ['backend', 'depth', 'chain', 'source_commit', 'binary_sha256', 'environment']:
        require(all(r[key] == runs[0][key] for r in runs), 'group mismatch: ' + key)
    output = {k:runs[0][k] for k in ['backend', 'depth', 'chain', 'source_commit', 'binary_sha256', 'environment']}
    output.update(trials=len(runs), elapsed_s=statistics.median(r['elapsed_s'] for r in runs),
                  peak_rss_gib=max(r['peak_rss_gib'] for r in runs), levels=[])
    for level in range(output['depth'] + 1):
        rows = [r['levels'][level] for r in runs]
        summary = dict(level=level)
        for key in ['proving_s', 'verification_ms', 'proof_bytes', 'preparation_plus_proving_s']:
            values = [r[key] for r in rows]
            summary[key] = None if any(v is None for v in values) else dict(median=statistics.median(values), min=min(values), max=max(values))
        output['levels'].append(summary)
    output['runs'] = runs
    return output


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--group', action='append', nargs='+', required=True, metavar='NAME_OR_PATH')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    groups = {}
    for name, *paths in args.group:
        require(name not in groups and paths, 'duplicate/empty group')
        groups[name] = group(paths)
    envs = [g['environment'] for g in groups.values()]
    require(all(env == envs[0] for env in envs), 'comparison environments differ')
    args.out.write_text(json.dumps(dict(status='complete_record_sets', groups=groups,
        scope='shared-host development trials; separate keys per level; native rows are not VM cycles; not an architectural ranking'), indent=2, allow_nan=False) + '\n')


if __name__ == '__main__':
    main()
