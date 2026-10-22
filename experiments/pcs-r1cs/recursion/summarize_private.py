#!/usr/bin/env python3
"""Validate complete local tree records and summarize per-level timings.

This checks experiment coverage and accounting, not cryptographic soundness.
The recorded binary verifies the actual proofs during the run.
"""
import argparse
import json
import math
from pathlib import Path
import statistics


KINDS = {'leaf_trace', 'setup', 'proof', 'node_trace', 'complete'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def summarize(directory):
    directory = Path(directory)
    started = json.loads((directory / 'started.json').read_text())
    result = json.loads((directory / 'result.json').read_text())
    require(result['returncode'] == 0 and result['stop_reason'] is None, 'run did not finish successfully')
    require(all(result.get(k) == v for k, v in started.items()), 'started/result provenance differs')
    command = result['command']
    depth = int(command[command.index('--depth') + 1])
    chain = int(command[command.index('--chain') + 1])
    require(1 <= depth <= 3 and 0 <= chain <= 1 << 20, 'invalid requested workload')
    records = [json.loads(line) for line in (directory / 'stdout.jsonl').read_text().splitlines()]
    require(all(r['kind'] in KINDS for r in records), 'unexpected or incomplete record')
    complete = [r for r in records if r['kind'] == 'complete']
    require(len(complete) == 1 and records[-1] == complete[0], 'missing or duplicated completion')
    complete = complete[0]
    require(complete['levels'] == depth and complete['chain'] == chain, 'wrong completed workload')
    require(complete['status'] == 'locally_verified' and complete['same_backend'] is True, 'unverified tree')
    for flag in ['single_fixed_circuit', 'lean_certificate', 'official_score']:
        require(complete[flag] is False, f'unexpected claim: {flag}')
    require(len(complete['root']) == 32 and all(type(x) is int and 0 <= x < 256 for x in complete['root']), 'invalid root digest')
    proofs = [r for r in records if r['kind'] == 'proof']
    setups = [r for r in records if r['kind'] == 'setup']
    require(len(proofs) == (1 << (depth + 1)) - 1, 'wrong proof count')
    require(len(setups) == depth + 1 and {r['level'] for r in setups} == set(range(depth + 1)), 'missing or duplicated setup')
    require({r['level'] for r in proofs} == set(range(depth + 1)), 'unexpected proof level')
    levels = []
    for level in range(depth + 1):
        rows = [r for r in proofs if r['level'] == level]
        expected = 1 << (depth - level)
        require(len(rows) == expected and {r['index'] for r in rows} == set(range(expected)), f'incomplete level {level}')
        setup, = [r for r in setups if r['level'] == level]
        padded = setup['rows']
        require(type(padded) is int and padded > 0 and padded & (padded - 1) == 0, 'invalid padded rows')
        variables, used, public = setup['native_shape']
        require(variables >= 2 and public >= 2 and used + (1 << (public - 1).bit_length()) <= padded, 'invalid native shape')
        require(0 < setup['compressions'] <= 1 << 16 and setup['official_score'] is False, 'invalid compression count or score claim')
        for row in rows:
            require(row['verified'] is True, 'proof did not verify')
            require(type(row['proof_bytes']) is int and 0 < row['proof_bytes'] <= 1 << 20, 'proof exceeds cap')
            require(all(math.isfinite(row[k]) and row[k] > 0 for k in ['proving_s', 'verification_ms']), 'invalid timing')
        levels.append(dict(level=level, proofs=len(rows), padded_native_rows=padded,
                           native_shape=setup['native_shape'], compressions=setup['compressions'],
                           median_proving_s=statistics.median(r['proving_s'] for r in rows),
                           median_verification_ms=statistics.median(r['verification_ms'] for r in rows),
                           min_total_proof_bytes=min(r['proof_bytes'] for r in rows),
                           max_total_proof_bytes=max(r['proof_bytes'] for r in rows)))
    for key in ['elapsed_s', 'peak_rss_gib', 'min_available_gib']:
        require(math.isfinite(result[key]) and result[key] > 0, 'invalid process accounting')
    require(result['peak_rss_gib'] <= result['budget_gib'] and result['min_available_gib'] >= 40, 'resource limits exceeded')
    return dict(status='complete_record_set', source_commit=result['source_commit'],
                binary_sha256=result['binary_sha256'], depth=depth, chain=chain,
                timing_scope='one sample per distinct proof; level median; no warmup',
                elapsed_s=result['elapsed_s'], peak_rss_gib=result['peak_rss_gib'],
                levels=levels, single_fixed_circuit=False, lean_certificate=False, official_score=False)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory), indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
