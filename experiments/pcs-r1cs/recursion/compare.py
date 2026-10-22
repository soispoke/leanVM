#!/usr/bin/env python3
"""Run and validate a matched native-field versus leanVM aggregation benchmark."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
FAN_INS = (1, 2, 4, 8)


def require(condition, message='incomplete or inconsistent benchmark evidence'):
    if not condition:
        raise ValueError(message)


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def load_job(directory, backend, fan_in, samples):
    result = json.loads((directory / 'result.json').read_text())
    require(result['returncode'] == 0 and result['stop_reason'] is None, result)
    rows = [json.loads(line) for line in (directory / 'stdout.jsonl').read_text().splitlines()]
    setup = [r for r in rows if r['kind'] == 'setup']
    runs = [r for r in rows if r['kind'] == 'sample']
    require(len(rows) == samples + 2 and len(setup) == 1 and len(runs) == samples + 1)
    require([r['sample'] for r in runs] == list(range(samples + 1)))
    require(all(r['backend'] == backend and r['fan_in'] == fan_in for r in rows))
    require(all(r['status'] == 'verified' and r['warmup'] == (r['sample'] == 0) for r in runs))
    require(runs[0]['negative_cases'] >= (7 if backend == 'native' else 1))
    require(setup[0]['oracle'] == 'blake2s' and setup[0]['child_log_rows'] == 12)
    stats = {}
    for key in ('prep_ms', 'prove_ms', 'verify_ms', 'total_certificate_bytes'):
        values = [r[key] for r in runs[1:]]
        stats[key] = dict(median=statistics.median(values), minimum=min(values), maximum=max(values))
    totals = [r['prep_ms'] + r['prove_ms'] + r['verify_ms'] for r in runs[1:]]
    stats['aggregate_total_ms'] = dict(median=statistics.median(totals), minimum=min(totals), maximum=max(totals))
    stats.update(setup_ms=setup[0]['setup_ms'], peak_rss_gib=result['peak_rss_gib'],
                 min_available_gib=result['min_available_gib'], negative_cases=runs[0]['negative_cases'])
    return runs, stats, result


def summarize(out, samples):
    summary = dict(status='validated', measured_samples_per_job=samples, warmups_per_job=1,
                   oracle='blake2s', child_log_rows=12, recursion_depth=1, jobs={})
    records = []
    for n in FAN_INS:
        matched = {}
        for backend in ('native', 'vm'):
            runs, stats, record = load_job(out / f'{backend}-{n}', backend, n, samples)
            summary['jobs'][f'{backend}-{n}'] = stats
            matched[backend] = runs
            records.append(record)
        for a, b in zip(matched['native'], matched['vm'], strict=True):
            require(a['public'] == b['public'], 'public claims differ between backends')
            require(a['child_proof_digests'] == b['child_proof_digests'], 'child proof bytes differ between backends')
    for key in ('binary_sha256', 'source_commit', 'hostname', 'kernel', 'logical_cpus', 'affinity'):
        require(all(record[key] == records[0][key] for record in records), f'environments differ: {key}')
        summary[key] = records[0][key]
    write_json(out / 'summary.json', summary)
    lines = ['# Matched outer aggregation', '',
             'Same child proofs and public claim, BLAKE2s, 16 workers, one warmup per job. These are single-level outer aggregations of independent proofs of one small application, not repeated self-recursion.', '',
             '| Children | Native prove (s) | leanVM prove (s) | Native verify (ms) | leanVM verify (ms) | Native certificate (MB) | leanVM certificate (MB) |',
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for n in FAN_INS:
        a, b = (summary['jobs'][f'{backend}-{n}'] for backend in ('native', 'vm'))
        med = lambda row, key: row[key]['median']
        lines.append(f"| {n} | {med(a,'prove_ms')/1000:.3f} | {med(b,'prove_ms')/1000:.3f} | {med(a,'verify_ms'):.1f} | {med(b,'verify_ms'):.1f} | {med(a,'total_certificate_bytes')/1e6:.3f} | {med(b,'total_certificate_bytes')/1e6:.3f} |")
    lines += ['', '| Children | Native setup (s) | leanVM setup (s) | Native peak RSS (GiB) | leanVM peak RSS (GiB) |',
              '| --- | ---: | ---: | ---: | ---: |']
    for n in FAN_INS:
        a, b = (summary['jobs'][f'{backend}-{n}'] for backend in ('native', 'vm'))
        lines.append(f"| {n} | {a['setup_ms']/1000:.3f} | {b['setup_ms']/1000:.3f} | {a['peak_rss_gib']:.2f} | {b['peak_rss_gib']:.2f} |")
    lines += ['', f"Each timing is the median of {samples} fresh measured samples. Sizes use decimal MB and include all public requests, chaining advice and serialization framing. Peak RSS covers each complete process, including setup, warmup and negative checks. Raw timing ranges, preparation times and totals are in summary.json. Shared-host measurements are indicative, not an architectural ranking.", '',
              'Child proving is shared and excluded. Preparation and one-time setup are reported separately. Native proving includes arithmetic prechecks, both arguments and their binding. Verification covers the complete certificate. The native verifier still processes a linear public hash table and walks public projections; it does not replay field arithmetic. The native backend uses a new field gate and an unproved composition of existing primitives; it is not the original Boolean full-adder backend or covered by its Lean theorem.', '']
    (out / 'TABLE.md').write_text('\n'.join(lines))
    return summary


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--summarize-only', action='store_true')
    args = parser.parse_args()
    require(args.samples > 0, 'sample count must be positive')
    out = args.out.resolve()
    if args.summarize_only:
        summarize(out, args.samples)
        return
    require(args.binary and args.binary.is_file(), 'provide a built benchmark binary')
    binary = args.binary.resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT, text=True).splitlines()
    manifest = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sorted(set(paths))
                if p.endswith(('.rs', '.toml', '.py')) or p == 'Cargo.lock'}
    write_json(out / 'source-sha256.json', manifest)
    cpu_model = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name'))
    write_json(out / 'environment.json', dict(cpu_model=cpu_model,
               rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
               rustflags=os.environ.get('RUSTFLAGS'), threads=16,
               source_status=subprocess.check_output(['git', 'status', '--short'], cwd=ROOT, text=True)))
    env = os.environ.copy()
    env['LEANVM_NUM_THREADS'] = '16'
    with (out / 'driver.log').open('w') as log:
        for n in FAN_INS:
            for backend in (('native', 'vm') if n in (1, 4) else ('vm', 'native')):
                print(f'START {backend} {n}', file=log, flush=True)
                command = [sys.executable, str(ROOT / 'experiments/pcs-r1cs/recursion/run.py'),
                           '--out', str(out / f'{backend}-{n}'), '--budget-gib', '32', '--', str(binary),
                           '--backend', backend, '--fan-in', str(n), '--samples', str(args.samples)]
                subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=log, check=True)
                load_job(out / f'{backend}-{n}', backend, n, args.samples)
                print(f'FINISH {backend} {n}', file=log, flush=True)
    summarize(out, args.samples)
    print(f'Validated all eight jobs. Results: {out / "TABLE.md"}', flush=True)


if __name__ == '__main__':
    main()
