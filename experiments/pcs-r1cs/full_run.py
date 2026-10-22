#!/usr/bin/env python3
"""Serial, resumable paired measurements. See --help; raw records are never overwritten."""
import argparse
import hashlib
import gzip
import json
import os
import pathlib
import platform
import signal
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
GIB = 1024**3
WORKLOADS = ['membership', 'blake2s-1kib', 'sha256-1kib', 'keccak256-1KiB',
             'shielded-transfer', 'falcon512', 'mpt-storage-proof']


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def memory():
    fields = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    return {k: int(v.split()[0]) * 1024 for k, v in fields.items()}


def write_json(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def validate(rows, kind):
    if kind == 'paired':
        measured = [r for r in rows if r.get('kind') == 'sample' and not r['warmup']]
        warmup = [r for r in rows if r.get('kind') == 'sample' and r['warmup']]
        assert len(measured) == len(warmup) == 1, 'missing or duplicate samples'
        assert warmup[0]['negative_guest_cases'] > 0, 'missing tampering checks'
        assert measured[0]['aggregate_prove_us'] > 0 and measured[0]['execution_gas'] > 0
    elif kind == 'tree':
        assert len(rows) == 1 and rows[0]['kind'] == 'tree' and rows[0]['negative_cases'] >= 6
        assert len(rows[0]['leaf_runs']) == rows[0]['leaves']
    elif kind == 'packed':
        assert len(rows) == 1 and len(rows[0]['prove_us_all']) == 3
        assert rows[0]['negative_cases'] == 3
    elif kind == 'capacity':
        assert len(rows) == 1 and rows[0]['status'] == 'unsupported'


def jobs(binary):
    for repeat in range(3):
        modes = ['pcs', 'r1cs'] if repeat % 2 == 0 else ['r1cs', 'pcs']
        seed = str(2026102200 + repeat * 100)
        for name in WORKLOADS:
            for mode in modes:
                example = 'comparison' if name == 'membership' else 'suite_comparison'
                args = [] if name == 'membership' else ['--workload', name]
                args += ['--samples', '1', '--seed', seed]
                args += ['--pcs'] if mode == 'pcs' else ['--oracle', 'blake2s']
                yield f'{name}-{mode}-r{repeat}', 'paired', 40, [str(binary / example), *args]
        for fan in [2, 4, 8]:
            for mode in modes:
                args = ['--fan-in', str(fan), '--samples', '1', '--seed', seed]
                args += ['--pcs'] if mode == 'pcs' else ['--oracle', 'blake2s']
                yield f'batch{fan}-{mode}-r{repeat}', 'paired', 70, [str(binary / 'batch'), *args]
        for leaves, per_leaf in [(2, 2), (4, 4)]:
            for mode in modes:
                args = ['--interface', 'pcs' if mode == 'pcs' else 'r1cs-vm', '--leaves', str(leaves),
                        '--per-leaf', str(per_leaf), '--seed', seed]
                yield f'tree{leaves}x{per_leaf}-{mode}-r{repeat}', 'tree', 100, [str(binary / 'tree'), *args]
    for name in WORKLOADS + ['ecdsa-secp256k1']:
        yield f'packed-{name}', 'packed', 80, [str(binary / 'packed'), '--repeat', '3', '--seed', '2026102200', name]
    for name in ['ecdsa-secp256k1', 'poseidon-bn254']:
        yield f'capacity-{name}', 'capacity', 120, [str(binary / 'suite_comparison'), '--workload', name, '--pcs', '--samples', '1']


def run_job(out, name, kind, budget, command, env):
    result_path = out / (name + '.result.json')
    if result_path.exists():
        previous = json.loads(result_path.read_text())
        assert previous['command'] == command and previous['status'] == 'passed', f'review prior result: {name}'
        validate(records(out / (name + '.jsonl')), kind)
        return previous
    assert not (out / (name + '.jsonl')).exists(), f'unfinished output must be reviewed: {name}'
    admission = subprocess.run(['memguard', 'admit', str(budget)], capture_output=True, text=True)
    assert admission.returncode == 0, admission.stdout
    result = dict(name=name, kind=kind, command=command, budget_gib=budget,
                  admission=admission.stdout.strip(), started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    with open(out / (name + '.jsonl'), 'w') as stdout, open(out / (name + '.stderr'), 'w') as stderr:
        p = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout,
                             stderr=stderr, start_new_session=True)
        start = time.monotonic()
        minimum = memory()['MemAvailable']
        peak = 0
        result['loadavg_start'] = pathlib.Path('/proc/loadavg').read_text().strip()
        while True:
            pid, status, usage = os.wait4(p.pid, os.WNOHANG)
            if pid:
                p.returncode = os.waitstatus_to_exitcode(status)
                break
            available = memory()['MemAvailable']
            minimum = min(minimum, available)
            try:
                fields = dict(line.split(':', 1) for line in pathlib.Path(f'/proc/{p.pid}/status').read_text().splitlines() if ':' in line)
                peak = max(peak, int(fields.get('VmRSS', '0 kB').split()[0]) * 1024)
            except FileNotFoundError:
                pass
            reason = ('memory headroom' if available < 40 * GIB else
                      'job memory budget' if peak > budget * GIB else
                      'one-hour timeout' if time.monotonic() - start > 3600 else None)
            if reason:
                os.killpg(p.pid, signal.SIGKILL)
                result['guard_stop'] = reason
                _, status, usage = os.wait4(p.pid, 0)
                p.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(.1)
        result.update(exit_code=p.returncode, wall_s=time.monotonic() - start,
                      minimum_available_gib=minimum / GIB, sampled_peak_rss_gib=peak / GIB,
                      peak_rss_gib=usage.ru_maxrss / 1024**2,
                      loadavg_end=pathlib.Path('/proc/loadavg').read_text().strip())
    try:
        assert result['exit_code'] == 0, 'nonzero exit'
        validate(records(out / (name + '.jsonl')), kind)
        result['status'] = 'passed'
    except (AssertionError, ValueError, KeyError) as exc:
        result.update(status='failed', error=str(exc))
    write_json(result_path, result)
    print(json.dumps(result), flush=True)
    assert result['status'] == 'passed', f'failed {name}; inspect preserved logs'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-dir', required=True, type=pathlib.Path)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    out, binary = args.out.resolve(), args.binary_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, LEANVM_NUM_THREADS='16')
    os.sched_setaffinity(0, set(range(16)))
    plan = list(jobs(binary))
    hashes = {name: digest(binary / name) for name in ['comparison', 'suite_comparison', 'batch', 'tree', 'packed']}
    if (out / 'manifest.json').exists():
        manifest = json.loads((out / 'manifest.json').read_text())
        assert manifest['binaries_sha256'] == hashes, 'binaries changed during run'
    else:
        source = subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard'], cwd=ROOT, text=True).splitlines()
        sources = {name: digest(ROOT / name) for name in sorted(set(source))
                   if (ROOT / name).is_file() and not name.startswith('experiments/pcs-r1cs/evidence/')}
        manifest = dict(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                        sources_sha256=sources, binaries_sha256=hashes, platform=platform.platform(),
                        hostname=platform.node(), cpu_count=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
                        mem_total_gib=memory()['MemTotal'] / GIB,
                        cpuinfo=pathlib.Path('/proc/cpuinfo').read_text().split('\n\n')[0],
                        rustflags='-C target-cpu=native -C target-feature=+pclmulqdq',
                        threads=16, paired_repeats=3, paired_warmups_per_process=1,
                        packed_repeats=3, packed_warmups_per_process=1, tree_warmups=0,
                        min_available_guard_gib=40, jobs=[dict(name=n, kind=k, budget_gib=b, command=c) for n,k,b,c in plan])
        write_json(out / 'manifest.json', manifest)
        with gzip.open(out / 'source.patch.gz', 'wb') as patch:
            patch.write(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT))
    results = []
    for name, kind, budget, command in plan:
        results.append(run_job(out, name, kind, budget, command, env))
        write_json(out / 'progress.json', dict(completed=len(results), total=len(plan), last=name))
    # Packed Poseidon cannot be admitted under the existing host policy. This is a lower bound,
    # not a predicted RSS: two 5*n F192 GKR trees, index stack/sigma and retained rate-1/2 codeword.
    n = 1 << 29
    gkr_elements = sum((5*n + (1 << (2*k))-1) // (1 << (2*k)) for k in range(16)) * 2
    lower = gkr_elements * 24 + 4*n*8 + 5*n*4 + 8*n*8
    write_json(out / 'packed-poseidon-capacity.json', dict(status='not_admitted', log_rows=29,
        minimum_retained_bytes=lower, minimum_retained_gib=lower / GIB, admission_ceiling_gib=200,
        reason='Retained GKR/index allocations alone exceed memguard admission; excludes circuit, Merkle tree and temporary workspaces. No proving time measured.'))
    write_json(out / 'complete.json', dict(status='complete', validated_jobs=len(results), expected_jobs=len(plan),
        unsupported_quotient=['ecdsa-secp256k1','poseidon-bn254'], packed_not_admitted=['poseidon-bn254']))


if __name__ == '__main__':
    main()
