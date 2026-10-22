#!/usr/bin/env python3
"""Bounded, source-bound development measurements; never a verification receipt.

Run an explicit command, not a shell string. Stdout/stderr remain separate;
JSONL stdout events retain their original line numbers. Linux only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import time

GIB = 1024 ** 3
THREAD_KEYS = ('LEANVM_NUM_THREADS', 'RAYON_NUM_THREADS', 'OMP_NUM_THREADS',
               'CARGO_BUILD_JOBS', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN')


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def available():
    return next(int(line.split()[1]) * 1024 for line in
                Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:'))


def group_sample(group):
    """Sample the command's own process group; no unrelated processes touched."""
    rss, count = 0, 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) != group or fields[0] == 'Z':
                continue
            count += 1
            for line in (entry / 'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    rss += int(line.split()[1]) * 1024
                    break
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return rss, count


def stop_group(group):
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def record(path, data):
    # Output directory is exclusively allocated by this invocation.
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(data, indent=2, allow_nan=False) + '\n')
    temp.replace(path)


def git_metadata(cwd):
    def git(*args):
        result = subprocess.run(['git', '-C', str(cwd), *args], capture_output=True,
                                text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    try:
        revision, status = git('rev-parse', 'HEAD'), git('status', '--porcelain')
        return {'revision': revision, 'dirty': None if status is None else bool(status)}
    except (OSError, subprocess.TimeoutExpired):
        return {'revision': None, 'dirty': None}


def machine(cpus):
    model = next((line.split(':', 1)[1].strip() for line in
                  Path('/proc/cpuinfo').read_text().splitlines()
                  if line.startswith('model name')), None)
    return {'platform': platform.platform(), 'cpu_model': model,
            'logical_cpus': os.cpu_count(), 'parent_affinity': sorted(os.sched_getaffinity(0)),
            'command_affinity': sorted(cpus),
            'thread_environment': {key: os.environ[key] for key in THREAD_KEYS if key in os.environ}}


def json_events(stdout, output):
    count = 0
    with stdout.open(errors='replace') as lines, output.open('w') as out:
        for number, line in enumerate(lines, 1):
            try:
                value = json.loads(line, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                out.write(json.dumps({'stdout_line': number, 'event': value}, allow_nan=False) + '\n')
                count += 1
    return count


def measure(command, cwd, out, timeout, reserve, budget, cpus, interval):
    out.mkdir()
    if available() < reserve:
        raise RuntimeError('global memory reserve unavailable before command')
    start = time.monotonic()
    peak, peak_processes, minimum = 0, 0, available()
    reason, usage, returncode = None, None, None
    with (out / 'stdout.log').open('wb') as stdout, (out / 'stderr.log').open('wb') as stderr:
        process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr,
                                   start_new_session=True,
                                   preexec_fn=lambda: os.sched_setaffinity(0, cpus))
        record(out / 'running.json', {'pid': process.pid, 'command': command, 'started_utc': utc()})
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    returncode = os.waitstatus_to_exitcode(status)
                    process.returncode = returncode
                    _, remaining = group_sample(process.pid)
                    if usage.ru_maxrss * 1024 > budget:
                        reason = 'wait4 RSS high water exceeded budget'
                    if remaining:
                        reason = 'command exited with live process-group descendants'
                    break
                mem = available()
                minimum = min(minimum, mem)
                rss, nprocs = group_sample(process.pid)
                peak, peak_processes = max(peak, rss), max(peak_processes, nprocs)
                elapsed = time.monotonic() - start
                reason = ('global memory reserve' if mem < reserve else
                          'sampled process-group RSS budget' if rss > budget else
                          'timeout' if elapsed >= timeout else None)
                if reason:
                    stop_group(process.pid)
                    _, status, usage = os.wait4(process.pid, 0)
                    returncode = os.waitstatus_to_exitcode(status)
                    process.returncode = returncode
                    break
                time.sleep(interval)
        finally:
            # Also clean up background children after a parent exits normally.
            stop_group(process.pid)
            if process.returncode is None:
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
    result = {'ok': returncode == 0 and reason is None, 'returncode': returncode,
              'stop_reason': reason, 'wall_seconds': time.monotonic() - start,
              'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
              'wait4_max_rss_kib': usage.ru_maxrss,
              'sampled_group_peak_rss_bytes': peak, 'sampled_peak_processes': peak_processes,
              'minimum_available_bytes': minimum,
              'rss_scope': 'wait4 high water and sampled sum across own process group; not cgroup peak',
              'cpu_scope': 'wait4 child accounting, including descendants the child waited for',
              'json_event_count': json_events(out / 'stdout.log', out / 'events.jsonl'),
              'stdout_sha256': digest(out / 'stdout.log'), 'stderr_sha256': digest(out / 'stderr.log')}
    record(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='new output directory; existing is refused')
    parser.add_argument('--cwd', type=Path, required=True)
    parser.add_argument('--source', type=Path, action='append', default=[], help='explicit file to hash before/after; repeatable')
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--timeout-seconds', type=float, default=7200)
    parser.add_argument('--reserve-gib', type=float, default=35)
    parser.add_argument('--budget-gib', type=float, default=64, help='sampled group RSS guard, not hard isolation')
    parser.add_argument('--sample-seconds', type=float, default=.1)
    parser.add_argument('--cpus', help='comma-separated allowed logical CPU IDs; default inherited affinity')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 1 <= args.repeat <= 30:
        parser.error('command required, repeat must be 1..30')
    numbers = (args.timeout_seconds, args.reserve_gib, args.budget_gib, args.sample_seconds)
    if not all(math.isfinite(x) for x in numbers) or args.timeout_seconds <= 0 or args.reserve_gib < 35 or args.budget_gib <= 0 or not .01 <= args.sample_seconds <= 1:
        parser.error('require finite positive timeout/budget, reserve >=35 GiB, sample .01..1s')
    cwd, out = args.cwd.resolve(strict=True), args.out.resolve()
    if not cwd.is_dir():
        parser.error('cwd must be a directory')
    allowed = set(os.sched_getaffinity(0))
    try:
        cpus = {int(x) for x in args.cpus.split(',')} if args.cpus else allowed
    except ValueError:
        parser.error('cpus must be comma-separated integers')
    if not cpus or not cpus <= allowed:
        parser.error('cpus must be a nonempty subset of inherited affinity')
    # PATH lookup is resolved once, ensuring the measured executable is the one hashed.
    binary = shutil.which(command[0], path=os.environ.get('PATH')) if '/' not in command[0] else str((cwd / command[0]).resolve())
    if not binary or not Path(binary).is_file():
        parser.error('executable not found')
    command[0] = str(Path(binary).resolve())
    sources = sorted(set((cwd / path).absolute() for path in args.source))
    paths = sorted(set([Path(command[0]), *sources]))
    if any(not path.is_file() for path in paths):
        parser.error('all --source paths must be regular files')
    before = {str(path): digest(path) for path in paths}
    if available() < args.reserve_gib * GIB:
        parser.error('global memory reserve unavailable; no command started')
    out.mkdir(parents=True, exist_ok=False)
    started = {'schema': 1, 'scope': 'development measurement only; no proof/security/official verification claim',
               'command': command, 'cwd': str(cwd), 'started_utc': utc(),
               'machine': machine(cpus), 'source_git': git_metadata(cwd),
               'tooling_git': git_metadata(Path(__file__).resolve().parents[1]),
               'harness_sha256': digest(Path(__file__).resolve()),
               'file_sha256_before': before,
               'hash_scope': 'explicit --source files and command executable only; scripts/dynamic libraries/build closure must be added explicitly',
               'limits': {'timeout_seconds_per_run': args.timeout_seconds, 'reserve_gib': args.reserve_gib,
                          'sampled_group_rss_budget_gib': args.budget_gib, 'sample_seconds': args.sample_seconds},
               'warmup_policy': 'none; each repeat is a fresh process; OS/page caches are not cleared'}
    record(out / 'started.json', started)
    runs, error = [], None
    try:
        for index in range(args.repeat):
            result = measure(command, cwd, out / f'run-{index:02d}', args.timeout_seconds,
                             args.reserve_gib * GIB, args.budget_gib * GIB, cpus, args.sample_seconds)
            runs.append(result)
            if not result['ok']:
                break
    except (Exception, KeyboardInterrupt) as exc:
        error = f'{type(exc).__name__}: {exc}'
    after = {str(path): digest(path) if path.is_file() else None for path in paths}
    unchanged = before == after
    result = dict(started, finished_utc=utc(), file_sha256_after=after, files_unchanged=unchanged,
                  runs=runs, error=error,
                  ok=not error and unchanged and len(runs) == args.repeat and all(run['ok'] for run in runs))
    if runs:
        result['median_wall_seconds'] = statistics.median(run['wall_seconds'] for run in runs)
    record(out / 'result.json', result)
    print(json.dumps({'ok': result['ok'], 'result': str(out / 'result.json'),
                      'median_wall_seconds': result.get('median_wall_seconds')}, allow_nan=False))
    raise SystemExit(0 if result['ok'] else 1)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    main()
