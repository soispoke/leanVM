#!/usr/bin/env python3
"""Run one recursion experiment with bounded memory and preserved evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time

GIB = 1024**3
ROOT = Path(__file__).resolve().parents[3]


def memory():
    fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return {key: int(value.split()[0]) * 1024 for key, value in fields.items()}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--budget-gib', type=int, default=64)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert command and 0 < args.budget_gib <= 120
    admission = subprocess.run([str(ROOT / 'experiments/pcs-r1cs/memguard'), 'admit', str(args.budget_gib)], capture_output=True, text=True)
    assert admission.returncode == 0, admission.stdout
    args.out.mkdir(parents=True, exist_ok=False)
    binary = Path(command[0])
    record = dict(command=command, cwd=str(ROOT), started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  kernel=platform.release(), hostname=platform.node(), admission=admission.stdout.strip(),
                  platform=platform.platform(), logical_cpus=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
                  total_memory_gib=memory()['MemTotal']/GIB,
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), budget_gib=args.budget_gib)
    (args.out / 'started.json').write_text(json.dumps(record, indent=2) + '\n')
    with (args.out / 'stdout.jsonl').open('w') as stdout, (args.out / 'stderr.log').open('w') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        (args.out / 'pid').write_text(str(process.pid) + '\n')
        minimum, peak, reason = memory()['MemAvailable'], 0, None
        start = time.monotonic()
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                peak = max(peak, usage.ru_maxrss * 1024)
                break
            available = memory()['MemAvailable']
            minimum = min(minimum, available)
            try:
                fields = dict(line.split(':', 1) for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if ':' in line)
                peak = max(peak, int(fields.get('VmRSS', '0 kB').split()[0]) * 1024)
            except FileNotFoundError:
                pass
            reason = ('system memory headroom' if available < 40 * GIB else
                      'process memory budget' if peak > args.budget_gib * GIB else
                      'two-hour timeout' if time.monotonic() - start > 7200 else None)
            if reason:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                break
            time.sleep(0.5)
    record.update(returncode=process.returncode, stop_reason=reason, elapsed_s=time.monotonic()-start,
                  min_available_gib=minimum/GIB, peak_rss_gib=peak/GIB,
                  finished_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    (args.out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)
    raise SystemExit(0 if process.returncode == 0 and reason is None else 1)


if __name__ == '__main__':
    main()
