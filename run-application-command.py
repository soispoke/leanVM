#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import sys
import time
import json

TREE = Path(__file__).resolve().parent
BASE = TREE.parent
which, label, *cmd = sys.argv[1:]
assert which == 'leanvm-riscv'
assert label.startswith('leanvm-riscv-')
assert not (BASE / label).exists(), 'Never overwrite an existing receipt'
is_build = Path(cmd[0]).name == 'cargo' and cmd[1] not in ('run', 'bench')
threads = 12
cpus = list(range(12, 24))
os.sched_setaffinity(0, cpus)
cpu_range = f'{cpus[0]}-{cpus[-1]}'
env = dict(os.environ, PATH='/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:' + os.environ['PATH'], RUSTUP_TOOLCHAIN='1.99.1', CARGO_TARGET_DIR=str(BASE / 'target-leanvm-riscv'), CARGO_BUILD_JOBS='12', RUSTFLAGS='-C target-cpu=native', LEANVM_NUM_THREADS=str(threads), RAYON_NUM_THREADS=str(threads))
args = ['python3', '/root/yukon-autoresearch/workspaces/yukon-latest-2e90b37/bin/bench-research.py', '--cwd', str(TREE), '--out', str(BASE / label), '--budget-gib', '96', '--reserve-gib', '40', '--timeout-seconds', '1800', '--cpus', ','.join(map(str, cpus))]
for name in subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '--', '*.rs', '*.py', '*.toml', 'Cargo.lock', '*.elf', 'expected.json'], cwd=TREE, text=True).splitlines():
    args += ['--source', name]
for flag in ('--source', '--direct', '--verify', '--root'):
    if flag in cmd:
        index = cmd.index(flag) + 1
        if index < len(cmd) and not cmd[index].startswith('--'):
            candidate = Path(cmd[index])
            if not candidate.is_absolute():
                candidate = TREE / candidate
            if candidate.is_file():
                args += ['--source', str(candidate.resolve())]
if Path(cmd[0]).is_file():
    args += ['--source', str(Path(cmd[0]).resolve())]
args += ['--source', str(Path(__file__).resolve()), '--', 'taskset', '-c', cpu_range, *cmd]

def other_benchmarks():
    found = {}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc / 'cmdline').read_bytes().split(b'\0')
            if any(a.endswith(b'/bench-research.py') for a in argv) and b'--cwd' in argv:
                cwd = argv[argv.index(b'--cwd') + 1].decode()
                if cwd != str(TREE) and Path(cwd).is_relative_to(BASE):
                    found[proc.name] = {'cwd': cwd, 'affinity': sorted(os.sched_getaffinity(int(proc.name)))}
        except (OSError, ValueError):
            continue
    return found

def observe_children(pid):
    global cpu_peak, cpu_samples
    try:
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except OSError:
        return
    for child in children:
        try:
            tasks = list(Path(f'/proc/{child}/task').iterdir())
            names = [(t / 'comm').read_text().strip() for t in tasks]
            if any(name.startswith('parallel-') for name in names):
                sample = {'pid': int(child), 'parallel_background_workers': sum(n.startswith('parallel-') for n in names), 'total_os_threads': len(tasks), 'thread_affinities': sorted({tuple(sorted(os.sched_getaffinity(int(t.name)))) for t in tasks})}
                fields = Path(f'/proc/{child}/stat').read_text().rsplit(')', 1)[1].split()
                ticks = int(fields[11]) + int(fields[12])
                now = time.monotonic()
                if child in cpu_previous:
                    old_ticks, old_time = cpu_previous[child]
                    cpu_peak = max(cpu_peak, 100 * (ticks - old_ticks) / os.sysconf('SC_CLK_TCK') / (now - old_time))
                    cpu_samples += 1
                cpu_previous[child] = (ticks, now)
                previous = observed.get(child)
                if previous is None or sample['parallel_background_workers'] > previous['parallel_background_workers']:
                    observed[child] = sample
        except (OSError, ValueError):
            pass
        observe_children(child)

load_average_start = os.getloadavg()
interference = other_benchmarks()
print(json.dumps({'resource_policy': 'dedicated_cpu_slices_no_wait', 'role': 'build' if is_build else 'benchmark', 'cpus': cpus, 'LEANVM_NUM_THREADS': threads, 'RAYON_NUM_THREADS': threads}), flush=True)
process = subprocess.Popen(args, env=env)
observed = {}
cpu_previous = {}
cpu_peak = 0.0
cpu_samples = 0
last_scan = time.monotonic()
while process.poll() is None:
    observe_children(process.pid)
    if time.monotonic() - last_scan >= 1:
        interference.update(other_benchmarks())
        last_scan = time.monotonic()
    time.sleep(0.05)
receipt = BASE / label
if receipt.is_dir():
    (receipt / 'concurrency-audit.json').write_text(json.dumps({'load_average_start': load_average_start, 'load_average_end': os.getloadavg(), 'other_benchmark_processes_observed': interference, 'timing_eligible': True, 'quiet_seconds': 0, 'policy': 'dedicated_cpu_slices_no_wait', 'role': 'build' if is_build else 'benchmark', 'cpus': cpus, 'taskset_cpus': cpu_range, 'threads': threads, 'LEANVM_NUM_THREADS': threads, 'RAYON_NUM_THREADS': threads, 'worker_observations': list(observed.values()), 'peak_sampled_cpu_percent': cpu_peak, 'cpu_sample_count': cpu_samples, 'cpu_sampling_scope': 'Measured process CPU across all threads; short interval samples include setup, not isolated proving', 'pool_count_scope': 'parallel background workers plus one inline dispatcher'}, indent=2) + '\n')
raise SystemExit(process.returncode)
