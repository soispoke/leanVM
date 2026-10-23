#!/usr/bin/env python3
"""Finish the per-relation policy screen; preserve all valid prior receipts."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

TREE = Path(__file__).resolve().parent.parent
PARENT = TREE.parent
ENV = dict(os.environ, YUKON_COMMAND_CPUS=','.join(map(str, range(24, 36))))
CPU_DIR = TREE / 'artifacts/laneC-policy-cpu'
CPU_DIR.mkdir(exist_ok=True)


def receipt(label, arguments):
    result_path = PARENT / label / 'result.json'
    if not result_path.exists():
        process = subprocess.Popen(['python3', str(PARENT / 'run-C-command.py'), TREE.name, label,
                                    'taskset', '-c', '24-35', 'target/release/examples/compiler_rows',
                                    *arguments], env=ENV)
        prior = {}
        observed = []
        while process.poll() is None:
            for entry in Path('/proc').iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    if (entry / 'comm').read_text().strip() != 'compiler_rows':
                        continue
                    if (entry / 'exe').resolve() != TREE / 'target/release/examples/compiler_rows':
                        continue
                    pid = int(entry.name)
                    affinity = sorted(os.sched_getaffinity(pid))
                    assert affinity == list(range(24, 36)), affinity
                    now = time.monotonic()
                    fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
                    value = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
                    if pid in prior:
                        old_time, old_value = prior[pid]
                        observed.append(100 * (value - old_value) / (now - old_time))
                    prior[pid] = (now, value)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            time.sleep(0.5)
        assert process.returncode == 0, label
        (CPU_DIR / f'{label}.json').write_text(json.dumps({
            'receipt': label, 'cpus': '24-35', 'threads': 12,
            'observed_affinity_exact': bool(prior), 'samples': len(observed),
            'peak_sampled_cpu_percent': max(observed, default=0),
            'scope': 'compiler_rows process user+system CPU / elapsed, sampled at approximately 500 ms',
        }, indent=2) + '\n')
    result = json.loads(result_path.read_text())
    assert result['ok'] and result['files_unchanged'], label
    return [json.loads(line) for line in (PARENT / label / 'run-00/stdout.log').read_text().splitlines()]


def selected(rows, kind):
    return next(row for row in rows if row.get('kind') == kind)


def stats(rows, key):
    values = [row[key] for row in rows]
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'n': len(values)}


capacity = selected(receipt('C-policy-mpt-capacity-t1', ['mpt', '--capacity-check']), 'capacity_check')
assert not capacity['admissible'] and capacity['padded_log_rows'] == 25
(TREE / 'artifacts/laneC-mpt-capacity.json').write_text(json.dumps(capacity, indent=2) + '\n')

fixtures = {}
for policy in 'AB':
    right = PARENT / 'artifacts' / f'C-policy-sha-right-{policy}.cert'
    label = f'C-policy-sha-right-{policy}-t1'
    extra = ['--trim'] if policy == 'B' else []
    receipt(label, ['sha1k', '--wallet-resources', '--seed', '20261025', '--out-certificate', str(right), *extra])
    left_label = 'C-boundary-sha1k-b1-A1-t1' if policy == 'A' else 'C-boundary-sha1k-b1-B2-t1'
    fixtures[policy] = (PARENT / 'artifacts' / f'{left_label}.cert', right)

merges = []
for block in range(1, 4):
    for position, policy in enumerate('ABAB', 1):
        label = f'C-policy-sha-leaf-b{block}-{policy}{position}-t1'
        root = PARENT / 'artifacts' / f'{label}.cert'
        left, right = fixtures[policy]
        extra = ['--trim'] if policy == 'B' else []
        lines = receipt(label, ['sha1k', '--leaf-merge', '--left-certificate', str(left),
                                '--right-certificate', str(right), '--out-certificate', str(root), *extra])
        merges.append({'block': block, 'position': position, 'policy': policy, 'receipt': label,
                       'AGGREGATOR': selected(lines, 'leaf_merge'),
                       'ONE-TIME setup': selected(lines, 'merge_key_setup')})
        (TREE / 'artifacts/laneC-sha-leaf-abab.json').write_text(json.dumps(merges, indent=2) + '\n')
    print(json.dumps({'workload': 'sha256-1kib', 'stage': 'leaf_merge', 'block': block,
                      'samples_per_policy': 2 * block}), flush=True)

summary = {}
for policy in 'AB':
    samples = [row['AGGREGATOR'] for row in merges if row['policy'] == policy]
    summary[policy] = {key: stats(samples, key) for key in [
        'merge2to1_leaf_ms', 'merge_core_ms', 'merged_proof_bytes', 'merge_peak_rss_kib',
        'merge_start_rss_kib', 'incoming_pair_verify_ms', 'merged_native_verify_ms']}
    root = PARENT / 'artifacts' / f'C-policy-sha-leaf-b3-{policy}{3 if policy == "A" else 4}-t1.cert'
    extra = ['--trim'] if policy == 'B' else []
    receipt(f'C-policy-sha-root-{policy}-verify-t1',
            ['sha1k', '--leaf-merge', '--verify-certificate', str(root), *extra])
(TREE / 'artifacts/laneC-sha-leaf-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'workload': 'sha256-1kib', 'AGGREGATOR': summary}), flush=True)

mpt = []
for block in range(1, 4):
    for position in [2, 4]:
        label = f'C-policy-mpt-b{block}-B{position}-t1'
        path = PARENT / 'artifacts' / f'{label}.cert'
        lines = receipt(label, ['mpt', '--trim', '--wallet-resources', '--out-certificate', str(path)])
        mpt.append({'block': block, 'position': position, 'policy': 'B', 'receipt': label,
                    'WALLET': selected(lines, 'wallet_only_mempool_ready_proof'),
                    'WALLET_RAM': selected(lines, 'wallet_transaction_ram'),
                    'MEMPOOL NODE': selected(lines, 'wallet_resource_verification'),
                    'ONE-TIME setup': selected(lines, 'wallet_key_setup'),
                    'control': {'admissible': False, 'capacity_receipt': 'C-policy-mpt-capacity-t1'}})
        (TREE / 'artifacts/laneC-mpt-policy-samples.json').write_text(json.dumps(mpt, indent=2) + '\n')
    print(json.dumps({'workload': 'mpt-storage-proof', 'block': block, 'trimmed_samples': 2 * block,
                      'control': 'unavailable: 2^25 required > 2^24 backend cap'}), flush=True)

full_path = PARENT / 'artifacts/C-policy-mpt-split-reconcile.cert'
lines = receipt('C-policy-mpt-split-reconcile-t1',
                ['mpt', '--trim', '--prove', '--out-certificate', str(full_path)])
full = selected(lines, 'mempool_ready_proof')
for row in mpt:
    path = PARENT / 'artifacts' / f'{row["receipt"]}.cert'
    assert path.read_bytes() == full_path.read_bytes(), row['receipt']
    assert row['WALLET']['base_key'] == full['base_key']

summary = {
    'control_admissible': False, 'trimmed_samples': len(mpt), 'cpus': '24-35', 'threads': 12,
    'WALLET_time_to_mempool_ready_proof_ms': stats([r['WALLET'] for r in mpt], 'time_to_mempool_ready_proof_ms'),
    'WALLET_proof_bytes': stats([r['WALLET'] for r in mpt], 'proof_bytes'),
    'WALLET_peak_rss_kib': stats([r['WALLET_RAM'] for r in mpt], 'transaction_peak_rss_kib'),
    'WALLET_start_rss_kib': stats([r['WALLET_RAM'] for r in mpt], 'transaction_start_rss_kib'),
    'MEMPOOL_NODE_native_verify_ms': stats([r['MEMPOOL NODE'] for r in mpt], 'native_verify_ms'),
    'ONE_TIME_setup_wallet_key_ms': stats([r['ONE-TIME setup'] for r in mpt], 'wallet_key_setup_ms'),
    'complete_split_base_reconciliation_receipt': 'C-policy-mpt-split-reconcile-t1',
    'certificate_bytes_identical_to_prove_base': True,
}
(TREE / 'artifacts/laneC-mpt-policy-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'workload': 'mpt-storage-proof', 'summary': summary}), flush=True)
