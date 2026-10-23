#!/usr/bin/env python3
"""Three ABAB blocks, six samples per policy; fresh processes and fixed wallet input."""
import json
import os
import statistics
import subprocess
from pathlib import Path

TREE = Path(__file__).resolve().parent.parent
PARENT = TREE.parent
ENV = dict(os.environ, YUKON_COMMAND_CPUS=','.join(map(str, range(24, 36))))
ROWS = []


def receipt(label, args):
    subprocess.run(['python3', str(PARENT / 'run-C-command.py'), TREE.name, label,
                    'taskset', '-c', '24-35', 'target/release/examples/compiler_rows',
                    'blake64', *args], env=ENV, check=True)
    result = json.loads((PARENT / label / 'result.json').read_text())
    assert result['ok'] and result['files_unchanged']
    return [json.loads(line) for line in (PARENT / label / 'run-00/stdout.log').read_text().splitlines()]


for block in range(1, 4):
    for position, policy in enumerate('ABAB', 1):
        label = f'C-abab-b64-b{block}-{policy}{position}-t1'
        timed_path = PARENT / 'artifacts' / f'{label}.cert'
        ram_path = PARENT / 'artifacts' / f'{label}-wallet-resources.cert'
        common = ['--trim'] if policy == 'B' else []
        timing = receipt(label, ['--prove', '--out-certificate', str(timed_path), *common])
        resources = receipt(label.replace('-t1', '-resources-t1'),
                            ['--wallet-resources', '--out-certificate', str(ram_path), *common])
        assert timed_path.read_bytes() == ram_path.read_bytes(), 'wallet RAM process must emit identical certificate'
        wallet = next(v for v in timing if v.get('kind') == 'mempool_ready_proof')
        verify = next(v for v in timing if v.get('kind') == 'native_verification')
        key = next(v for v in resources if v.get('kind') == 'wallet_key_setup')
        ram = next(v for v in resources if v.get('kind') == 'wallet_transaction_ram')
        assert wallet['base_key'] == key['base_key']
        ROWS.append({'block': block, 'position': position, 'policy': policy,
                     'timing_receipt': label, 'resources_receipt': label.replace('-t1', '-resources-t1'),
                     'WALLET': wallet, 'WALLET_RAM': ram, 'MEMPOOL NODE': verify, 'ONE-TIME setup': key})
        (TREE / 'artifacts/laneC-abab.json').write_text(json.dumps(ROWS, indent=2) + '\n')
    print(json.dumps({'block_completed': block, 'samples_per_policy': 2 * block}), flush=True)

summary = {}
for policy in 'AB':
    rows = [r for r in ROWS if r['policy'] == policy]
    def stats(values):
        return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'n': len(values)}
    summary[policy] = {
        'WALLET_time_to_mempool_ready_proof_ms': stats([r['WALLET']['time_to_mempool_ready_proof_ms'] for r in rows]),
        'WALLET_witness_ms': stats([r['WALLET']['witness_ms'] for r in rows]),
        'WALLET_proof_ms': stats([r['WALLET']['proof_ms'] for r in rows]),
        'WALLET_proof_bytes': stats([r['WALLET']['proof_bytes'] for r in rows]),
        'WALLET_transaction_peak_rss_kib': stats([r['WALLET_RAM']['transaction_peak_rss_kib'] for r in rows]),
        'WALLET_transaction_start_rss_kib': stats([r['WALLET_RAM']['transaction_start_rss_kib'] for r in rows]),
        'WALLET_transaction_additional_peak_rss_kib': stats([r['WALLET_RAM']['transaction_additional_peak_rss_kib'] for r in rows]),
        'MEMPOOL_NODE_native_verify_ms': stats([r['MEMPOOL NODE']['native_verify_ms'] for r in rows]),
        'ONE_TIME_setup_wallet_key_setup_ms': stats([r['ONE-TIME setup']['wallet_key_setup_ms'] for r in rows]),
        'ONE_TIME_setup_wallet_key_peak_rss_kib': stats([r['ONE-TIME setup']['wallet_key_setup_peak_rss_kib'] for r in rows]),
    }
(TREE / 'artifacts/laneC-abab-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2), flush=True)
