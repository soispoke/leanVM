#!/usr/bin/env python3
"""Derive bridge padding from saved lowering receipts and validate against measured shapes."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TREE = ROOT.parent
BRIDGE = TREE / 'crates/format_recursion/src/private_bridge.rs'
source = BRIDGE.read_text()
assert re.search(r'const MIN_BLOCKS: usize = 128;', source)
assert '.max(13)' in source


def power2(n):
    return 1 << (n - 1).bit_length()


def aligned(n, alignment):
    return (n + alignment - 1) // alignment * alignment


measurements = {(v['workload'], v['trim']): v for v in json.loads((ROOT / 'laneC-mempool.json').read_text())}
records = []
for row in json.loads((ROOT / 'laneC-census.json').read_text()):
    if 'arithmetic_rows' not in row:
        continue
    key = (row['workload'], row['trim'])
    measured = measurements.get(key)
    # All measured programs fix 162 public variables after adding the 18 padding words.
    reference = measured or measurements[(row['workload'], True)]
    shape = reference['base_shape']
    full_public = int(re.search(r'public_len: (\d+)', shape)[1])
    public_rows = power2(full_public)
    actual_blocks = row['compressions']
    blocks = power2(max(actual_blocks, 128))
    connector = aligned(public_rows + row['arithmetic_rows'], blocks)
    required = connector + 6 * blocks
    padded = max(8192, power2(required))
    log_rows = padded.bit_length() - 1
    lower = padded // 2
    # Lower boundary must fit both public rows and six rows per padded hash block.
    target_compiler_rows = lower - 6 * blocks - public_rows
    reduction = max(0, row['arithmetic_rows'] - target_compiler_rows)
    if measured:
        assert int(re.search(r'log_rows: (\d+)', shape)[1]) == log_rows
        assert int(re.search(r'connector_start: (\d+)', shape)[1]) == connector
        assert int(re.search(r'block_log: (\d+)', shape)[1]) == blocks.bit_length() - 1
    # Arithmetic effect only, not an admitted alternative proof configuration.
    counterfactual_blocks = power2(actual_blocks)
    counterfactual_required = aligned(public_rows + row['arithmetic_rows'], counterfactual_blocks) + 6 * counterfactual_blocks
    counterfactual_padded = max(8192, power2(counterfactual_required))
    records.append({
        'workload': row['workload'], 'trim': row['trim'], 'source_receipt': row['receipt'],
        'compiler_rows': row['arithmetic_rows'], 'actual_bridge_gates': required - public_rows,
        'actual_index_rows_including_public': required,
        'padded_rows': padded, 'padded_log_rows': log_rows,
        'next_lower_power_of_two': lower, 'gates_above_next_lower_boundary': required - lower,
        'gate_margin_percent_of_lower_boundary': 100 * (required - lower) / lower,
        'gate_only_margin_excluding_public_rows': required - public_rows - lower,
        'minimum_compiler_rows_to_remove_for_next_boundary': reduction,
        'public_variables': full_public, 'public_rows': public_rows,
        'connector_alignment_rows': connector - public_rows - row['arithmetic_rows'],
        'connector_rows': 6 * blocks, 'actual_hash_blocks': actual_blocks, 'padded_hash_blocks': blocks,
        'minimum_arithmetic_rows': 8192, 'arithmetic_floor_binding': padded == 8192,
        'measured_shape_checked': measured is not None,
        'backend_admissible': log_rows <= 24,
        'counterfactual_without_hash_block_floor': {
            'blocks': counterfactual_blocks, 'bridge_gates': counterfactual_required,
            'padded_rows': counterfactual_padded,
            'arithmetic_boundary_crossed': counterfactual_padded < padded,
        },
    })

result = {'scope': 'Derived census from frozen receipts; no new timing run or parameter change',
          'bridge_source_sha256': hashlib.sha256(BRIDGE.read_bytes()).hexdigest(),
          'formula': 'required = ceil((next_pow2(public_len) + compiler_rows) / blocks) * blocks + 6 * blocks; padded = max(8192, next_pow2(required)); blocks = next_pow2(max(actual_blocks, 128))',
          'records': records}
(ROOT / 'laneC-padding.json').write_text(json.dumps(result, indent=2) + '\n')
lookup = {(r['workload'], r['trim']): r for r in records}
table = '|Workload|Gate rows excluding public prefix, control → trimmed|Padded log rows, control → trimmed|Index rows above next lower boundary (including public), control → trimmed|Crosses boundary?|\n|---|---:|---:|---:|---|\n'
for name in ['sha256-1kib', 'keccak256-1KiB', 'mpt-storage-proof', 'blake2s-64b', 'blake2s-1kib', 'shielded-transfer', 'falcon512']:
    a, b = lookup[(name, False)], lookup[(name, True)]
    table += f"|{name}|{a['actual_bridge_gates']:,} → {b['actual_bridge_gates']:,}|{a['padded_log_rows']} → {b['padded_log_rows']}|{a['gates_above_next_lower_boundary']:,} → {b['gates_above_next_lower_boundary']:,}|{'yes' if b['padded_log_rows'] < a['padded_log_rows'] else 'no'}|\n"
(ROOT / 'laneC-padding-table.md').write_text(table)
print(table)
print('Validated', sum(r['measured_shape_checked'] for r in records), 'measured base shapes; untrimmed MPT is a non-admissible theoretical shape.')
