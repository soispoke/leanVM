#!/usr/bin/env python3
"""Validate the BLAKE2s Flock baseline records, not its cryptographic soundness."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def summarize(directory):
    directory = Path(directory)
    receipt = json.loads((directory / 'result.json').read_text())
    run = json.loads((directory / 'run-00/result.json').read_text())
    started = json.loads((directory / 'started.json').read_text())
    require(all(receipt.get(k) == v for k, v in started.items()), 'receipt provenance changed')
    require(receipt['runs'] == [run], 'run receipt mismatch')
    require(receipt['command'][-3:] == ['8', '256', '3'], 'wrong requested workload')
    require(receipt['ok'] and receipt['files_unchanged'] and run['ok'], 'failed or changed run')
    require(run['returncode'] == 0 and run['stop_reason'] is None, 'incomplete process')
    require(not receipt['source_git']['dirty'], 'unfrozen source')
    require(receipt['file_sha256_before'] == receipt['file_sha256_after'], 'source hashes changed')
    require(receipt['limits']['reserve_gib'] >= 40, 'insufficient reserve')
    require(run['minimum_available_bytes'] >= 40 * 2**30, 'reserve violated')
    require(run['sampled_group_peak_rss_bytes'] <= receipt['limits']['sampled_group_rss_budget_gib'] * 2**30, 'RSS guard violated')
    require(receipt['machine']['command_affinity'] == list(range(16)), 'wrong CPU affinity')
    require(receipt['machine']['thread_environment']['RAYON_NUM_THREADS'] == '16', 'wrong workers')
    for stream in ['stdout', 'stderr']:
        actual = hashlib.sha256((directory / f'run-00/{stream}.log').read_bytes()).hexdigest()
        require(actual == run[f'{stream}_sha256'], f'{stream} hash mismatch')
    records = [json.loads(line) for line in (directory / 'run-00/stdout.log').read_text().splitlines() if line.startswith('{')]
    require(len(records) == run['json_event_count'], 'event count mismatch')
    require(all(r['record'] in {'shared_vk_setup', 'stage', 'statement', 'summary'} for r in records), 'unknown event')
    shared = [r for r in records if r['record'] == 'shared_vk_setup']
    require(len(shared) == 1, 'VK setup coverage')
    shared = shared[0]
    require(shared['trials'] == 3 and shared['same_process'] and shared['excluded_warmups'] == 0, 'wrong repeat policy')
    require(math.isfinite(shared['vk_setup_ms']) and shared['vk_setup_ms'] > 0, 'invalid VK time')
    trials = []
    for trial in range(3):
        rows = [r for r in records if r.get('trial') == trial]
        stages = [r for r in rows if r['record'] == 'stage']
        summaries = [r for r in rows if r['record'] == 'summary']
        statements = [r for r in rows if r['record'] == 'statement']
        require(len(stages) == 15 and len(summaries) == len(statements) == 1, 'missing trial stages')
        require([r['ordinal'] for r in stages] == list(range(15)), 'stage ordering')
        require(Counter(r['kind'] for r in stages) == Counter(leaf=8, first_level=4, base=1, spine=2), 'wrong tower geometry')
        summary, statement = summaries[0], statements[0]
        require(summary['leaves'] == 8 and summary['blocks_per_leaf'] == 256 and summary['total_compressions'] == 2048, 'wrong workload')
        require(summary['verified'] is True and summary['mutation_rejections'] == 9, 'verification or mutation coverage')
        require(summary['construction'] == 'succinct-flock-blake2s-adaptation' and summary['profile'] == 'Chain128', 'wrong construction')
        state = bytes(64)
        for _ in range(2048):
            state = hashlib.blake2s(state).digest() + bytes(32)
        require(statement['h_start'] == [0] * 16 and statement['h_end'] == list(struct.unpack('<16I', state)), 'independent endpoint mismatch')
        require(statement['total_compressions'] == 2048, 'wrong statement length')
        for r in stages:
            for key in ['builder_call_ms_including_setup_and_self_checks', 'setup_ms', 'walk_ms', 'tapes_ms', 'witgen_ms', 'prove_ms', 'replica_checks_ms', 'accumulator_self_discharge_ms', 'builder_verify_ms', 'online_wall_ms']:
                require(math.isfinite(r[key]) and r[key] >= 0, 'invalid stage timing')
            require(r['online_wall_ms'] > 0 and r['prove_ms'] > 0 and r['proof_bytes'] > 0, 'empty stage')
            require(r['online_wall_ms'] + 1 >= r['prove_ms'], 'proving exceeds online wall')
            require(r['builder_call_ms_including_setup_and_self_checks'] + 1 >= r['online_wall_ms'], 'online exceeds builder call')
        for key in ['full_prove_ms_including_setup', 'root_discharge_ms', 'consumer_verify_ms']:
            require(math.isfinite(summary[key]) and summary[key] > 0, 'invalid trial time')
        require(summary['full_prove_ms_including_setup'] + 1 >= sum(r['builder_call_ms_including_setup_and_self_checks'] for r in stages), 'unaccounted builder calls')
        root = stages[-1]
        require(summary['bundle_bytes'] > summary['proof_bytes'] == root['proof_bytes'], 'incomplete root size')
        trials.append(dict(trial=trial, root_online_s=root['online_wall_ms'] / 1000,
                           root_prove_component_s=root['prove_ms'] / 1000,
                           root_setup_s=root['setup_ms'] / 1000,
                           root_replica_checks_s=root['replica_checks_ms'] / 1000,
                           root_accumulator_self_discharge_s=root['accumulator_self_discharge_ms'] / 1000,
                           consumer_verify_s=summary['consumer_verify_ms'] / 1000,
                           tower_creation_including_setup_s=summary['full_prove_ms_including_setup'] / 1000,
                           proof_bytes=summary['proof_bytes'], bundle_bytes=summary['bundle_bytes']))
    require(len(records) == 1 + 3 * 17, 'extra or missing records')
    return dict(status='complete_record_set', policy=shared['policy'], trials=trials,
                medians={k: statistics.median(t[k] for t in trials) for k in trials[0] if k != 'trial'},
                shared_vk_setup_s=shared['vk_setup_ms'] / 1000,
                process_wall_s=run['wall_seconds'], peak_rss_gib=run['wait4_max_rss_kib'] / 2**20,
                source=receipt['source_git'], tooling=receipt['tooling_git'], runner_sha256=receipt['harness_sha256'],
                scope='Warm shared-process BLAKE2s Flock adaptation; a sequential 64-byte-state chain, not the matched tagged tree. No formal security or official score claim.')


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory), indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
