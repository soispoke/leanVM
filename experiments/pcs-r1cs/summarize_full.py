#!/usr/bin/env python3
"""Validate a full_run output directory and regenerate its tables from raw samples."""
import argparse
import collections
import json
import pathlib
import statistics


def med(xs):
    return statistics.median(xs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=pathlib.Path)
    args = parser.parse_args()
    out = args.evidence
    manifest = json.loads((out/'manifest.json').read_text())
    complete = json.loads((out/'complete.json').read_text())
    assert complete['validated_jobs'] == complete['expected_jobs'] == len(manifest['jobs'])
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    trees = collections.defaultdict(lambda: collections.defaultdict(list))
    packed = []
    identities = collections.defaultdict(set)
    results = []
    total_negatives = 0
    for job in manifest['jobs']:
        name, kind = job['name'], job['kind']
        result = json.loads((out/(name+'.result.json')).read_text())
        assert result['status'] == 'passed' and result['exit_code'] == 0
        assert result['minimum_available_gib'] >= 30
        results.append(result)
        rows = [json.loads(s) for s in (out/(name+'.jsonl')).read_text().splitlines() if s.strip()]
        if kind == 'paired':
            measured = [r for r in rows if r.get('kind') == 'sample' and not r['warmup']]
            warmup = [r for r in rows if r.get('kind') == 'sample' and r['warmup']]
            assert len(measured) == len(warmup) == 1
            row = measured[0]
            total_negatives += warmup[0]['negative_guest_cases']
            label = name.rsplit('-', 2)[0]
            for setup in rows:
                if setup.get('kind') == 'setup' and 'app_id' in setup:
                    identities[label].add(tuple(setup['app_id']))
            mode = 'pcs' if row['interface'] == 'pcs' else 'r1cs'
            assert mode in name and row['interface'] in ('pcs','r1cs-vm')
            row['process_peak_rss_gib'] = result['peak_rss_gib']
            groups[label][mode].append(row)
        elif kind == 'tree':
            assert len(rows)==1
            row=rows[0]
            total_negatives += row['negative_cases']
            mode = 'pcs' if row['interface']=='pcs' else 'r1cs'
            trees[f"{row['leaves']}x{row['per_leaf']}"][mode].append(row)
        elif kind == 'packed':
            assert len(rows)==1 and len(rows[0]['prove_us_all'])==3
            total_negatives += rows[0]['negative_cases']
            packed.append(rows[0])
        else:
            assert len(rows)==1 and rows[0]['status']=='unsupported'
    summary = dict(completed_jobs=len(results),minimum_available_gib=min(r['minimum_available_gib'] for r in results),
                   peak_job_rss_gib=max(r['peak_rss_gib'] for r in results),
                   reported_negative_cases=total_negatives, paired={},trees={},packed=packed)
    cpu = dict((k.strip(),v.strip()) for k,v in (line.split(':',1) for line in manifest.get('cpuinfo','').splitlines() if ':' in line)).get('model name', 'recorded Linux CPU').strip()
    hardware = f"Hardware: {cpu}; 16 pinned threads (CPUs 0-15); {manifest.get('mem_total_gib', 0):.1f} GiB RAM. Fresh binaries explicitly enable pclmulqdq."
    lines = ['# Full Linux run, 22 October 2026','',hardware,'',
             'PCS uses a Keccak application transcript; R1CS uses the VM-native BLAKE2s transcript. Each cell is a median of three measured proofs on the same 16 pinned logical CPUs. Raw samples retain every stage. These are shared-host measurements, not a dedicated-machine performance limit.','',
             '## One application','',
             '| Statement | Rows, padded | Client proof, PCS / R1CS (s) | Aggregate proof, PCS / R1CS (s) | Execution gas, PCS / R1CS |',
             '| --- | ---: | ---: | ---: | ---: |']
    order = ['membership','blake2s-1kib','sha256-1kib','keccak256-1KiB','shielded-transfer','falcon512','mpt-storage-proof','batch2','batch4','batch8']
    for label in order:
        modes=groups[label]
        assert len(modes['pcs'])==len(modes['r1cs'])==3
        assert len(identities[label]) <= 1, f'circuit identity changed: {label}'
        for p, r in zip(modes['pcs'], modes['r1cs']):
            if 'statement' in p:
                assert p['statement'] == r['statement'], f'paired statement mismatch: {label}'
        stats={}
        for mode,rs in modes.items():
            stats[mode]={k:med([r[k] for r in rs]) for k in ['client_us','aggregate_prove_us','aggregate_verify_us','serial_warm_us','serial_cold_us','base_cycles','aggregate_transport_bytes','execution_gas','process_peak_rss_gib']}
            stats[mode]['aggregate_prove_us_range']=[min(r['aggregate_prove_us'] for r in rs),max(r['aggregate_prove_us'] for r in rs)]
        ratios=[r['aggregate_prove_us']/p['aggregate_prove_us'] for r,p in zip(modes['r1cs'],modes['pcs'])]
        stats['median_paired_aggregate_ratio']=med(ratios)
        stats['paired_aggregate_ratio_range']=[min(ratios),max(ratios)]
        summary['paired'][label]=stats
        if label.startswith('batch'):continue
        log=modes['pcs'][0].get('log_rows',20)
        p,r=stats['pcs'],stats['r1cs']
        lines.append(f"| {label} | 2^{log} | {p['client_us']/1e6:.3f} / {r['client_us']/1e6:.3f} | {p['aggregate_prove_us']/1e6:.3f} / {r['aggregate_prove_us']/1e6:.3f} | {p['execution_gas']:,.0f} / {r['execution_gas']:,.0f} |")
    lines += ['', 'Client proof includes witness generation, quotient PIOP and PCS openings. Aggregate proof is the recursive VM prover alone. The circuits and inputs match across interfaces; the client proof bytes differ because the transcript hashes differ.', '',
              '## Batching and recursion','',
              '| Applications in one aggregate | PCS aggregate proof (s) | R1CS aggregate proof (s) | PCS / R1CS base VM cycles |','| --- | ---: | ---: | ---: |']
    for label in ['membership','batch2','batch4','batch8']:
        p,r=summary['paired'][label]['pcs'],summary['paired'][label]['r1cs']
        n=1 if label=='membership' else int(label[5:])
        lines.append(f"| {n} | {p['aggregate_prove_us']/1e6:.3f} | {r['aggregate_prove_us']/1e6:.3f} | {p['base_cycles']:,.0f} / {r['base_cycles']:,.0f} |")
    lines += ['', 'Batches use independent membership instances. Trees below use matching membership leaf aggregates; tree times have no explicit warmup.', '',
              '| Tree (leaf aggregates x applications per leaf) | All leaf proofs, PCS / R1CS (s) | Root proof, PCS / R1CS (s) | Root cycles, PCS / R1CS |',
              '| --- | ---: | ---: | ---: |']
    for label,modes in trees.items():
        assert len(modes['pcs'])==len(modes['r1cs'])==3
        ss={}
        for mode,rs in modes.items():
            ss[mode]=dict(root_prove_us=med([r['root_prove_us'] for r in rs]),root_base_cycles=med([r['root_base_cycles'] for r in rs]),
                          leaf_prove_us=med([sum(x['prove_us'] for x in r['leaf_runs']) for r in rs]),
                          verify_us=med([r['verify_us'] for r in rs]))
        summary['trees'][label]=ss
        p,r=ss['pcs'],ss['r1cs']
        lines.append(f"| {label} | {p['leaf_prove_us']/1e6:.3f} / {r['leaf_prove_us']/1e6:.3f} | {p['root_prove_us']/1e6:.3f} / {r['root_prove_us']/1e6:.3f} | {p['root_base_cycles']:,.0f} / {r['root_base_cycles']:,.0f} |")
    lines += ['', '## Separate packed-backend experiment', '',
              'This proves the same Boolean circuit relation with a different proof system. It is not either interface\'s recursive aggregate, is not zero knowledge, and has no Lean soundness proof.', '',
              '| Statement | Prove median (s) | Measured range (s) | Verify (ms) | Proof bytes | Process peak RSS (GiB) |',
              '| --- | ---: | ---: | ---: | ---: |']
    for r in packed:
        times=r['prove_us_all']
        lines.append(f"| {r['statement']} | {r['prove_us_median']/1e6:.3f} | {min(times)/1e6:.3f}-{max(times)/1e6:.3f} | {r['verify_us']/1e3:.2f} | {r['proof_bytes']:,} | {r['peak_rss_kib']/2**20:.2f} |")
    lines += ['', '## Limits and accounting', '',
              '- ECDSA (2^26 padded rows) and Poseidon (2^29) exceed the quotient implementation\'s 2^23-row domain. No paired interface time is measured for them.',
              '- Packed Poseidon was not admitted: retained GKR and index allocations alone need about 218 GiB, before the circuit and temporary memory. See `packed-poseidon-capacity.json`.',
              '- Gas is application-contract execution in the prototype. It excludes transaction/calldata charges, ordinary application state, registry/publication and native claim coverage. PCS assumes the proposed 10-gas FIELD_MUL opcode.',
              '- Setup is excluded from the main proof tables. Raw `serial_cold_us` adds shared setup and guest compilation to the timed serial stages; it is a stage-sum model, not a process-start measurement.',
              f"- {len(results)} jobs completed; reported tampering rejections: {total_negatives:,}. Minimum sampled system memory available: {summary['minimum_available_gib']:.1f} GiB. Maximum job RSS: {summary['peak_job_rss_gib']:.1f} GiB.",
              '- Timings are measurements of these implementations and hashes. They do not prove equal performance, protocol optimality or architectural dominance.', '',
              'Reproduce with `full_run.py`; regenerate these tables with `summarize_full.py`. `manifest.json` pins the commands, CPU, binary hashes and source hashes. Each `.jsonl` has raw protocol results; its `.result.json` has process status, peak RSS and the memory guard record.', '']
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (out/'README.md').write_text('\n'.join(lines))


if __name__=='__main__':main()
