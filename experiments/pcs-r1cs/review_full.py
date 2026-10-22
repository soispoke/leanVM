#!/usr/bin/env python3
"""Independent checks of published tables, source provenance and run completeness."""
import argparse
import hashlib
import json
import pathlib
import re
import statistics

ROOT = pathlib.Path(__file__).resolve().parents[2]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=pathlib.Path)
    parser.add_argument('--binary-dir', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.evidence
    manifest = json.loads((out/'manifest.json').read_text())
    summary = json.loads((out/'summary.json').read_text())
    complete = json.loads((out/'complete.json').read_text())
    assert complete['validated_jobs'] == len(manifest['jobs']) == 82
    assert len({j['name'] for j in manifest['jobs']}) == 82
    for job in manifest['jobs']:
        status = json.loads((out/(job['name']+'.result.json')).read_text())
        assert status['status']=='passed' and status['exit_code']==0
        assert status['command']==job['command']
        assert status['minimum_available_gib']>=30
    for name,want in manifest['binaries_sha256'].items():
        assert sha(args.binary_dir/name)==want,name
    changed=[]
    checked=0
    for name,want in manifest['sources_sha256'].items():
        if name.startswith(('crates/','formal/')) or name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','.cargo/config.toml']:
            checked+=1
            if sha(ROOT/name)!=want:changed.append(name)
    # Added membership export after timing; this helper is not linked to any measured binary.
    assert set(changed) <= {'crates/circuit_suite/examples/export_rows.rs'},changed
    text=(out/'README.md').read_text()
    names=['membership','blake2s-1kib','sha256-1kib','keccak256-1KiB','shielded-transfer','falcon512','mpt-storage-proof']
    for name in names:
        row=next(line for line in text.splitlines() if line.startswith('| '+name+' |'))
        columns=[s.strip() for s in row.split('|')[1:-1]]
        assert len(columns)==5
        measured={}
        ids=set()
        for mode in ['pcs','r1cs']:
            measured[mode]=[]
            for repeat in range(3):
                records=[json.loads(s) for s in (out/f'{name}-{mode}-r{repeat}.jsonl').read_text().splitlines()]
                setup=next(r for r in records if r.get('kind')=='setup')
                ids.add(tuple(setup['app_id']))
                samples=[r for r in records if r.get('kind')=='sample' and r.get('warmup') is False]
                assert len(samples)==1
                measured[mode].append(samples[0])
        assert len(ids)==1
        for p,r in zip(measured['pcs'],measured['r1cs']):assert p['statement']==r['statement']
        for col,key in [(2,'client_us'),(3,'aggregate_prove_us')]:
            expected=' / '.join(f"{statistics.median(r[key] for r in measured[mode])/1e6:.3f}" for mode in ['pcs','r1cs'])
            assert columns[col]==expected,(name,key,columns[col],expected)
        gas=' / '.join(f"{statistics.median(r['execution_gas'] for r in measured[mode]):,.0f}" for mode in ['pcs','r1cs'])
        assert columns[4]==gas
    capacity=json.loads((out/'packed-poseidon-capacity.json').read_text())
    assert capacity['status']=='not_admitted' and capacity['minimum_retained_gib']>capacity['admission_ceiling_gib']
    for name in ['ecdsa-secp256k1','poseidon-bn254']:
        record=json.loads((out/f'capacity-{name}.jsonl').read_text())
        assert record['status']=='unsupported' and record['log_rows']>record['maximum_log_rows']
    for path in [ROOT/'experiments/pcs-r1cs/README.md',ROOT/'experiments/pcs-r1cs/format/compact/README.md']:
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text()):
            if '://' not in link:assert (path.parent/link.split('#')[0]).exists(),(path,link)
    result=dict(status='passed',validated_jobs=82,supported_statement_pairs=21,measured_binaries_sha256=manifest['binaries_sha256'],
                checked_source_hashes=checked,post_measurement_export_helper_changes=changed,
                independent_tables_check='client/aggregate seconds, gas, matching circuit identities and paired statements',
                preserved_formal_sources=True,minimum_sampled_memory_available_gib=summary['minimum_available_gib'],
                note='Rust/library and formal sources match the recorded run. Export helper gained membership output after timing; measured binaries unchanged. Benchmark/result prose was completed after timing.')
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
