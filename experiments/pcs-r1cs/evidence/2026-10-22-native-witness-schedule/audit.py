#!/usr/bin/env python3
"""Recheck frozen source/binary, retained tree receipts and circuit-size equality."""
from pathlib import Path
import hashlib, importlib.util, json, statistics, subprocess
base=Path(__file__).resolve().parent
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
spec=importlib.util.spec_from_file_location('trees',root/'experiments/pcs-r1cs/recursion/summarize_trees.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
reports={}
for directory in sorted(base.glob('schedule-depth*')):
    if not (directory/'summary.json').exists():continue
    old=json.loads((directory/'summary.json').read_text())
    groups={name:module.group([directory/f'{name}-trial-{i}' for i in range(group['trials'])]) for name,group in old['groups'].items()}
    assert groups==old['groups'],directory
    for guard_path in directory.glob('*-guard/result.json'):
        guard=json.loads(guard_path.read_text())
        assert guard['ok'] and guard['files_unchanged'] and guard['file_sha256_before']==guard['file_sha256_after'],guard_path
        assert guard['tooling_git']['revision']=='58b0915ae37a851bcd770734b1a397274fc83d22'
        assert guard['harness_sha256']==hashlib.sha256((base/'bench-research-used.py').read_bytes()).hexdigest()
        run=json.loads((guard_path.parent/'run-00/result.json').read_text());assert run['ok'] and run['stop_reason'] is None
        for stream in ['stdout','stderr']:
            assert hashlib.sha256((guard_path.parent/f'run-00/{stream}.log').read_bytes()).hexdigest()==run[f'{stream}_sha256']
        module.load(directory/guard_path.parent.name.removesuffix('-guard'))
    for trial in ['warmup',*[f'trial-{i}' for i in range(groups['candidate']['trials'])]]:
        streams={name:[json.loads(line) for line in (directory/f'{name}-{trial}/stdout.jsonl').read_text().splitlines()] for name in ['baseline','candidate']}
        # The optimization must preserve the exact circuit geometry and all proof lengths.
        shapes={name:[(r['level'],r['rows'],r['compressions'],r['native_shape']) for r in rows if r['kind']=='setup'] for name,rows in streams.items()}
        assert shapes['baseline']==shapes['candidate'],(directory,trial,'circuit changed')
        sizes={name:[(r['level'],r['index'],r['proof_bytes']) for r in rows if r['kind']=='proof'] for name,rows in streams.items()}
        assert sizes['baseline']==sizes['candidate'],(directory,trial,'proof length changed')
    roots={name:g['levels'][-1] for name,g in groups.items()}
    times={name:r['preparation_plus_proving_s']['median'] for name,r in roots.items()}
    paired=[100*(1-c['levels'][-1]['preparation_plus_proving_s']/b['levels'][-1]['preparation_plus_proving_s']) for b,c in zip(groups['baseline']['runs'],groups['candidate']['runs'])]
    reports[directory.name]=dict(root_metrics=roots,root_time_reduction_pct=100*(1-times['candidate']/times['baseline']),candidate_vs_vm_time_pct=100*(times['candidate']/times['leanvm']-1),paired_reduction_pct=paired,median_paired_reduction_pct=statistics.median(paired),whole_process_s={name:g['elapsed_s'] for name,g in groups.items()},max_rss_gib={name:g['peak_rss_gib'] for name,g in groups.items()},circuit_shapes_and_proof_lengths_identical=True)
freeze=json.loads((base/'freeze.json').read_text())
assert hashlib.sha256(Path(freeze['binary']).read_bytes()).hexdigest()==freeze['binary_sha256']
for name,digest in freeze['files'].items():assert hashlib.sha256((base/'candidate'/name).read_bytes()).hexdigest()==digest,name
changed=subprocess.check_output(['git','diff','--name-only','8a8e8ada',freeze['source_commit']],cwd=base/'candidate',text=True).splitlines()
assert changed==['crates/format_recursion/src/private_recursion.rs','crates/format_recursion/src/private_trace.rs'],changed
report=dict(status='passed',candidate=freeze['source_commit'],changed_files=changed,reports=reports,scope='Runtime and source checks; no new formal security certificate')
(base/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
for name,data in reports.items():print(name,'root reduction',round(data['root_time_reduction_pct'],2),'candidate vs VM',round(data['candidate_vs_vm_time_pct'],2),'paired',data['paired_reduction_pct'])
