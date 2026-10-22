#!/usr/bin/env python3
from pathlib import Path
import json,subprocess,hashlib,sys,time
base=Path(__file__).resolve().parent
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
candidate=json.loads((base/'preprocessing-freeze.json').read_text())
specs={'baseline':('/root/yukon-autoresearch/workspaces/leanr1cs-parity-20261022/private_tree-compact-plan','f1b6626fc546956085f4512d8210f715e6dd256b','61aa7593645c0a7838f3a40e61bb0826b0dd78b77826413335178a29ae474713'),'candidate':(candidate['binary'],candidate['source_commit'],candidate['binary_sha256'])}
for path,revision,digest in specs.values():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
out=base/'preprocessing-depth3';out.mkdir(exist_ok=False)
plan=[('warmup',['baseline','candidate'])]+[(f'trial-{i}', ['baseline','candidate'] if i%2==0 else ['candidate','baseline']) for i in range(3)]
(out/'plan.json').write_text(json.dumps(dict(specs=specs,plan=plan,depth=3,chain=16,workers=16,cpus=list(range(16)),policy='One excluded fresh-process warmup per backend, three alternating fresh-process pairs; shared host.'),indent=2)+'\n')
for trial,order in plan:
 for name in order:
  path,revision,digest=specs[name]
  print(name,trial,flush=True)
  args=['python3',str(root/'experiments/pcs-r1cs/recursion/run.py'),'--out',str(out/f'{name}-{trial}'),'--budget-gib','32','--binary-source-commit',revision,'--',path,'--depth','3','--chain','16']
  subprocess.run(['python3',str(base/'run-command.py'),str(out/f'{name}-{trial}-guard'),*args],check=True)
groups=[]
for name in specs:groups+=['--group',name,*[str(out/f'{name}-trial-{i}') for i in range(3)]]
subprocess.run(['python3',str(root/'experiments/pcs-r1cs/recursion/summarize_trees.py'),*groups,'--out',str(out/'summary.json')],check=True)
s=json.loads((out/'summary.json').read_text())
for name,group in s['groups'].items():print(name,json.dumps(group['levels'][-1]),flush=True)
