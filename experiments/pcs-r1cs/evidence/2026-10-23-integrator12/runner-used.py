#!/usr/bin/env python3
from pathlib import Path
import json, os, subprocess, sys
os.sched_setaffinity(0,range(12))
base=Path(__file__).resolve().parent
which,label,*cmd=sys.argv[1:]
tree=base/which
if not cmd:
    raise SystemExit('Expected a command')
effective_cmd=cmd
if cmd[0] == 'env':
    effective_cmd=cmd[1:]
    while effective_cmd and '=' in effective_cmd[0]:
        effective_cmd=effective_cmd[1:]
role=os.environ.get('YUKON_COMMAND_ROLE')
if role is None:
    role='build' if len(effective_cmd)>1 and effective_cmd[0] == 'cargo' and effective_cmd[1] in ('build','check','test','clippy','fmt','doc') else 'bench'
if role not in ('bench','build'):
    raise SystemExit('YUKON_COMMAND_ROLE must be bench or build')
if effective_cmd[:2] in (['cargo','run'],['cargo','bench']):
    raise SystemExit('Build with cargo build first, then measure the frozen executable directly; lane A uses cores 0-11')
cpus=range(12)
threads='12'
for arg in cmd[:len(cmd)-len(effective_cmd)]:
    name,_,value=arg.partition('=')
    if name in ('LEANVM_NUM_THREADS','RAYON_NUM_THREADS') and value != threads:
        raise SystemExit(f'{name} must be {threads} for resource role {role}')
env=dict(os.environ,PATH='/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:'+os.environ['PATH'],RUSTUP_TOOLCHAIN='1.99.1',CARGO_TARGET_DIR=os.environ.get('YUKON_CARGO_TARGET_DIR',str(base/'target-vm-common')),CARGO_BUILD_JOBS='12',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq',LEANVM_NUM_THREADS=threads,RAYON_NUM_THREADS=threads)
args=['taskset','-c','0-11','python3','/root/yukon-autoresearch/workspaces/yukon-latest-2e90b37/bin/bench-research.py','--cwd',str(tree),'--out',str(base/label),'--budget-gib','96','--reserve-gib','40','--timeout-seconds','1800','--cpus',','.join(map(str,cpus))]
for name in subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','--','*.rs','*.py','*.toml','Cargo.lock'],cwd=tree,text=True).splitlines():args+=['--source',name]
args+=['--source',str(Path(__file__).resolve()),'--source',str(base/'artifacts/application-closure-plan.json'),'--',*cmd]
status=subprocess.run(args,env=env).returncode
receipt=base/label/'result.json'
if receipt.exists():
    result=json.loads(receipt.read_text())
    result.update(threads=12,cpus='0-11',lane='A',resource_role=role)
    receipt.write_text(json.dumps(result,indent=2)+'\n')
raise SystemExit(status)
