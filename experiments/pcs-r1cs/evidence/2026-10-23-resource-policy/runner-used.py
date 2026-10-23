#!/usr/bin/env python3
from pathlib import Path
import os, subprocess, sys
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
if role not in ('bench','build','client4'):
    raise SystemExit('YUKON_COMMAND_ROLE must be bench, build or client4')
if effective_cmd[:2] in (['cargo','run'],['cargo','bench']):
    raise SystemExit('Build on cores 32-47 with cargo build first, then measure the executable directly on cores 0-15')
cpus={'bench':range(16),'build':range(32,48),'client4':range(4)}[role]
threads='4' if role == 'client4' else '16'
for arg in cmd[:len(cmd)-len(effective_cmd)]:
    name,_,value=arg.partition('=')
    if name in ('LEANVM_NUM_THREADS','RAYON_NUM_THREADS') and value != threads:
        raise SystemExit(f'{name} must be {threads} for resource role {role}')
env=dict(os.environ,PATH='/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:'+os.environ['PATH'],RUSTUP_TOOLCHAIN='1.99.1',CARGO_TARGET_DIR=os.environ.get('YUKON_CARGO_TARGET_DIR',str(base/'target-vm-common')),CARGO_BUILD_JOBS='4',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq',LEANVM_NUM_THREADS=threads,RAYON_NUM_THREADS=threads)
args=['python3','/root/yukon-autoresearch/workspaces/yukon-latest-2e90b37/bin/bench-research.py','--cwd',str(tree),'--out',str(base/label),'--budget-gib','96','--reserve-gib','40','--timeout-seconds','1800','--cpus',','.join(map(str,cpus))]
for name in subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','--','*.rs','*.py','*.toml','Cargo.lock'],cwd=tree,text=True).splitlines():args+=['--source',name]
args+=['--source',str(Path(__file__).resolve()),'--source',str(base/'artifacts/application-closure-plan.json'),'--',*cmd]
raise SystemExit(subprocess.run(args,env=env).returncode)
