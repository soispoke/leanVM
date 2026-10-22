#!/usr/bin/env python3
from pathlib import Path
import os, subprocess, sys
base=Path(__file__).resolve().parent
which,label,*cmd=sys.argv[1:]
tree=base/which
env=dict(os.environ,PATH='/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:'+os.environ['PATH'],RUSTUP_TOOLCHAIN='1.99.1',CARGO_TARGET_DIR=str(base/'target'),CARGO_BUILD_JOBS='4',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq',LEANVM_NUM_THREADS='16')
args=['python3','/root/yukon-autoresearch/bin/bench-research.py','--cwd',str(tree),'--out',str(base/label),'--budget-gib','96','--reserve-gib','40','--timeout-seconds','1800','--cpus',os.environ.get('YUKON_COMMAND_CPUS', ','.join(map(str,range(16))))]
for name in subprocess.check_output(['git','ls-files','*.rs','*.toml','Cargo.lock'],cwd=tree,text=True).splitlines():args+=['--source',name]
args+=['--source',str(Path(__file__).resolve()),'--',*cmd]
raise SystemExit(subprocess.run(args,env=env).returncode)
