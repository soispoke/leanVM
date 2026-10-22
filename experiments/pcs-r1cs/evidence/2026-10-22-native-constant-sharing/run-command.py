#!/usr/bin/env python3
import os,sys,json,subprocess,time,hashlib
from pathlib import Path
base=Path(__file__).resolve().parent
tree=base/'prover'
out=base/sys.argv[1]
cmd=sys.argv[2:]
env=os.environ.copy()
env['PATH']='/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:'+env['PATH']
env.update(RUSTUP_HOME='/root/.rustup',CARGO_HOME='/root/.cargo',RUSTUP_TOOLCHAIN='1.99.1',CARGO_TARGET_DIR=str(base/'prover-target'),CARGO_BUILD_JOBS='4',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq',LEANVM_NUM_THREADS='16')
(base/'command-state.json').write_text(json.dumps(dict(status='running',pid=os.getpid(),command=cmd,out=str(out),started=time.time()))+'\n')
subprocess.run([str(tree/'experiments/pcs-r1cs/memguard'),'admit','32'],check=True)
runner=Path('/root/yukon-autoresearch/bin/bench-research.py')
args=['python3',str(runner),'--cwd',str(tree),'--out',str(out),'--budget-gib','32','--reserve-gib','40','--timeout-seconds','900','--cpus',','.join(map(str,range(16)))]
for source in subprocess.check_output(['git','ls-files','*.rs','*.toml','Cargo.lock'],cwd=tree,text=True).splitlines():args+=['--source',source]
args+=['--source',str(Path(__file__).resolve())]
r=subprocess.run(args+['--']+cmd,cwd=tree,env=env)
(base/'command-state.json').write_text(json.dumps(dict(status='complete' if r.returncode==0 else 'failed',pid=os.getpid(),out=str(out),returncode=r.returncode,finished=time.time()))+'\n')
raise SystemExit(r.returncode)
