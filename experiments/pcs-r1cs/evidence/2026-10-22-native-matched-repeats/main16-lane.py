import subprocess, os, json, sys, time, hashlib
from pathlib import Path
lane=Path(__file__).resolve().parent
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
out=lane/sys.argv[1]
cmd=sys.argv[2:]
env=os.environ.copy()
env.update(RUSTUP_HOME='/root/.rustup', CARGO_HOME='/root/.cargo', RUSTUP_TOOLCHAIN='1.99.1', CARGO_TARGET_DIR='/root/workspaces/mission-9abcee72/target-verified-pclmul', RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq', LEANVM_NUM_THREADS='16')
state=lane/'main-state.json'
state.write_text(json.dumps(dict(status='running',pid=os.getpid(),command=cmd,out=str(out),started=time.time()))+'\n')
subprocess.run([str(root/'experiments/pcs-r1cs/memguard'),'admit','32'],check=True)
args=['python3','/root/yukon-autoresearch/bin/bench-research.py','--out',str(out),'--cwd',str(root),'--budget-gib','32','--reserve-gib','40','--cpus',','.join(map(str,range(16))),'--timeout-seconds','900']
for source in subprocess.check_output(['git','ls-files','*.rs','*.toml','Cargo.lock'],cwd=root,text=True).splitlines(): args += ['--source',str(root/source)]
if Path(cmd[0]).is_file(): args += ['--source',cmd[0]]
run=subprocess.run(args+['--']+cmd,cwd=root,env=env)
state.write_text(json.dumps(dict(status='complete' if run.returncode==0 else 'failed',pid=os.getpid(),out=str(out),returncode=run.returncode,finished=time.time()))+'\n')
raise SystemExit(run.returncode)
