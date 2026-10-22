import os, subprocess, json, hashlib, time, sys
from pathlib import Path
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
out=root/'experiments/pcs-r1cs/evidence/2026-10-22-private-index4-performance'
out.mkdir(exist_ok=False)
freeze=root/'experiments/pcs-r1cs/evidence/2026-10-22-perf-index4-final-build/frozen.json'
for _ in range(180):
 if freeze.exists(): break
 time.sleep(2)
else: raise RuntimeError('frozen build not ready')
frozen=json.loads(freeze.read_text())
rev=frozen['source_commit']
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==rev
base=Path('/root/workspaces/mission-9abcee72/scratch/perf-20261022')
native=base/'frozen/private_tree-index4'
vm=base/'frozen/chain_tree_vm-final'
baseline=base/'private_tree-baseline'
env=os.environ.copy()
env.update(LEANVM_NUM_THREADS='16',RUSTUP_TOOLCHAIN='1.99.1',RUSTFLAGS='-C target-cpu=native -C target-feature=+pclmulqdq')
config=dict(source_commit=rev,yukon_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd='/root/yukon-autoresearch',text=True).strip(),samples=3,warmups=0,chain=16,cpus=list(range(16)),threads=16,native_joint_log_inv_rate=2,native_index_log_inv_rate=4,vm_log_inv_rates=[1,2],baseline_source='eb8985ceb918b48aff2494603e6ee81c940b8c10',vm_source='bd2f8fc38c269f08ddcc8b2ea571fb45dfb10a47',binaries={str(b):hashlib.sha256(b.read_bytes()).hexdigest() for b in [native,vm,baseline]},started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
(out/'config.json').write_text(json.dumps(config,indent=2)+'\n')
(out/'source-sha256.json').write_text(json.dumps({s:hashlib.sha256((root/s).read_bytes()).hexdigest() for s in subprocess.check_output(['git','ls-files','*.rs','*.toml','Cargo.lock'],cwd=root,text=True).splitlines()},indent=2)+'\n')
(out/'driver-state.json').write_text(json.dumps(dict(status='running',pid=os.getpid()))+'\n')
def run(name,sample,depth,binary,source,chain=16,budget=32,extra=()):
 print('START',name,sample,flush=True)
 args=['taskset','-c','0-15',sys.executable,'experiments/pcs-r1cs/recursion/run.py','--out',str(out/f'{name}-{sample}'),'--budget-gib',str(budget),'--binary-source-commit',source,'--',str(binary),'--depth',str(depth),'--chain',str(chain),*extra]
 subprocess.run(args,cwd=root,env=env,check=True)
 print('DONE',name,sample,flush=True)
run('smoke',0,2,native,rev)
run('full',0,3,native,rev,chain=16384,budget=80)
for sample in range(3):
 pair=[('baseline',baseline,config['baseline_source']),('optimized',native,rev)]
 if sample%2: pair.reverse()
 for name,binary,source in pair: run(name,sample,2,binary,source)
for depth in [1,3]:
 for sample in range(3):
  variants=[('native',native,rev,()),('vm1',vm,config['vm_source'],('--log-inv-rate','1')),('vm2',vm,config['vm_source'],('--log-inv-rate','2'))]
  variants=variants[sample:]+variants[:sample]
  for name,binary,source,extra in variants: run(f'{name}-depth{depth}',sample,depth,binary,source,extra=extra)
(out/'driver-state.json').write_text(json.dumps(dict(status='complete',pid=os.getpid(),finished_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))+'\n')
