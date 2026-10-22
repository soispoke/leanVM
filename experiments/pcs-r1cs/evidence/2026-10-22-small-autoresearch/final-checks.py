from pathlib import Path
import subprocess
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
base=Path(__file__).resolve().parent
small=root/'experiments/pcs-r1cs/evidence/2026-10-22-small-autoresearch'
sources=[*small.glob('*.py'),small/'baseline-freeze.json',small/'README.md',root/'experiments/pcs-r1cs/recursion/summarize_trees.py']
checks=[('small-trace-audit',['python3',str(small/'audit-series.py'),'trace']),('small-stack-audit',['python3',str(small/'audit-series.py'),'stack']),('small-worker-audit',['python3',str(small/'audit-workers.py')]),('small-retention-audit',['python3',str(small/'audit_retention.py')]),('small-record-tests',['python3','-m','unittest','discover','-s','experiments/pcs-r1cs/recursion','-p','test_*.py'])]
for label,command in checks:
 argv=['python3','/root/yukon-autoresearch/bin/bench-research.py','--cwd',str(root),'--out',str(base/label),'--budget-gib','2','--reserve-gib','40','--timeout-seconds','120']
 for source in sources:argv+=['--source',str(source)]
 subprocess.run([*argv,'--',*command],check=True)
print('FINAL CHECKS PASSED')
