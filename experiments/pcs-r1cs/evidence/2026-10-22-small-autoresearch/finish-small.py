from pathlib import Path
import subprocess
b=Path(__file__).resolve().parent
for depth in (1,2):
 subprocess.run(['python3',str(b/'measure-workers-precise.py'),'wide-validation',str(depth),'256','3','32'],cwd=b,check=True)
subprocess.run(['python3',str(b/'audit-workers.py')],cwd=b,check=True)
print('SMALL VALIDATION COMPLETE',flush=True)
