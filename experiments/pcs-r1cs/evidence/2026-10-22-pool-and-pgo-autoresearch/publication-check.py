#!/usr/bin/env python3
from pathlib import Path
import subprocess,sys
ROOT=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
DEST=ROOT/'experiments/pcs-r1cs/evidence/2026-10-22-pool-and-pgo-autoresearch'
subprocess.run([sys.executable,str(DEST/'verify-archive.py')],check=True)
subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT/'experiments/pcs-r1cs/recursion'),'-p','test_*.py'],check=True)
subprocess.run(['git','diff','--check'],cwd=ROOT,check=True)
print('Publication checks passed',flush=True)
