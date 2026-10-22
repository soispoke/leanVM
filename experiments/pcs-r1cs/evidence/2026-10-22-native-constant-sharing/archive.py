#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,shutil,subprocess
base=Path(__file__).resolve().parent
root=Path('/root/workspaces/mission-9abcee72/leanvm-opt')
out=root/'experiments/pcs-r1cs/evidence/2026-10-22-native-constant-sharing'
out.mkdir(exist_ok=False)
exclude={'compiler','prover','compiler-target','prover-target','private_tree-constants','private_tree-preprocessing','__pycache__'}
for source in base.iterdir():
    if source.name in exclude or source.name.startswith('.'):
        continue
    if source.is_dir(): shutil.copytree(source,out/source.name)
    else: shutil.copy2(source,out/source.name)
print(out)
