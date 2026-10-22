#!/usr/bin/env python3
"""Rerun the complete published Flock tower with the current Yukon runner."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
PRIOR = ROOT / 'experiments/pcs-r1cs/evidence/2026-10-22-flock-blake2s-baseline'
TREE = Path('/root/yukon-autoresearch/workspaces/leanr1cs-parity-20261022/flock-blake2s')
BINARY = Path('/root/yukon-autoresearch/workspaces/leanr1cs-parity-20261022/flock-b2s-final-inputs/tower_blake2s')
SOURCES = json.loads((PRIOR / 'source-sha256.json').read_text())
for name, digest in SOURCES.items():
    assert hashlib.sha256((TREE / name).read_bytes()).hexdigest() == digest, name
assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == '6714ce77567fe06e13e478b0f827dde28dfafe9b997425822a61e319f41c2fd2'
subprocess.run([str(ROOT / 'experiments/pcs-r1cs/memguard'), 'admit', '16'], check=True)
args = ['python3', '/root/yukon-autoresearch/bin/bench-research.py', '--cwd', str(TREE),
        '--out', str(BASE / 'flock-8x256'), '--budget-gib', '16', '--reserve-gib', '40',
        '--timeout-seconds', '2400', '--cpus', ','.join(map(str, range(16)))]
for name in SOURCES:
    args += ['--source', str(TREE / name)]
args += ['--source', str(Path(__file__).resolve()), '--', str(BINARY), '8', '256', '3']
env = dict(os.environ, RAYON_NUM_THREADS='16', RUSTUP_TOOLCHAIN='1.99.1', RUSTFLAGS='-C target-cpu=native')
subprocess.run(args, env=env, check=True)
subprocess.run(['python3', str(ROOT / 'experiments/pcs-r1cs/recursion/summarize_flock.py'),
                str(BASE / 'flock-8x256'), '--out', str(BASE / 'flock-summary.json')], check=True)
