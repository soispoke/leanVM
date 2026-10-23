"""Sequential pinned measurements; run after the release tests finish."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BIN = ROOT.parent / "target-ht-L2r/release/examples/deferred_merge"
env = dict(os.environ, LEANVM_NUM_THREADS="12", RAYON_NUM_THREADS="12")
cases = [
    "same B A direct",
    "same B B carried",
    "same B A carried",
    "same B B direct",
    "same C B carried",
    "mixed B B carried",
    "mixed C B carried",
]
order = []
for repeat in range(3):
    for spec in cases if repeat != 1 else cases[::-1]:
        name = "final-" + spec.replace(" ", "-") + f"-{repeat + 1}.json"
        print(name, flush=True)
        result = subprocess.run(
            ["taskset", "-c", "12-23", "env", "LEANVM_NUM_THREADS=12", "RAYON_NUM_THREADS=12", str(BIN), *spec.split()],
            cwd=ROOT, env=env, text=True, capture_output=True, check=True,
        )
        data = json.loads(result.stdout)
        assert data["verified"]
        (OUT / name).write_text(result.stdout)
        if result.stderr:
            (OUT / (name + ".stderr")).write_text(result.stderr)
        order.append(name)
baseline = BIN.with_name("shielded_native")
for repeat in range(1, 4):
    result = subprocess.run(
        ["taskset", "-c", "12-23", str(baseline), "merge", "0", "/tmp/L2r-unused-proof"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=True,
    )
    (OUT / f"fixed-shielded-merge-{repeat}.json").write_text(result.stdout)
(OUT / "provenance.json").write_text(json.dumps({
    "binary_sha256": hashlib.sha256(BIN.read_bytes()).hexdigest(),
    "parent_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "order": order, "cores": "12-23", "threads": 12,
    "fixed_baseline_binary_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
    "matrix_prover": "CSR", "root_settlement": "source instruction generator, no CSR evaluation",
}, indent=2) + "\n")
