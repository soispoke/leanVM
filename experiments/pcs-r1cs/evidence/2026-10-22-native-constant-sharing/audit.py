#!/usr/bin/env python3
"""Revalidate retained trees and compute scoped improvements from raw records."""
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import sys

base = Path(__file__).resolve().parent
validator = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("trees", validator)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
reports = {}
for directory in sorted(base.glob("*-depth*")):
    if not (directory / "summary.json").exists():
        continue
    old = json.loads((directory / "summary.json").read_text())
    groups = {name: module.group([directory / f"{name}-trial-{i}" for i in range(3)])
              for name in old["groups"]}
    assert groups == old["groups"], directory
    for guard_dir in directory.glob("*-guard"):
        guard = json.loads((guard_dir / "result.json").read_text())
        assert guard["ok"] is True and guard["files_unchanged"] is True, guard_dir
        assert guard["file_sha256_before"] == guard["file_sha256_after"], guard_dir
        run = json.loads((guard_dir / "run-00/result.json").read_text())
        assert run["ok"] is True and run["stop_reason"] is None, guard_dir
        for file in ["stdout", "stderr"]:
            assert hashlib.sha256((guard_dir / f"run-00/{file}.log").read_bytes()).hexdigest() == run[f"{file}_sha256"]
        module.load(directory / guard_dir.name.removesuffix("-guard"))
    roots = {name: group["levels"][-1] for name, group in groups.items()}
    baseline, candidate = [roots[name]["preparation_plus_proving_s"]["median"] for name in ["baseline", "candidate"]]
    paired = [100 * (1 - c["levels"][-1]["preparation_plus_proving_s"] / b["levels"][-1]["preparation_plus_proving_s"])
              for b, c in zip(groups["baseline"]["runs"], groups["candidate"]["runs"])]
    reports[directory.name] = dict(root_metrics=roots,
        root_reduction_pct=100 * (1 - candidate / baseline), paired_reduction_pct=paired,
        median_paired_reduction_pct=statistics.median(paired),
        whole_process_s={name: group["elapsed_s"] for name, group in groups.items()},
        max_process_rss_gib={name: group["peak_rss_gib"] for name, group in groups.items()})
for filename, tree in [("constants-freeze.json", "compiler"), ("preprocessing-freeze.json", "prover")]:
    freeze = json.loads((base / filename).read_text())
    assert hashlib.sha256(Path(freeze["binary"]).read_bytes()).hexdigest() == freeze["binary_sha256"]
    for name, digest in freeze["files"].items():
        assert hashlib.sha256((base / tree / name).read_bytes()).hexdigest() == digest, name
report = dict(status="passed", reports=reports,
              scope="Tests and source audit, no formal security or implementation-equivalence certificate")
(base / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
for name, report in reports.items():
    print(name, "root reduction", round(report["root_reduction_pct"], 3), "paired", report["paired_reduction_pct"])
