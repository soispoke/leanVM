#!/usr/bin/env python3
"""Run the matched prototype and retain a complete, immutable evidence directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
MATCHED = ("client_us", "witness_us", "piop_prove_us", "opening_prove_us", "admission_piop_us", "admission_openings_us")
TOTAL = (*MATCHED[:1], *MATCHED[-2:], "hint_prep_us", "aggregate_prove_us", "aggregate_verify_us", "evm_with_context_us", "coverage_us")


def validate(rows, processes, samples):
    """Reject missing, duplicated, mismatched or non-finite sample records."""
    import math
    expected = {(p, f, s, m) for p in range(processes) for f in (1, 2) for s in range(samples + 1) for m in ("pcs", "r1cs")}
    actual = {}
    for row in rows:
        key = (row["process"], row["fan_in"], row["sample"], row["interface"])
        if key not in expected or key in actual:
            raise ValueError(f"unexpected or duplicate sample: {key}")
        if row["warmup"] != (row["sample"] == 0):
            raise ValueError(f"invalid warmup flag: {key}")
        for name, value in row.items():
            if isinstance(value, (int, float)) and (not math.isfinite(value) or value < 0):
                raise ValueError(f"invalid metric {name}: {key}")
        if not math.isclose(row["serial_warm_us"], sum(row[k] for k in TOTAL), rel_tol=1e-10):
            raise ValueError(f"inconsistent total: {key}")
        if row["execution_gas"] != row["fan_in"] * (10971 if row["interface"] == "pcs" else 61):
            raise ValueError(f"changed execution gas: {key}")
        actual[key] = row
    if actual.keys() != expected:
        raise ValueError(f"missing samples: {expected - actual.keys()}")
    for p, f, s, m in expected:
        if m != "pcs":
            continue
        a, b = actual[p, f, s, "pcs"], actual[p, f, s, "r1cs"]
        if any(a[k] != b[k] for k in MATCHED):
            raise ValueError(f"client/admission inputs differ: {(p, f, s)}")


def digest_sources():
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    selected = [ROOT / os.fsdecode(f) for f in files if f and (f.endswith((b".rs", b".toml", b".lock", b".py")))]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in selected if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--processes", type=int, default=3)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if args.processes < 1 or args.samples < 1:
        parser.error("processes and samples must be positive")
    out = args.output.resolve()
    # Exclusive directory creation preserves failed and incomplete runs too.
    out.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env["LEANVM_NUM_THREADS"] = "8"
    commands = []
    manifest = {
        "status": "running", "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT)),
        "platform": platform.platform(), "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "workers": {"LEANVM_NUM_THREADS": "8", "efficiency_workers": "upstream default"},
        "processes": args.processes, "samples": args.samples, "sources": digest_sources(),
        "scope": "serial prototype stages; native coverage adapter; no application state or block execution proving",
    }
    if platform.system() == "Darwin":
        manifest["hardware"] = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def run(name, command, gb):
        guard = Path.home() / ".local/bin/memguard"
        receipts = []
        if platform.system() == "Darwin" and not guard.is_file():
            raise RuntimeError("memguard is required on this Mac")
        while guard.is_file():
            check = subprocess.run([str(guard), "admit", str(gb)], text=True, capture_output=True)
            receipts.append(check.stdout + check.stderr)
            if check.returncode == 0 and check.stdout.startswith("ok:"):
                break
            time.sleep(5)
        measured = (["/usr/bin/time", "-l"] if platform.system() == "Darwin" else []) + command
        start = time.monotonic()
        with (out / f"{name}.log").open("x") as log:
            result = subprocess.run(measured, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        commands.append(dict(name=name, command=command, expected_peak_gb=gb, admissions=receipts,
                             seconds=time.monotonic()-start, returncode=result.returncode))
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect its log")
        return [json.loads(line) for line in (out / f"{name}.log").read_text().splitlines() if line.startswith("{")]

    try:
        run("clippy", ["cargo", "clippy", "--locked", "--release", "-p", "rec_aggregation", "--all-targets", "--", "-D", "warnings"], 12)
        run("unit", ["cargo", "test", "--locked", "--release", "-p", "rec_aggregation", "--example", "comparison"], 12)
        run("build", ["cargo", "build", "--locked", "--release", "-p", "rec_aggregation", "--examples"], 12)
        rows = []
        for process in range(args.processes):
            for fan, binary in [(1, "comparison"), (2, "batch")]:
                command = [f"target/release/examples/{binary}", "--samples", str(args.samples), "--seed", str(902+1000*process+100*fan)]
                if fan > 1:
                    command += ["--fan-in", str(fan)]
                records = run(f"fan{fan}-process{process}", command, 35)
                if any(r.get("kind") == "capacity" for r in records):
                    raise ValueError("requested measurement exceeds backend capacity")
                rows.extend(dict(r, process=process, fan_in=fan) for r in records if r.get("kind") == "sample")
                (out / "samples.json").write_text(json.dumps(rows, indent=2) + "\n")
        validate(rows, args.processes, args.samples)
        if digest_sources() != manifest["sources"]:
            raise ValueError("sources changed during measurement")
        summary = {}
        for fan in (1, 2):
            summary[str(fan)] = {}
            for mode in ("pcs", "r1cs"):
                samples = [r for r in rows if r["fan_in"] == fan and r["interface"] == mode and not r["warmup"]]
                keys = [k for k, v in samples[0].items() if type(v) in (float, int)]
                summary[str(fan)][mode] = {"n": len(samples), "metrics": {k: {"median": statistics.median(r[k] for r in samples),
                    "min": min(r[k] for r in samples), "max": max(r[k] for r in samples)} for k in keys}}
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        shutil.copyfile(ROOT / "Cargo.lock", out / "Cargo.lock")
        manifest["status"] = "complete"
    except BaseException as error:
        manifest.update(status="failed", error=str(error))
        raise
    finally:
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
