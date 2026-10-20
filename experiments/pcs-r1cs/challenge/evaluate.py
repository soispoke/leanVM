#!/usr/bin/env python3
"""Track A evaluator: score a prover-only candidate against the frozen baseline.

The candidate build runs only the timed `challenge aggregate` step. The reference
build (the baseline commit) generates the hidden workload and client proofs, then
recompiles the aggregate program and verifies the candidate's proof, so soundness
never depends on candidate code. See README.md for the rules.
"""

import argparse
import fnmatch
import json
import os
import pathlib
import platform
import secrets
import statistics
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
MANIFEST = json.loads((HERE / "challenge.json").read_text())


def git(*args, cwd=REPO):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def changed_paths(base, cand):
    return [p for p in git("diff", "--name-only", base, cand).splitlines() if p]


def frozen_violations(paths):
    return [p for p in paths if not any(fnmatch.fnmatch(p, g) for g in MANIFEST["editable"])]


def checkout(rev, root):
    path = root / rev
    if not path.exists():
        git("worktree", "add", "--detach", str(path), rev)
    return path


def build(tree, target):
    subprocess.run(
        ["cargo", "build", "--locked", "--release", "-q", "-p", "rec_aggregation", "--example", "challenge"],
        cwd=tree,
        check=True,
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
    )
    return target / "release" / "examples" / "challenge"


def run(binary, *args, threads=None):
    """Run once; return (exit code, stdout, wall seconds, this child's peak RSS in GiB, stderr)."""
    env = dict(os.environ)
    if threads:
        env["LEANVM_NUM_THREADS"] = str(threads)
    with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
        start = time.perf_counter()
        child = subprocess.Popen([str(binary), *map(str, args)], stdout=out, stderr=err, env=env)
        _, status, usage = os.wait4(child.pid, 0)
        wall = time.perf_counter() - start
        child.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        err.seek(0)
        return child.returncode, out.read(), wall, usage.ru_maxrss / 1024**2, err.read()


def cpu_flags():
    try:
        line = next(l for l in open("/proc/cpuinfo") if l.startswith("flags"))
        return set(line.split(":", 1)[1].split())
    except (OSError, StopIteration):
        return set()


def evaluate(args):
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    base, cand = git("rev-parse", args.baseline), git("rev-parse", args.candidate)
    record = {"baseline": base, "candidate": cand, "interface": args.interface, "fan_in": args.fan_in}
    record["host"] = {"machine": platform.machine(), "node": platform.node(), "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()}
    missing = [f for f in MANIFEST["timing_requires_cpu_flags"] if f not in cpu_flags()] if platform.machine() == "x86_64" else []
    record["timing_valid"] = not missing
    if missing:
        record["timing_note"] = f"host lacks {missing}: field arithmetic runs a software fallback, so times are not representative"

    def finish(status, **extra):
        record.update(status=status, **extra)
        (out / "result.json").write_text(json.dumps(record, indent=1))
        print(json.dumps(record, indent=1))
        return 0 if status == "accepted" else 1

    violations = frozen_violations(changed_paths(base, cand))
    if violations:
        return finish("rejected", reason="edits outside the editable paths", paths=violations)
    trees = out / "trees"
    reference = build(checkout(base, trees), out / "target-reference")
    candidate = build(checkout(cand, trees), out / "target-candidate")

    # Hidden workload: the seed never enters the candidate tree or its process.
    seed = int.from_bytes(secrets.token_bytes(8), "little") if args.seed is None else args.seed
    (out / "seed").write_text(str(seed))
    for step, extra in [("workload", ["--seed", seed, "--fan-in", args.fan_in, "--out", out / "workload.bin"]), ("clients", ["--interface", args.interface, "--workload", out / "workload.bin", "--out", out / "clients.bin"])]:
        code, _, _, _, err = run(reference, step, *extra, threads=args.threads)
        if code:
            return finish("error", reason=f"reference {step} failed", stderr=err[-2000:])

    reps = []
    for rep in range(args.reps):
        proof = out / f"aggregate-{rep}.bin"
        code, stdout, wall, peak, err = run(candidate, "aggregate", "--interface", args.interface, "--clients", out / "clients.bin", "--out", proof, threads=args.threads)
        if code:
            return finish("rejected", reason="candidate aggregate failed", rep=rep, stderr=err[-2000:])
        code, verdict, _, _, err = run(reference, "verify", "--interface", args.interface, "--clients", out / "clients.bin", "--proof", proof, threads=args.threads)
        v = json.loads(verdict.strip().splitlines()[-1]) if verdict.strip() else {"ok": False}
        if code or not v.get("ok"):
            return finish("rejected", reason="reference verifier rejected the aggregate", rep=rep, verdict=v, stderr=err[-2000:])
        reps.append({"aggregate_wall_s": wall, "peak_rss_gib": peak, "candidate_report": json.loads(stdout.strip().splitlines()[-1]), **v})
        if rep == 0:
            # The verifier must not be vacuous: a flipped proof byte is rejected.
            data = bytearray(proof.read_bytes())
            data[len(data) // 2] ^= 1
            tampered = out / "tampered.bin"
            tampered.write_bytes(bytes(data))
            code, verdict, _, _, _ = run(reference, "verify", "--interface", args.interface, "--clients", out / "clients.bin", "--proof", tampered, threads=args.threads)
            if code == 0:
                return finish("error", reason="reference verifier accepted a tampered proof")
    scores = [(r["aggregate_wall_s"] + r["verify_us"] / 1e6) / args.fan_in for r in reps]
    record.update(reps=reps, score_s_per_app=statistics.median(scores), scores=scores)

    if args.baseline_result:
        b = json.loads(pathlib.Path(args.baseline_result).read_text())
        assert b["interface"] == args.interface and b["fan_in"] == args.fan_in and b["baseline"] == base
        lim = MANIFEST["limits"]
        worst = lambda key: max(r[key] for r in reps)
        for key, ratio in [("peak_rss_gib", lim["peak_rss_ratio"]), ("proof_bytes", lim["proof_bytes_ratio"]), ("execution_gas", lim["execution_gas_ratio"])]:
            if worst(key) > ratio * max(r[key] for r in b["reps"]):
                return finish("rejected", reason=f"{key} exceeds {ratio} x baseline")
        bs = b["scores"]
        median = statistics.median(bs)
        spread = (max(bs) - min(bs)) / (2 * median)
        threshold = max(MANIFEST["noise"]["min_gain"], MANIFEST["noise"]["range_multiplier"] * spread)
        speedup = median / record["score_s_per_app"]
        record.update(speedup=speedup, required_gain=threshold, improvement=record["timing_valid"] and speedup - 1 > threshold)
    return finish("accepted")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--interface", choices=MANIFEST["interfaces"], required=True)
    p.add_argument("--fan-in", type=int, default=MANIFEST["fan_in"])
    p.add_argument("--reps", type=int, default=MANIFEST["reps"])
    p.add_argument("--threads", type=int)
    p.add_argument("--seed", type=int, help="fixed workload seed (calibration only; scored runs draw a fresh one)")
    p.add_argument("--baseline-result", help="result.json of the baseline evaluated against itself")
    p.add_argument("--out", required=True)
    sys.exit(evaluate(p.parse_args()))


if __name__ == "__main__":
    main()
