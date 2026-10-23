#!/usr/bin/env python3
"""Run L1 native-row wallets and independent verifiers on their assigned CPUs."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def run(command, output, error, repo):
    pid = os.fork()
    if pid == 0:
        os.chdir(repo)
        for target, path in [(1, output), (2, error)]:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            os.dup2(fd, target)
            os.close(fd)
        os.execvp(command[0], command)
    _, status, usage = os.wait4(pid, 0)
    if status:
        raise RuntimeError(f"{command} exited {status}: {error.read_text()}")
    rows = [json.loads(line) for line in output.read_text().splitlines() if line.startswith("{")]
    row = next(row for row in rows if "wallet_prove_s" in row or "verify_ms" in row)
    row["process_peak_rss_kib"] = usage.ru_maxrss
    return row


def main():
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=repo.parent / "artifacts")
    parser.add_argument("--target", type=Path, default=repo.parent / "target-ht-L1")
    parser.add_argument("--workload", action="append")
    args = parser.parse_args()
    root = args.artifacts.resolve()
    raw = root / "hometurf-L1-final"
    raw.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    workloads = args.workload or ["blake2s-64b", "blake2s-1kib", "hashchain-16", "hashchain-256", "hashchain-4096", "merkle-20", "merkle-32", "leanxmss", "shielded"]
    prefix = ["taskset", "-c", "0-11", "env", "RAYON_NUM_THREADS=12", "LEANVM_NUM_THREADS=12"]
    for name in workloads:
        if name.startswith("blake2s"):
            binary, params = "native_hash_application", ["64" if name.endswith("64b") else "1024"]
        elif name == "leanxmss":
            binary, params = "xmss_native", []
        elif name == "shielded":
            binary, params = "shielded_native", ["0"]
        else:
            kind, count = name.split("-")
            binary, params = "hometurf_native", [kind, count]
        proof = raw / f"{name}.proof"
        for mode, role in [("prove", "wallet"), ("verify", "mempool")]:
            command = prefix + [str(args.target.resolve() / "release/examples" / binary), mode] + params + [str(proof)]
            result = run(command, raw / f"{name}-{role}.jsonl", raw / f"{name}-{role}.stderr", repo)
            if "output" in result:
                reference_path = root / "hometurf-L2" / f"{name}.output.json"
                if reference_path.exists():
                    assert result["output"] == json.loads(reference_path.read_text()), name
            note = "Final L1 native-row run; exact L2 statement/output; fixed sizes in R1CS key versus VM runtime sizes; wallet includes witness+proof+encoding; verify includes decoding in separate process; wait4 RSS includes setup/fixture; joint committed words exclude fixed index; source " + commit
            if name == "leanxmss":
                note += "; 294 candidate WOTS edges selected by constrained digits versus 99 VM-executed edges; full target-sum and index checks"
            entries = []
            metrics = [("wallet_prove_s", "wallet_prove_s", "s"), ("proof_bytes", "wallet_proof_bytes", "bytes"), ("verify_ms", "mempool_verify_ms", "ms"), ("process_peak_rss_kib", role + "_peak_rss_kib", "KiB"), ("committed_words", "committed_words", "F64 words"), ("compressions", "hash_compressions", "compressions"), ("arithmetic_rows", "prebridge_arithmetic_rows", "rows"), ("gate_rows", "prebridge_arithmetic_rows", "rows"), ("native_log_rows", "native_log_rows", "log2 rows"), ("hash_block_log", "hash_block_log", "log2 blocks")]
            for key, metric, unit in metrics:
                if key in result:
                    entries.append(dict(system="r1cs", workload=name, role=role, metric=metric, value=result[key], unit=unit, threads=12, cpus="0-11", commit=commit, lane="L1", note=note))
            with (root / "hometurf-12t.jsonl").open("a") as output:
                for entry in entries:
                    output.write(json.dumps(entry) + "\n")
            (raw / f"{name}-{role}-summary.json").write_text(json.dumps(result) + "\n")
            print(name, role, json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
