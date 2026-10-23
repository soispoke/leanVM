#!/usr/bin/env python3
"""Measure relation-default native wallets and standalone mempool verification."""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess

from measure_hometurf import run


def main():
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, default=repo.parent / "target-ht-L1")
    args = parser.parse_args()
    raw = args.output.resolve()
    raw.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    binary = args.target.resolve() / "release/examples/application_role_profile"
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    prefix = ["taskset", "-c", "0-11", "env", "LEANVM_NUM_THREADS=12", "RAYON_NUM_THREADS=12"]
    for name in ["sha256-1kib", "keccak256-1KiB", "mpt-storage-proof"]:
        proof = raw / f"{name}.cert"
        base = prefix + [str(binary), "--workload", name]
        wallet = run(base + ["--role", "native-client", "--out", str(proof)],
                     raw / f"{name}-wallet.jsonl", raw / f"{name}-wallet.stderr", repo)
        records = [json.loads(line) for line in (raw / f"{name}-wallet.jsonl").read_text().splitlines() if line.startswith("{")]
        setup = next(row for row in records if row.get("kind") == "role_setup")
        witness = next(row for row in records if row.get("kind") == "native_application_witness")
        assert witness["trim_unused_outputs"] is True
        assert wallet["cpus"] == "0-11" and wallet["threads"] == 12
        hex_hash = lambda value: bytes(value).hex()
        command = base + ["--role", "mempool", "--input", str(proof),
                          "--statement", hex_hash(wallet["statement"]), "--base-key", hex_hash(setup["key"])]
        verifier = run(command, raw / f"{name}-mempool.jsonl", raw / f"{name}-mempool.stderr", repo)
        assert verifier["status"] == "verified" and verifier["verification_process"] == "standalone"
        summary = dict(wallet=wallet, verifier=verifier, setup=setup, witness=witness,
                       commit=commit, binary_sha256=binary_hash)
        (raw / f"{name}-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        entries = []
        for role, row, metrics in [
            ("wallet", wallet, [("wallet_prove_s", "s"), ("wallet_proof_bytes", "bytes"), ("process_peak_rss_kib", "KiB")]),
            ("mempool", verifier, [("mempool_verify_ms", "ms")]),
        ]:
            for metric, unit in metrics:
                entries.append(dict(system="r1cs", workload=name, role=role,
                                    metric="wallet_peak_rss_kib" if metric == "process_peak_rss_kib" else metric,
                                    value=row[metric], unit=unit, threads=12, cpus="0-11", commit=commit, lane="L1",
                                    note="Approved relation-default output trimming; inverse commitment rate 4; separate wallet/mempool processes; wallet witness+proof+encoding excludes setup/reference; RSS includes setup; binary SHA256 " + binary_hash))
        with (repo.parent / "artifacts/matched-12t.jsonl").open("a") as output:
            fcntl.flock(output, fcntl.LOCK_EX)
            for row in entries:
                output.write(json.dumps(row) + "\n")
        print(name, json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
