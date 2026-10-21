#!/usr/bin/env python3
"""Client proving on an Android phone (the Pixel 7 reference device) over adb.

The phone does what an application's device does: witness generation, the PIOP and the
three openings, for the Keccak transcript (`pcs`, shared with the Keccak R1CS control) and
the VM's BLAKE2s transcript (`r1cs-vm`). Aggregation needs far more memory than the
phone's 8 GB and is measured on a node instead. Runs alternate between transcripts with a
cooldown, and each records the battery temperature, because phones throttle when hot.
`--local` runs the same commands on this machine, to test the pipeline without a phone.
"""
import argparse
import json
import pathlib
import statistics
import subprocess
import time

REMOTE = "/data/local/tmp/leanvm-bench"


def shell(args, command, check=True):
    full = ["sh", "-c", command] if args.local else ["adb", *(["-s", args.serial] if args.serial else []), "shell", command]
    result = subprocess.run(full, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"{command!r} failed: {result.stderr[-2000:]}")
    return result.stdout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, help="the `challenge` example built for the device (see build-android.sh)")
    p.add_argument("--out", required=True)
    p.add_argument("--reps", type=int, default=5)
    p.add_argument("--apps", type=int, default=1, help="client proofs per run")
    p.add_argument("--threads", type=int, default=4, help="LEANVM_NUM_THREADS; a Pixel 7 has two X1, two A78 and four A55 cores")
    p.add_argument("--cooldown", type=int, default=60, help="seconds between runs")
    p.add_argument("--serial")
    p.add_argument("--local", action="store_true")
    args = p.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    root = str(out.resolve() / "device") if args.local else REMOTE
    shell(args, f"rm -rf {root} && mkdir -p {root}")
    if args.local:
        subprocess.run(["cp", args.binary, f"{root}/challenge"], check=True)
    else:
        subprocess.run(["adb", *(["-s", args.serial] if args.serial else []), "push", args.binary, f"{root}/challenge"], check=True, capture_output=True)
    shell(args, f"chmod 755 {root}/challenge")
    device = {
        "model": shell(args, "getprop ro.product.model", check=False).strip(),
        "android": shell(args, "getprop ro.build.version.release", check=False).strip(),
        "soc": shell(args, "getprop ro.soc.model", check=False).strip(),
        "kernel": shell(args, "uname -a").strip(),
        "memory": shell(args, "grep MemTotal /proc/meminfo").strip(),
        "cpu_features": sorted(set(shell(args, "grep -m1 -i -E '^(Features|flags)' /proc/cpuinfo", check=False).split(":", 1)[-1].split())),
        "threads": args.threads,
    }
    if not args.local and device["memory"] and "Pixel 7" not in device["model"]:
        print(f"note: device is {device['model']!r}, not a Pixel 7")
    records = []
    for rep in range(args.reps):
        for interface in (("pcs", "r1cs-vm") if rep % 2 == 0 else ("r1cs-vm", "pcs")):
            temperature = shell(args, "dumpsys battery | grep temperature", check=False).strip()
            seed = 7000 + rep
            run = (f"cd {root} && export LEANVM_NUM_THREADS={args.threads} && ./challenge workload --seed {seed} --fan-in {args.apps} --out w{rep}.bin"
                   f" && ./challenge clients --interface {interface} --workload w{rep}.bin --out c{rep}-{interface}.bin")
            start = time.monotonic()
            lines = [json.loads(l) for l in shell(args, run).splitlines() if l.startswith("{")]
            wall = time.monotonic() - start
            for k, client in enumerate(lines):
                records.append(dict(client, rep=rep, app=k, run_wall_s=wall, battery=temperature))
            (out / "records.json").write_text(json.dumps({"device": device, "records": records}, indent=1))
            time.sleep(args.cooldown)
    summary = {}
    for interface in ("pcs", "r1cs-vm"):
        rows = [r for r in records if r["interface"] == interface]
        summary[interface] = {k: {"median": statistics.median(r[k] for r in rows), "min": min(r[k] for r in rows), "max": max(r[k] for r in rows)}
                              for k in ("client_us", "piop_us", "opening_us", "admission_us") if rows}
        peaks = [r["peak_rss_kib"] for r in rows if r.get("peak_rss_kib")]
        if peaks:
            summary[interface]["peak_rss_mib"] = max(peaks) / 1024
    (out / "summary.json").write_text(json.dumps({"device": device, "summary": summary}, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
