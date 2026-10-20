#!/usr/bin/env python3
"""Tabulate this directory's runs: exact work per application and committed size by interface and batch size."""
import json
import math
import pathlib

HERE = pathlib.Path(__file__).parent
rows = {}
for path in sorted((HERE / "runs").glob("*.jsonl")):
    for line in path.read_text().splitlines():
        x = json.loads(line)
        if x.get("kind") not in ("sample", "dry-run"):
            continue
        n = x.get("fan_in", 1)
        key = (x["interface"], n)
        committed = x.get("committed") or 2 ** float(x["stats"].split("TOTAL_COMMITTED 2^")[1])
        row = rows.setdefault(key, {"interface": x["interface"], "fan_in": n})
        row.update(
            cycles_per_app=x["base_cycles"] / n,
            log_committed=round(math.log2(committed), 3),
            code_len=x["code_len"],
            proven=row.get("proven", False) or x["kind"] == "sample",
        )
        for k in ("execution_gas", "negative_guest_cases"):
            if k in x:
                row[k] = x[k]
order = {"pcs": 0, "r1cs-vm": 1, "r1cs": 2}
table = sorted(rows.values(), key=lambda r: (r["fan_in"], order[r["interface"]]))
(HERE / "summary.json").write_text(json.dumps(table, indent=1))
print("| Batch | Interface | VM cycles per app | log2 committed | Bytecode | Proved here |")
print("| ---: | --- | ---: | ---: | ---: | --- |")
for r in table:
    print(f"| {r['fan_in']} | {r['interface']} | {r['cycles_per_app']:,.0f} | {r['log_committed']} | {r['code_len']:,} | {'yes' if r['proven'] else 'shape only'} |")
