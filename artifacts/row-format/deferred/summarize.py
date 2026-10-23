import json
from pathlib import Path
import statistics

out = Path(__file__).resolve().parent
groups = {}
provenance = json.loads((out / "provenance.json").read_text())
for name in provenance["order"]:
    data = json.loads((out / name).read_text())
    key = "-".join(data[k] for k in ["case", "format", "outer_backend", "mode"])
    groups.setdefault(key, []).append(data)
summary = {}
fields = [
    "merge_s", "native_child_checks_s", "fold_prover_s", "record_s", "outer_prover_s",
    "core_verify_ms", "own_merge_matrix_settle_ms", "peak_rss_kib",
    "additional_peak_rss_kib", "setup_s", "proof_bytes", "rows", "compressions",
    "committed_words", "carried_claim_bytes", "fold_proof_bytes",
]
for key, runs in sorted(groups.items()):
    r = {}
    for field in fields:
        values = [x[field] for x in runs if x[field] is not None]
        r[field] = statistics.median(values) if values else None
    r["merge_range_s"] = [min(x["merge_s"] for x in runs), max(x["merge_s"] for x in runs)]
    r["wallets"] = [
        {field: statistics.median(x["wallets"][i][field] for x in runs)
         for field in ["wallet_s", "source_witness_s", "proof_bytes", "words", "peak_rss_kib", "additional_peak_rss_kib"]}
        for i in range(2)
    ]
    r["settlements"] = [
        {"app": item["app"], "ms": statistics.median(x["root_settlements"][i]["ms"] for x in runs)}
        for i, item in enumerate(runs[0]["root_settlements"])
    ]
    r["root_total_ms"] = statistics.median(
        x["core_verify_ms"] + (x["own_merge_matrix_settle_ms"] or 0) + sum(c["ms"] for c in x["root_settlements"])
        for x in runs
    )
    r["sparse_shape"] = runs[0]["sparse_shape"]
    r["carried_shapes"] = runs[0]["carried_shapes"]
    summary[key] = r
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
