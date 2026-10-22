"""Score a compact-description candidate on the fixed benchmark.

A candidate is a directory with:
  encode        executable: encode IN.rows OUT.desc
  decode.py     the SPECIFICATION decoder, Python 3 stdlib only: python3 decode.py IN.desc OUT.rows
  decode_fast   optional executable with the same interface, for circuits too large for decode.py

Exactness: the decoded rows file must be byte-identical to the benchmark's .rows (hence the same circuit, wiring
and index root). decode.py is run on every circuit whose .rows is below --py-limit bytes; above it decode_fast is
used, and only if decode.py and decode_fast agreed on every smaller circuit.
Reported: description bytes, xz -9e bytes (informational: an enshrined decoder cannot assume xz), the decoder's
logical lines, decode seconds.

    python3 score.py CANDIDATE_DIR [--only a,b] [--py-limit BYTES]
"""
import hashlib, json, lzma, os, subprocess, sys, time, ast, tempfile
from pathlib import Path

ROWS = Path(__file__).resolve().parent / "rows"
ORDER = ["membership", "blake2s-1kib", "sha256-1kib", "keccak256-1kib", "shielded-transfer", "falcon512",
         "mpt-storage-proof", "ecdsa-secp256k1", "poseidon-bn254"]


def logical_lines(path):
    """Statements of the decoder, by the AST: each simple statement and each compound header counts once;
    docstrings, comments, blank lines and imports do not."""
    tree = ast.parse(Path(path).read_text())
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and not isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            n += 1
    return n


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 24), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    global ROWS
    cand = Path(sys.argv[1]).resolve()
    if "--rows-dir" in sys.argv:
        ROWS = Path(sys.argv[sys.argv.index("--rows-dir") + 1]).resolve()
    only = None
    py_limit = 400 << 20
    args = sys.argv[2:]
    if "--only" in args:
        only = args[args.index("--only") + 1].split(",")
    if "--py-limit" in args:
        py_limit = int(args[args.index("--py-limit") + 1])
    selected = only if only is not None else ORDER
    if not selected or len(set(selected)) != len(selected) or set(selected) - set(ORDER):
        raise SystemExit("empty, duplicate or unknown requested circuit")
    missing = [name for name in selected if not (ROWS / f"{name}.rows").is_file()]
    if missing:
        raise SystemExit("missing reference rows: " + ", ".join(missing))
    fast = cand / "decode_fast"
    agree = True
    results = {"candidate": cand.name, "decoder_logical_lines": logical_lines(cand / "decode.py"), "circuits": {}}
    with tempfile.TemporaryDirectory() as tmp:
        for name in ORDER:
            src = ROWS / f"{name}.rows"
            if name not in selected:
                continue
            desc, out = Path(tmp) / f"{name}.desc", Path(tmp) / f"{name}.out"
            t = time.time()
            subprocess.run([str(cand / "encode"), str(src), str(desc)], check=True)
            enc_s = time.time() - t
            data = desc.read_bytes()
            r = {"rows_bytes": src.stat().st_size, "desc_bytes": len(data), "encode_s": round(enc_s, 2)}
            r["xz_bytes"] = len(lzma.compress(data, preset=9 | lzma.PRESET_EXTREME)) if len(data) < (1 << 30) else None
            want = sha(src)
            use_py = src.stat().st_size <= py_limit
            if use_py:
                t = time.time()
                subprocess.run([sys.executable, "-I", str(cand / "decode.py"), str(desc), str(out)], check=True)
                r["decode_py_s"] = round(time.time() - t, 2)
                r["exact_py"] = sha(out) == want
                if fast.exists():
                    subprocess.run([str(fast), str(desc), str(out)], check=True)
                    r["fast_agrees"] = sha(out) == want
                    agree &= r["fast_agrees"]
            else:
                if not fast.exists() or not agree:
                    r["exact_fast"] = None
                    r["note"] = "too large for decode.py and no trusted decode_fast"
                else:
                    t = time.time()
                    subprocess.run([str(fast), str(desc), str(out)], check=True)
                    r["decode_fast_s"] = round(time.time() - t, 2)
                    r["exact_fast"] = sha(out) == want
            out.unlink(missing_ok=True)
            results["circuits"][name] = r
            print(json.dumps({name: r}), flush=True)
    ok = len(results["circuits"]) == len(selected) and all(v.get("exact_py", v.get("exact_fast")) and v.get("fast_agrees", True) for v in results["circuits"].values())
    results["all_exact"] = ok
    results["total_desc_bytes"] = sum(v["desc_bytes"] for v in results["circuits"].values())
    print(json.dumps({k: v for k, v in results.items() if k != "circuits"}))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
