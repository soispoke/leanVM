"""Run a generator source natively (as Python) and write its rows: python3 run.py OUT.rows LOG_ROWS SRC..."""
import struct, sys
out = []
def row(x, y, c):
    out.extend((x, y, c))
    return 511 + len(out) // 3
def N():
    return 512 + len(out) // 3
g = {"row": row, "N": N}
src = "\n".join(open(f).read() for f in sys.argv[3:])
exec(compile(src, "gen", "exec"), g)
pub = g["PUBLIC"]
assert len(pub) == 512
open(sys.argv[1], "wb").write(b"ROWS" + bytes([int(sys.argv[2])]) + struct.pack(f"<I{512 + len(out)}I", 512 + len(out) // 3, *pub, *out))
