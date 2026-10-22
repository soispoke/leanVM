"""Run a generator source natively, comparing every row with a reference .rows file as it is made (streaming,
for circuits too large to hold): python3 run_check.py REF.rows SRC...  Stops at the first difference."""
import struct, sys
ref = open(sys.argv[1], 'rb')
hdr = ref.read(9)
used = struct.unpack('<I', hdr[5:9])[0]
refpub = struct.unpack('<512I', ref.read(2048))
n = [512]
buf = [b'', 0]
def row(x, y, c):
    r = n[0]
    if buf[1] >= len(buf[0]):
        buf[0] = ref.read(12 << 20); buf[1] = 0
    want = struct.unpack_from('<3I', buf[0], buf[1]); buf[1] += 12
    if (x, y, c) != want:
        raise SystemExit(f"row {r}: got {(x, y, c)} want {want}")
    n[0] += 1
    if n[0] % 10000000 == 0: print("rows ok", n[0], flush=True)
    return r
def N():
    return n[0]
g = {"row": row, "N": N}
src = "\n".join(open(f).read() for f in sys.argv[2:])
exec(compile(src, "gen", "exec"), g)
pub = tuple(g["PUBLIC"])
print("rows", n[0], "of", used, "public", "OK" if pub == refpub else "DIFFER", "log", hdr[4])

assert n[0] == used and pub == refpub, "incomplete rows or different public sources"
assert buf[1] == len(buf[0]) and ref.read(1) == b"", "trailing reference rows"
