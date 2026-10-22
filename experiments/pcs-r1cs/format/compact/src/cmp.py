"""Compare two rows files; report the first differing source."""
import sys, struct
a = open(sys.argv[1], 'rb').read(); b = open(sys.argv[2], 'rb').read()
print("header", a[:9] == b[:9], a[4], b[4], struct.unpack('<I', a[5:9]), struct.unpack('<I', b[5:9]), "len", len(a), len(b))
n = min(len(a), len(b))
if a[:n] == b[:n] and len(a) == len(b): print("IDENTICAL"); sys.exit()
i = next(i for i in range(9, n, 4) if a[i:i+4] != b[i:i+4]) if a[:n] != b[:n] else n
k = (i - 9) // 4
def src(d, k): return struct.unpack('<I', d[9+4*k:13+4*k])[0]
if k < 512: print("public bit", k, src(a,k), src(b,k))
else:
    r = 512 + (k - 512) // 3
    print("row", r, "slot", (k-512) % 3)
    for rr in range(max(512, r-3), r+3):
        kk = 512 + 3*(rr-512)
        print(rr, [src(a,kk+j) for j in range(3) if 13+4*(kk+j) <= len(a)], [src(b,kk+j) for j in range(3) if 13+4*(kk+j) <= len(b)])

sys.exit(1)
