# blake2s-1kib (circuit_suite/src/blake2s.rs)
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SIG = 0xdc3e9bf5167482a5a417d2c803b9ef6a2684f05931ce7bdb8293670a4def15c91ef57d438b0a6c2d386cb1efa4275098f04a562ebcd1397491763eadf250c8b357b20c16df984aefedcba9876543210

def word(w):
    return [2 * ((w >> i) & 1) for i in range(32)]

def add(x, y):
    out = []
    cy = 0
    for i in range(32):
        s = fa(x[i], y[i], cy)
        cy = s[1]
        out.append(s[0])
    return out

def xorrot(p, q, by):
    m = [xor(p[i], q[i]) for i in range(32)]
    return [m[(i + by) % 32] for i in range(32)]

def compress(h, m, t, last):
    v = h + [word(w) for w in IV]
    v[12] = word(IV[4] ^ t)
    if last:
        v[14] = word(IV[6] ^ 0xFFFFFFFF)
    for r in range(10):
        for g in range(8):
            q = g // 4
            a = g % 4
            b = 4 + (g + q) % 4
            c = 8 + (g + 2 * q) % 4
            d = 12 + (g + 3 * q) % 4
            for half in range(2):
                w = (SIG >> (4 * (16 * r + 2 * g + half))) & 15
                s = add(v[a], v[b])
                v[a] = add(s, m[w])
                v[d] = xorrot(v[d], v[a], 16 - 8 * half)
                v[c] = add(v[c], v[d])
                v[b] = xorrot(v[b], v[c], 12 - 5 * half)
    return [[xor3(h[i][j], v[i][j], v[i + 8][j]) for j in range(32)] for i in range(8)]

msg = inputs(8192)
H = [word(w) for w in IV]
H[0] = word(IV[0] ^ 0x01010020)
for k in range(16):
    H = compress(H, [msg[512 * k + 32 * i:512 * k + 32 * i + 32] for i in range(16)], 64 * k + 64, k == 15)
digest = []
for i in range(8):
    digest = digest + H[i]
PUBLIC = finish(digest + [0 for i in range(256)])
