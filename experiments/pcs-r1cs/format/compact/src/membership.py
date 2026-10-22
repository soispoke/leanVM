# membership (flock/src/quotient/circuit.rs): Builder level, sources are codes (0, 1, 2 + r).
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PIV = [IV[0] ^ 0x01010020] + IV[1:]
SIG = 0xdc3e9bf5167482a5a417d2c803b9ef6a2684f05931ce7bdb8293670a4def15c91ef57d438b0a6c2d386cb1efa4275098f04a562ebcd1397491763eadf250c8b357b20c16df984aefedcba9876543210

def R(x, y, c):
    return row(x, y, c) + 2

def inp():
    r = N()
    row(r + 2, 0, 0)
    return r + 2

CO = 0

def carry_one():
    global CO
    if CO == 0:
        CO = R(1, 1, 0)
    return CO

def add(x, y):
    out = []
    cy = 0
    for i in range(32):
        cy = R(x[i], y[i], cy)
        out.append(cy)
    return out

def const(w):
    return [(w >> i) & 1 for i in range(32)]

def mixrot(p, q, by):
    m = [R(p[i], q[i], 0) for i in range(32)]
    return [m[(i + by) % 32] for i in range(32)]

def compress(m):
    v = [const(w) for w in PIV + IV]
    v[12] = const(IV[4] ^ 64)
    v[14] = const(IV[6] ^ 0xFFFFFFFF)
    for r in range(10):
        for g in range(8):
            h = g // 4
            a = g % 4
            b = 4 + (g + h) % 4
            c = 8 + (g + 2 * h) % 4
            d = 12 + (g + 3 * h) % 4
            for half in range(2):
                w = (SIG >> (4 * (16 * r + 2 * g + half))) & 15
                s = add(v[a], v[b])
                v[a] = add(s, m[32 * w:32 * w + 32])
                v[d] = mixrot(v[d], v[a], 16 - 8 * half)
                v[c] = add(v[c], v[d])
                v[b] = mixrot(v[b], v[c], 12 - 5 * half)
    out = []
    for k in range(8):
        for i in range(32):
            cy = 0
            if (PIV[k] >> i) & 1:
                cy = carry_one()
            out.append(R(v[k][i], v[k + 8][i], cy))
    return out

x = [inp() for i in range(256)]
y = compress(x + [(0x11 >> (i % 8)) & 1 for i in range(256)])
node = compress(x + [(0x22 >> (i % 8)) & 1 for i in range(256)])
for lvl in range(32):
    sib = [inp() for i in range(256)]
    dirn = inp()
    left = []
    right = []
    for i in range(256):
        swap = R(dirn, R(node[i], sib[i], 0), 0)
        left.append(R(node[i], 0, swap))
        right.append(R(sib[i], 0, swap))
    node = compress(left + right)
PUBLIC = [R(w, 0, 0) for w in y] + [R(w, 0, 0) for w in node]
