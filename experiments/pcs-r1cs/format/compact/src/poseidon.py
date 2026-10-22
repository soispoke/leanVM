# poseidon-bn254 (circuit_suite/src/poseidon.rs, Workload PoseidonSponge<1024>), over nonnative.py. The constants of
# circomlib's optimised form are derived here: the Grain LFSR round constants and Cauchy MDS matrix of the reference
# (hadeshash), the sparse partial-round matrices, and the round constants moved back past the partial rounds.
R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

def rinv(a):
    e = R - 2
    x = 1
    for i in range(254):
        x = x * x % R
        if (e >> (253 - i)) & 1:
            x = x * a % R
    return x

def grain_bit():
    global GST
    b = ((GST >> 62) ^ (GST >> 51) ^ (GST >> 38) ^ (GST >> 23) ^ (GST >> 13) ^ GST) & 1
    GST = (GST >> 1) | (b << 79)
    return b

def grain_raw():
    v = 0
    n = 0
    for jt in range(10000):
        if n == 254:
            break
        if grain_bit():
            v = 2 * v + grain_bit()
            n += 1
        else:
            grain_bit()
    return v

def grain_const():
    for it in range(100):
        v = grain_raw()
        if v < R:
            return v
    return 0

def mv3(a, v):
    return [(a[i][0] * v[0] + a[i][1] * v[1] + a[i][2] * v[2]) % R for i in range(3)]

def mm3(a, b):
    return [[(a[i][0] * b[0][j] + a[i][1] * b[1][j] + a[i][2] * b[2][j]) % R for j in range(3)] for i in range(3)]

GST = 1208925819174894048508930
for i in range(160):
    grain_bit()
CR = [[grain_const() for j in range(3)] for i in range(65)]
XS = [grain_raw() for i in range(6)]
MD = [[rinv(XS[i] + XS[3 + j]) for j in range(3)] for i in range(3)]
MT = [[MD[j][i] for j in range(3)] for i in range(3)]
DET = 0
MI = []
for i in range(3):
    row_ = []
    for j in range(3):
        a1 = (j + 1) % 3
        a2 = (j + 2) % 3
        b1 = (i + 1) % 3
        b2 = (i + 2) % 3
        row_.append(MD[a1][b1] * MD[a2][b2] - MD[a1][b2] * MD[a2][b1])
    MI.append(row_)
for j in range(3):
    DET += MD[0][j] * MI[j][0]
DI = rinv(DET % R)
MI = [[MI[i][j] * DI % R for j in range(3)] for i in range(3)]
# The sparse matrices, last partial round first.
MMUL = MT
VS = []
WS = []
for i in range(57):
    a = MMUL[1][1]
    b = MMUL[1][2]
    c = MMUL[2][1]
    d = MMUL[2][2]
    di = rinv((a * d - b * c) % R)
    w1 = MMUL[1][0]
    w2 = MMUL[2][0]
    VS.append([MMUL[0][1], MMUL[0][2]])
    WS.append([(d * w1 - b * w2) * di % R, (a * w2 - c * w1) * di % R])
    MMUL = mm3(MT, [[1, 0, 0], [0, a, b], [0, c, d]])
OPT_S = []
for r in range(57):
    OPT_S = OPT_S + [MT[0][0]] + WS[56 - r] + VS[56 - r]
KS = [0 for i in range(57)]
for ii in range(57):
    i = 60 - ii
    u = mv3(MI, CR[i + 1])
    KS[i - 4] = u[0]
    CR[i] = [CR[i][0], (CR[i][1] + u[1]) % R, (CR[i][2] + u[2]) % R]
OPT_C = CR[0] + mv3(MI, CR[1]) + mv3(MI, CR[2]) + mv3(MI, CR[3]) + mv3(MI, CR[4]) + KS + mv3(MI, CR[62]) + \
    mv3(MI, CR[63]) + mv3(MI, CR[64])
OPT_M = MT
OPT_P = MMUL

# A linear form: [terms ([id, coefficient] lists), constant].
def comb(parts, k):
    terms = []
    kk = k % R
    for pt in parts:
        c = pt[0]
        f = pt[1]
        for t in f[0]:
            a = c * t[1] % R
            found = 0
            for o in terms:
                if o[0] == t[0]:
                    o[1] = (o[1] + a) % R
                    found = 1
                    break
            if not found:
                terms.append([t[0], a])
        kk = (kk + c * f[1]) % R
    out = []
    for o in terms:
        if o[1] != 0:
            out.append(o)
    return [out, kk]

def lvar(i):
    return [[[i, 1]], 0]

INTS = []

def add_int(x):
    INTS.append(x)
    return len(INTS) - 1

def materialise(f, canonical):
    terms = f[0]
    k = f[1]
    if not terms:
        return add_int(iconst(k))
    if not canonical and len(terms) == 1 and terms[0][1] == 1:
        x = INTS[terms[0][0]]
        if k == 0:
            return terms[0][0]
        mx = x[1] + k
        return add_int([add_words(x[0], const_word(k, blen(k)))[:blen(mx)], mx])
    ts = []
    for t in terms:
        c = t[1]
        if len(wnaf(c - R, 2)) < len(wnaf(c, 2)):
            c = c - R
        ts.append([3, INTS[t[0]], [], c])
    ts.append([4, [], [], k])
    return add_int(reduce_to(R, ts, canonical))

def pow5(x):
    xi = INTS[x]
    v = xi[1]
    if nvars(xi[0]) == 0:
        return add_int(iconst(v * v % R * v % R * v % R * v % R))
    t = reduce_to(R, [[2, xi, [], 0]], 0)
    u = reduce_to(R, [[2, t, [], 0]], 0)
    return add_int(reduce_to(R, [[0, u, xi, 0]], 0))

def full(s, c, mat):
    y = []
    for i in range(3):
        x = materialise(s[i], 0)
        yy = pow5(x)
        y.append(comb([[1, lvar(yy)]], OPT_C[c + i] if c >= 0 else 0))
    for i in range(3):
        s[i] = comb([[mat[0][i], y[0]], [mat[1][i], y[1]], [mat[2][i], y[2]]], 0)

def partial(s, rnd):
    x = materialise(s[0], 0)
    y = comb([[1, lvar(pow5(x))]], OPT_C[15 + rnd])
    sp = OPT_S[5 * rnd:5 * rnd + 5]
    s0 = comb([[sp[0], y], [sp[1], s[1]], [sp[2], s[2]]], 0)
    for k in range(1, 3):
        s[k] = comb([[1, s[k]], [sp[2 + k], y]], 0)
        if len(s[k][0]) > 2:
            s[k] = lvar(materialise(s[k], 0))
    s[0] = s0

def permute(s):
    for i in range(3):
        s[i] = comb([[1, s[i]]], OPT_C[i])
    for rnd in range(3):
        full(s, (rnd + 1) * 3, OPT_M)
    full(s, 12, OPT_P)
    for rnd in range(57):
        partial(s, rnd)
    for rnd in range(3):
        full(s, 72 + rnd * 3, OPT_M)
    full(s, -1, OPT_M)

WIRES = inputs(8192)
ELEMS = []
for ci in range(34):
    st = 31 * ci
    nb = min(31, 1024 - st)
    w = [0 for i in range(8 * nb)]
    for o in range(nb):
        for j in range(8):
            w[8 * (nb - 1 - o) + j] = WIRES[8 * (st + o) + j]
    ELEMS.append(add_int([w, (1 << (8 * nb)) - 1]))
S = [[[], 0], [[], 0], [[], 0]]
for pi in range(17):
    S[1] = comb([[1, S[1]], [1, lvar(ELEMS[2 * pi])]], 0)
    S[2] = comb([[1, S[2]], [1, lvar(ELEMS[2 * pi + 1])]], 0)
    permute(S)
H = INTS[materialise(S[0], 1)][0]
valid = all_bits(CHECKS)
pub = [0 for i in range(512)]
for i in range(32):
    for j in range(8):
        b = 8 * (31 - i) + j
        pub[8 * i + j] = H[b] if b < len(H) else 0
pub[256] = valid
PUBLIC = finish(pub)
