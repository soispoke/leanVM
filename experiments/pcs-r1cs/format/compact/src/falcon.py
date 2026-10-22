# falcon512 (circuit_suite/src/falcon.rs), over ckt.py.
# globals used most, listed early so they get one-byte slots (never run)
if 0:
    PRE = [i, z, x, l, acc, j, y, k, a, p, u, v, t, s, w, b, cx, kk, mass, d, ln, dmax, KB, bits, out, fl, pay, m, best, dmin, f, shift, cpar, TB, TK, TF, valid, pmin, jj]
Q = 12289

def bitlen(x):
    n = 0
    for i in range(200):
        if x == 0:
            break
        x >>= 1
        n += 1
    return n

def norm(w):
    if w < 4:
        return 2 * cval(w)
    if w & 2 and (w >> 2) in TO_SUM:
        return 4 * TO_SUM[w >> 2] + (w & 1)
    return w

def fa_lit(a, b, d):
    ops = [norm(a), norm(b), norm(d)]
    nv = 0
    ng = 0
    for w in ops:
        if w > 3:
            nv += 1
            ng += w & 1
    f = 2 * ng > nv
    r = fa(ops[0] ^ f, ops[1] ^ f, ops[2] ^ f)
    return [r[0] ^ f, r[1] ^ f]

# A bit-kind literal as a carry-kind one (tb = 1) or the converse (tb = 0), one cached row.
def conv(w, tb):
    if w < 4 or (w >> 1) & 1 == tb:
        return w
    r = w >> 2
    m = [TO_SUM, TO_CARRY][tb]
    if r not in m:
        m[r] = flip_row(r) if tb else row(0, 0, r + 2)
    return 4 * m[r] + 2 * tb + (w & 1)

def reduce_column(bits, carries, one, top, nxt):
    for it in range(1 << 40):
        e = len(bits) + len(carries) + one
        if e < 2:
            return 2 * one if e == one else (bits + carries)[0]
        ops = []
        if e == 2:
            if one:
                ops = [2, (bits + carries)[0], 0]
            elif bits and carries:
                ops = [bits.pop(), carries.pop(), 0]
            elif bits:
                ops = [bits.pop(), bits.pop(), 0]
            else:
                ops = [conv(carries.pop(), 0), carries.pop(), 0]
        elif carries and len(bits) >= 2:
            ops = [bits.pop(), bits.pop(), carries.pop()]
        elif one and len(bits) >= 2:
            one = 0
            ops = [bits.pop(), bits.pop(), 2]
        elif one and len(bits) == 1 and carries:
            one = 0
            ops = [bits.pop(), 2, carries.pop()]
        elif not carries:
            carries.append(conv(bits.pop(), 1))
        else:
            bits.append(conv(carries.pop(), 0))
        if ops:
            r = fa_lit(ops[0], ops[1], ops[2])
            if not top:
                nxt.append(r[1])
            if e == 2:
                return r[0]
            bits.append(r[0])

def compress(cols, width):
    cols = cols[:width]
    f = [{}, {}]
    for col in cols:
        for w in col:
            w = norm(w)
            if w > 3 and (w | 1) not in POS:
                f[1 - (w & 1)][w] = 1
    neg = 1 if len(f[1]) < len(f[0]) else 0
    out = []
    carry_in = []
    ones_in = 0
    for k in range(width):
        top = k + 1 == width
        bits = []
        carries = []
        ones = ones_in
        for w in cols[k] + carry_in:
            w = norm(w)
            if w < 4:
                ones += cval(w)
            else:
                if w & 1 != neg:
                    w = positive(w ^ neg) ^ neg
                w = norm(w)
                [bits, carries][(w >> 1) & 1].append(w)
        ones_in = 0 if top else ones // 2
        nxt = []
        out.append(reduce_column(bits, carries, ones & 1, top, nxt))
        carry_in = nxt
    return out

# Acc = [cols, max, konst]
def acc_new():
    return [[], 0, 0]

def lit(acc, w, e, negative):
    if w < 4:
        acc[2] += cval(w) * (1 - 2 * negative) << e
    else:
        cols = acc[0]
        for i in range(e + 1 - len(cols)):
            cols.append([])
        cols[e].append(w ^ negative)
        acc[2] -= negative << e
        acc[1] += 1 << e

def acc_word(acc, x, shift, negative):
    for i in range(len(x)):
        lit(acc, x[i], i + shift, negative)

def acc_finish(acc, width):
    k = acc[2] % (1 << width)
    cols = acc[0]
    for i in range(width - len(cols)):
        cols.append([])
    for e in range(width):
        if (k >> e) & 1:
            cols[e].append(2)
    return compress(cols, width)

def geq_const(x, k):
    add = (1 << len(x)) - k
    carry = 0
    for i in range(len(x)):
        carry = fa_lit(x[i], 2 * ((add >> i) & 1), carry)[1]
    return carry

def any_lits(lits):
    o = -1
    a = -1
    for w in lits:
        w = norm(w)
        if w == 2:
            return 2
        if w > 3:
            if w & 1:
                a = w ^ 1 if a < 0 else and2(w ^ 1, a)
            else:
                o = w if o < 0 else or2(w, o)
    if o < 0:
        return 0 if a < 0 else a ^ 1
    if a < 0:
        return o
    return or2(o, a ^ 1)

def all_lits(lits):
    return any_lits([w ^ 1 for w in lits]) ^ 1

def mux(s, a, b):
    if a == b:
        return a
    return xor(b, and2(s, xor(a, b)))

# ---------------- lazy arithmetic modulo q
REPS = [{}, {}]

# The fewest (tight: the lightest) signed digits [exponent, negative] of r, r - q, r + q or r - 2q (NAF each).
def rep(r, tight):
    m = REPS[tight]
    if r not in m:
        bkey = 1 << 99
        for c in [r, r - Q, r + Q, r - 2 * Q]:
            n = abs(c)
            d = []
            e = 0
            mass = 0
            for it in range(80):
                if n == 0:
                    break
                if n & 1:
                    z = 2 - (n & 3)
                    n -= z
                    d.append([e, (z < 0) ^ (c < 0)])
                    mass += 1 << e
                n >>= 1
                e += 1
            key = ((1 - tight) * len(d) << 80) + mass * 1000 + len(d)
            if key < bkey:
                bkey = key
                m[r] = d
    return m[r]

# MV = [wires, coefs, k, max]
def mv_word(bits):
    return [bits, [1 << i for i in range(len(bits))], 0, (1 << len(bits)) - 1]

def lin_add(acc, x, coef, fold, tight):
    ws = x[0]
    cfs = x[1]
    for i in range(len(ws)):
        w = ws[i]
        cf = cfs[i]
        if (coef == 1 or coef == Q - 1) and cf & (cf - 1) == 0 and cf < 1 << fold:
            lit(acc, w, bitlen(cf) - 1, coef != 1)
        else:
            for dg in rep(coef * (cf % Q) % Q, tight):
                lit(acc, w, dg[0], dg[1])
    acc[2] += coef * (x[2] % Q) % Q

# coef_a a + coef_b b (b = [] for none) as a word modulo q, the constant riding along.
def lsum(a, ca, b, cb, fold):
    acc = acc_new()
    lin_add(acc, a, ca, fold, 0)
    if b:
        lin_add(acc, b, cb, fold, 0)
    mv = mv_word(acc_finish([acc[0], acc[1], 0], max(bitlen(acc[1]), 1)))
    mv[2] = acc[2] % Q
    mv[3] = acc[1]
    return mv

def signed_mv(sign, mag, negate):
    w = len(mag)
    ws = []
    cfs = []
    for i in range(w):
        ws.append(xor(mag[i], sign))
        cfs.append(Q - (1 << i) if negate else 1 << i)
    ws.append(sign)
    cfs.append((1 << w) - 1 if negate else Q + 1 - (1 << w))
    return [ws, cfs, 0, 0]

# ---------------- Keccak-f[1600] and SHAKE256
RC = []
R = 1
for i in range(24):
    v = 0
    for j in range(7):
        v |= (R & 1) << (1 << j) - 1
        R = (R << 1) ^ (R >> 7) * 0x171
    RC.append(v)
ROT = [0 for i in range(25)]
x = 1
y = 0
for i in range(24):
    ROT[x + 5 * y] = (i + 1) * (i + 2) // 2 % 64
    x, y = [y, (2 * x + 3 * y) % 5]

def chi_bit(a, b, d):
    if b < 4:
        return a if cval(b) else xor(a, d)
    if d < 4:
        return xor(a, b ^ 1) if cval(d) else a
    bn = b & 1
    dn = d & 1
    b &= -2
    d &= -2
    t = or2(b, d) if dn > bn else and2(b, d)
    if bn == dn:
        return xor3(a, [d, b][bn], t)
    return xor(a, t) ^ dn

PAIRS = {}
KB = []

def pair(i, y, z):
    key = (i * 5 + y) * 64 + z
    if key not in PAIRS:
        u = KB[i + 5 * y][z]
        kappa = 1 - (u & 1)
        PAIRS[key] = fa(u & -2, KB[(i + 1) % 5 + 5 * y][z] & -2, 2 * kappa) + [kappa]
    return PAIRS[key]

def theta_d(cpar):
    return [[xor(cpar[(x + 4) % 5][z], cpar[(x + 1) % 5][(z + 63) % 64]) for z in range(64)] for x in range(5)]

def sblock(bits, p):
    return [[bits[p * 1088 + l * 64 + z] if l < 17 and p * 1088 < len(bits) else 0 for z in range(64)] for l in range(25)]

H = [inputs(14) for i in range(512)]
MSG = inputs(256)
NONCE = inputs(320)
S2S = []
S2M = []
for i in range(512):
    S2S.append(inp())
    S2M.append(inputs(11))
S1S = []
S1M = []
for i in range(512):
    S1S.append(inp())
    S1M.append(inputs(13))

PK = [0 for i in range(897 * 8)]
PK[0] = 2
PK[3] = 2
for i in range(512):
    for j in range(14):
        s = 14 * i + 13 - j
        PK[8 * (1 + s // 8) + 7 - s % 8] = H[i][j]
OUTS = []
for SH in range(2):
    msg = [PK, NONCE][SH] + MSG
    out_len = [32, 1224][SH]
    mlen = len(msg) // 8
    total = (mlen // 136 + 1) * 136
    bits = msg
    for i in range(8 * (total - mlen)):
        bits.append(2 * ((0x1F >> i) & 1 ^ (i == 8 * (total - mlen) - 1)))
    blocks = total // 136
    squeezes = (out_len + 135) // 136
    perms = blocks + squeezes - 1
    state = sblock(bits, 0)
    out = []
    for p in range(perms):
        need = [p + 1 < perms or l < (out_len - (squeezes - 1) * 136 + 7) // 8 for l in range(25)]
        xin = []
        if p + 1 < blocks:
            xin = sblock(bits, p + 1)
        # keccak_f
        a = state
        cpar = []
        for x in range(5):
            cx = []
            for z in range(64):
                cx.append(xor(xor(xor(a[x][z], a[x + 5][z]), xor(a[x + 10][z], a[x + 15][z])), a[x + 20][z]))
            cpar.append(cx)
        d = theta_d(cpar)
        t = [[xor(a[l][z], d[l % 5][z]) for z in range(64)] for l in range(25)]
        for r in range(24):
            # rho, pi
            KB = [[] for l in range(25)]
            for x in range(5):
                for y in range(5):
                    tl = t[x + 5 * y]
                    if tl:
                        KB[y + 5 * ((2 * x + 3 * y) % 5)] = [tl[(z + 64 - ROT[x + 5 * y]) % 64] for z in range(64)]
            # chi, iota as terms TB ^ TK ^ TF: TB a bit-kind literal, TK a carry (or 0), TF a constant
            last = r == 23
            PAIRS = {}
            TB = [[] for l in range(25)]
            TK = [[] for l in range(25)]
            TF = [[] for l in range(25)]
            for y in range(5):
                for x in range(5):
                    l = x + 5 * y
                    if need[l] or not last:
                        for z in range(64):
                            a = KB[l][z]
                            b = KB[(x + 1) % 5 + 5 * y][z]
                            d = KB[(x + 2) % 5 + 5 * y][z]
                            if a < 4 or b < 4 or d < 4:
                                u = chi_bit(a, b, d)
                                k = 0
                                f = 0
                            else:
                                k = pair((x + 1) % 5, y, z)[1]
                                if b & 1 == d & 1:
                                    pr = pair(x, y, z)
                                    u = pr[0]
                                    f = pr[2] ^ (a & 1)
                                else:
                                    u = a & -2
                                    f = (a & 1) ^ ((d & 1) > (b & 1))
                            TB[l].append(u)
                            TK[l].append(k)
                            TF[l].append(f ^ (l == 0 and (RC[r] >> z) & 1))
            if last:
                state = []
                for l in range(25):
                    cx = []
                    if need[l]:
                        for z in range(64):
                            u = TB[l][z]
                            k = TK[l][z]
                            fl = TF[l][z]
                            if xin:
                                cx.append(xor3(u, xin[l][z], k) ^ fl)
                            elif (fl ^ (u & 1)) and k > 3:
                                cx.append(fa(u & -2, 2, k)[0])
                            else:
                                cx.append(xor(u, k) ^ fl)
                    state.append(cx)
            else:
                cpar = []
                for x in range(5):
                    cx = []
                    for z in range(64):
                        fl = TF[x][z]
                        u = TB[x][z]
                        for y in range(1, 5):
                            fl ^= TF[x + 5 * y][z]
                            u = xor3(u, TB[x + 5 * y][z], TK[x + 5 * y - 5][z])
                        cx.append(xor(u, TK[x + 20][z]) ^ fl)
                    cpar.append(cx)
                d = theta_d(cpar)
                t = [[xor3(TB[l][z], d[l % 5][z], TK[l][z]) ^ TF[l][z] for z in range(64)] for l in range(25)]
        if p + 1 >= blocks:
            for i in range(min(out_len * 8 - len(out), 1088)):
                out.append(state[i // 64][i % 64])
    OUTS.append(out)
out = OUTS[1]

# HashToPoint: sample tests and compaction
pay = []
reject = []
for i in range(612):
    pay.append([positive(out[(2 * i + 1) * 8 + j] if j < 8 else out[2 * i * 8 + j - 8]) for j in range(16)])
for smp in pay:
    reject.append(geq_const(smp, 61445))
valid = [positive(r ^ 1) for r in reject]
shift = []
rr = [0 for i in range(7)]
overflow = []
for rej in reject:
    shift.append(list(rr))
    carry = rej
    for i in range(7):
        s = fa_lit(rr[i], carry, 0)
        rr[i] = s[0]
        carry = s[1]
    overflow.append(carry)
lim = 612
for k in range(7):
    kk = 1 << k
    new_lim = min(612, 512 + 128 - (2 << k))
    src_lim = min(lim, new_lim + kk)
    m = [and2(valid[i], shift[i][k]) for i in range(src_lim)]
    npay = []
    nvalid = []
    nshift = []
    for p in range(new_lim):
        if p + kk < src_lim:
            s = m[p + kk]
            pa = pay[p + kk]
            pb = pay[p]
            npay.append([mux(s, pa[i], pb[i]) for i in range(16)])
            sa = shift[p + kk]
            sb = shift[p]
            nshift.append([0 if b <= k else mux(s, sa[b], sb[b]) for b in range(7)])
            nvalid.append(xor3(valid[p], s, m[p]))
        else:
            npay.append(pay[p])
            nshift.append(shift[p])
            nvalid.append(xor(valid[p], m[p]))
    pay = npay
    valid = nvalid
    shift = nshift
    lim = new_lim
all_valid = all_lits(valid[:512])
H2P_OK = and2(all_valid, any_lits(overflow) ^ 1)

# relation
OK = []
for hi in H:
    OK.append(geq_const(hi, Q) ^ 1)
for mg in S1M:
    OK.append(geq_const(mg, Q // 2 + 1) ^ 1)
D = []
for i in range(512):
    D.append(lsum(mv_word(pay[i]), 1, signed_mv(S1S[i], S1M[i], 1), 1, 16))
S2V = [signed_mv(S2S[i], S2M[i], 0) for i in range(512)]
# zetas: psi = 11^((q-1)/1024), psi^bitrev9(k)
PW = [1]
for i in range(6132):
    PW.append(PW[i] * 11 % Q)
ZT = []
for k in range(512):
    br = 0
    for i in range(9):
        br |= ((k >> i) & 1) << (8 - i)
    ZT.append(PW[12 * br])
FS = []
for SEL in range(3):
    a = [S2V, [mv_word(hi) for hi in H], D][SEL]
    k = 0
    ln = 256
    for layer in range(9):
        for st in range(256 // ln):
            k += 1
            for j in range(st * 2 * ln, st * 2 * ln + ln):
                t = lsum(a[j + ln], ZT[k], [], 0, 0)
                x = a[j]
                if len(x[0]) > 16 or x[3] == 0:
                    x = lsum(x, 1, [], 0, 16)
                a[j] = lsum(x, 1, t, 1, 64)
                a[j + ln] = lsum(x, 1, t, Q - 1, 64)
        ln //= 2
    if SEL < 2:
        # fold tightly into two's-complement words [bits, lo, hi]
        fo = []
        for v in a:
            acc = acc_new()
            lin_add(acc, v, 1, 13, 1)
            k = acc[2] % Q
            mass = acc[1]
            w = max(bitlen(mass), 1)
            for it in range(200):
                lo = -(1 << (w - 1))
                hi_k = (1 << (w - 1)) - 1 - mass
                kk = lo + (k - lo) % Q
                if kk <= hi_k:
                    best = kk
                    t = kk
                    for it2 in range(1 << 40):
                        if t > hi_k:
                            break
                        if abs(t + mass // 2) < abs(best + mass // 2):
                            best = t
                        t += Q
                    break
                w += 1
            acc[2] = best
            fo.append([acc_finish(acc, w), best, best + mass])
        FS.append(fo)

# pointwise checks
ZB = []
for i in range(512):
    x = FS[0][i]
    y = FS[1][i]
    z = a[i]
    xb = x[0]
    yb = y[0]
    wx = len(xb)
    wy = len(yb)
    zw = z[0]
    c0 = 2 * z[2]
    pmin = 1 << 200
    pmax = -pmin
    for u in x[1:]:
        for v in y[1:]:
            pmin = min(pmin, 2 * u * v)
            pmax = max(pmax, 2 * u * v)
    dmin = pmin - 2 * min((1 << len(zw)) - 1, z[3]) - c0
    dmax = pmax - c0
    kmin = dmin // Q
    k0 = -kmin
    bits = max(bitlen(dmax // Q + 1 - kmin), 1)
    kw = inputs(bits)
    acc = acc_new()
    for j in range(wx):
        for jj in range(wy):
            f = (j + 1 == wx) != (jj + 1 == wy)
            lit(acc, fa(xb[j] & -2, yb[jj] & -2, 2 * f)[0] ^ ((xb[j] ^ yb[jj]) & 1), j + jj, 1)
            acc[2] += f << (j + jj)
    for v in [xb, yb]:
        for j in range(len(v)):
            lit(acc, v[j], j, j + 1 != len(v))
    acc_word(acc, zw, 1, 1)
    acc[2] -= c0
    for b in range(bits):
        for e in [0, 12, 13]:
            lit(acc, kw[b], b + e, 1)
    acc[2] += k0 * Q
    ZB = ZB + acc_finish(acc, bitlen(max(abs(dmin), abs(dmax)) + Q * ((1 << bits) + abs(k0))) + 1)
OK.append(any_lits(ZB) ^ 1)
REL_OK = all_lits(OK)

# norm
acc = acc_new()
mx = 0
for g in [S1M, S2M]:
    w = len(g[0])
    lin = acc_new()
    for m in g:
        for i in range(w):
            for j in range(i + 1, w):
                lit(acc, xor(m[i], m[j]), i + j, 1)
        acc_word(lin, m, 0, 0)
    s = acc_finish(lin, bitlen(len(g) * ((1 << w) - 1)))
    acc_word(acc, s, w, 0)
    acc_word(acc, s, 0, 1)
    mx += len(g) * ((1 << w) - 1) * ((1 << w) - 1)
l = bitlen(mx)
acc[2] += (1 << l) - 34034726 - 1
NORM_OK = acc_finish(acc, l + 1)[l] ^ 1
# encoding length: sum floor(|s2_i| / 128) <= 392
acc = acc_new()
for mg in S2M:
    for i in range(7, 11):
        lit(acc, mg[i], i - 7, 0)
acc[2] += (1 << 13) - 393
LEN_OK = acc_finish(acc, 14)[13] ^ 1
PUBLIC = finish(OUTS[0] + [all_lits([H2P_OK, REL_OK, NORM_OK, LEN_OK])] + [0 for i in range(255)])
