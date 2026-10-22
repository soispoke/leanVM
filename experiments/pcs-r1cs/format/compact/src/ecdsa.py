# ecdsa-secp256k1 (circuit_suite/src/secp256k1.rs, Workload Ecdsa), over nonnative.py.
PM = (1 << 256) - (1 << 32) - 977
NM = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
BETA = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
LAM = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72

def powmod(b, e, m):
    r = 1
    for i in range(256):
        if (e >> (255 - i)) & 1:
            r = r * r * b % m
        else:
            r = r * r % m
    return r

def nat_add(a, b):
    l = (b[1] - a[1]) * powmod((b[0] - a[0]) % PM, PM - 2, PM) % PM
    x = (l * l - a[0] - b[0]) % PM
    return [x, (l * (a[0] - x) - a[1]) % PM]

def nat_double(a):
    l = 3 * a[0] * a[0] * powmod(2 * a[1] % PM, PM - 2, PM) % PM
    x = (l * l - 2 * a[0]) % PM
    return [x, (l * (a[0] - x) - a[1]) % PM]

def L(a, k):
    return [3, a, [], k]

def const_point(q):
    return [iconst(q[0]), iconst(q[1])]

def sub_p(a, b):
    mx = a[1] + PM
    acc = new_acc(blen(mx))
    aword(acc, a[0], 0, 0)
    aword(acc, b[0], 0, 1)
    konst(acc, PM)
    return [to_word(acc), mx]

def check_ne_p(d):
    CHECKS.append(eq_words(d[0], const_word(PM, len(d[0]))) ^ 1)

def cong(terms):
    CHECKS.append(congruence(PM, terms))

def ec_add(a, s1, b, s2):
    l = hint(256)
    x3 = residue_hint(PM)
    y3 = residue_hint(PM)
    dx = sub_p(b[0], a[0])
    check_ne_p(dx)
    cong([[0, l, dx, 0], L(b[1], -s2), L(a[1], s1)])
    cong([[2, l, [], 0], L(a[0], -1), L(b[0], -1), L(x3, -1)])
    d13 = sub_p(a[0], x3)
    cong([[0, l, d13, 0], L(y3, -1), L(a[1], -s1)])
    return [x3, y3]

def double_add(a, xt, ye, d):
    l1 = hint(256)
    x3 = residue_hint(PM)
    l2 = hint(256)
    x4 = residue_hint(PM)
    y4 = hint(256)
    dx = sub_p(xt, a[0])
    check_ne_p(dx)
    cong([[0, l1, dx, 0], [5, d, ye, -2], L(ye, 1), L(a[1], 1)])
    cong([[2, l1, [], 0], L(x3, -1), L(a[0], -1), L(xt, -1)])
    d3 = sub_p(x3, a[0])
    check_ne_p(d3)
    sl = nn_add(l1, l2)
    cong([[0, sl, d3, 0], L(a[1], 2)])
    cong([[2, l2, [], 0], L(x4, -1), L(x3, -1), L(a[0], -1)])
    d4 = sub_p(a[0], x4)
    cong([[0, l2, d4, 0], L(y4, -1), L(a[1], -1)])
    return [x4, y4]

def mux_word(s, a, b):
    out = []
    for i in range(len(a)):
        if a[i] == b[i]:
            out.append(a[i])
        else:
            out.append(xor(b[i], and2(s, xor(a[i], b[i]))))
    return out

def pick(table, diffs, sel, coord):
    lvl1 = []
    for k in range(4):
        lo = table[2 * k][coord][0]
        d = diffs[k][coord]
        lvl1.append([xor(lo[i], and2(sel[0], d[i])) for i in range(len(d))])
    l2a = mux_word(sel[1], lvl1[1], lvl1[0])
    l2b = mux_word(sel[1], lvl1[3], lvl1[2])
    return mux_word(sel[2], l2b, l2a)

z = hint(256)
r = hint(256)
s = hint(256)
qx = residue_hint(PM)
qy = residue_hint(PM)
for x in [r, s]:
    CHECKS.append(lt_const(x[0], NM))
    CHECKS.append(any_bits(x[0]))
w = residue_hint(NM)
CHECKS.append(congruence(NM, [[0, s, w, 0], [4, [], [], -1]]))
digits = []
OFF = (1 << 130) - 1
for u in [z, [r[0], NM - 1]]:
    b1 = hint(130)
    b2 = hint(130)
    CHECKS.append(congruence(NM, [L(b1, 2), L(b2, 2 * LAM), [4, [], [], -OFF * (1 + LAM)],
                                  [1, u, w, 0]]))
    digits.append(b1)
    digits.append(b2)
t = reduce_to(PM, [[2, qx, [], 0]], 0)
u = reduce_to(PM, [[0, t, qx, 0]], 0)
cong([[2, qy, [], 0], L(u, -1), [4, [], [], -7]])
bx = reduce_to(PM, [L(qx, BETA)], 1)
q = [qx, qy]
pq = [bx, qy]
v1 = ec_add(q, 1, pq, 1)
v2 = ec_add(q, 1, pq, -1)
G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8]
PG = [G[0] * BETA % PM, G[1]]
cs = [const_point(nat_add(G, [PG[0], PM - PG[1]])), const_point(nat_add(G, PG))]
table = []
for i in range(8):
    e3 = (i >> 1) & 1
    e4 = (i >> 2) & 1
    v = v1 if e3 == e4 else v2
    table.append(ec_add(cs[i & 1], 1, v, 1 if e3 else -1))
diffs = []
for k in range(4):
    diffs.append([[xor(table[2 * k][c][0][i], table[2 * k + 1][c][0][i]) for i in range(256)] for c in range(2)])
ox = 0x5a4ae046c7bdc84682537fb12f1a1a80a19c89dcba427f7c73bc7a537e48d148
oy = powmod((ox * ox * ox + 7) % PM, (PM + 1) // 4, PM)
if oy & 1:
    oy = PM - oy
acc = const_point([ox, oy])
for jj in range(130):
    j = 129 - jj
    b = [d[0][j] for d in digits]
    sel = [xor3(b[0], b[k + 1], 2) for k in range(3)]
    xt = [pick(table, diffs, sel, 0), PM - 1]
    ye = [pick(table, diffs, sel, 1), PM - 1]
    acc = double_add(acc, xt, ye, [[b[0]], 1])
end = [ox, oy]
for i in range(130):
    end = nat_double(end)
rpt = ec_add(acc, 1, const_point(end), -1)
rn = add_words(r[0], const_word(NM, 256))
e1 = eq_words(rpt[0][0], r[0])
e2 = eq_words(rpt[0][0], rn)
CHECKS.append(nfa(e1, e2, 2)[1])
valid = all_bits(CHECKS)
pub = [0 for i in range(512)]
for i in range(32):
    for bb in range(8):
        pub[8 * i + bb] = z[0][8 * (31 - i) + bb]
for i in range(31):
    for bb in range(8):
        pub[8 * (32 + i) + bb] = qx[0][8 * (30 - i) + bb]
pub[504] = valid
pub[505] = qy[0][0]
PUBLIC = finish(pub)
