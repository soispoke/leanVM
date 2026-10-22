# mpt-storage-proof (circuit_suite/src/mpt.rs, Params::MAINNET, Keccak). Needs ckt.py, keccak_tables.py,
# keccak.py, mpt_tables.py. Bytes are lists of 8 wires, low bit first. Gadgets of lib.rs/mpt.rs specialised to
# the arguments they get here (mulk only by 32: a shift, no rows; lek's k always fits a's width).
PERM = 0

def bitlen(v):
    for i in range(64):
        if v >> i == 0:
            return i

def kword(k, n):
    return [2 * ((k >> i) & 1) for i in range(n)]

def zext(w, n):
    return (w + [0 for i in range(n)])[0:n]

def addc(x, y, cy):
    out = []
    for i in range(len(x)):
        sc = fa(x[i], y[i], cy)
        cy = sc[1]
        out.append(sc[0])
    return [out, cy]

def addw(a, b, n):
    return addc(zext(a, n), zext(b, n), 0)[0]

def addk(a, k, n):
    return addw(a, kword(k, n), n)

def subw(x, y):
    return addc(x, [w ^ 1 for w in y], 2)

def anyw(x):
    if len(x) == 0:
        return 0
    for it in range(12):
        if len(x) < 2:
            break
        nx = [or2(x[2 * i], x[2 * i + 1]) for i in range(len(x) // 2)]
        if len(x) % 2:
            nx.append(x[len(x) - 1])
        x = nx
    return x[0]

def allw(x):
    return anyw([w ^ 1 for w in x]) ^ 1

def mux(s, a, b):
    if a == b:
        return a
    return xor(b, and2(s, xor(a, b)))

def muxw(s, a, b):
    n = max(len(a), len(b))
    a = zext(a, n)
    b = zext(b, n)
    return [mux(s, a[i], b[i]) for i in range(n)]

def eqk(a, k):
    return allw([a[i] ^ ((k >> i) & 1) ^ 1 for i in range(len(a))])

def eqw(a, b):
    n = max(len(a), len(b))
    a = zext(a, n)
    b = zext(b, n)
    return anyw([xor(a[i], b[i]) for i in range(n)]) ^ 1

def lek(a, k):
    return subw(kword(k, len(a)), a)[1]

def popcount(bits):
    st = []
    for i in range(len(bits)):
        st.append([bits[i]])
        for t in range(5):
            if (i + 1) >> t & 1:
                break
            b = st.pop()
            a = st.pop()
            st.append(addw(a, b, len(a) + 1))
    return st[0]

def therm(v, n):
    k = len(v)
    ns = [n]
    for i in range(k):
        ns.append(min(ns[i], 1 << (k - i - 1)))
    low = [0 for j in range(ns[k])]
    for i in range(k):
        half = 1 << i
        out = []
        for j in range(ns[k - i - 1]):
            if j < half:
                out.append(or2(v[i], low[j]))
            elif j < 2 * half:
                out.append(and2(v[i], low[j - half]))
            else:
                out.append(0)
        low = out
    return low

def shift_elems(data, off, max_off, width):
    zero = [0 for j in range(len(data[0]))]
    nbits = bitlen(max_off)
    cur = data[0:max_off + width]
    for bb in range(nbits):
        b = nbits - 1 - bb
        sh = 1 << b
        s = off[b] if b < len(off) else 0
        cur = cur + [zero for i in range(2 * sh + width)]
        cur = [[mux(s, cur[i + sh][j], cur[i][j]) for j in range(len(zero))] for i in range(width + min(max_off, sh - 1))]
    return (cur + [zero for i in range(width)])[0:width]

def nibbles_of(bs):
    out = []
    for b in bs:
        out = out + [b[4:8], b[0:4]]
    return out

def byte_bits(bs):
    out = []
    for b in bs:
        out = out + b
    return out

def ibytes(n):
    return [inputs(8) for i in range(n)]

# ------------------------------------------------------------------ keccak sponge
def sponge(blocks, against):
    # against != []: the digest diff after every block (sponge_diff); else the final digest bits (sponge)
    global PERM
    lanes = [[[], [], 0] for i in range(1600)]
    outs = []
    for bi in range(len(blocks)):
        for i in range(1088):
            lpush(lanes[i], blocks[bi][i])
        parity = parity_chain(lanes)
        final = bi + 1 == len(blocks)
        for r in range(24):
            tab = r - 1
            if final and r == 23:
                tab = 23
            elif PERM < 2 and r > 0:
                tab = 23 + 22 * PERM + r
            st = kround(lanes, parity, RC[r], final and r == 23, r < 23, tab)
            lanes = st[0]
            parity = st[1]
        PERM += 1
        if against:
            outs.append([reduce(plus(lanes[j], against[j]), -1) for j in range(256)])
    if not against:
        for j in range(256):
            outs.append(reduce(lanes[j], -1))
    return outs

def kfixed(bs):
    msg = byte_bits(bs)
    nb = len(msg) // 1088 + 1
    bits = msg + [0 for i in range(nb * 1088 - len(msg))]
    bits[len(msg)] = 2
    bits[nb * 1088 - 1] = 2
    d = sponge([bits[1088 * i:1088 * i + 1088] for i in range(nb)], [])
    return [d[8 * i:8 * i + 8] for i in range(32)]

def kcheck(bs, ln, expect):
    n = len(bs)
    nb = n // 136 + 1
    total = 136 * nb
    th = therm(ln[0:bitlen(total)], total)
    msg = []
    for j in range(total):
        for b in range(8):
            d = bs[j][b] if j < n else 0
            msg.append(d if j < 32 else and2(d, th[j]))
        if j >= 32:
            msg[8 * j] = xor(msg[8 * j], xor(th[j - 1], th[j]))
    sel = []
    for b in range(1, nb + 1):
        s = xor(th[136 * (b - 1) - 1] if b > 1 else 2, th[136 * b - 1])
        at = 1088 * b - 1
        msg[at] = xor(msg[at], s)
        sel.append(s)
    diffs = sponge([msg[1088 * i:1088 * i + 1088] for i in range(nb)], byte_bits(expect))
    return and2(anyw([and2(sel[i], anyw(diffs[i]) ^ 1) for i in range(nb)]), th[31])

# ------------------------------------------------------------------ slots
def big3(b):
    return and2(and2(b[5], b[4]), b[3])

def hdr_ok(b, f):
    g = big3(b)
    return and2(and2(b[7], b[6] ^ f), g ^ 1)

def two_item(node, hl2, single, key_sh):
    lw = bitlen(len(node) + 320)
    b0 = node[0]
    so = hdr_ok(b0, 0)
    ok = mux(hl2, eqk(b0, 0xf8), so)
    hl = [hl2 ^ 1, hl2]
    ln = addw(hl, muxw(hl2, node[1], b0[0:6]), lw)
    pb = [mux(hl2, node[2][i], node[1][i]) for i in range(8)]
    plen = pb[0:6]
    nz = anyw(plen)
    pbig = big3(pb)
    ns_ok = and2(and2(and2(pb[7], pb[6] ^ 1), nz), pbig ^ 1)
    ok = and2(ok, mux(single, pb[7] ^ 1, ns_ok))
    plen_eff = muxw(single, kword(1, 6), plen)
    f = []
    for i in range(8):
        a = mux(single, node[2][i], node[3][i])
        f.append(mux(hl2, a, mux(single, node[1][i], node[2][i])))
    ok = and2(ok, or2(f[7], f[6]) ^ 1)
    odd = f[4]
    nn = [odd] + subw(plen_eff, kword(1, 6))[0]
    pl = [and2(w, single ^ 1) for w in plen]
    q = addw(addk(hl, 1, 3), pl, lw)
    ns = single ^ 1
    s_off = [odd ^ 1, xor(hl2, ns)]
    s_off.append(and2(hl2, ns))
    path = shift_elems(nibbles_of(node)[3:72], s_off, 5, 64)
    mask = therm(nn, 64)
    mism = [and2(anyw([xor(path[i][b], key_sh[i][b]) for b in range(4)]), mask[i]) for i in range(64)]
    return [ok, ln, f[5], nn, anyw(mism) ^ 1, q]

def inner_slot(s, key_sh, n):
    node = s[0]
    is_branch = s[2]
    occ = s[3]
    pay = addk(zext([0, 0, 0, 0, 0] + popcount(occ), 10), 17, 10)
    hl1 = lek(pay, 55)
    hl3 = anyw(pay[8:])
    hlsel = [0, hl1, or2(hl1, hl3) ^ 1, hl3]
    hl = addk(addw([hl1 ^ 1], [hl3], 2), 1, 2)
    ln = addw(hl, pay, 10)
    e1 = eqw(node[0], pay[0:6] + [2, 2])
    e2 = and2(eqk(node[0], 0xf8), eqw(node[1], zext(pay, 8)))
    a = eqk(node[0], 0xf9)
    b = eqw(node[1], zext(pay[8:], 8))
    d = eqw(node[2], zext(pay, 8))
    e3 = and2(and2(a, b), d)
    h1 = and2(hl1, e1)
    h2 = and2(hlsel[2], e2)
    hdr = anyw([h1, h2, and2(hl3, e3)])
    e = [2]
    items = []
    for j in range(17):
        acc = []
        for hlv in range(2, 4):
            for m in range(min(9 * hlv - 11, j) + 1):
                at = hlv + j + 32 * m
                if at < 532:
                    bt = node[at]
                    lits = [bt[i] ^ (i != 7) for i in range(8)]
                    if j < 16:
                        lits[5] = xor(bt[5], occ[j]) ^ 1
                    eqb = allw(lits)
                    acc.append(and2(and2(hlsel[hlv], e[m]), eqb))
        items.append(anyw(acc))
        if j < 16:
            ee = [0] + e + [0]
            e = [mux(occ[j], ee[m], ee[m + 1]) for m in range(len(e) + 1)]
    items_ok = allw(items)
    kk = key_sh[0]
    occ_k = shift_elems([[occ[i]] for i in range(16)], kk, 15, 1)[0][0]
    below = therm(kk, 16)
    hm = zext([0, 0, 0, 0, 0] + popcount([and2(occ[i], below[i]) for i in range(16)]), 10)
    pk = addw(addw(hl, kk, 10), hm, 10)
    b_ok = allw([hdr, items_ok, occ_k, subw(n, kword(64, 8))[1] ^ 1])
    t2 = two_item(node, s[4], s[5], key_sh)
    q = t2[5]
    o = muxw(is_branch, pk, q)
    ln = muxw(is_branch, ln, t2[1])
    consumed = muxw(is_branch, kword(1, 8), zext(t2[3], 8))
    win = shift_elems(node, o, 498, 33)
    hdr = eqk(win[0], 0xa0)
    fills = eqw(addk(q, 33, 10), t2[1])
    fits = lek(addw(n, t2[3], 9), 64)
    ok = mux(is_branch, b_ok, allw([t2[0], t2[2] ^ 1, t2[4], hdr, fills, fits]))
    return [and2(ok, lek(ln, 532)), ln, win[1:], consumed]

def leaf_slot(s, account, key_sh, n):
    node = s[0]
    vform = s[3]
    big_n = len(node)
    lw = bitlen(big_n + 320)
    t2 = two_item(node, s[1], s[2], key_sh)
    q = t2[5]
    w2 = shift_elems(node, q, 58, 2)
    ends = eqk(addw(n, t2[3], 9), 64)
    vlen = []
    if account:
        item_ok = mux(vform, eqk(w2[0], 0xb8), hdr_ok(w2[0], 1))
        e_long = addw(addk(q, 2, lw), w2[1], lw)
        end = muxw(vform, e_long, addw(addk(q, 1, lw), w2[0][0:6], lw))
    else:
        vl = w2[1][0:6]
        nz = anyw(vl)
        le = lek(vl, 32)
        nested = eqw(w2[0], addk(w2[1], 1, 8))
        item_ok = mux(vform, w2[0][7] ^ 1, allw([w2[1][7], w2[1][6] ^ 1, nz, le, nested]))
        e_single = addk(q, 1, lw)
        end = muxw(vform, e_single, addw(addk(q, 2, lw), vl, lw))
        vlen = muxw(vform, kword(1, 6), vl)
    fills = eqw(end, t2[1])
    ok = allw([t2[0], t2[2], t2[4], ends, item_ok, fills, lek(t2[1], big_n)])
    from_min = subw(t2[1], kword(32, len(t2[1])))[0]
    zb = [0 for i in range(8)]
    out = shift_elems(([zb for i in range(65 - 33 * (1 - account))] + node)[32:], from_min, big_n - 32, 32)
    if not account:
        keep = therm(vlen, 32)
        out = [[and2(out[i][b], keep[31 - i]) for b in range(8)] for i in range(32)]
    return [ok, t2[1], out]

def walk(root, key, inner, leaf, account):
    key_nibs = nibbles_of(key)
    h = root
    n = kword(0, 8)
    valid = 2
    prev = 0
    for s in inner:
        o = inner_slot(s, shift_elems(key_nibs, n, 64, 64), n)
        good = and2(o[0], kcheck(s[0], o[1], h))
        act = s[1]
        v1 = or2(act ^ 1, good)
        valid = allw([valid, v1, or2(prev ^ 1, act)])
        prev = act
        h = [muxw(act, o[2][i], h[i]) for i in range(32)]
        n = muxw(act, addw(n, o[3], 8), n)
    o = leaf_slot(leaf, account, shift_elems(key_nibs, n, 64, 64), n)
    return [allw([valid, o[0], kcheck(leaf[0], o[1], h)]), o[2]]

def inner_in():
    return [ibytes(532), inp(), inp(), inputs(16), inp(), inp()]

ROOT = ibytes(32)
ADDR = ibytes(20)
SLOT = ibytes(32)
AIN = [inner_in() for i in range(8)]
ALEAF = [ibytes(148), inp(), inp(), inp()]
SIN = [inner_in() for i in range(6)]
SLEAF = [ibytes(70), inp(), inp(), inp()]
AKEY = kfixed(ADDR)
SKEY = kfixed(SLOT)
VA = walk(ROOT, AKEY, AIN, ALEAF, 1)
VS = walk(VA[1], SKEY, SIN, SLEAF, 0)
VALID = and2(VA[0], VS[0])
PUBLIC = finish(byte_bits(kfixed(ROOT + ADDR + SLOT + VS[1])) + [VALID] + [0 for i in range(255)])
