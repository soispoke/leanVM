# keccak256-1kib (circuit_suite/src/keccak.rs). A Lin is [bits, carries, neg]. The annealed chi patterns are
# the table PAT: table t, row r, digit 2 bad + comp in base 10.
RC = []
for rc_i in range(24):
    rc_v = 0
    for rc_j in range(7):
        rc_r = 1
        for rc_k in range((rc_j + 7 * rc_i) % 255):
            rc_r = rc_r << 1
            if rc_r & 256:
                rc_r = rc_r ^ 0x171
        rc_v = rc_v | (rc_r & 1) << ((1 << rc_j) - 1)
    RC.append(rc_v)
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]

def lpush(l, w):
    if w < 4:
        l[2] ^= cval(w)
    else:
        l[2] ^= w & 1
        if w & 2:
            l[1].append(w & -2)
        else:
            l[0].append(w & -2)

def lof(w):
    l = [[], [], 0]
    lpush(l, w)
    return l

def plus(l, w):
    m = [list(l[0]), list(l[1]), l[2]]
    lpush(m, w)
    return m

def plan(b, k):
    rows = []
    for it in range(b + k):
        if b + k <= 1:
            break
        c = 0
        if k > 0:
            c = 1
            k -= 1
        taken = 0
        for s in range(2):
            if b + k > 0:
                if b > 0:
                    b -= 1
                else:
                    k -= 1
                taken += 1
        rows.append(c == 0 or taken < 2)
        b += 1
    return rows

def reduce(l, want):
    bits = list(l[0])
    carries = list(l[1])
    neg = l[2]
    if len(bits) + len(carries) == 0:
        return 2 * neg
    rows = plan(len(bits), len(carries))
    if len(rows) == 0:
        if bits:
            return bits.pop() ^ neg
        return carries.pop() ^ neg
    last = -1
    for i in range(len(rows)):
        if rows[i]:
            last = i
    one = 0
    if want >= 0 and last >= 0:
        one = want ^ neg
    out = 0
    for i in range(len(rows)):
        k = -1
        if carries:
            k = carries.pop()
        ops = []
        for s in range(2):
            if bits:
                ops.append(bits.pop())
            elif carries:
                ops.append(carries.pop())
        if rows[i] and i == last and one:
            ops.append(2)
        if k >= 0:
            ops.append(k)
        for s in range(3 - len(ops)):
            ops.append(0)
        out = fa(ops[0], ops[1], ops[2])[0]
        bits.append(out)
    return out ^ neg ^ one

def simple(l):
    return len(l[0]) <= 1 and len(l[1]) <= 1

def parity_chain(lanes):
    for l in lanes:
        for it in range(len(l[1])):
            if len(l[1]) <= 1:
                break
            kc = l[1].pop()
            if l[0]:
                x = l[0].pop()
            else:
                x = l[1].pop()
            y = 0
            if l[0]:
                y = l[0].pop()
            l[0].append(fa(x, y, kc)[0])
    out = []
    for x in range(5):
        for z in range(64):
            start = 64 * x + z
            for y in range(5):
                i = 64 * (x + 5 * (4 - y)) + z
                if not simple(lanes[i]):
                    start = i
            s = reduce(lanes[start], -1)
            lanes[start] = lof(s)
            p = s
            for y in range(5):
                i = 64 * (x + 5 * y) + z
                if i != start:
                    if not simple(lanes[i]):
                        lanes[i] = lof(reduce(lanes[i], -1))
                    p = reduce(plus(lanes[i], p), -1)
            out.append(p)
    return out

def pattern(bad, x):
    d = (x + 5 - bad) % 5
    return d == 0 or d == 3

def kround(lanes, parity, rc, final, chain, tab):
    needed = []
    for i in range(1600):
        y = (i // 64) // 5
        needed.append(not final or (2 * ((i // 64) % 5) + 3 * y) % 5 == 0)
    if len(parity) == 0:
        for x in range(5):
            for z in range(64):
                l = [[], [], 0]
                for y in range(5):
                    m = lanes[64 * (x + 5 * y) + z]
                    l[0] = l[0] + m[0]
                    l[1] = l[1] + m[1]
                    l[2] ^= m[2]
                parity.append(reduce(l, -1))
    fixed = []
    for l in lanes:
        f = -1
        if True not in plan(len(l[0]) + 1, len(l[1])):
            f = l[2]
        fixed.append(f)
    bad = []
    comp = []
    t = PAT[tab]
    for r in range(320):
        if tab < 0:
            bad.append(r // 64)
            comp.append(0)
        else:
            bad.append((t % 10) // 2)
            comp.append(t % 2)
            t = t // 10
    dcache = {}
    b = [0 for i in range(1600)]
    used = [[0, 0] for i in range(320)]
    for ps in range(2):
        for x in range(5):
            for y in range(5):
                for z in range(64):
                    i = 64 * (x + 5 * y) + z
                    if needed[i] and (fixed[i] >= 0) == (ps == 0):
                        j = 64 * (y + 5 * ((2 * x + 3 * y) % 5)) + (z + ROT[x][y]) % 64
                        r = 64 * (j // 320) + j % 64
                        want = pattern(bad[r], (j // 64) % 5) ^ comp[r]
                        n = 64 * x + z
                        if fixed[i] >= 0:
                            pol = want ^ fixed[i]
                            used[n][pol] = 1
                        elif used[n][1] and not used[n][0]:
                            pol = 1
                        else:
                            used[n][0] = 1
                            pol = 0
                        key = 2 * n + pol
                        if key not in dcache:
                            dl = lof(parity[64 * ((x + 4) % 5) + z])
                            lpush(dl, parity[64 * ((x + 1) % 5) + (z + 63) % 64])
                            dcache[key] = reduce(dl, pol)
                        if fixed[i] >= 0:
                            b[j] = reduce(plus(lanes[i], dcache[key]), -1)
                        else:
                            b[j] = reduce(plus(lanes[i], dcache[key]), want)
    out = [[[], [], 0] for i in range(1600)]
    for yy in range(5):
        for xx in range(5):
            if not final or (yy == 0 and xx < 4):
                for z in range(64):
                    b0 = b[64 * (xx + 5 * yy) + z]
                    b1 = b[64 * ((xx + 1) % 5 + 5 * yy) + z]
                    b2 = b[64 * ((xx + 2) % 5 + 5 * yy) + z]
                    p1 = b1 & -2
                    p2 = b2 & -2
                    l = lof(b0)
                    if b1 & 1 and not b2 & 1:
                        lpush(l, fa(p1, p2, 0)[1])
                    elif b2 & 1 and not b1 & 1:
                        lpush(l, fa(p1, p2, 2)[1] ^ 1)
                    else:
                        lpush(l, fa(p1, p2, 0)[1])
                        if b1 & 1:
                            lpush(l, p1)
                        else:
                            lpush(l, p2)
                    if xx == 0 and yy == 0 and (rc >> z) & 1:
                        l[2] ^= 1
                    out[64 * (xx + 5 * yy) + z] = l
    par = []
    if chain:
        par = parity_chain(out)
    return [out, par]
