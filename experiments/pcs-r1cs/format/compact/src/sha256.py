# sha256 (circuit_suite/src/sha256.rs): Twins, add_many, compress. Absent is -1.
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
     0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
     0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
     0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
     0xc67178f2]
SIV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
TWC = {}
TWB = {}
PEND = []

def is_carry(w):
    return w > 3 and w & 2 == 2

def fits_c(w):
    return w > 3 and w & 3 == 2

def fits_xy(w):
    return w < 4 or w & 3 == 0

def carry_known(w):
    if w < 4 or w & 2:
        return w
    p = w & -2
    if p in TWC:
        return TWC[p] ^ (w & 1)
    return -1

def tw_carry(w):
    k = carry_known(w)
    if k >= 0:
        return k
    p = w & -2
    z = 0
    for i in range(len(PEND)):
        q = PEND.pop()
        if q not in TWB:
            z = q
            break
    bk = fa(p, p, z)
    TWC[p] = bk[1]
    TWB[bk[1]] = p
    if z != 0:
        TWB[z] = bk[0]
        TWC[bk[0]] = z
    return bk[1] ^ (w & 1)

def bit_known(z):
    if not is_carry(z):
        return z
    p = z & -2
    if p in TWB:
        return TWB[p] ^ (z & 1)
    return -1

def want_bit(z):
    if fits_c(z) and z not in TWB:
        PEND.append(z)

def pred(w, k):
    if k == 0:
        return fits_c(w)
    if k == 1:
        return True
    if k == 2:
        return fits_c(w) and bit_known(w) < 0
    if k == 3:
        q = carry_known(w)
        return q >= 0 and fits_c(q)
    if k == 4:
        return fits_xy(w)
    q = bit_known(w)
    return q >= 0 and fits_xy(q)

def take(pool, k):
    for i in range(len(pool)):
        x = pool[i]
        if pred(x, k):
            last = pool.pop()
            if i < len(pool):
                pool[i] = last
            return x
    return -1

def pick(pool, one):
    if len(pool) + one == 2:
        z = take(pool, 0)
        if z < 0:
            z = 0
        x = take(pool, 1)
        y = 0
        if z == 0:
            y = take(pool, 1)
        if is_carry(x):
            b = bit_known(x)
            if b >= 0:
                x = b
        return [x, y, z, one]
    z = take(pool, 2)
    if z < 0:
        z = take(pool, 0)
    if z < 0:
        if one:
            one = 0
            z = 2
        else:
            w = take(pool, 3)
            if w >= 0:
                z = carry_known(w)
            else:
                w = take(pool, 4)
                if w < 0:
                    w = pool.pop()
                z = tw_carry(w)
    xy = []
    for s in range(2):
        w = take(pool, 4)
        if w < 0:
            w = take(pool, 5)
            if w >= 0:
                w = bit_known(w)
            elif one:
                one = 0
                w = 2
            else:
                w = pool.pop()
        xy.append(w)
    return [xy[0], xy[1], z, one]

def add_many(ops, konst, width):
    ones = [(konst >> j) & 1 for j in range(width + 1)]
    ones[width] = 0
    cols = [[] for j in range(width)]
    for op in ops:
        for j in range(min(len(op), width)):
            w = op[j]
            if w < 4:
                ones[j] += cval(w)
            else:
                cols[j].append(w)
    out = []
    carries = []
    for j in range(width):
        top = j + 1 == width
        pool = cols[j] + carries
        carries = []
        ones[j + 1] += ones[j] // 2
        one = ones[j] % 2
        for it in range(len(pool) + 2):
            n = len(pool)
            if n == 0:
                out.append(2 * one)
                break
            if n == 1:
                if one:
                    out.append(pool[0] ^ 1)
                    if not top:
                        carries.append(pool[0])
                else:
                    out.append(pool[0])
                break
            xyz = pick(pool, one)
            one = xyz[3]
            if top:
                pool.append(xor3(xyz[0], xyz[1], xyz[2]))
            else:
                sk = fa(xyz[0], xyz[1], xyz[2])
                pool.append(sk[0])
                if sk[1] < 4:
                    ones[j + 1] += cval(sk[1])
                else:
                    carries.append(sk[1])
    return out

def maj(a, b, c):
    if a & b & c & 1:
        return fa(a ^ 1, b ^ 1, c ^ 1)[1] ^ 1
    return fa(a, b, c)[1]

def maj_tw(x, y, pref):
    ops = [pref, y, x]
    for i in range(3):
        k = carry_known(ops[i])
        if k >= 0 and (fits_c(k) or k < 4):
            rest = [ops[(i + 1) % 3], ops[(i + 2) % 3]]
            if i == 1:
                rest = [ops[0], ops[2]]
            return maj(rest[0], rest[1], k)
    return maj(x, y, tw_carry(pref))

def xor3_tw(x, y, z):
    ops = [z, y, x]
    for i in range(3):
        k = carry_known(ops[i])
        if k >= 0:
            rest = [ops[(i + 1) % 3], ops[(i + 2) % 3]]
            if i == 1:
                rest = [ops[0], ops[2]]
            return xor3(rest[0], rest[1], k)
    if x < 4 or y < 4 or z < 4:
        return xor3(x, y, z)
    return xor3(x, y, tw_carry(z))

def sig(x, r1, r2, r3, sh):
    out = []
    for j in range(32):
        t = 0
        if j + r3 < 32 or not sh:
            t = x[(j + r3) % 32]
        out.append(xor3_tw(x[(j + r1) % 32], x[(j + r2) % 32], t))
    return out

def is_var(op):
    for w in op:
        if w > 3:
            return 1
    return 0

def compress(h, blk):
    w = list(blk)
    a = [h[3], h[2], h[1], h[0]]
    e = [h[7], h[6], h[5], h[4]]
    for t in range(64):
        at = a[t + 3]
        bt = a[t + 2]
        ct = a[t + 1]
        et = e[t + 3]
        ft = e[t + 2]
        gt = e[t + 1]
        mj = [maj_tw(at[j], bt[j], ct[j]) for j in range(32)]
        ch = []
        for j in range(32):
            ch.append(maj_tw(gt[j], xor(et[j], gt[j]), ft[j]))
        for m in mj[2:] + ch[2:]:
            want_bit(m)
        for j in range(32):
            if (0xfbe8006d >> j) & 1 != t & 1:
                tw_carry(at[j])
        for x in et:
            tw_carry(x)
        s0 = sig(at, 2, 13, 22, 0)
        s1 = sig(et, 6, 11, 25, 0)
        if t >= 16:
            ss0 = sig(w[t - 15], 7, 18, 3, 1)
            ss1 = sig(w[t - 2], 17, 19, 10, 1)
            w.append(add_many([ss1, w[t - 7], ss0, w[t - 16]], 0, 32))
        sc = (1 <= t and t <= 48) + 2 * (14 <= t and t <= 61)
        m = [0, 0x0c386982, 0xc3184018, 0x6b782908][sc]
        for j in range(32):
            if (m >> j) & 1:
                tw_carry(w[t][j])
        t1o = [e[t], s1, ch, w[t]]
        if is_var(e[t]) + is_var(s1) + is_var(ch) + is_var(w[t]) >= 2:
            t1 = add_many(t1o, K[t], 32)
            en = add_many([a[t], t1], 0, 32)
            an = add_many([t1, s0, mj], 0, 32)
        else:
            en = add_many(t1o + [a[t]], K[t], 32)
            an = add_many(t1o + [s0, mj], K[t], 32)
        global PEND
        PEND = []
        a.append(an)
        e.append(en)
    return [add_many([h[i], a[67 - i] if i < 4 else e[71 - i]], 0, 32) for i in range(8)]
