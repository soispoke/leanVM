# nonnative.rs (circuit_suite) over ckt.py: Acc, compress, products, congruences (circuit building only: no values).
# An Int is [word, max]; an Acc is [cols, k, neg]; a Term is [kind, a, b, k]: 0 Mul(a, b, shift k), 1 NegMul,
# 2 Sq(a, shift k), 3 Scaled(a, k), 4 Const(k), 5 Gated(g=a, b, k).

def blen(x):
    x = abs(x)
    n = 0
    for i in range(12):
        s = 2048 >> i
        if x >> s:
            x = x >> s
            n += s
    return n + x

def nfa(a, b, d):
    v = 0
    for w in [a, b, d]:
        if w > 3:
            v += 2 * (w & 1) - 1
    if v > 0:
        r = fa(a ^ 1, b ^ 1, d ^ 1)
        return [r[0] ^ 1, r[1] ^ 1]
    return fa(a, b, d)

def nand(a, b):
    return nfa(a, b, 0)[1]

def all_bits(bits):
    ch = [[], []]
    for w in bits:
        if w == 0 or w == 3:
            return 0
        if w > 3:
            ch[w & 1].append(w)
    out = []
    for ws in ch:
        if ws:
            acc = ws[0]
            for w in ws[1:]:
                acc = nand(acc, w)
            out.append(acc)
    if len(out) == 2:
        return nand(out[0], out[1])
    return out[0] if out else 2

def any_bits(bits):
    return all_bits([w ^ 1 for w in bits]) ^ 1

def pad(x, n):
    return x + [0 for i in range(n - len(x))]

def add_words(x, y):
    n = max(len(x), len(y))
    x = pad(x, n)
    y = pad(y, n)
    carry = 0
    out = []
    for i in range(n):
        s, carry = nfa(x[i], y[i], carry)
        out.append(s)
    return out + [carry]

def lt_const(x, k):
    n = len(x)
    if blen(k) > n:
        return 2
    if k == 0:
        return 0
    comp = (1 << n) - k
    carry = 0
    for i in range(n):
        carry = nfa(x[i], 2 * ((comp >> i) & 1), carry)[1]
    return carry ^ 1

def eq_words(x, y):
    n = max(len(x), len(y))
    x = pad(x, n)
    y = pad(y, n)
    return any_bits([xor(x[i], y[i]) for i in range(n)]) ^ 1

def const_word(k, n):
    return [2 * ((k >> i) & 1) for i in range(n)]

# Width-win NAF digits [position, digit] (win 2: the non-adjacent form).
def wnaf(k, win):
    out = []
    m = 1 << win
    for i in range(5000):
        if k == 0:
            break
        if k & 1:
            d = k % m
            if d >= m >> 1:
                d -= m
            out.append([i, d])
            k -= d
        k = k >> 1
    return out

def new_acc(width):
    return [[[] for i in range(width)], 0, 0]

def abit(acc, w, pos):
    cols = acc[0]
    if pos < len(cols):
        if acc[2]:
            acc[1] -= 1 << pos
            w = w ^ 1
        if w > 3:
            cols[pos].append(w)
        elif w == 1 or w == 2:
            acc[1] += 1 << pos

# + w 2^shift, or - w 2^shift when sg.
def aword(acc, w, shift, sg):
    acc[2] ^= sg
    for i in range(len(w)):
        abit(acc, w[i], shift + i)
    acc[2] ^= sg

def scaled_bit(acc, w, shift, k):
    for e in wnaf(k, 2):
        aword(acc, [w], shift + e[0], e[1] < 0)

def konst(acc, k):
    acc[1] += -k if acc[2] else k

def wclass(w):
    return 4 if w < 4 else (w & 1) * 2 + ((w >> 1) & 1)

# The plans (classes of a triple, then of a pair), cheapest first: 7-bit codes 25 a + 5 b + d.
PLANS = 36819239403875955872669387386968180683641443477915257146839133268741507911455667811450415424426886967729
PLAN_MEMO = {}

def find_plan(pool, n):
    key = n
    for c in range(5):
        key = key * 4 + min(len(pool[c]), 3)
    if key not in PLAN_MEMO:
        for i in range(20 * n - 25):
            code = PLANS >> (7 * (i + 105 - 35 * n)) & 127
            p = [code // 25, code // 5 % 5, code % 5][3 - n:]
            cnt = [0, 0, 0, 0, 0]
            for c in p:
                cnt[c] += 1
            ok = 1
            for c in range(5):
                if cnt[c] > len(pool[c]):
                    ok = 0
            if ok:
                PLAN_MEMO[key] = p
                break
    return PLAN_MEMO[key]

def compress(acc, target):
    cols = acc[0]
    m = len(cols)
    k = acc[1] % (1 << m)
    out = []
    for w in range(m):
        pool = [[], [], [], [], []]
        col = cols[w]
        cols[w] = []
        for b in col:
            pool[wclass(b)].append(b)
        ln = len(col) + ((k >> w) & 1)
        if (k >> w) & 1:
            pool[4].append(2)
        for it in range(ln + 1):
            if ln <= target:
                break
            n = 2 if ln == 2 else 3
            ops = [pool[c].pop() for c in find_plan(pool, n)] + [0]
            s, carry = nfa(ops[0], ops[1], ops[2])
            ln -= n
            if s != 0 and s != 3:
                pool[wclass(s)].append(s)
                ln += 1
            if w + 1 < m and carry != 0 and carry != 3:
                cols[w + 1].append(carry)
        out.append(pool[0] + pool[1] + pool[2] + pool[3] + pool[4])
    return out

def to_word(acc):
    return [col[0] if col else 0 for col in compress(acc, 1)]

def is_zero(acc):
    acc[1] -= 1
    bits = []
    for col in compress(acc, 2):
        bits.append(xor(col[0], col[1]) if len(col) == 2 else (col[0] if col else 0))
    return all_bits(bits)

def nvars(w):
    c = 0
    for x in w:
        if x > 3:
            c += 1
    return c

def school(acc, a, b, shift, sq):
    ka = [0 for x in a]
    kb = ka
    if sq:
        b = a
        and_form = 0
    else:
        kb = [0 for x in b]
        and_form = min(nvars(a), nvars(b)) <= 2
    k = 0
    width = len(acc[0])
    for i in range(len(a)):
        x = a[i]
        if sq:
            if x == 1 or x == 2:
                k += 1 << (2 * i)
            elif x > 3:
                ka[i] += 1 << (2 * i)
        for j in range(i + 1 if sq else 0, len(b)):
            t = i + j + sq
            if shift + i + j >= width:
                break
            y = b[j]
            if x == 0 or x == 3 or y == 0 or y == 3:
                pass
            elif x < 4 and y < 4:
                k += 1 << t
            elif x < 4:
                if sq:
                    kb[j] += 1 << t
                else:
                    abit(acc, y, shift + t)
            elif y < 4:
                if sq:
                    ka[i] += 1 << t
                else:
                    abit(acc, x, shift + t)
            elif not sq and (t == 0 or and_form):
                abit(acc, nand(x, y), shift + t)
            else:
                abit(acc, xor3(x, y, 2), shift + t - 1)
                e = 1 << (t - 1)
                ka[i] += e
                kb[j] += e
                k -= e
    for i in range(len(a)):
        scaled_bit(acc, a[i], shift, ka[i])
    if not sq:
        for j in range(len(b)):
            scaled_bit(acc, b[j], shift, kb[j])
    konst(acc, k << shift)

def trim(w):
    n = len(w)
    for it in range(len(w)):
        if w[n - 1] != 0 and w[n - 1] != 3:
            break
        n -= 1
    return w[:n]

# mul_into / square_into (recursive in Rust: Karatsuba above 24 bits) by an explicit stack. A frame: [phase, acc, a,
# b, shift, square, parent, slot, h, z0, z2]; slot > 0: the frame computes mul / square into its own acc, written as
# a word to parent[slot] (z0 or z2).
def prod_into(acc, a, b, shift, sq):
    stack = [[0, acc, a, b, shift, sq, [], 0]]
    for it in range(1000000):
        if not stack:
            break
        f = stack[-1]
        ph, acc, a, b, shift, sq, par, slot = f[:8]
        f[0] = ph + 1
        if ph == 0:
            a = trim(a)
            b = trim(b)
            n = max(len(a), len(b))
            if n <= 24 or (not sq and min(len(a), len(b)) <= n // 2):
                school(acc, a, b, shift, sq)
                f[0] = 3
            else:
                h = (n + 1) // 2
                if not sq:
                    a = pad(a, n)
                    b = pad(b, n)
                f[2] = a
                f[3] = b
                f.append(h)
                f.append(0)
                f.append(0)
                stack.append([0, new_acc(2 * (n - h)), a[h:], b[h:], 0, sq, f, 10])
                stack.append([0, new_acc(2 * h), a[:h], b[:h], 0, sq, f, 9])
        else:
            h = f[8] if len(f) > 8 else 0
            if ph == 1:
                a = add_words(a[:h], a[h:])
                f[2] = a
                if not sq:
                    b = add_words(b[:h], b[h:])
                    f[3] = b
                stack.append([0, acc, a[:h], b[:h], shift + h, sq, [], 0])
            else:
                if ph == 2:
                    if sq:
                        school(acc, [a[h]], a[:h], shift + 2 * h + 1, 0)
                        abit(acc, a[h], shift + 3 * h)
                    else:
                        school(acc, [a[h]], b[:h], shift + 2 * h, 0)
                        school(acc, [b[h]], a[:h], shift + 2 * h, 0)
                        abit(acc, nand(a[h], b[h]), shift + 3 * h)
                    aword(acc, f[9], shift, 0)
                    aword(acc, f[10], shift + 2 * h, 0)
                    aword(acc, f[9], shift + h, 1)
                    aword(acc, f[10], shift + h, 1)
                stack.pop()
                if slot:
                    par[slot] = to_word(acc)
    return 0

def const_mul_into(acc, w, k):
    w = trim(w)
    n = len(w)
    best = -1
    bwin = 0
    for i in range(6):
        win = i + 2
        c = ((1 << (win - 2)) - 1 + len(wnaf(k, win))) * (n + win)
        if best < 0 or c < best:
            best = c
            bwin = win
    if best >= len(wnaf(k, 2)) * n or n == 0:
        bwin = 2
    table = [w]
    for i in range((1 << (bwin - 2)) - 1):
        table.append(trim(add_words(table[-1], [0] + w)))
    for e in wnaf(k, bwin):
        aword(acc, table[(abs(e[1]) - 1) // 2], e[0], e[1] < 0)

CHECKS = []

def hint(bits):
    return [inputs(bits), (1 << bits) - 1]

def iconst(k):
    return [const_word(k, blen(k)), k]

def congruence(p, terms):
    lo = 0
    hi = 0
    for t in terms:
        ty = t[0]
        if ty == 4:
            lo += t[3]
            hi += t[3]
        else:
            if ty < 3:
                x = t[1][1] * (t[1][1] if ty == 2 else t[2][1]) << t[3]
                if ty == 1:
                    x = -x
            else:
                x = t[ty // 2][1] * t[3]
            if x < 0:
                lo += x
            else:
                hi += x
    o = (-lo + p - 1) // p if lo < 0 else 0
    top = hi + o * p
    qbits = max(blen(top // p), 1)
    q = hint(qbits)
    acc = new_acc(max(blen(top), blen(((1 << qbits) - 1) * p - lo - o * p)))
    for t in terms:
        ty = t[0]
        if ty < 3:
            acc[2] = ty == 1
            prod_into(acc, t[1][0], t[2][0] if ty < 2 else [], t[3], ty == 2)
            acc[2] = 0
        elif ty == 4:
            konst(acc, t[3])
        else:
            w = t[1][0]
            if ty == 5:
                g0 = w[0] if w else 0
                w = [nand(g0, x) for x in t[2][0]]
            const_mul_into(acc, w, t[3])
    konst(acc, o * p)
    const_mul_into(acc, q[0], -p)
    return is_zero(acc)

def residue_hint(p):
    r = hint(blen(p))
    CHECKS.append(lt_const(r[0], p))
    return [r[0], p - 1]

def reduce_to(p, terms, canonical):
    r = residue_hint(p) if canonical else hint(blen(p))
    CHECKS.append(congruence(p, terms + [[3, r, [], -1]]))
    return r

def nn_add(a, b):
    mx = a[1] + b[1]
    return [add_words(a[0], b[0])[:blen(mx)], mx]
