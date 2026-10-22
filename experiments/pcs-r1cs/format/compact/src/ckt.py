# Ckt (circuit_suite/src/lib.rs) in the generator language. A wire is an int: a constant b with negation n is
# 2 b + n; row r's sum bit is 4 r + n, its carry 4 r + 2 + n. Negation is `^ 1`.
TO_SUM = {}
TO_CARRY = {}
POS = {}
INPUTS = {}
CO = 0

def inp():
    r = N()
    row(r + 2, 0, 0)
    INPUTS[r] = 1
    return 4 * r

def inputs(n):
    return [inp() for i in range(n)]

def cval(w):
    return (w ^ (w >> 1)) & 1

def flip_row(r):
    if r in TO_CARRY:
        return TO_CARRY[r]
    c = row(r + 2, 1, 0)
    TO_CARRY[r] = c
    POS[4 * r + 1] = 4 * c
    return c

def positive(w):
    if w & 1 == 0:
        return w
    if w < 4:
        return w ^ 3
    if w in POS:
        return POS[w]
    if w & 2:
        r = row(1, 0, (w >> 2) + 2)
    else:
        r = flip_row(w >> 2)
    POS[w] = 4 * r
    return 4 * r

def bit_src(w):
    if w < 4:
        return w >> 1
    r = w >> 2
    if w & 2 == 0:
        return r + 2
    if r not in TO_SUM:
        TO_SUM[r] = row(0, 0, r + 2)
    return TO_SUM[r] + 2

def carry_one():
    global CO
    if CO == 0:
        CO = row(1, 1, 0) + 2
    return CO

def carry_src(w):
    if w == 0:
        return 0
    if w < 4:
        return carry_one()
    if w & 2:
        return (w >> 2) + 2
    return flip_row(w >> 2) + 2

def fa(a, b, c):
    ones = 0
    vs = []
    for w in [a, b, c]:
        if w < 4:
            ones += cval(w)
        else:
            vs.append(w)
    if len(vs) == 0:
        return [2 * (ones & 1), 2 * (ones >> 1)]
    if len(vs) == 1:
        x = vs[0]
        if ones == 0:
            return [x, 0]
        if ones == 1:
            return [x ^ 1, x]
        return [x, 2]
    ops = [positive(a), positive(b), positive(c)]
    pick = 2
    for i in range(3):
        if ops[2 - i] > 3 and ops[2 - i] & 2:
            pick = 2 - i
    if not (ops[pick] > 3 and ops[pick] & 2):
        for i in range(3):
            if ops[2 - i] < 4:
                pick = 2 - i
        for i in range(3):
            if ops[2 - i] == 0:
                pick = 2 - i
    cs = carry_src(ops.pop(pick))
    x = bit_src(ops[0])
    r = row(x, bit_src(ops[1]), cs)
    return [4 * r, 4 * r + 2]

def xor3(a, b, c):
    s = fa(a & -2, b & -2, c & -2)[0]
    return s ^ ((a ^ b ^ c) & 1)

def xor(a, b):
    return xor3(a, b, 0)

def and2(a, b):
    return fa(a, b, 0)[1]

def or2(a, b):
    return fa(a, b, 2)[1]

def finish(public):
    pub = {}
    out = []
    for w in public:
        if w not in pub:
            p = positive(w)
            x = bit_src(p)
            if p > 3 and p & 2 == 0 and (p >> 2) in INPUTS:
                pub[w] = (p >> 2) + 2
            else:
                pub[w] = row(x, 0, 0) + 2
        out.append(pub[w])
    return out
