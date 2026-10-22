"""The decoder of a circuit description that is a program of a small total language.

A description is varints: log_rows, the number of variable slots, then one expression in prefix form. Values are
integers, lists and dicts. The only effect is `row(x, y, c)`, which appends a row (sources coded 0 the zero, 1 the
one, 2 + r row r) and returns its index; at the end slot 0 holds the 512 public sources.

Totality: there is no while and no recursion. A loop runs `range(n)` with `n` evaluated once; a function may only
call functions defined before it (the call binds when it is parsed, and a function is defined only once its body
is parsed). Every loop step, call and primitive operation spends fuel, a list result as much as its length, from a
budget of 2^(log_rows + 10): the work is linear in the circuit's rows and the program halts, with the rows or an
error. Integers are kept below 2^4096 and shifts below 4096, so no single step is large.
"""
import operator as o, struct, sys

d = open(sys.argv[1], "rb").read()
p = 0


def u():
    global p
    v = s = 0
    while d[p] > 127:
        v |= (d[p] & 127) << s
        p, s = p + 1, s + 7
    p += 1
    return v | d[p - 1] << s


log_rows, V = u(), [0] * u()
assert log_rows <= 32
fuel, out, F = [1 << log_rows + 10], [], []


def tick(k):
    fuel[0] -= k
    assert fuel[0] > 0


def throw(e):
    raise e


class Ret(Exception):
    pass


class Brk(Exception):
    pass


def row(x, y, c):
    out.extend((x, y, c))
    return 511 + len(out) // 3


STRICT = [(2, o.add), (2, o.sub), (2, lambda a, b: +a * +b), (2, o.floordiv), (2, o.mod), (2, o.and_), (2, o.or_),
          (2, o.xor), (2, lambda a, b: a << b if b < 4096 else 0 // 0), (2, o.rshift), (2, o.eq), (2, o.ne),
          (2, o.lt), (2, o.le), (1, o.neg), (1, o.not_), (2, o.getitem), (3, lambda a, i, j: a[i:j]),
          (3, o.setitem), (1, len), (2, lambda a, x: a.append(x)), (2, lambda a, i: a.pop(i)), (2, o.contains),
          (0, dict), (3, lambda m, k, v: m.get(k, v)), (3, row), (0, lambda: 512 + len(out) // 3)]


def strict(f, a):
    def g():
        r = f(*[x() for x in a])
        tick(1 + len(r) if type(r) is list else 1)
        assert type(r) is not int or r.bit_length() < 4096
        return r
    return g


def loop(s, n, b):
    try:
        for V[s] in range(n):
            tick(1)
            b()
    except Brk:
        pass


def call(f, a):
    tick(1)
    for s, x in zip(f[0], [x() for x in a]):
        V[s] = x
    try:
        f[1]()
    except Ret as r:
        return r.args[0]


def P():
    op = u()
    if op > 12:
        n, f = STRICT[op - 13]
        return strict(f, [P() for _ in range(n)])
    if op == 0:
        k = u()
        return lambda: k
    if op == 1:
        s = u()
        return lambda: V[s]
    if op == 2:
        s, e = u(), P()
        return lambda: V.__setitem__(s, e())
    if op == 3:
        a = [P() for _ in range(u())]
        return lambda: [x() for x in a]
    if op == 6:
        s = [u() for _ in range(u())]
        F.append((s, P()))
        return lambda: None
    if op == 7:
        f = F[u()]
        a = [P() for _ in f[0]]
        return lambda: call(f, a)
    if op == 8:
        e = P()
        return lambda: throw(Ret(e()))
    if op == 9:
        return lambda: throw(Brk())
    s = u() if op in (4, 12) else 0
    a, b = P(), P()
    c = P() if op == 5 else None
    return {4: lambda: loop(s, a(), b), 5: lambda: b() if a() else c(), 10: lambda: a() and b(),
            11: lambda: a() or b(), 12: lambda: [tick(1) or b() for V[s] in range(a())]}[op]


P()()
assert p == len(d) and len(V[0]) == 512
open(sys.argv[2], "wb").write(b"ROWS" + bytes([log_rows]) + struct.pack(f"<I{512 + len(out)}I", 512 + len(out) // 3,
                                                                        *V[0], *out))
