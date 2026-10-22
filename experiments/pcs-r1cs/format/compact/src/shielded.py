# shielded-transfer (circuit_suite/src/shielded.rs), over the sha256 library.
def chain(bits, isand):
    acc = bits[0]
    for b in bits[1:]:
        if isand:
            acc = and2(b, acc)
        else:
            acc = or2(b, acc)
    return acc

def any_bits(bits):
    neg = []
    pos = []
    for w in bits:
        if w > 3 and w & 1:
            neg.append(w ^ 1)
        else:
            pos.append(w)
    if pos:
        a = chain(pos, 0)
        if neg:
            return or2(a, chain(neg, 1) ^ 1)
        return a
    if neg:
        return chain(neg, 1) ^ 1
    return 0

def eq_bits(x, y):
    return any_bits([xor(x[i], y[i]) for i in range(len(x))]) ^ 1

def tagged(t, parts):
    m = [2 * ((t >> i) & 1) for i in range(8)]
    for p in parts:
        m = m + p
    return sha256(m)

INP = inputs(8 * 1680)

def by(at, n):
    return INP[8 * at:8 * (at + n)]

def num(at, n):
    return [INP[8 * (at + n - 1 - k // 8) + k % 8] for k in range(8 * n)]

root = by(0, 32)
domain = by(32, 32)
public_amount = num(64, 16)
fee = num(80, 16)
recipient = by(96, 20)
authorizer = by(116, 20)
ok = []
nullifiers = []
in_values = []
in_nonzero = []
for k in range(2):
    at = 136 + k * 724
    spend_key = by(at, 32)
    value = num(at + 64, 16)
    index = num(at + 80, 4)
    owner = tagged(1, [spend_key])
    inner = tagged(5, [owner, by(at + 32, 32)])
    commitment = tagged(2, [inner, by(at + 64, 16)])
    current = commitment
    for level in range(20):
        sib = by(at + 84 + 32 * level, 32)
        left = []
        right = []
        for i in range(256):
            u = and2(index[level], xor(current[i], sib[i]))
            left.append(xor(current[i], u))
            right.append(xor(sib[i], u))
        current = tagged(4, [left, right])
    occurrence = tagged(7, [commitment, by(at + 80, 4)])
    nk = tagged(6, [domain, spend_key])
    nullifiers.append(tagged(3, [nk, occurrence]))
    ok.append(any_bits(index[20:]) ^ 1)
    nonzero = any_bits(value)
    member = eq_bits(current, root)
    ok.append(or2(nonzero ^ 1, member))
    in_values.append(value)
    in_nonzero.append(nonzero)
commitments = []
out_values = []
for k in range(2):
    at = 136 + 2 * 724 + k * 48
    inner = by(at, 32)
    value = num(at + 32, 16)
    commitments.append(tagged(2, [inner, by(at + 32, 16)]))
    b0 = inner[248]
    b1 = inner[249]
    high_zero = any_bits(inner[:248] + inner[250:]) ^ 1
    low = b0
    other = b1
    if k:
        low = b1
        other = b0
    own_sink = and2(high_zero, and2(low, other ^ 1))
    is_sink = and2(high_zero, xor(b0, b1))
    nonzero = any_bits(value)
    ok.append(or2(nonzero, own_sink))
    ok.append(or2(nonzero ^ 1, is_sink ^ 1))
    out_values.append(value)
ok.append(or2(in_nonzero[0], in_nonzero[1]))
lhs = add_many([in_values[0], in_values[1]], 0, 130)
rhs = add_many([out_values[0], out_values[1], public_amount, fee], 0, 130)
ok.append(eq_bits(lhs, rhs))
ok.append(any_bits(authorizer))
amount_nonzero = any_bits(public_amount)
recipient_nonzero = any_bits(recipient)
ok.append(xor(amount_nonzero, recipient_nonzero) ^ 1)
ok.append(eq_bits(nullifiers[0], nullifiers[1]) ^ 1)
ok.append(eq_bits(commitments[0], commitments[1]) ^ 1)
valid = any_bits([w ^ 1 for w in ok]) ^ 1
digest = tagged(8, [nullifiers[0], nullifiers[1], commitments[0], commitments[1], by(0, 136)])
PUBLIC = finish(digest + [valid] + [0 for i in range(255)])
