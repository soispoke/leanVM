# Included after the canonical recursion guest by the matched tree harness.
# Digest cells are canonical128-bit values; decomposition binds every byte shift.
def chain_shift8(value):
    bits = StackBuf(128)
    hint_decompose_bits(bits, value, 128)
    original = 0
    shifted = 0
    carry = 0
    for j in unroll(0, 128):
        assert bits[j] * bits[j] == bits[j]
        original += bits[j] * const(2 ** j)
        if const(j // 120 == 0):
            shifted += bits[j] * const(2 ** (j + 8))
        else:
            carry += bits[j] * const(2 ** (j - 120))
    assert original == value
    return shifted, carry


def chain_hash32(a, b, tag: Const, tail: Const, length: Const):
    aa, ac = chain_shift8(a)
    bb, bc = chain_shift8(b)
    out = StackBuf(2)
    blake2s([aa + tag, bb + ac], [bc + tail, 0], out, counter=length, final=1)
    return out


def chain_hash_node(a, b, c, d):
    aa, ac = chain_shift8(a)
    bb, bc = chain_shift8(b)
    cc, cd = chain_shift8(c)
    dd, dc = chain_shift8(d)
    mid = StackBuf(2)
    blake2s([aa + 78, bb + ac], [cc + bc, dd + cd], mid, counter=64, final=0)
    out = StackBuf(2)
    blake2s([dc, 0], [0, 0], out, cv=mid, counter=65, final=1)
    return out


def chain_wrap(seed_0, seed_1, digest_0, digest_1, defer, n: Const):
    # Same canonical serialization as upstream statement_digest, specialized to
    # this record's authorized bytecode dimension. Include all three field limbs.
    cells = StackBuf(4 * ((6 + 3 * ((n + 1) // 2) + 3) // 4))
    cells[0] = seed_0
    cells[1] = seed_1
    cells[2] = digest_0
    cells[3] = digest_1
    cells[4] = 0
    cells[5] = 0
    for p in unroll(0, (n + 1) // 2):
        s = defer[GEN ** (2 * p)]
        if const(2 * p + 1 == n):
            t = 0
        else:
            t = defer[GEN ** (2 * p + 1)]
        s_lo = StackBuf(2)
        t_lo = StackBuf(2)
        hint_f192_limbs(s_lo, s)
        hint_f192_limbs(t_lo, t)
        cells[6 + 3 * p] = pack64x2(s_lo[0], s_lo[1])
        cells[7 + 3 * p] = pack64x2(((s + s_lo[0]) * Y_INV + s_lo[1]) * Y_INV, t_lo[0])
        cells[8 + 3 * p] = pack64x2(t_lo[1], ((t + t_lo[0]) * Y_INV + t_lo[1]) * Y_INV)
    for k in unroll(6 + 3 * ((n + 1) // 2), 4 * ((6 + 3 * ((n + 1) // 2) + 3) // 4)):
        cells[k] = 0
    st = StackBuf(2)
    blake2s(cells[0:2], cells[2:4], st, counter=64, final=1 // ((6 + 3 * ((n + 1) // 2) + 3) // 4))
    for b in unroll(1, (6 + 3 * ((n + 1) // 2) + 3) // 4):
        nxt = StackBuf(2)
        blake2s(cells[4 * b:4 * b + 2], cells[4 * b + 2:4 * b + 4], nxt, cv=st, counter=64 * (b + 1), final=(b + 1) // ((6 + 3 * ((n + 1) // 2) + 3) // 4))
        st = nxt
    return st[0], st[1]
