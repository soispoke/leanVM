# The canonical verifier and deferred-claim batching precede these helpers.
def common_height(height, left, right):
    a = StackBuf(32)
    b = StackBuf(32)
    h = StackBuf(32)
    hint_decompose_bits(a, left, 32)
    hint_decompose_bits(b, right, 32)
    hint_decompose_bits(h, height, 32)
    aa = 0
    bb = 0
    hh = 0
    for i in unroll(0, 32):
        assert a[i] * a[i] == a[i]
        assert b[i] * b[i] == b[i]
        assert h[i] * h[i] == h[i]
        aa += a[i] * const(2 ** i)
        bb += b[i] * const(2 ** i)
        hh += h[i] * const(2 ** i)
    assert aa == left
    assert bb == right
    assert hh == height
    less = 0
    equal = 1
    for j in unroll(0, 32):
        i = const(31 - j)
        less += equal * (1 + a[i]) * b[i]
        equal *= 1 + a[i] + b[i]
    carry = 1
    for i in unroll(0, 32):
        bit = a[i] + less * (a[i] + b[i])
        assert h[i] == bit + carry
        carry *= bit
    assert carry == 0
    return


def main():
    meta = StackBuf(4)
    hint_witness(meta, "tree_meta")
    seed_0 = meta[0]
    seed_1 = meta[1]
    n_children_g = meta[2]
    height = meta[3]
    assert (n_children_g + 1) * (n_children_g + GEN ** 2) == 0
    digest = HeapBuf(2)
    defer_stmt = HeapBuf(DEFER_STMT_CELLS)
    if n_children_g == 1:
        assert height == 0
        state = HeapBuf(2 * (TREE_CHAIN + 1))
        hint_witness(state[0:2], "start")
        for i in mul_range(1, GEN ** TREE_CHAIN):
            p = state * i * i
            h = chain_hash32(p[1], p[GEN], 67, 0, 33)
            p[GEN ** 2] = h[0]
            p[GEN ** 3] = h[1]
        h = chain_hash32(state[GEN ** (2 * TREE_CHAIN)], state[GEN ** (2 * TREE_CHAIN + 1)], 76, TREE_CHAIN_TAIL, 41)
        digest[1] = h[0]
        digest[GEN] = h[1]
        leaf_values = StackBuf(3)
        hint_witness(leaf_values, "leaf_defer")
        for k in unroll(0, BYTECODE_VARS):
            defer_stmt[GEN ** k] = 0
        defer_stmt[GEN ** DEFER_STMT_BC_VALUE] = leaf_values[0]
        for k in unroll(0, 2 * K_LOG):
            defer_stmt[GEN ** (DEFER_STMT_MAT_POINT + k)] = 0
        defer_stmt[GEN ** DEFER_STMT_A_VALUE] = leaf_values[1]
        defer_stmt[GEN ** DEFER_STMT_B_VALUE] = leaf_values[2]
    else:
        g_logs_pow2, g_squares = exponent_tables()
        child_pi = HeapBuf(4)
        child_fresh = HeapBuf(2 * DEFER_SIZE)
        child_carried = HeapBuf(2 * DEFER_STMT_CELLS)
        digests = HeapBuf(4)
        heights = StackBuf(2)
        hint_witness(digests[0:4], "tree_digests")
        hint_witness(heights, "tree_heights")
        common_height(height, heights[0], heights[1])
        for c in unroll(0, 2):
            carried = child_carried * GEN ** (c * DEFER_STMT_CELLS)
            hint_witness(carried[0:DEFER_STMT_CELLS], "child_defer")
            child_digest = digests * GEN ** (2 * c)
            pi_0, pi_1 = statement_digest(seed_0, seed_1, child_digest, heights[c], 0, carried)
            child_pi[GEN ** (2 * c)] = pi_0
            child_pi[GEN ** (2 * c + 1)] = pi_1
            verify_sub(pi_0, pi_1, seed_0, seed_1, g_logs_pow2, g_squares, child_fresh * GEN ** (c * DEFER_SIZE))
        aggregate_claims(GEN ** 2, child_pi, child_fresh, child_carried, defer_stmt)
        h = chain_hash_node(digests[1], digests[GEN], digests[GEN ** 2], digests[GEN ** 3])
        digest[1] = h[0]
        digest[GEN] = h[1]
    own_0, own_1 = statement_digest(seed_0, seed_1, digest, height, 0, defer_stmt)
    out = GEN ** 0
    assert out[1] == own_0
    assert out[GEN] == own_1
    return
