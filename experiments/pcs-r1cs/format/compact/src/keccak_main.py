# keccak256-1kib main: 8 blocks; round r >= 1 uses table r - 1, the final round table 23.
msg = inputs(8192)
bits = msg + [0 for i in range(512)]
bits[8192] = 2
bits[8703] = 2
lanes = [[[], [], 0] for i in range(1600)]
parity = []
for blk in range(8):
    for i in range(1088):
        lpush(lanes[blk * 0 + i], bits[1088 * blk + i])
    parity = parity_chain(lanes)
    for r in range(24):
        tab = r - 1
        if blk == 7 and r == 23:
            tab = 23
        st = kround(lanes, parity, RC[r], blk == 7 and r == 23, r < 23, tab)
        lanes = st[0]
        parity = st[1]
digest = []
for j in range(256):
    w = reduce(lanes[j], -1)
    lanes[j] = lof(w)
    digest.append(w)
PUBLIC = finish(digest + [0 for i in range(256)])
