def sha256(msg):
    ln = len(msg) // 8
    total = (ln + 72) // 64 * 64
    H = [[2 * ((v >> i) & 1) for i in range(32)] for v in SIV]
    for b in range(total // 64):
        blk = []
        for t in range(16):
            wd = []
            for k in range(32):
                i = 64 * b + 4 * t + 3 - k // 8
                if i < ln:
                    wd.append(msg[8 * i + k % 8])
                else:
                    v = 0
                    if i == ln:
                        v = 0x80
                    if i >= total - 8:
                        v = (8 * ln >> (8 * (total - 1 - i))) & 255
                    wd.append(2 * ((v >> (k % 8)) & 1))
            blk.append(wd)
        H = compress(H, blk)
    return [H[n // 32][24 - 8 * ((n // 8) % 4) + n % 8] for n in range(256)]
