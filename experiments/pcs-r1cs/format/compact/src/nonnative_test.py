PM = (1 << 256) - (1 << 32) - 977
a = residue_hint(PM)
b = residue_hint(PM)
g = hint(1)
r = reduce_to(PM, [[0, a, b, 0], [5, g, a, -2], [3, b, [], 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee]], 1)
q = reduce_to(PM, [[2, r, [], 0], [1, a, r, 3], [4, [], [], -7]], 0)
valid = all_bits(CHECKS)
PUBLIC = finish(r[0] + q[0] + [valid] + [0 for i in range(511 - 2 * 256)] if 0 else r[0] + q[0][:255] + [valid])
