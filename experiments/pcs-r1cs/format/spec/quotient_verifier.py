"""The circuit format's verifier, written from the protocol and independent of the Rust code.

What a protocol that enshrines the format must specify on top of leanPCS (the field, the transcript and the
opening of committed tables): the gate, the cell layout, the public bits, and this reduction of a proof to four
claims on three committed tables (`crates/flock/src/quotient.rs`, `reduce`; `doc/quotient/main.tex`). The field
and the transcript are the leanVM Python verifier's (`python-verifier/verifier.py`), which is leanPCS's side.

    python3 quotient_verifier.py DUMP_DIR NAME     # checks the claims Rust derived from the same proof
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "python-verifier"))
from verifier import E, K, ONE, ZERO, Digest, Proof, Transcript, VerificationError, require  # noqa: E402

REGION = 11  # the public bits are the X and Y cells of the span of the first 11 basis vectors


def S(x: K) -> K:
    return x * x + x


def cantor_basis(count: int) -> list[K]:
    """beta[0] = 1 and S(beta[k + 1]) = beta[k], each the solution with its low bit clear."""
    pivots: dict[int, tuple[int, int]] = {}
    for j in range(64):
        image, source = S(K(1 << j)).value, 1 << j
        while image:
            top = image.bit_length() - 1
            if top not in pivots:
                pivots[top] = (image, source)
                break
            image ^= pivots[top][0]
            source ^= pivots[top][1]

    def solve(target: K) -> K:
        image, source = target.value, 0
        while image:
            top = image.bit_length() - 1
            require(top in pivots, "outside the image of S")
            image ^= pivots[top][0]
            source ^= pivots[top][1]
        return K(source & ~1 & (2**64 - 1))

    beta = [K(1)]
    for _ in range(1, count):
        beta.append(solve(beta[-1]))
    return beta


BETA = cantor_basis(28)


def coordinates(count: int) -> list[K]:
    """b with coordinate k of a point of the region equal to sum_j b[j - k] w_j."""
    b = [K(1)] * count
    for d in range(1, count):
        acc = K(0)
        for e in range(1, d + 1):
            acc = acc + BETA[e] * b[d - e]
        b[d] = acc
    return b


def row_vanishing(m: int) -> list[K]:
    """tau with sum_k tau[k] w_k vanishing exactly on the span of beta[2..m], tau[m - 2] = 1."""
    n = m - 2
    rows = [[BETA[j - k] if k <= j else K(0) for k in range(n + 1)] for j in range(2, m)]
    for col in range(n):
        pivot = next(r for r in range(col, n) if rows[r][col])
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inverse = E(rows[col][col]).inv().c0
        rows[col] = [x * inverse for x in rows[col]]
        for r in range(n):
            factor = rows[r][col]
            if r != col and factor:
                rows[r] = [x + factor * p for x, p in zip(rows[r], rows[col])]
    return [rows[k][n] for k in range(n)] + [K(1)]


def bit_weight(j: int) -> E:
    return E(1 << j) if j < 64 else E(0, 1 << (j - 64))


def halves(data: bytes) -> list[E]:
    out = []
    for h in range(2):
        v = int.from_bytes(data[16 * h : 16 * h + 16], "big")
        out.append(E(v & (2**64 - 1), v >> 64))
    return out


def seed(index_root: bytes, statement: bytes) -> tuple[Digest, Digest]:
    """The transcript's seed: a digest of the circuit, then of the statement's four 128-bit halves."""
    circuit = hashlib.blake2s(b"flock-quotient-vm-1" + index_root).digest()
    words = b"".join(int(x.c0).to_bytes(8, "little") + int(x.c1).to_bytes(8, "little") for x in halves(statement[:32]) + halves(statement[32:]))
    return Digest(circuit), Digest(hashlib.blake2s(words).digest())


def reduce(transcript: Transcript, statement: bytes, log_rows: int) -> dict:
    """The proof read from the transcript, down to the two commitments it names and four claims."""
    m = log_rows + 2
    s = halves(statement[:32]) + halves(statement[32:])

    def root() -> bytes:
        a, b = transcript.next_scalar(), transcript.next_scalar()
        require(a.c2 == 0 and b.c2 == 0, "a root is two 128-bit scalars")
        return b"".join(int(x).to_bytes(8, "little") for x in (a.c0, a.c1, b.c0, b.c1))

    witness_root = root()
    alpha, beta, gamma = transcript.sample(), transcript.sample(), transcript.sample()
    quotient_root = root()
    t = transcript.sample()
    a = [transcript.next_scalar() for _ in range(4)]
    nxt = transcript.next_scalar()
    rho = transcript.sample()
    transcript.finish()

    w = [t]
    for k in range(m + 1):
        w.append(w[k] * w[k] + w[k])

    # The four cells of the row of t: a[0] + first a[1] + second (a[2] + first a[3]).
    theta = BETA[1]

    def cell(shift: K, second: bool) -> E:
        first, sec = t + E(shift), (w[1] + ONE if second else w[1])
        return a[0] + first * a[1] + sec * (a[2] + first * a[3])

    x, y, c, v = cell(K(0), False), cell(K(1), False), cell(theta, True), cell(theta + K(1), True)

    # The gate: v is the sum bit plus theta times the carry of x's bit, y's bit and c's carry.
    def bit(u: E) -> E:
        return u * (E(theta) * u + E(theta * theta))

    bx, by, carry = bit(x), bit(y), c * c + c
    gate = v + bx + by + carry + E(theta) * (bx * by + carry * (bx + by))

    # The public weight at t, and the target the weighted public bits must reach.
    b = coordinates(REGION)
    g2 = gamma * gamma
    gammas = [gamma, g2, g2 * g2]
    public = ONE
    for k in range(REGION, m):
        public = public * (ONE + w[k])
    for k in range(REGION):
        coordinate = w[k]
        for j in range(k + 1, REGION):
            coordinate = coordinate + E(b[j - k]) * w[j]
        if k == 0:
            slope = ONE + bit_weight(1)
        elif k == 1:
            slope = ONE
        elif k < 8:
            slope = ONE + bit_weight(1 << (k - 1))
        else:
            slope = ONE + gammas[k - 8]
        public = public * (ONE + coordinate * slope)
    target = s[0] + gamma * s[1] + g2 * (s[2] + gamma * s[3]) + gammas[2]

    tau = row_vanishing(m)
    rows = ZERO
    for k in range(m - 1):
        rows = rows + E(tau[k]) * w[k]
    d, d_next = alpha + x + beta * t, alpha + x + beta * nxt
    product = d * d_next
    copies = d + d_next + public * x * product

    denominators = [ONE + wk for wk in w] + [product + w[m], rows]
    total = ONE
    for value in denominators:
        total = total * value
    require(bool(total), "a denominator vanishes")
    inv = [value.inv() for value in denominators]
    u = [w[k] * inv[k] for k in range(m + 2)]
    copy_inverse, rows_inverse = inv[m + 2], inv[m + 3]
    middle = inv[2]
    for k in range(3, m):
        middle = middle * inv[k]
    wiring_scale = middle * inv[0] * inv[1]
    quotient_scale = wiring_scale * inv[m] * inv[m + 1]

    r2 = rho * rho
    opened = (ONE + r2) * (a[0] + rho * (a[0] + a[1])) + r2 * (a[2] + rho * (a[2] + a[3]))
    Y = E(0, 1)
    d0, d1 = ONE + Y, ONE + Y * Y
    y0, y1, scale = Y * d0.inv(), Y * Y * d1.inv(), (d0 * d1).inv()
    identities = (ONE + rho) * copies * rows + rho * product * gate
    return {
        "roots": [witness_root.hex(), quotient_root.hex()],
        "witness": ([rho, r2, *u[2 : m + 1]], opened * middle * inv[m]),
        "wiring": (u[:m], nxt * wiring_scale),
        "quotient": ([*u, w[m] * copy_inverse, rho, y0, y1], scale * quotient_scale * copy_inverse * rows_inverse * identities),
        "sum": ([ONE] * m + [ZERO] * 4 + [y0, y1], scale * target),
    }


def check(dump_dir: Path, name: str) -> None:
    meta = json.loads((dump_dir / f"{name}.json").read_text())
    statement, index_root = bytes.fromhex(meta["statement"]), bytes.fromhex(meta["index_root"])
    stream = dump_dir / f"{name}.stream"
    empty = dump_dir / f"{name}.merkle"
    empty.write_bytes(b"")

    def run(statement: bytes, index_root: bytes) -> dict:
        return reduce(Transcript(Proof.load(stream, empty), *seed(index_root, statement)), statement, meta["log_rows"])

    got = run(statement, index_root)
    as_e = lambda x: E(*x)  # noqa: E731
    require(got["roots"] == meta["roots"], "roots")
    for key in ("witness", "wiring", "quotient", "sum"):
        point, value = got[key]
        require([*point] == [as_e(p) for p in meta[key]["point"]], f"{key} point")
        require(value == as_e(meta[key]["value"]), f"{key} value")
    # The claims are bound to the statement and the circuit: change either and the claims change.
    for other_statement, other_root in ((bytes([statement[0] ^ 1]) + statement[1:], index_root), (statement, bytes([index_root[0] ^ 1]) + index_root[1:])):
        changed = run(other_statement, other_root)
        require(changed["quotient"][1] != got["quotient"][1] or changed["sum"][1] != got["sum"][1], "claims ignore the seed")
    print(json.dumps({"statement": name, "log_rows": meta["log_rows"], "claims_match_rust": True, "seed_binding_checked": True}))


if __name__ == "__main__":
    for name in sys.argv[2:]:
        check(Path(sys.argv[1]), name)
