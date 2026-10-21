"""The circuit format as a protocol would fix it: a description's bytes, what circuit they denote, and what
statement that circuit proves for some input. No field and no proof system: the relation is Boolean, and the
quotient argument (`quotient_verifier.py`) is one way to prove it.

    python3 format.py DIR NAME     # decodes DIR/NAME.qcd, evaluates it on DIR/NAME.inputs, compares DIR/NAME.statement
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

PUBLIC_ROWS, WORD_BITS, PUBLIC_BITS = 512, 128, 512
ZERO, ONE = "zero", "one"


class Invalid(Exception):
    """Not a description, or not a well-formed circuit."""


def varints(data: bytes, at: int):
    while True:
        value, shift = 0, 0
        while True:
            if at >= len(data) or shift > 63:
                raise Invalid("truncated varint")
            byte = data[at]
            at += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        yield value, at


def decode(data: bytes) -> tuple[int, list[tuple], list]:
    """The rows (three sources each, a source a constant or a row) and the 512 public sources."""
    if data[:4] != b"QCD1" or len(data) < 6:
        raise Invalid("magic")
    log_rows = data[4]
    if not 12 <= log_rows <= 32:
        raise Invalid("log_rows")
    stream = varints(data, 5)
    used, at = next(stream)
    if not PUBLIC_ROWS <= used <= 1 << log_rows:
        raise Invalid("used")
    public, at = [], 5
    for _ in range(PUBLIC_BITS):
        k, at = next(stream)
        if k >= 2 and k - 2 >= used:
            raise Invalid("public source")
        public.append(ZERO if k == 0 else ONE if k == 1 else k - 2)
    # The public rows: words 0 to 3 read the statement's bits, two a row; word 4 is a one then zeros; the rest zeros.
    rows: list[tuple] = []
    for r in range(PUBLIC_ROWS):
        word, pair = r // (WORD_BITS // 2), r % (WORD_BITS // 2)

        def bit(j: int):
            if word < 4:
                return public[256 * (word // 2) + 8 * (16 * (word % 2) + 15 - j // 8) + j % 8]
            return ONE if word == 4 and j == 0 else ZERO

        rows.append((bit(2 * pair), bit(2 * pair + 1), ZERO))
    for r in range(PUBLIC_ROWS, used):
        sources = []
        for _ in range(3):
            k, at = next(stream)
            if k >= 2 and k - 2 > r:
                raise Invalid(f"source of row {r}")
            sources.append(ZERO if k == 0 else ONE if k == 1 else r - (k - 2))
        rows.append(tuple(sources))
    if at != len(data):
        raise Invalid("trailing bytes")
    rows.extend([(ZERO, ZERO, ZERO)] * ((1 << log_rows) - used))
    return log_rows, rows, public


def check(rows: list[tuple], public: list) -> list[int]:
    """Well-formedness, what the soundness theorem's circuit meaning assumes; returns the input rows in order.
    An input row reads its own bit and two zeros; every other row reads constants or earlier non-public rows;
    the public rows are read by no row, and each public bit is a row that reads one source and two zeros."""
    inputs = []
    for r, (x, y, c) in enumerate(rows):
        if (x, y, c) == (r, ZERO, ZERO):
            inputs.append(r)
            continue
        for s in (x, y, c):
            if isinstance(s, int) and not (PUBLIC_ROWS <= s < r or (r < PUBLIC_ROWS and s >= PUBLIC_ROWS)):
                raise Invalid(f"row {r} reads row {s}")
    for s in public:
        if not isinstance(s, int) or rows[s][1:] != (ZERO, ZERO):
            raise Invalid("a public bit is a row reading one source and two zeros")
    return inputs


def evaluate(rows: list[tuple], public: list, inputs: list[int], bits: list[int]) -> bytes:
    """Each row's bit and carry: the sum and carry of its x's bit, its y's bit and its c's carry."""
    value = [0] * len(rows)  # bit | carry << 1
    for r, b in zip(inputs, bits):
        value[r] = b

    def read(s, carry: bool) -> int:
        if s == ZERO:
            return 0
        if s == ONE:
            return 0 if carry else 1  # the constant one has no carry
        return value[s] >> 1 if carry else value[s] & 1

    is_input = set(inputs)
    for r in range(PUBLIC_ROWS, len(rows)):
        if r in is_input:
            continue
        x, y, c = rows[r]
        a, b, d = read(x, False), read(y, False), read(c, True)
        value[r] = (a ^ b ^ d) | ((a & b) | (d & (a ^ b))) << 1
    out = bytearray(64)
    for i, s in enumerate(public):
        out[i // 8] |= (value[s] & 1) << (i % 8)
    return bytes(out)


def identity(data: bytes) -> bytes:
    """An application's identity: its description's digest, under the format's version."""
    return hashlib.blake2s(b"leanccs-format-v1" + data).digest()


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    for name in sys.argv[2:]:
        data = (directory / f"{name}.qcd").read_bytes()
        log_rows, rows, public = decode(data)
        inputs = check(rows, public)
        packed = (directory / f"{name}.inputs").read_bytes()
        bits = [(packed[i // 8] >> (i % 8)) & 1 for i in range(len(inputs))]
        statement = evaluate(rows, public, inputs, bits)
        assert statement == (directory / f"{name}.statement").read_bytes(), "the statement differs from Rust's"
        print({"statement": name, "log_rows": log_rows, "inputs": len(inputs), "statement_matches_rust": True, "identity": identity(data).hex()})
