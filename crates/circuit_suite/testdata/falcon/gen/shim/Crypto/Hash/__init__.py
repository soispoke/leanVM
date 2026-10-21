import hashlib


class _Shake:
    def __init__(self):
        self.buf = b""
        self.off = 0

    def update(self, data):
        assert self.off == 0
        self.buf += bytes(data)

    def read(self, n):
        out = hashlib.shake_256(self.buf).digest(self.off + n)[self.off:]
        self.off += n
        return out


class SHAKE256:
    @staticmethod
    def new(data=b""):
        s = _Shake()
        s.update(data)
        return s
