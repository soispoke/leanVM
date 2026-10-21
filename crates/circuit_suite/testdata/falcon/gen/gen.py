"""Generate Falcon-512 test vectors with tprest/falcon.py (the Python reference, with signing).

Usage: python3 -I gen.py <path to a tprest/falcon.py checkout (commit 5145a81)> <keys> <messages per key>
           > falcon512_vectors.json
The shim/ directory stands in for numpy (set_printoptions only), pycryptodome's SHAKE256 (hashlib) and beartype
(identity), which falcon.py imports. Messages are 32 bytes; s2 is decoded from the signature with falcon.py's
decompress, c and s1 recomputed with its HashToPoint and NTT multiplication.
"""
import sys, os, json, hashlib
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "shim"))
sys.path.insert(1, sys.argv[1])  # path to falcon.py checkout
from falcon import Falcon, HEAD_LEN, SALT_LEN, deserialize_to_poly
from encoding import decompress
from ntt import sub_zq, mul_zq
q = 12289

def nist_pk(h):
    # FIPS/NIST round-3 public key encoding: header 0x00 + logn, then 14-bit coefficients, MSB first.
    bits = "".join(format(c, "014b") for c in h)
    return bytes([0x09]) + int(bits, 2).to_bytes(len(bits) // 8, "big")

out = []
f = Falcon(512)
nkeys, nmsg = int(sys.argv[2]), int(sys.argv[3])
for k in range(nkeys):
    sk, vk = f.keygen()
    h = deserialize_to_poly(vk, 512)
    for j in range(nmsg):
        msg = hashlib.sha256(b"falcon test message %d %d" % (k, j) + os.urandom(8)).digest()
        sig = f.sign(sk, msg)
        assert f.verify(vk, msg, sig)
        salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
        s2 = decompress(sig[HEAD_LEN + SALT_LEN:], 666 - HEAD_LEN - SALT_LEN, 512)
        c = f.__hash_to_point__(msg, salt)
        s1 = sub_zq(c, mul_zq(s2, h))
        s1 = [(x + (q >> 1)) % q - (q >> 1) for x in s1]
        norm = sum(x * x for x in s1) + sum(x * x for x in s2)
        out.append({
            "h": h, "pk": nist_pk(h).hex(), "msg": msg.hex(), "nonce": salt.hex(),
            "sig": sig.hex(), "s2": s2, "c": c, "s1": s1, "norm": norm,
        })
        print("key", k, "msg", j, "norm", norm, file=sys.stderr)
json.dump(out, sys.stdout)
