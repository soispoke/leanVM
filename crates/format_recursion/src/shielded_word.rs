//! Shielded relation using the same shared-byte lowering as Falcon.
use crate::{native_hash::Word, word_lowering::Lowering};
use primitives::field::F192;
struct C {
    lower: Lowering,
}
impl C {
    fn k(&mut self, v: u64) -> Word {
        self.lower.b.constant(v)
    }
    fn v(&self, w: Word) -> u64 {
        self.lower.b.value(w).c0
    }
    fn xor(&mut self, a: Word, b: Word) -> Word {
        let one = self.lower.b.one();
        self.lower.b.gate(a, one, b)
    }
    fn mul(&mut self, a: Word, b: Word) -> Word {
        let z = self.lower.b.zero();
        self.lower.b.gate(a, b, z)
    }
    fn not(&mut self, a: Word) -> Word {
        let one = self.lower.b.one();
        self.xor(a, one)
    }
    fn zero(&mut self, a: Word) -> Word {
        let z = self.lower.b.input(u64::from(self.lower.b.value(a) == F192::ZERO));
        let inverse = self.lower.b.scalar(self.lower.b.value(a).inv());
        let product = self.mul(a, inverse);
        let nz = self.not(z);
        self.lower.b.assert_eq(product, nz);
        let az = self.mul(a, z);
        let zero = self.lower.b.zero();
        self.lower.b.assert_eq(az, zero);
        z
    }
    fn eq(&mut self, a: &[Word], b: &[Word]) -> Word {
        assert_eq!(a.len(), b.len());
        let mut ok = self.lower.b.one();
        for (&x, &y) in a.iter().zip(b) {
            let diff = self.xor(x, y);
            let z = self.zero(diff);
            ok = self.mul(ok, z);
        }
        ok
    }
    fn nonzero(&mut self, a: &[Word]) -> Word {
        let mut zero = self.lower.b.one();
        for &w in a {
            let z = self.zero(w);
            zero = self.mul(zero, z);
        }
        self.not(zero)
    }
    fn assert(&mut self, w: Word) {
        let one = self.lower.b.one();
        self.lower.b.assert_eq(w, one);
    }
    fn pack(&mut self, bytes: &[Word]) -> Word {
        let mut acc = self.lower.b.zero();
        for (i, &w) in bytes.iter().enumerate() {
            let weight = self.k(1u64 << (8 * i));
            acc = self.lower.b.gate(w, weight, acc);
        }
        acc
    }
    fn unpack(&mut self, w: Word) -> Vec<Word> {
        let v = self.v(w);
        let bytes: Vec<_> = (0..8).map(|i| self.lower.byte(((v >> (8 * i)) & 255) as u8)).collect();
        let packed = self.pack(&bytes);
        self.lower.b.assert_eq(w, packed);
        bytes
    }
    fn hash(&mut self, tag: Option<u8>, parts: &[&[Word]]) -> Vec<Word> {
        let mut msg = Vec::new();
        if let Some(t) = tag {
            msg.push(self.k(t as u64));
        }
        for p in parts {
            msg.extend_from_slice(p);
        }
        let len = msg.len();
        let blocks = len.div_ceil(64).max(1);
        let iv = flock::hash::param_iv();
        let mut h = std::array::from_fn(|i| self.k(u64::from(iv[2 * i]) | (u64::from(iv[2 * i + 1]) << 32)));
        for block in 0..blocks {
            let mut bytes = msg[(block * 64).min(len)..((block + 1) * 64).min(len)].to_vec();
            let z = self.lower.b.zero();
            bytes.resize(64, z);
            let m = std::array::from_fn(|i| self.pack(&bytes[i * 8..i * 8 + 8]));
            let counter = self.k(if block + 1 == blocks {
                len as u64
            } else {
                64 * (block as u64 + 1)
            });
            let flags = self.k(if block + 1 == blocks { u32::MAX as u64 } else { 0 });
            h = self.lower.b.compress(h, m, counter, flags);
        }
        h.into_iter().flat_map(|w| self.unpack(w)).collect()
    }
    fn add(&mut self, a: &[Word], b: &[Word]) -> Vec<Word> {
        let mut a = a.to_vec();
        a.resize(17, Word::ZERO);
        let mut b = b.to_vec();
        b.resize(17, Word::ZERO);
        let (sum, carry) = self.lower.add(&a, &b);
        self.lower.b.assert_eq(carry, Word::ZERO);
        sum
    }
}
pub fn application(payload: &[u8]) -> Lowering {
    assert_eq!(payload.len(), circuit_suite::shielded_blake2s::INPUT_BYTES);
    let mut c = C {
        lower: Lowering::default(),
    };
    let input: Vec<_> = payload.iter().map(|&v| c.lower.byte(v)).collect();
    let root = &input[..32];
    let domain = &input[32..64];
    let mut ok = Vec::new();
    let mut nfs = Vec::new();
    let mut in_values = Vec::new();
    let mut funded = Vec::new();
    for k in 0..2 {
        let at = 136 + k * 724;
        let note = &input[at..at + 724];
        let key = &note[..32];
        let rho = &note[32..64];
        let value = &note[64..80];
        let pk = c.hash(Some(1), &[key]);
        let inner = c.hash(Some(5), &[&pk, rho]);
        let cm = c.hash(Some(2), &[&inner, value]);
        let mut bits = Vec::new();
        for &w in note[80..84].iter().rev() {
            bits.extend(c.lower.b.bits(w, 8));
        }
        let z = c.lower.b.zero();
        for &bit in &bits[20..] {
            c.lower.b.assert_eq(bit, z);
        }
        let mut current = cm.clone();
        for (level, &bit) in bits[..20].iter().enumerate() {
            let sibling = &note[84 + 32 * level..84 + 32 * (level + 1)];
            let mut left = Vec::new();
            let mut right = Vec::new();
            for (&a, &b) in current.iter().zip(sibling) {
                let diff = c.xor(a, b);
                let swap = c.mul(bit, diff);
                left.push(c.xor(a, swap));
                right.push(c.xor(b, swap));
            }
            current = c.hash(Some(4), &[&left, &right]);
        }
        let occurrence = c.hash(Some(7), &[&cm, &note[80..84]]);
        let nk = c.hash(Some(6), &[domain, key]);
        nfs.push(c.hash(Some(3), &[&nk, &occurrence]));
        let nonzero = c.nonzero(value);
        let member = c.eq(&current, root);
        let not_member = c.not(member);
        let invalid = c.mul(nonzero, not_member);
        let valid = c.not(invalid);
        ok.push(valid);
        funded.push(nonzero);
        in_values.push(value.iter().rev().copied().collect::<Vec<_>>());
    }
    let mut cms = Vec::new();
    let mut out_values = Vec::new();
    for k in 0..2 {
        let out = &input[1584 + 48 * k..1584 + 48 * (k + 1)];
        let inner = &out[..32];
        let value = &out[32..48];
        cms.push(c.hash(Some(2), &[inner, value]));
        let mut sink0 = vec![c.lower.b.zero(); 32];
        sink0[31] = c.k(1);
        let mut sink1 = vec![c.lower.b.zero(); 32];
        sink1[31] = c.k(2);
        let is0 = c.eq(inner, &sink0);
        let is1 = c.eq(inner, &sink1);
        let own = if k == 0 { is0 } else { is1 };
        let sink = c.xor(is0, is1);
        let nz = c.nonzero(value);
        let empty = c.not(nz);
        let notown = c.not(own);
        let bad = c.mul(empty, notown);
        ok.push(c.not(bad));
        let bad = c.mul(nz, sink);
        ok.push(c.not(bad));
        out_values.push(value.iter().rev().copied().collect::<Vec<_>>());
    }
    let both_empty = {
        let a = c.not(funded[0]);
        let b = c.not(funded[1]);
        c.mul(a, b)
    };
    ok.push(c.not(both_empty));
    let lhs = c.add(&in_values[0], &in_values[1]);
    let rhs = c.add(&out_values[0], &out_values[1]);
    let amount: Vec<_> = input[64..80].iter().rev().copied().collect();
    let fee: Vec<_> = input[80..96].iter().rev().copied().collect();
    let rhs = c.add(&rhs, &amount);
    let rhs = c.add(&rhs, &fee);
    ok.push(c.eq(&lhs, &rhs));
    ok.push(c.nonzero(&input[116..136]));
    let nz_amount = c.nonzero(&input[64..80]);
    let nz_recipient = c.nonzero(&input[96..116]);
    let diff = c.xor(nz_amount, nz_recipient);
    ok.push(c.not(diff));
    let same = c.eq(&nfs[0], &nfs[1]);
    ok.push(c.not(same));
    let same = c.eq(&cms[0], &cms[1]);
    ok.push(c.not(same));
    for w in ok {
        c.assert(w);
    }
    let statement = c.hash(Some(8), &[&nfs[0], &nfs[1], &cms[0], &cms[1], &input[..136]]);
    let digest = c.hash(None, &[&statement]);
    let output: [u8; 32] = std::array::from_fn(|i| c.v(digest[i]) as u8);
    for bytes in digest.chunks(8) {
        let w = c.pack(bytes);
        c.lower.b.expose(w);
    }
    assert_eq!(
        output,
        primitives::hash::hash(&circuit_suite::shielded_blake2s::reference::verify(payload).unwrap())
    );
    c.lower.b.keccak_f([Word::ZERO; 25]);
    c.lower
}
