//! ECDSA signature verification over secp256k1.
//!
//! # Statement
//! Public: the message hash `z` and the public key `Q`; private: the signature `(r, s)`. A hash would be needed to
//! fit all of `Q` beside `z` and a validity bit in 64 bytes, so the key is bound by its x-coordinate's low 248 bits
//! and its y-coordinate's parity:
//! - bytes `0..32`: `z`, the 32-byte hash, big-endian (used as the integer `z`, reduced modulo `n` by the checks);
//! - bytes `32..63`: the low 248 bits of `Q.x` (bytes `1..32` of its big-endian encoding);
//! - byte `63`: bit 0 the validity bit, bit 1 the parity of `Q.y`.
//!
//! `valid = 1` proves: there are a point `Q` on the curve with those x bits and that parity, and `1 <= r, s < n`,
//! with `x(u1 G + u2 Q) = r (mod n)` for `u1 = z / s`, `u2 = r / s (mod n)` (standard ECDSA verification). The
//! only slack against an exact key is the top byte of `Q.x`: another key matching the statement must agree with
//! `Q` on 248 bits of x and be one whose signature the prover has, about `2^248` work to find.
//!
//! # Verification
//! - `w = s^-1 (mod n)` by a hint; `u1 = z w`, `u2 = r w` are never materialised: hints `k1..k4` with
//!   `k1 + k2 lambda = z w` and `k3 + k4 lambda = r w (mod n)` (GLV, `lambda` the endomorphism's eigenvalue,
//!   `phi(x, y) = (beta x, y) = lambda (x, y)`) are checked directly against the products. Each `k` is odd with
//!   `|k| < 2^130`, written in [`DIGITS`] signed digits `+-1`: `k = 2 B - (2^DIGITS - 1)` for a hint `B`.
//! - `R = k1 G + k2 phi(G) + k3 Q + k4 phi(Q)` by a joint left-to-right loop: every digit position adds one of
//!   sixteen points `+-(G + e2 phi(G) + e3 Q + e4 phi(Q))` (eight computed once, the sign folded into the next
//!   congruence), with the combined double-and-add `2P + T = (P + T) + P` of Eisenträger-Lauter-Montgomery: five
//!   products a digit (`lambda1 (xT - xP)`, `lambda1^2`, `(lambda1 + lambda2)(x3 - xP)`, `lambda2^2`,
//!   `lambda2 (xP - x4)`), all affine with hinted slopes and coordinates, no inversion.
//! - `R.x = r` or `R.x = r + n` (canonical `R.x < p`).
//!
//! # Soundness
//! Every congruence holds over the integers for every hint ([`crate::nonnative::Nn::congruence`]). The affine
//! formulas are the group law when their slopes are determined, that is when the x-coordinates differ: each
//! addition checks `x2 != x1` (canonical coordinates, `x2 + p - x1 != p`), and the combined step also `x3 != xP`.
//! Doubling never occurs alone (no `y = 0` case). Starting from a table point and adding table points, every
//! accumulator is a curve point by induction (`Q` is checked on the curve; secp256k1 has cofactor 1), so the end
//! point is `k1 G + k2 phi(G) + k3 Q + k4 phi(Q) = u1 G + u2 Q`, which is not the point at infinity (an affine
//! result exists). A sum hitting an excluded case (equal x-coordinates) makes `valid = 0`: for honest random
//! instances this has negligible probability, so it is a completeness limitation, never a soundness one. The
//! loop starts from a fixed point `Off` of unknown discrete logarithm ([`offset_point`]) and subtracts the
//! constant `2^DIGITS Off` at the end, so no partial sum is the point at infinity (starting from a table point
//! instead, the top two digit vectors of short scalars cancel and the first step meets `T = -P`).
//!
//! # Costs (rows, measured by `row_breakdown`)
//! 42,795,741 rows (`2^25.35`, closed on `2^26`), 355,256 free inputs: scalars (`1/s`, two GLV checks) 243,217;
//! key on the curve 151,259; table (`phi(Q)`, two sums, eight points) 1,905,818; selection 8,707 a digit; the 130
//! combined double-and-add steps 301,288 each (39,167,466: three 256 x 257 products, two squares, five
//! quotients); the end (offset subtracted, `x(R)` compared) 191,267.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};

use crate::nonnative::{
    Acc, Int, Modulus, Nn, Term, add_words, any, eq_words, lt_const, secp256k1_n, secp256k1_p, to_word,
};
use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload};

/// Signed digits of each GLV scalar.
pub const DIGITS: usize = 130;

fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}

/// The endomorphism's field constant: `phi(x, y) = (beta x, y)`.
pub fn beta() -> BigUint {
    hex("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee")
}

/// The eigenvalue: `phi(P) = lambda P`.
pub fn lambda() -> BigUint {
    hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72")
}

pub fn generator() -> (BigUint, BigUint) {
    (
        hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    )
}

// ----------------------------------------------------------------------------------------------------------------
// Native affine arithmetic modulo p (for hints; the statement comes from k256).

fn fp() -> BigUint {
    secp256k1_p().p
}

fn inv(a: &BigUint, m: &BigUint) -> BigUint {
    a.modpow(&(m - 2u32), m)
}

fn sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    ((a % m) + m - (b % m)) % m
}

/// A native affine point (no infinity: the circuit never represents it).
pub type Pt = (BigUint, BigUint);

pub fn native_add(a: &Pt, b: &Pt) -> Pt {
    let p = fp();
    let l = sub(&b.1, &a.1, &p) * inv(&sub(&b.0, &a.0, &p), &p) % &p;
    let x = sub(&sub(&(&l * &l % &p), &a.0, &p), &b.0, &p);
    let y = sub(&(&l * sub(&a.0, &x, &p) % &p), &a.1, &p);
    (x, y)
}

pub fn native_double(a: &Pt) -> Pt {
    let p = fp();
    let l = BigUint::from(3u32) * &a.0 * &a.0 % &p * inv(&(BigUint::from(2u32) * &a.1 % &p), &p) % &p;
    let x = sub(&(&l * &l % &p), &(BigUint::from(2u32) * &a.0), &p);
    let y = sub(&(&l * sub(&a.0, &x, &p) % &p), &a.1, &p);
    (x, y)
}

/// The loop's starting point, of unknown discrete logarithm: the first x at or above SHA-256 of a label with
/// `x^3 + 7` a square, and the even root.
pub fn offset_point() -> Pt {
    use sha2::{Digest, Sha256};
    let p = fp();
    let mut x = BigUint::from_bytes_be(&Sha256::digest(b"circuit_suite secp256k1 ecdsa offset")) % &p;
    loop {
        let rhs = (&x * &x * &x + 7u32) % &p;
        let y = rhs.modpow(&((&p + 1u32) / 4u32), &p);
        if &y * &y % &p == rhs {
            let y = if y.bit(0) { &p - y } else { y };
            return (x, y);
        }
        x += 1u32;
    }
}

pub fn native_neg(a: &Pt) -> Pt {
    let p = fp();
    (a.0.clone(), sub(&BigUint::zero(), &a.1, &p))
}

pub fn native_phi(a: &Pt) -> Pt {
    let p = fp();
    (&a.0 * beta() % &p, a.1.clone())
}

/// Signed GLV decomposition `k = k1 + k2 lambda (mod n)`, both odd, `|k1|, |k2| < 2^DIGITS`.
pub fn glv(k: &BigUint) -> (BigInt, BigInt) {
    let n = BigInt::from(secp256k1_n().p);
    let a1 = BigInt::from(hex("3086d221a7d46bcde86c90e49284eb15"));
    let b1 = -BigInt::from(hex("e4437ed6010e88286f547fa90abfe4c3"));
    let a2 = BigInt::from(hex("114ca50f7a8e2f3f657c1108d9d44cfd8"));
    let b2 = a1.clone();
    let k = BigInt::from(k.clone());
    let round = |x: BigInt| -> BigInt {
        // Nearest integer to x / n.
        let (q, r) = (&x / &n, &x % &n);
        if BigInt::from(2) * r.abs() >= n {
            q + x.signum()
        } else {
            q
        }
    };
    let c1 = round(&b2 * &k);
    let c2 = round(-&b1 * &k);
    let k1 = &k - &c1 * &a1 - &c2 * &a2;
    let k2 = -&c1 * &b1 - &c2 * &b2;
    // Make both odd by adding a lattice vector (a + b lambda = 0 mod n); v1, v2 reduce to independent parities.
    let mut best: Option<(BigInt, BigInt)> = None;
    for (i, j) in (-2..=2).flat_map(|i| (-2..=2).map(move |j| (i, j))) {
        let (i, j) = (BigInt::from(i), BigInt::from(j));
        let (x, y): (BigInt, BigInt) = (&k1 + &a1 * &i + &a2 * &j, &k2 + &b1 * &i + &b2 * &j);
        if x.bit(0) && y.bit(0) {
            let m = x.abs().max(y.abs());
            if best.as_ref().is_none_or(|(bx, by)| m < bx.abs().max(by.abs())) {
                best = Some((x, y));
            }
        }
    }
    let (x, y) = best.unwrap();
    let lam = BigInt::from(lambda());
    assert_eq!(((&x + &y * lam - &k) % &n + &n) % &n, BigInt::zero());
    assert!(
        x.bits() < DIGITS as u64 && y.bits() < DIGITS as u64,
        "decomposition too long: {} {} (from {} {})",
        x.bits(),
        y.bits(),
        k1.bits(),
        k2.bits()
    );
    (x, y)
}

/// The digit word `B` of an odd `k = 2 B - (2^DIGITS - 1)`.
pub fn digits_of(k: &BigInt) -> BigUint {
    let v: BigInt = (k + (BigInt::one() << DIGITS) - BigInt::one()) / 2;
    v.to_biguint().unwrap()
}

// ----------------------------------------------------------------------------------------------------------------
// The circuit.

/// A point: canonical x (`max < p`), y bounded.
#[derive(Clone)]
struct P {
    x: Int,
    y: Int,
}

/// Rows by part.
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub scalars: usize,
    pub key: usize,
    pub table: usize,
    pub select: usize,
    pub steps: usize,
    pub n_steps: usize,
    pub finish: usize,
}

struct Ec<'a, 'b> {
    nn: &'b mut Nn<'a>,
    p: Modulus,
}

impl Ec<'_, '_> {
    fn v(&self, f: impl FnOnce() -> BigUint) -> Option<BigUint> {
        self.nn.value_of(f)
    }

    /// `a + p - b` exactly, for a canonical `b`: congruent to `a - b`, in `[1, a.max + p]`.
    fn sub_p(&mut self, a: &Int, b: &Int) -> Int {
        debug_assert!(b.max < self.p.p);
        let max = &a.max + &self.p.p;
        let width = max.bits() as usize;
        let mut acc = Acc::new(width);
        acc.word(&a.w, 0);
        acc.neg_word(&b.w, 0);
        acc.konst(&BigInt::from(self.p.p.clone()));
        let w = to_word(self.nn.c, acc);
        let v = self.v(|| a.val() + &self.p.p - b.val());
        Int { w, max, v }
    }

    /// Whether a value in `[1, 2p)` is not `p`, that is not `0 (mod p)` (recorded).
    fn check_ne_p(&mut self, d: &Int) {
        let pw: Word = (0..d.w.len()).map(|i| Wire::constant(self.p.p.bit(i as u64))).collect();
        let e = eq_words(self.nn.c, &d.w, &pw);
        self.nn.check(e.not());
    }

    fn canonical(&mut self, v: Option<BigUint>) -> Int {
        let m = self.p.clone();
        self.nn.residue_hint(&m, || v.unwrap())
    }

    fn congruence(&mut self, terms: &[Term]) {
        let m = self.p.clone();
        let ok = self.nn.congruence(&m, terms);
        self.nn.check(ok);
    }

    /// `s1 P1 + s2 P2` for signs `s1, s2` applied to the y-coordinates: hints `lambda`, `x3`, `y3`.
    fn add(&mut self, a: &P, s1: i64, b: &P, s2: i64) -> P {
        let p = self.p.p.clone();
        let sy = |y: &BigUint, s: i64| if s > 0 { y % &p } else { sub(&BigUint::zero(), y, &p) };
        let r = self.v(|| {
            let (pa, pb) = (
                (a.x.val().clone(), sy(a.y.val(), s1)),
                (b.x.val().clone(), sy(b.y.val(), s2)),
            );
            let l = sub(&pb.1, &pa.1, &p) * inv(&sub(&pb.0, &pa.0, &p), &p) % &p;
            let x3 = sub(&sub(&(&l * &l % &p), &pa.0, &p), &pb.0, &p);
            let y3 = sub(&(&l * sub(&pa.0, &x3, &p) % &p), &pa.1, &p);
            pack(&[l, x3, y3])
        });
        let bits = self.p.bits;
        let part = |k: usize| r.as_ref().map(|r| unpack(r, k));
        let l = {
            let v = part(0);
            self.nn.hint(bits, || v.unwrap())
        };
        let x3 = self.canonical(part(1));
        let y3 = self.canonical(part(2));
        let dx = self.sub_p(&b.x, &a.x);
        self.check_ne_p(&dx);
        self.congruence(&[Term::Mul(&l, &dx, 0), Term::Lin(&b.y, -s2), Term::Lin(&a.y, s1)]);
        self.congruence(&[
            Term::Sq(&l, 0),
            Term::Lin(&a.x, -1),
            Term::Lin(&b.x, -1),
            Term::Lin(&x3, -1),
        ]);
        let d13 = self.sub_p(&a.x, &x3);
        self.congruence(&[Term::Mul(&l, &d13, 0), Term::Lin(&y3, -1), Term::Lin(&a.y, -s1)]);
        P { x: x3, y: y3 }
    }

    /// `2 P + T` with `T = (xt, sign * ye)`, `sign = 2 d - 1`: `(P + T) + P`, hints `lambda1, x3, lambda2, x4, y4`.
    fn double_add(&mut self, a: &P, xt: &Int, ye: &Int, d: &Int) -> P {
        let p = self.p.p.clone();
        let r = self.v(|| {
            let yt = if d.val().is_one() {
                ye.val() % &p
            } else {
                sub(&BigUint::zero(), ye.val(), &p)
            };
            let (xp, yp) = (a.x.val().clone(), a.y.val() % &p);
            let l1 = sub(&yt, &yp, &p) * inv(&sub(xt.val(), &xp, &p), &p) % &p;
            let x3 = sub(&sub(&(&l1 * &l1 % &p), &xp, &p), xt.val(), &p);
            let t = BigUint::from(2u32) * &yp * inv(&sub(&x3, &xp, &p), &p) % &p;
            let l2 = sub(&sub(&BigUint::zero(), &l1, &p), &t, &p);
            let x4 = sub(&sub(&(&l2 * &l2 % &p), &xp, &p), &x3, &p);
            let y4 = sub(&(&l2 * sub(&xp, &x4, &p) % &p), &yp, &p);
            pack(&[l1, x3, l2, x4, y4])
        });
        let bits = self.p.bits;
        let part = |k: usize| r.as_ref().map(|r| unpack(r, k));
        let l1 = {
            let v = part(0);
            self.nn.hint(bits, || v.unwrap())
        };
        let x3 = self.canonical(part(1));
        let l2 = {
            let v = part(2);
            self.nn.hint(bits, || v.unwrap())
        };
        let x4 = self.canonical(part(3));
        let y4 = {
            let v = part(4);
            self.nn.hint(bits, || v.unwrap())
        };
        // lambda1 (xT - xP) = sign ye - yP, with sign ye = 2 d ye - ye.
        let dx = self.sub_p(xt, &a.x);
        self.check_ne_p(&dx);
        self.congruence(&[
            Term::Mul(&l1, &dx, 0),
            Term::Gated(d, ye, -2),
            Term::Lin(ye, 1),
            Term::Lin(&a.y, 1),
        ]);
        // lambda1^2 = x3 + xP + xT.
        self.congruence(&[
            Term::Sq(&l1, 0),
            Term::Lin(&x3, -1),
            Term::Lin(&a.x, -1),
            Term::Lin(xt, -1),
        ]);
        // (lambda1 + lambda2)(x3 - xP) = -2 yP, with x3 != xP.
        let d3 = self.sub_p(&x3, &a.x);
        self.check_ne_p(&d3);
        let sl = self.nn.add(&l1, &l2);
        self.congruence(&[Term::Mul(&sl, &d3, 0), Term::Lin(&a.y, 2)]);
        // lambda2^2 = x4 + x3 + xP.
        self.congruence(&[
            Term::Sq(&l2, 0),
            Term::Lin(&x4, -1),
            Term::Lin(&x3, -1),
            Term::Lin(&a.x, -1),
        ]);
        // lambda2 (xP - x4) = y4 + yP.
        let d4 = self.sub_p(&a.x, &x4);
        self.congruence(&[Term::Mul(&l2, &d4, 0), Term::Lin(&y4, -1), Term::Lin(&a.y, -1)]);
        P { x: x4, y: y4 }
    }
}

/// Values packed into one (300 bits a value).
fn pack(v: &[BigUint]) -> BigUint {
    v.iter().rev().fold(BigUint::zero(), |acc, x| (acc << 300) | x)
}

fn unpack(r: &BigUint, k: usize) -> BigUint {
    (r >> (300 * k)) % (BigUint::one() << 300)
}

fn const_point(q: &Pt) -> P {
    P {
        x: Int::constant(&q.0),
        y: Int::constant(&q.1),
    }
}

/// The eight table points `G + e2 phi(G) + e3 Q + e4 phi(Q)`, index bits `(e2, e3, e4)` (bit set: `+`).
pub fn native_table(q: &Pt) -> Vec<Pt> {
    let g = generator();
    let (pg, pq) = (native_phi(&g), native_phi(q));
    (0..8)
        .map(|i| {
            let s = |b: usize, x: &Pt| if (i >> b) & 1 == 1 { x.clone() } else { native_neg(x) };
            let c = native_add(&g, &s(0, &pg));
            let v = native_add(&s(1, q), &s(2, &pq));
            native_add(&c, &v)
        })
        .collect()
}

/// The inputs of an instance: hash, signature, key.
#[derive(Clone, Debug)]
pub struct Inputs {
    pub z: BigUint,
    pub r: BigUint,
    pub s: BigUint,
    pub qx: BigUint,
    pub qy: BigUint,
}

/// The verification circuit: public bits, free inputs (when `inst` is given), rows by part.
pub fn circuit(c: &mut Ckt, inst: Option<&Inputs>) -> (Vec<Wire>, Vec<bool>, Stats) {
    let mut nn = match inst {
        Some(_) => Nn::with_witness(c),
        None => Nn::new(c),
    };
    let mut st = Stats::default();
    let (pm, nm) = (secp256k1_p(), secp256k1_n());
    let get = |f: fn(&Inputs) -> &BigUint| -> BigUint { inst.map(f).cloned().unwrap_or_default() };
    let mark = |nn: &Nn| nn.c.rows();

    // Inputs.
    let z = nn.hint(256, || get(|i| &i.z));
    let r = nn.hint(256, || get(|i| &i.r));
    let s = nn.hint(256, || get(|i| &i.s));
    let qx = nn.residue_hint(&pm, || get(|i| &i.qx));
    let qy = nn.residue_hint(&pm, || get(|i| &i.qy));

    // Scalars: 1 <= r, s < n; w = 1/s; k1 + k2 lambda = z w, k3 + k4 lambda = r w (mod n).
    let r0 = mark(&nn);
    for x in [&r, &s] {
        let lt = lt_const(nn.c, &x.w, &nm.p);
        nn.check(lt);
        let nz = any(nn.c, &x.w);
        nn.check(nz);
    }
    let mut r_mod = r.clone();
    r_mod.max = &nm.p - 1u32;
    let w = nn.invmod(&nm, &s);
    let ks: Vec<(BigInt, BigInt)> = match nn.has_values() {
        true => {
            let (zv, rv, wv) = (z.val().clone(), r.val().clone(), w.val().clone());
            vec![glv(&(&zv * &wv % &nm.p)), glv(&(&rv * &wv % &nm.p))]
        }
        false => vec![],
    };
    let mut digits = vec![];
    for (j, u) in [&z, &r_mod].into_iter().enumerate() {
        let b1 = nn.hint(DIGITS, || digits_of(&ks[j].0));
        let b2 = nn.hint(DIGITS, || digits_of(&ks[j].1));
        // (2 B1 - (2^D - 1)) + (2 B2 - (2^D - 1)) lambda - u w = 0 (mod n).
        let lam = BigInt::from(lambda());
        let off = (BigInt::one() << DIGITS) - 1;
        let ok = nn.congruence(
            &nm,
            &[
                Term::Lin(&b1, 2),
                Term::Scaled(&b2, BigInt::from(2) * &lam),
                Term::Const(-&off * (BigInt::one() + &lam)),
                Term::NegMul(u, &w, 0),
            ],
        );
        nn.check(ok);
        digits.push(b1);
        digits.push(b2);
    }
    st.scalars = mark(&nn) - r0;

    // The key on the curve: qy^2 = qx^3 + 7.
    let r0 = mark(&nn);
    let t = nn.reduce_to(&pm, &[Term::Sq(&qx, 0)], false);
    let u = nn.reduce_to(&pm, &[Term::Mul(&t, &qx, 0)], false);
    let ok = nn.congruence(
        &pm,
        &[Term::Sq(&qy, 0), Term::Lin(&u, -1), Term::Const(BigInt::from(-7))],
    );
    nn.check(ok);
    st.key = mark(&nn) - r0;

    // The table.
    let r0 = mark(&nn);
    let mut ec = Ec {
        nn: &mut nn,
        p: pm.clone(),
    };
    let bx = {
        let m = ec.p.clone();
        ec.nn.reduce(&m, &[Term::Scaled(&qx, BigInt::from(beta()))])
    };
    let q = P {
        x: qx.clone(),
        y: qy.clone(),
    };
    let pq = P { x: bx, y: qy.clone() };
    let v1 = ec.add(&q, 1, &pq, 1);
    let v2 = ec.add(&q, 1, &pq, -1);
    let g = generator();
    let pg = native_phi(&g);
    let cs = [
        const_point(&native_add(&g, &native_neg(&pg))),
        const_point(&native_add(&g, &pg)),
    ];
    let table: Vec<P> = (0..8)
        .map(|i| {
            let (e2, e3, e4) = (i & 1, (i >> 1) & 1, (i >> 2) & 1);
            let (v, sign) = match (e3, e4) {
                (1, 1) => (&v1, 1),
                (1, 0) => (&v2, 1),
                (0, 1) => (&v2, -1),
                _ => (&v1, -1),
            };
            ec.add(&cs[e2], 1, v, sign)
        })
        .collect();
    // First-level differences of the selection trees, shared by every digit.
    let diffs: Vec<(Word, Word)> = (0..4)
        .map(|k| {
            let (a, b) = (&table[2 * k], &table[2 * k + 1]);
            (
                a.x.w.iter().zip(&b.x.w).map(|(&x, &y)| ec.nn.c.xor(x, y)).collect(),
                a.y.w.iter().zip(&b.y.w).map(|(&x, &y)| ec.nn.c.xor(x, y)).collect(),
            )
        })
        .collect();
    st.table = mark(ec.nn) - r0;
    let ymax = table.iter().map(|t| t.y.max.clone()).max().unwrap();

    // The loop, high digit first, from the offset point (so that no partial sum is the point at infinity or
    // meets a table point but with negligible probability).
    let mut acc = const_point(&offset_point());
    for j in (0..DIGITS).rev() {
        let r0 = mark(ec.nn);
        let b: Vec<Wire> = digits.iter().map(|d| d.w[j]).collect();
        let bv: Vec<u32> = digits
            .iter()
            .map(|d| d.v.as_ref().map_or(0, |v| v.bit(j as u64) as u32))
            .collect();
        // Index bits e_k = [b1 == bk]: d1 e_k = d_k.
        let sel: Vec<Wire> = (1..4).map(|k| ec.nn.c.xor3(b[0], b[k], Wire::ONE)).collect();
        let idx = (1..4).map(|k| ((bv[0] == bv[k]) as usize) << (k - 1)).sum::<usize>();
        let pick = |ec: &mut Ec, coord: usize| -> Word {
            let lvl1: Vec<Word> = (0..4)
                .map(|k| {
                    let lo = if coord == 0 {
                        &table[2 * k].x.w
                    } else {
                        &table[2 * k].y.w
                    };
                    let d = if coord == 0 { &diffs[k].0 } else { &diffs[k].1 };
                    lo.iter()
                        .zip(d)
                        .map(|(&l, &dd)| {
                            let t = ec.nn.c.and(sel[0], dd);
                            ec.nn.c.xor(l, t)
                        })
                        .collect()
                })
                .collect();
            let l2a = ec.nn.c.mux_word(sel[1], &lvl1[1], &lvl1[0]);
            let l2b = ec.nn.c.mux_word(sel[1], &lvl1[3], &lvl1[2]);
            ec.nn.c.mux_word(sel[2], &l2b, &l2a)
        };
        let xt = Int {
            w: pick(&mut ec, 0),
            max: &pm.p - 1u32,
            v: ec.v(|| table_value(&table, idx, 0)),
        };
        let ye = Int {
            w: pick(&mut ec, 1),
            max: ymax.clone(),
            v: ec.v(|| table_value(&table, idx, 1)),
        };
        let d1 = Int {
            w: vec![b[0]],
            max: BigUint::one(),
            v: ec.v(|| BigUint::from(bv[0])),
        };
        st.select += mark(ec.nn) - r0;
        let r0 = mark(ec.nn);
        st.n_steps += 1;
        acc = ec.double_add(&acc, &xt, &ye, &d1);
        st.steps += mark(ec.nn) - r0;
    }
    // R = acc - 2^DIGITS Off.
    let r0 = mark(ec.nn);
    let end = (0..DIGITS).fold(offset_point(), |a, _| native_double(&a));
    let rpt = ec.add(&acc, 1, &const_point(&end), -1);
    st.finish = mark(ec.nn) - r0;

    // x(R) = r or r + n.
    let r0 = mark(ec.nn);
    let nw: Word = (0..256).map(|i| Wire::constant(nm.p.bit(i))).collect();
    let rn = add_words(ec.nn.c, &r.w, &nw);
    let e1 = eq_words(ec.nn.c, &rpt.x.w, &r.w);
    let e2 = eq_words(ec.nn.c, &rpt.x.w, &rn);
    let ok = crate::nonnative::or(ec.nn.c, e1, e2);
    ec.nn.check(ok);
    st.finish += mark(ec.nn) - r0;
    DEBUG_CHECKS.with(|d| *d.borrow_mut() = nn.checks().to_vec());
    let valid = nn.valid();

    // The statement.
    let mut public = vec![Wire::ZERO; PUBLIC_BITS];
    for i in 0..32 {
        for b in 0..8 {
            public[8 * i + b] = z.w[8 * (31 - i) + b];
        }
    }
    for i in 0..31 {
        for b in 0..8 {
            public[8 * (32 + i) + b] = qx.w[8 * (30 - i) + b];
        }
    }
    public[8 * 63] = valid;
    public[8 * 63 + 1] = qy.w[0];
    let inputs = nn.inputs().to_vec();
    (public, inputs, st)
}

thread_local! {
    /// The checks of the last circuit built (for debugging).
    pub static DEBUG_CHECKS: std::cell::RefCell<Vec<Wire>> = const { std::cell::RefCell::new(vec![]) };
}

fn table_value(table: &[P], idx: usize, coord: usize) -> BigUint {
    let t = &table[idx];
    if coord == 0 {
        t.x.val().clone()
    } else {
        t.y.val().clone()
    }
}

/// An instance: a k256 key and signature on a hash from the seed.
pub fn sample(seed: u64) -> (Inputs, [u8; 32]) {
    let mut bytes = [0u8; 32];
    let mut x = seed ^ 0x2545f4914f6cdd1d;
    for b in bytes.iter_mut() {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (x >> 33) as u8;
    }
    let sk = SigningKey::from_bytes(&bytes.into()).unwrap();
    let mut z = [0u8; 32];
    for b in z.iter_mut() {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (x >> 29) as u8;
    }
    let sig: Signature = sk.sign_prehash(&z).unwrap();
    let vk = VerifyingKey::from(&sk);
    let pt = vk.to_encoded_point(false);
    let inp = Inputs {
        z: BigUint::from_bytes_be(&z),
        r: BigUint::from_bytes_be(&sig.r().to_bytes()),
        s: BigUint::from_bytes_be(&sig.s().to_bytes()),
        qx: BigUint::from_bytes_be(pt.x().unwrap()),
        qy: BigUint::from_bytes_be(pt.y().unwrap()),
    };
    (inp, z)
}

/// The statement of inputs, by k256: z, the low 248 bits of Q.x, and the flags (validity by k256's verifier).
pub fn statement(inp: &Inputs) -> [u8; 64] {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let be = |v: &BigUint| -> [u8; 32] {
        let b = v.to_bytes_be();
        let mut o = [0u8; 32];
        o[32 - b.len()..].copy_from_slice(&b);
        o
    };
    let valid = (|| {
        let mut enc = [0u8; 65];
        enc[0] = 4;
        enc[1..33].copy_from_slice(&be(&inp.qx));
        enc[33..].copy_from_slice(&be(&inp.qy));
        let vk = VerifyingKey::from_sec1_bytes(&enc).ok()?;
        let sig = Signature::from_scalars(be(&inp.r), be(&inp.s)).ok()?;
        vk.verify_prehash(&be(&inp.z), &sig).ok()
    })()
    .is_some();
    let mut st = [0u8; 64];
    st[..32].copy_from_slice(&be(&inp.z));
    st[32..63].copy_from_slice(&be(&inp.qx)[1..]);
    st[63] = valid as u8 | ((inp.qy.bit(0) as u8) << 1);
    st
}

/// ECDSA verification over secp256k1 (public z and key, private signature).
pub struct Ecdsa;

impl Workload for Ecdsa {
    const NAME: &'static str = "ecdsa-secp256k1";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        circuit(c, None).0
    }

    fn instance(seed: u64) -> Instance {
        let (inp, _) = sample(seed);
        let mut c = Ckt::new();
        let (_, inputs, _) = circuit(&mut c, Some(&inp));
        Instance {
            inputs,
            statement: statement(&inp),
        }
    }

    /// A signature on another hash: the honest computation for the wrong `z` (all hints computed for it).
    fn invalid_instance(seed: u64) -> Option<Instance> {
        let (mut inp, _) = sample(seed);
        inp.z += 1u32;
        let mut c = Ckt::new();
        let (_, inputs, _) = circuit(&mut c, Some(&inp));
        Some(Instance {
            inputs,
            statement: statement(&inp),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonnative::tests::{Rng, Sliced, exhaust, gadget};
    use crate::read_statement;
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    fn k256_point(k: &BigUint) -> Pt {
        let mut b = [0u8; 32];
        let kb = k.to_bytes_be();
        b[32 - kb.len()..].copy_from_slice(&kb);
        let s = Scalar::from_repr(b.into()).unwrap();
        let a = (ProjectivePoint::GENERATOR * s).to_affine();
        let e = a.to_encoded_point(false);
        (
            BigUint::from_bytes_be(e.x().unwrap()),
            BigUint::from_bytes_be(e.y().unwrap()),
        )
    }

    #[test]
    fn constants_and_native_arithmetic_match_k256() {
        let g = generator();
        assert_eq!(k256_point(&BigUint::one()), g);
        assert_eq!(k256_point(&lambda()), native_phi(&g), "lambda G = (beta x, y)");
        let mut rng = Rng(3);
        let n = secp256k1_n().p;
        let nb = BigInt::from(n.clone());
        for _ in 0..50 {
            let (a, b) = (rng.below(&n), rng.below(&n));
            let (pa, pb) = (k256_point(&a), k256_point(&b));
            assert_eq!(native_add(&pa, &pb), k256_point(&((&a + &b) % &n)));
            let k = rng.below(&n);
            let (k1, k2) = glv(&k);
            assert!(k1.bit(0) && k2.bit(0));
            let lam = BigInt::from(lambda());
            assert_eq!(((k1 + k2 * lam) % &nb + &nb) % &nb, BigInt::from(k));
        }
        // The decomposition's bound (asserted inside), on many scalars and the edges.
        for k in (0..20000)
            .map(|_| rng.below(&n))
            .chain([BigUint::zero(), BigUint::one(), &n - 1u32])
        {
            glv(&k);
        }
        assert_eq!(native_double(&g), k256_point(&BigUint::from(2u32)));
        let off = offset_point();
        let p = secp256k1_p().p;
        assert_eq!((&off.1 * &off.1) % &p, (&off.0 * &off.0 * &off.0 + 7u32) % &p);
    }

    fn md(a: i64, p: u64) -> u64 {
        a.rem_euclid(p as i64) as u64
    }

    fn inv_small(a: u64, p: u64) -> u64 {
        (1..p).find(|i| i * a % p == 1).unwrap()
    }

    /// The addition gadget at p = 7, every hint, sampled operands (canonical x): accepted means the affine
    /// formula's result and x1 != x2; when x1 != x2 exactly one hint assignment is accepted.
    #[test]
    fn point_add_sound_for_every_hint() {
        let p = 7u64;
        let m = Modulus::new(BigUint::from(p));
        let mut rng = Rng(11);
        for case in 0..24 {
            let v: Vec<u64> = (0..4).map(|_| rng.next() % p).collect();
            let (x1, y1, y2) = (v[0], v[1], v[3]);
            let x2 = if case % 4 == 0 { x1 } else { v[2] };
            for (s1, s2) in [(1i64, 1i64), (-1, -1), (1, -1)] {
                let (s, outs) = gadget(|nn| {
                    let a = P {
                        x: Int::constant(&BigUint::from(x1)),
                        y: Int::constant(&BigUint::from(y1)),
                    };
                    let b = P {
                        x: Int::constant(&BigUint::from(x2)),
                        y: Int::constant(&BigUint::from(y2)),
                    };
                    let mut ec = Ec { nn, p: m.clone() };
                    let r = ec.add(&a, s1, &b, s2);
                    vec![r.x.w, r.y.w]
                });
                let mut accepted = 0;
                let mut lam = 0;
                exhaust(&s, |_, vv, lane| {
                    if Sliced::word(vv, &outs[2], lane) == 1 {
                        accepted += 1;
                        assert_ne!(x1, x2, "equal x accepted");
                        let l = md(s2 * y2 as i64 - s1 * y1 as i64, p) * inv_small(md(x2 as i64 - x1 as i64, p), p) % p;
                        lam = l;
                        let x3 = md((l * l) as i64 - x1 as i64 - x2 as i64, p);
                        let y3 = md(l as i64 * (x1 as i64 - x3 as i64) - s1 * y1 as i64, p);
                        assert_eq!(
                            (Sliced::word(vv, &outs[0], lane), Sliced::word(vv, &outs[1], lane)),
                            (x3, y3)
                        );
                    }
                });
                // The slope hint is not canonical: each of its representatives below 2^bits is accepted.
                let reps = (0..8).filter(|v| v % p == lam).count() as u32;
                assert_eq!(
                    accepted,
                    if x1 != x2 { reps } else { 0 },
                    "case {case}: ({x1},{y1}) + ({x2},{y2})"
                );
            }
        }
    }

    /// The combined double-and-add at p = 3, every hint, sampled operands: accepted means `(P + T) + P` by the
    /// affine formulas with both x-differences nonzero.
    #[test]
    fn double_add_sound_for_every_hint() {
        let p = 3u64;
        let m = Modulus::new(BigUint::from(p));
        let mut rng = Rng(12);
        let (mut honest, mut excluded) = (0, 0);
        while honest < 4 || excluded < 2 {
            let v: Vec<u64> = (0..5).map(|_| rng.next() % p).collect();
            let (xp, yp, xt, ye, d) = (v[0], v[1], v[2], v[3], v[4] & 1);
            let yt = if d == 1 { ye } else { md(-(ye as i64), p) };
            // The expected result and hints (lambda1, lambda2, y4), when defined.
            let expect = (xt != xp)
                .then(|| {
                    let l1 = md(yt as i64 - yp as i64, p) * inv_small(md(xt as i64 - xp as i64, p), p) % p;
                    let x3 = md((l1 * l1) as i64 - xp as i64 - xt as i64, p);
                    (l1, x3)
                })
                .and_then(|(l1, x3)| {
                    (x3 != xp).then(|| {
                        let t = 2 * yp * inv_small(md(x3 as i64 - xp as i64, p), p) % p;
                        let l2 = md(-(l1 as i64) - t as i64, p);
                        let x4 = md((l2 * l2) as i64 - xp as i64 - x3 as i64, p);
                        let y4 = md(l2 as i64 * (xp as i64 - x4 as i64) - yp as i64, p);
                        (l1, l2, x4, y4)
                    })
                });
            if (expect.is_some() && honest >= 4) || (expect.is_none() && excluded >= 2) {
                continue;
            }
            let (s, outs) = gadget(|nn| {
                let c = |x: u64| Int::constant(&BigUint::from(x));
                let a = P { x: c(xp), y: c(yp) };
                let mut ec = Ec { nn, p: m.clone() };
                let mut ye_i = c(ye);
                ye_i.max = BigUint::from(p - 1);
                let dd = c(d);
                let r = ec.double_add(&a, &c(xt), &ye_i, &dd);
                vec![r.x.w, r.y.w]
            });
            let mut accepted = 0;
            exhaust(&s, |_, vv, lane| {
                if Sliced::word(vv, &outs[2], lane) == 1 {
                    accepted += 1;
                    let got = (Sliced::word(vv, &outs[0], lane), Sliced::word(vv, &outs[1], lane) % p);
                    assert_eq!(Some(got), expect.map(|e| (e.2, e.3)));
                }
            });
            // The slopes and y4 are not canonical: every representative below 2^bits is accepted.
            let reps = |v: u64| (0..4).filter(|x| x % p == v).count();
            match expect {
                Some((l1, l2, _, y4)) => {
                    honest += 1;
                    assert_eq!(accepted, reps(l1) * reps(l2) * reps(y4));
                }
                None => {
                    excluded += 1;
                    assert_eq!(accepted, 0);
                }
            }
            println!("double-add mod {p}: {} input and hint bits enumerated", s.n_inputs());
        }
    }

    #[test]
    fn whole_verification() {
        let (circuit, srcs, used) = crate::build::<Ecdsa>();
        println!("ecdsa: {used} rows, closed on 2^{}", circuit.log_rows);
        circuit.check_wired().unwrap();
        for seed in 1..=3 {
            let inst = Ecdsa::instance(seed);
            let st = read_statement(&circuit.values(&inst.inputs), &srcs);
            assert_eq!(st, inst.statement, "seed {seed}");
            assert_eq!(st[63] & 1, 1);
            let bad = Ecdsa::invalid_instance(seed).unwrap();
            let got = read_statement(&circuit.values(&bad.inputs), &srcs);
            assert_eq!(got, bad.statement);
            assert_eq!(got[63] & 1, 0, "wrong z");
        }
        // Wrong r, wrong s, s = 0, r = n, a key off the curve: honest hints for the wrong inputs.
        let (inp, _) = sample(4);
        let n = secp256k1_n().p;
        let cases: Vec<(&str, Inputs)> = vec![
            (
                "r + 1",
                Inputs {
                    r: &inp.r + 1u32,
                    ..inp.clone()
                },
            ),
            (
                "s + 1",
                Inputs {
                    s: &inp.s + 1u32,
                    ..inp.clone()
                },
            ),
            (
                "s = 0",
                Inputs {
                    s: BigUint::zero(),
                    ..inp.clone()
                },
            ),
            (
                "r = r + n",
                Inputs {
                    r: (&inp.r + &n) % (BigUint::one() << 256),
                    ..inp.clone()
                },
            ),
            (
                "Q off the curve",
                Inputs {
                    qy: &inp.qy + 1u32,
                    ..inp.clone()
                },
            ),
            (
                "-Q",
                Inputs {
                    qy: &secp256k1_p().p - &inp.qy,
                    ..inp.clone()
                },
            ),
        ];
        for (what, bad) in &cases {
            let mut c = Ckt::new();
            let (_, inputs, _) = circuit_fn(&mut c, bad);
            let got = read_statement(&circuit.values(&inputs), &srcs);
            assert_eq!(got, statement(bad), "{what}");
            assert_eq!(got[63] & 1, 0, "{what} accepted");
        }
        // Malicious hints: one bit flipped in a spread of hint positions.
        let inst = Ecdsa::instance(5);
        let n_in = inst.inputs.len();
        let mut rng = Rng(77);
        for _ in 0..12 {
            let i = 1280 + (rng.next() as usize) % (n_in - 1280);
            let mut bad = inst.inputs.clone();
            bad[i] = !bad[i];
            let got = read_statement(&circuit.values(&bad), &srcs);
            assert_eq!(got[63] & 1, 0, "hint bit {i} flipped and accepted");
        }
    }

    #[test]
    #[ignore]
    fn debug_checks() {
        let (inp, _) = sample(1);
        let mut c = Ckt::new();
        let (public, inputs, _) = circuit(&mut c, Some(&inp));
        let checks = DEBUG_CHECKS.with(|d| d.borrow().clone());
        let (cc, _) = c.finish(&public);
        let v = cc.values(&inputs);
        let bad: Vec<usize> = checks
            .iter()
            .enumerate()
            .filter(|(_, w)| !w.value(&v))
            .map(|(i, _)| i)
            .collect();
        println!("{} checks, failing: {:?}", checks.len(), &bad[..bad.len().min(40)]);
    }

    fn circuit_fn(c: &mut Ckt, inp: &Inputs) -> (Vec<Wire>, Vec<bool>, Stats) {
        circuit(c, Some(inp))
    }

    #[test]
    fn row_breakdown() {
        let mut c = Ckt::new();
        let (_, _, st) = circuit(&mut c, None);
        println!(
            "ecdsa: {} rows, {} inputs; scalars {}, key on curve {}, table {}, selection {} ({} a digit), \
             double-and-add steps {} ({} each, {} steps), final check {}",
            c.rows(),
            c.n_inputs(),
            st.scalars,
            st.key,
            st.table,
            st.select,
            st.select / DIGITS,
            st.steps,
            st.steps / st.n_steps,
            st.n_steps,
            st.finish
        );
    }
}
