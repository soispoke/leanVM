//! Poseidon over BN254 (circomlib parameters: `x^5`, `t = 3`, 8 full and 57 partial rounds), hashing a private
//! 1,024-byte message.
//!
//! # Statement
//! The message is cut into 31-byte big-endian chunks (33 full chunks and a last one of one byte: 34 field
//! elements). A sponge of rate 2 and capacity 1 starts from the zero state `[0, 0, 0]`; each pair of elements is
//! added to `state[1]` and `state[2]` and the state permuted (17 permutations). The digest is `state[0]`.
//! Bytes `0..32` of the statement are the digest, big-endian; byte 32 is the validity bit; bytes `33..64` are zero.
//! The first absorption is exactly circomlib's `poseidon([m0, m1])` (state `[0, m0, m1]`).
//!
//! # Reference
//! [`permute_ref`] is the plain circomlib permutation (`poseidon_reference.js`) on `ark-bn254`'s `Fr`, with the
//! round constants and MDS matrix of `circomlibjs/src/poseidon_constants.json`, and is checked against the
//! published vector `poseidon([1, 2])`. The circuit instead follows circomlib's optimised form
//! (`poseidon_opt.js`, from neptune: the partial rounds' MDS factored into sparse matrices, the round constants
//! moved accordingly; constants from `poseidon_constants_opt.json`), which computes the same permutation; a test
//! checks the two agree. The instance's digest comes from the plain reference.
//!
//! # Circuit
//! Field elements are pending linear forms (`sum c_j x_j + k` over materialised integers): additions of round
//! constants, absorption and the matrices cost nothing until an element must be an operand of a product. Then it
//! is materialised: a hint `x` of 254 bits and the congruence `sum c_j x_j + k - x = 0 (mod r)`
//! ([`Nn::congruence`]: each coefficient a constant multiplication, `-q r` another). The S-box `y = x^5` is three
//! hinted products `t = x^2`, `u = t^2`, `y = u x`, each a congruence (two squares, one product). Hints other
//! than the digest need not be canonical: a congruence fixes the residue class, which is all later congruences
//! use; the digest is range-checked below `r`. A partial round materialises `state[0]` (three coefficients) and,
//! once their forms grow past [`LIMIT`] terms, `state[1]` and `state[2]` (a sparse update `s + c y` each).
//! Soundness is that of [`Nn::congruence`]: every check holds over the integers for every hint value, so
//! `valid = 1` means every materialised element is the Poseidon value modulo `r`.
//!
//! # Costs (rows, measured)
//! - S-box: 182,435 (two squares, a product, three quotients `q r`).
//! - Full round: 666,018 (three S-boxes, three materialisations of three coefficients each).
//! - Partial round: 281,253 (one S-box; `state[0]` materialised from three coefficients; `state[1]`, `state[2]`
//!   every second round).
//! - Permutation: 21,547,660 (the first one, whose initial state is half constant, 21,171,529).
//! - 1 KiB (17 permutations): 366,007,556 rows (`2^28.45`, closed on `2^29`), 3,292,490 free inputs (8,192
//!   message bits, the rest hints); counted in 154 s with a 9.2 GB peak; built, closed, checked wired and
//!   evaluated against the reference for three seeds and an invalid instance in 1,223 s with a 30.2 GB peak.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::nonnative::{Int, Modulus, Nn, Term, add_words, bn254_r, const_word, naf};
use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Workload};

pub const T: usize = 3;
pub const ROUNDS_F: usize = 8;
pub const ROUNDS_P: usize = 57;
pub const MESSAGE_BYTES: usize = 1024;
pub const CHUNK: usize = 31;
/// A partial round's `state[1]`, `state[2]` are materialised once their forms hold more terms than this.
pub const LIMIT: usize = 2;

fn big(h: &str) -> BigUint {
    BigUint::parse_bytes(h.as_bytes(), 16).unwrap()
}

fn fr(h: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&big(h).to_bytes_be())
}

fn pow5(x: Fr) -> Fr {
    x.square().square() * x
}

/// The plain circomlib permutation (`poseidon_reference.js`).
pub fn permute_ref(mut s: [Fr; 3]) -> [Fr; 3] {
    let m: Vec<Vec<Fr>> = M.iter().map(|r| r.iter().map(|h| fr(h)).collect()).collect();
    for r in 0..ROUNDS_F + ROUNDS_P {
        for i in 0..T {
            s[i] += fr(C[r * T + i]);
        }
        if !(ROUNDS_F / 2..ROUNDS_F / 2 + ROUNDS_P).contains(&r) {
            s = s.map(pow5);
        } else {
            s[0] = pow5(s[0]);
        }
        s = std::array::from_fn(|i| (0..T).map(|j| m[i][j] * s[j]).sum());
    }
    s
}

/// The message's field elements: 31-byte big-endian chunks, the last one short.
pub fn chunks(msg: &[u8]) -> Vec<BigUint> {
    msg.chunks(CHUNK).map(BigUint::from_bytes_be).collect()
}

/// The sponge (rate 2, capacity 1, zero initial state) over the chunks, with the plain permutation.
pub fn hash_ref(msg: &[u8]) -> Fr {
    let elems: Vec<Fr> = chunks(msg)
        .iter()
        .map(|x| Fr::from_be_bytes_mod_order(&x.to_bytes_be()))
        .collect();
    assert!(elems.len().is_multiple_of(2), "an even number of elements");
    let mut s = [Fr::ZERO; 3];
    for pair in elems.chunks(2) {
        s[1] += pair[0];
        s[2] += pair[1];
        s = permute_ref(s);
    }
    s[0]
}

/// The digest's 32 bytes, big-endian.
pub fn digest_bytes(h: Fr) -> [u8; 32] {
    let b = h.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// A field element pending as `sum c_j x_j + k` over materialised integers (by index), coefficients modulo `r`.
#[derive(Clone, Debug, Default)]
struct Lf {
    terms: Vec<(usize, BigUint)>,
    k: BigUint,
}

impl Lf {
    fn konst(k: BigUint) -> Lf {
        Lf { terms: vec![], k }
    }

    fn var(id: usize) -> Lf {
        Lf {
            terms: vec![(id, BigUint::one())],
            k: BigUint::zero(),
        }
    }

    /// `sum_i c_i f_i + k`.
    fn comb(parts: &[(&BigUint, &Lf)], k: &BigUint, r: &BigUint) -> Lf {
        let mut out = Lf::konst(k % r);
        for (c, f) in parts {
            for (id, a) in &f.terms {
                let a = (*c * a) % r;
                match out.terms.iter_mut().find(|t| t.0 == *id) {
                    Some(t) => t.1 = (&t.1 + a) % r,
                    None => out.terms.push((*id, a)),
                }
            }
            out.k = (&out.k + *c * &f.k) % r;
        }
        out.terms.retain(|t| !t.1.is_zero());
        out
    }
}

/// Rows spent, by part.
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub sbox: usize,
    pub n_sbox: usize,
    pub materialise: usize,
    pub n_materialise: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub perms: Vec<usize>,
}

struct Pos<'a, 'b> {
    nn: &'b mut Nn<'a>,
    m: Modulus,
    ints: Vec<Int>,
    limit: usize,
    stats: Stats,
}

impl Pos<'_, '_> {
    fn int(&mut self, x: Int) -> usize {
        self.ints.push(x);
        self.ints.len() - 1
    }

    fn is_const(&self, id: usize) -> bool {
        self.ints[id].w.iter().all(|w| w.as_const().is_some())
    }

    /// The coefficient `c` or `c - r`, whichever has fewer signed digits.
    fn signed(&self, c: &BigUint) -> BigInt {
        let a = BigInt::from(c.clone());
        let b = &a - BigInt::from(self.m.p.clone());
        if naf(&b).len() < naf(&a).len() { b } else { a }
    }

    /// An integer holding the form's value modulo `r` (canonical if asked).
    fn materialise(&mut self, f: &Lf, canonical: bool) -> usize {
        let r0 = self.nn.c.rows();
        let id = if f.terms.is_empty() {
            self.int(Int::constant(&f.k))
        } else if !canonical && f.terms.len() == 1 && f.terms[0].1.is_one() {
            // x + k exactly, with an adder: no hint.
            let x = self.ints[f.terms[0].0].clone();
            if f.k.is_zero() {
                return f.terms[0].0;
            }
            let w = add_words(self.nn.c, &x.w, &const_word(&f.k, f.k.bits() as usize));
            let max = &x.max + &f.k;
            let v = x.v.as_ref().map(|v| v + &f.k);
            self.int(Int {
                w: w[..max.bits() as usize].to_vec(),
                max,
                v,
            })
        } else {
            let coeffs: Vec<BigInt> = f.terms.iter().map(|(_, c)| self.signed(c)).collect();
            let ints = &self.ints;
            let mut terms: Vec<Term> = f
                .terms
                .iter()
                .zip(&coeffs)
                .map(|((id, _), c)| Term::Scaled(&ints[*id], c.clone()))
                .collect();
            terms.push(Term::Const(BigInt::from(f.k.clone())));
            let x = self.nn.reduce_to(&self.m, &terms, canonical);
            self.stats.n_materialise += 1;
            self.int(x)
        };
        self.stats.materialise += self.nn.c.rows() - r0;
        id
    }

    /// `x^5`: hints `t = x^2`, `u = t^2`, `y = u x`, each a congruence.
    fn pow5(&mut self, x: usize) -> usize {
        if self.is_const(x) {
            let v = self.ints[x].val().modpow(&BigUint::from(5u32), &self.m.p);
            return self.int(Int::constant(&v));
        }
        let r0 = self.nn.c.rows();
        let xi = self.ints[x].clone();
        let t = self.nn.reduce_to(&self.m, &[Term::Sq(&xi, 0)], false);
        let u = self.nn.reduce_to(&self.m, &[Term::Sq(&t, 0)], false);
        let y = self.nn.reduce_to(&self.m, &[Term::Mul(&u, &xi, 0)], false);
        self.stats.sbox += self.nn.c.rows() - r0;
        self.stats.n_sbox += 1;
        self.int(y)
    }

    /// A full round: every element materialised and raised to the fifth power, the constants (if any) added, the
    /// matrix applied transposed (`new[i] = sum_j mat[j][i] y_j`).
    fn full(&mut self, s: &mut [Lf; 3], c: Option<usize>, mat: &[[&str; 3]; 3]) {
        let r0 = self.nn.c.rows();
        let r = self.m.p.clone();
        let y: Vec<Lf> = (0..T)
            .map(|i| {
                let x = self.materialise(&s[i], false);
                let y = self.pow5(x);
                let k = c.map(|c| big(OPT_C[c + i])).unwrap_or_default();
                Lf::comb(&[(&BigUint::one(), &Lf::var(y))], &k, &r)
            })
            .collect();
        *s = std::array::from_fn(|i| {
            let cs: Vec<BigUint> = (0..T).map(|j| big(mat[j][i])).collect();
            Lf::comb(
                &[(&cs[0], &y[0]), (&cs[1], &y[1]), (&cs[2], &y[2])],
                &BigUint::zero(),
                &r,
            )
        });
        self.stats.full_rounds += self.nn.c.rows() - r0;
    }

    /// A partial round in sparse form (`poseidon_opt.js`).
    fn partial(&mut self, s: &mut [Lf; 3], round: usize) {
        let r0 = self.nn.c.rows();
        let r = self.m.p.clone();
        let x = self.materialise(&s[0], false);
        let y = self.pow5(x);
        let y = Lf::comb(
            &[(&BigUint::one(), &Lf::var(y))],
            &big(OPT_C[(ROUNDS_F / 2 + 1) * T + round]),
            &r,
        );
        let sp: Vec<BigUint> = (0..2 * T - 1).map(|j| big(OPT_S[(2 * T - 1) * round + j])).collect();
        let one = BigUint::one();
        let s0 = Lf::comb(&[(&sp[0], &y), (&sp[1], &s[1]), (&sp[2], &s[2])], &BigUint::zero(), &r);
        for k in 1..T {
            s[k] = Lf::comb(&[(&one, &s[k]), (&sp[T + k - 1], &y)], &BigUint::zero(), &r);
            if s[k].terms.len() > self.limit {
                let id = self.materialise(&s[k], false);
                s[k] = Lf::var(id);
            }
        }
        s[0] = s0;
        self.stats.partial_rounds += self.nn.c.rows() - r0;
    }

    /// The permutation, optimised form.
    fn permute(&mut self, s: &mut [Lf; 3]) {
        let r0 = self.nn.c.rows();
        let r = self.m.p.clone();
        let one = BigUint::one();
        for i in 0..T {
            s[i] = Lf::comb(&[(&one, &s[i])], &big(OPT_C[i]), &r);
        }
        for round in 0..ROUNDS_F / 2 - 1 {
            self.full(s, Some((round + 1) * T), &OPT_M);
        }
        self.full(s, Some((ROUNDS_F / 2) * T), &OPT_P);
        for round in 0..ROUNDS_P {
            self.partial(s, round);
        }
        for round in 0..ROUNDS_F / 2 - 1 {
            self.full(s, Some((ROUNDS_F / 2 + 1) * T + ROUNDS_P + round * T), &OPT_M);
        }
        self.full(s, None, &OPT_M);
        self.stats.perms.push(self.nn.c.rows() - r0);
    }
}

/// The sponge circuit over a private message of `len` bytes (an even number of chunks): the 512 public bits, the
/// free inputs (when `msg` is given) and the row breakdown.
pub fn circuit(c: &mut Ckt, msg: Option<&[u8]>, len: usize, limit: usize) -> (Vec<Wire>, Vec<bool>, Stats) {
    assert_eq!(len.div_ceil(CHUNK) % 2, 0);
    let mut nn = match msg {
        Some(_) => Nn::with_witness(c),
        None => Nn::new(c),
    };
    let bits: Vec<bool> = match msg {
        Some(m) => m.iter().flat_map(|&b| (0..8).map(move |j| (b >> j) & 1 == 1)).collect(),
        None => vec![false; 8 * len],
    };
    let wires = nn.input_bits(&bits);
    let mut pos = Pos {
        nn: &mut nn,
        m: bn254_r(),
        ints: vec![],
        limit,
        stats: Stats::default(),
    };
    // The chunks as integers: the byte at offset `o` of a chunk of `n` bytes weighs `256^(n-1-o)`.
    let mut elems = vec![];
    for start in (0..len).step_by(CHUNK) {
        let n = CHUNK.min(len - start);
        let mut w = vec![Wire::ZERO; 8 * n];
        for o in 0..n {
            for j in 0..8 {
                w[8 * (n - 1 - o) + j] = wires[8 * (start + o) + j];
            }
        }
        let v = msg.map(|m| BigUint::from_bytes_be(&m[start..start + n]));
        let id = pos.int(Int {
            w,
            max: (BigUint::one() << (8 * n)) - 1u32,
            v,
        });
        elems.push(id);
    }
    let r = pos.m.p.clone();
    let one = BigUint::one();
    let mut s: [Lf; 3] = Default::default();
    for pair in elems.chunks(2) {
        s[1] = Lf::comb(&[(&one, &s[1]), (&one, &Lf::var(pair[0]))], &BigUint::zero(), &r);
        s[2] = Lf::comb(&[(&one, &s[2]), (&one, &Lf::var(pair[1]))], &BigUint::zero(), &r);
        pos.permute(&mut s);
    }
    let out = pos.materialise(&s[0], true);
    let h = pos.ints[out].clone();
    let stats = pos.stats.clone();
    let valid = nn.valid();
    let mut public = vec![Wire::ZERO; PUBLIC_BITS];
    for i in 0..32 {
        for j in 0..8 {
            let b = 8 * (31 - i) + j;
            public[8 * i + j] = h.w.get(b).copied().unwrap_or(Wire::ZERO);
        }
    }
    public[8 * 32] = valid;
    let inputs = nn.inputs().to_vec();
    (public, inputs, stats)
}

/// The message of an instance.
pub fn message(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e3779b97f4a7c15) ^ 0x5bd1e995;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// The statement for a message: digest (big-endian), then the validity bit.
pub fn statement(msg: &[u8], valid: bool) -> [u8; 64] {
    let mut st = [0u8; 64];
    st[..32].copy_from_slice(&digest_bytes(hash_ref(msg)));
    st[32] = valid as u8;
    st
}

/// Poseidon (circomlib, BN254, t = 3) sponge over a private message of `LEN` bytes.
pub struct PoseidonSponge<const LEN: usize>;

/// The workload: a 1,024-byte message.
pub type Poseidon1K = PoseidonSponge<MESSAGE_BYTES>;

impl<const LEN: usize> Workload for PoseidonSponge<LEN> {
    const NAME: &'static str = "poseidon-bn254";

    fn build(c: &mut Ckt) -> Vec<Wire> {
        circuit(c, None, LEN, LIMIT).0
    }

    fn instance(seed: u64) -> Instance {
        let msg = message(seed, LEN);
        let mut c = Ckt::new();
        let (_, inputs, _) = circuit(&mut c, Some(&msg), LEN, LIMIT);
        Instance {
            inputs,
            statement: statement(&msg, true),
        }
    }

    /// A tampered hint (a bit of the first S-box's `x^2`): the digest stays, the validity bit drops.
    fn invalid_instance(seed: u64) -> Option<Instance> {
        let mut inst = Self::instance(seed);
        let msg = message(seed, LEN);
        // The first hint follows the message bits (the first permutation's first hint is `t` of `state[1]`).
        let i = 8 * LEN + 3 + (seed as usize % 200);
        inst.inputs[i] = !inst.inputs[i];
        inst.statement = statement(&msg, false);
        Some(inst)
    }
}

/// circomlib round constants, t = 3 (`poseidon_constants.json` `C[1]`), round by round.
const C: [&str; 195] = [
    "0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e",
    "00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864",
    "08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5",
    "2f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d0",
    "2b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf2",
    "0319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa",
    "28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d",
    "2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78",
    "234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc632",
    "15b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d428",
    "0dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f6",
    "1bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c",
    "10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559",
    "1f6d48149b8e7f7d9b257d8ed5fbbaf42932498075fed0ace88a9eb81f5627f6",
    "1d9655f652309014d29e00ef35a2089bfff8dc1c816f0dc9ca34bdb5460c8705",
    "04df5a56ff95bcafb051f7b1cd43a99ba731ff67e47032058fe3d4185697cc7d",
    "0672d995f8fff640151b3d290cedaf148690a10a8c8424a7f6ec282b6e4be828",
    "099952b414884454b21200d7ffafdd5f0c9a9dcc06f2708e9fc1d8209b5c75b9",
    "052cba2255dfd00c7c483143ba8d469448e43586a9b4cd9183fd0e843a6b9fa6",
    "0b8badee690adb8eb0bd74712b7999af82de55707251ad7716077cb93c464ddc",
    "119b1590f13307af5a1ee651020c07c749c15d60683a8050b963d0a8e4b2bdd1",
    "03150b7cd6d5d17b2529d36be0f67b832c4acfc884ef4ee5ce15be0bfb4a8d09",
    "2cc6182c5e14546e3cf1951f173912355374efb83d80898abe69cb317c9ea565",
    "005032551e6378c450cfe129a404b3764218cadedac14e2b92d2cd73111bf0f9",
    "233237e3289baa34bb147e972ebcb9516469c399fcc069fb88f9da2cc28276b5",
    "05c8f4f4ebd4a6e3c980d31674bfbe6323037f21b34ae5a4e80c2d4c24d60280",
    "0a7b1db13042d396ba05d818a319f25252bcf35ef3aeed91ee1f09b2590fc65b",
    "2a73b71f9b210cf5b14296572c9d32dbf156e2b086ff47dc5df542365a404ec0",
    "1ac9b0417abcc9a1935107e9ffc91dc3ec18f2c4dbe7f22976a760bb5c50c460",
    "12c0339ae08374823fabb076707ef479269f3e4d6cb104349015ee046dc93fc0",
    "0b7475b102a165ad7f5b18db4e1e704f52900aa3253baac68246682e56e9a28e",
    "037c2849e191ca3edb1c5e49f6e8b8917c843e379366f2ea32ab3aa88d7f8448",
    "05a6811f8556f014e92674661e217e9bd5206c5c93a07dc145fdb176a716346f",
    "29a795e7d98028946e947b75d54e9f044076e87a7b2883b47b675ef5f38bd66e",
    "20439a0c84b322eb45a3857afc18f5826e8c7382c8a1585c507be199981fd22f",
    "2e0ba8d94d9ecf4a94ec2050c7371ff1bb50f27799a84b6d4a2a6f2a0982c887",
    "143fd115ce08fb27ca38eb7cce822b4517822cd2109048d2e6d0ddcca17d71c8",
    "0c64cbecb1c734b857968dbbdcf813cdf8611659323dbcbfc84323623be9caf1",
    "028a305847c683f646fca925c163ff5ae74f348d62c2b670f1426cef9403da53",
    "2e4ef510ff0b6fda5fa940ab4c4380f26a6bcb64d89427b824d6755b5db9e30c",
    "0081c95bc43384e663d79270c956ce3b8925b4f6d033b078b96384f50579400e",
    "2ed5f0c91cbd9749187e2fade687e05ee2491b349c039a0bba8a9f4023a0bb38",
    "30509991f88da3504bbf374ed5aae2f03448a22c76234c8c990f01f33a735206",
    "1c3f20fd55409a53221b7c4d49a356b9f0a1119fb2067b41a7529094424ec6ad",
    "10b4e7f3ab5df003049514459b6e18eec46bb2213e8e131e170887b47ddcb96c",
    "2a1982979c3ff7f43ddd543d891c2abddd80f804c077d775039aa3502e43adef",
    "1c74ee64f15e1db6feddbead56d6d55dba431ebc396c9af95cad0f1315bd5c91",
    "07533ec850ba7f98eab9303cace01b4b9e4f2e8b82708cfa9c2fe45a0ae146a0",
    "21576b438e500449a151e4eeaf17b154285c68f42d42c1808a11abf3764c0750",
    "2f17c0559b8fe79608ad5ca193d62f10bce8384c815f0906743d6930836d4a9e",
    "2d477e3862d07708a79e8aae946170bc9775a4201318474ae665b0b1b7e2730e",
    "162f5243967064c390e095577984f291afba2266c38f5abcd89be0f5b2747eab",
    "2b4cb233ede9ba48264ecd2c8ae50d1ad7a8596a87f29f8a7777a70092393311",
    "2c8fbcb2dd8573dc1dbaf8f4622854776db2eece6d85c4cf4254e7c35e03b07a",
    "1d6f347725e4816af2ff453f0cd56b199e1b61e9f601e9ade5e88db870949da9",
    "204b0c397f4ebe71ebc2d8b3df5b913df9e6ac02b68d31324cd49af5c4565529",
    "0c4cb9dc3c4fd8174f1149b3c63c3c2f9ecb827cd7dc25534ff8fb75bc79c502",
    "174ad61a1448c899a25416474f4930301e5c49475279e0639a616ddc45bc7b54",
    "1a96177bcf4d8d89f759df4ec2f3cde2eaaa28c177cc0fa13a9816d49a38d2ef",
    "066d04b24331d71cd0ef8054bc60c4ff05202c126a233c1a8242ace360b8a30a",
    "2a4c4fc6ec0b0cf52195782871c6dd3b381cc65f72e02ad527037a62aa1bd804",
    "13ab2d136ccf37d447e9f2e14a7cedc95e727f8446f6d9d7e55afc01219fd649",
    "1121552fca26061619d24d843dc82769c1b04fcec26f55194c2e3e869acc6a9a",
    "00ef653322b13d6c889bc81715c37d77a6cd267d595c4a8909a5546c7c97cff1",
    "0e25483e45a665208b261d8ba74051e6400c776d652595d9845aca35d8a397d3",
    "29f536dcb9dd7682245264659e15d88e395ac3d4dde92d8c46448db979eeba89",
    "2a56ef9f2c53febadfda33575dbdbd885a124e2780bbea170e456baace0fa5be",
    "1c8361c78eb5cf5decfb7a2d17b5c409f2ae2999a46762e8ee416240a8cb9af1",
    "151aff5f38b20a0fc0473089aaf0206b83e8e68a764507bfd3d0ab4be74319c5",
    "04c6187e41ed881dc1b239c88f7f9d43a9f52fc8c8b6cdd1e76e47615b51f100",
    "13b37bd80f4d27fb10d84331f6fb6d534b81c61ed15776449e801b7ddc9c2967",
    "01a5c536273c2d9df578bfbd32c17b7a2ce3664c2a52032c9321ceb1c4e8a8e4",
    "2ab3561834ca73835ad05f5d7acb950b4a9a2c666b9726da832239065b7c3b02",
    "1d4d8ec291e720db200fe6d686c0d613acaf6af4e95d3bf69f7ed516a597b646",
    "041294d2cc484d228f5784fe7919fd2bb925351240a04b711514c9c80b65af1d",
    "154ac98e01708c611c4fa715991f004898f57939d126e392042971dd90e81fc6",
    "0b339d8acca7d4f83eedd84093aef51050b3684c88f8b0b04524563bc6ea4da4",
    "0955e49e6610c94254a4f84cfbab344598f0e71eaff4a7dd81ed95b50839c82e",
    "06746a6156eba54426b9e22206f15abca9a6f41e6f535c6f3525401ea0654626",
    "0f18f5a0ecd1423c496f3820c549c27838e5790e2bd0a196ac917c7ff32077fb",
    "04f6eeca1751f7308ac59eff5beb261e4bb563583ede7bc92a738223d6f76e13",
    "2b56973364c4c4f5c1a3ec4da3cdce038811eb116fb3e45bc1768d26fc0b3758",
    "123769dd49d5b054dcd76b89804b1bcb8e1392b385716a5d83feb65d437f29ef",
    "2147b424fc48c80a88ee52b91169aacea989f6446471150994257b2fb01c63e9",
    "0fdc1f58548b85701a6c5505ea332a29647e6f34ad4243c2ea54ad897cebe54d",
    "12373a8251fea004df68abcf0f7786d4bceff28c5dbbe0c3944f685cc0a0b1f2",
    "21e4f4ea5f35f85bad7ea52ff742c9e8a642756b6af44203dd8a1f35c1a90035",
    "16243916d69d2ca3dfb4722224d4c462b57366492f45e90d8a81934f1bc3b147",
    "1efbe46dd7a578b4f66f9adbc88b4378abc21566e1a0453ca13a4159cac04ac2",
    "07ea5e8537cf5dd08886020e23a7f387d468d5525be66f853b672cc96a88969a",
    "05a8c4f9968b8aa3b7b478a30f9a5b63650f19a75e7ce11ca9fe16c0b76c00bc",
    "20f057712cc21654fbfe59bd345e8dac3f7818c701b9c7882d9d57b72a32e83f",
    "04a12ededa9dfd689672f8c67fee31636dcd8e88d01d49019bd90b33eb33db69",
    "27e88d8c15f37dcee44f1e5425a51decbd136ce5091a6767e49ec9544ccd101a",
    "2feed17b84285ed9b8a5c8c5e95a41f66e096619a7703223176c41ee433de4d1",
    "1ed7cc76edf45c7c404241420f729cf394e5942911312a0d6972b8bd53aff2b8",
    "15742e99b9bfa323157ff8c586f5660eac6783476144cdcadf2874be45466b1a",
    "1aac285387f65e82c895fc6887ddf40577107454c6ec0317284f033f27d0c785",
    "25851c3c845d4790f9ddadbdb6057357832e2e7a49775f71ec75a96554d67c77",
    "15a5821565cc2ec2ce78457db197edf353b7ebba2c5523370ddccc3d9f146a67",
    "2411d57a4813b9980efa7e31a1db5966dcf64f36044277502f15485f28c71727",
    "002e6f8d6520cd4713e335b8c0b6d2e647e9a98e12f4cd2558828b5ef6cb4c9b",
    "2ff7bc8f4380cde997da00b616b0fcd1af8f0e91e2fe1ed7398834609e0315d2",
    "00b9831b948525595ee02724471bcd182e9521f6b7bb68f1e93be4febb0d3cbe",
    "0a2f53768b8ebf6a86913b0e57c04e011ca408648a4743a87d77adbf0c9c3512",
    "00248156142fd0373a479f91ff239e960f599ff7e94be69b7f2a290305e1198d",
    "171d5620b87bfb1328cf8c02ab3f0c9a397196aa6a542c2350eb512a2b2bcda9",
    "170a4f55536f7dc970087c7c10d6fad760c952172dd54dd99d1045e4ec34a808",
    "29aba33f799fe66c2ef3134aea04336ecc37e38c1cd211ba482eca17e2dbfae1",
    "1e9bc179a4fdd758fdd1bb1945088d47e70d114a03f6a0e8b5ba650369e64973",
    "1dd269799b660fad58f7f4892dfb0b5afeaad869a9c4b44f9c9e1c43bdaf8f09",
    "22cdbc8b70117ad1401181d02e15459e7ccd426fe869c7c95d1dd2cb0f24af38",
    "0ef042e454771c533a9f57a55c503fcefd3150f52ed94a7cd5ba93b9c7dacefd",
    "11609e06ad6c8fe2f287f3036037e8851318e8b08a0359a03b304ffca62e8284",
    "1166d9e554616dba9e753eea427c17b7fecd58c076dfe42708b08f5b783aa9af",
    "2de52989431a859593413026354413db177fbf4cd2ac0b56f855a888357ee466",
    "3006eb4ffc7a85819a6da492f3a8ac1df51aee5b17b8e89d74bf01cf5f71e9ad",
    "2af41fbb61ba8a80fdcf6fff9e3f6f422993fe8f0a4639f962344c8225145086",
    "119e684de476155fe5a6b41a8ebc85db8718ab27889e85e781b214bace4827c3",
    "1835b786e2e8925e188bea59ae363537b51248c23828f047cff784b97b3fd800",
    "28201a34c594dfa34d794996c6433a20d152bac2a7905c926c40e285ab32eeb6",
    "083efd7a27d1751094e80fefaf78b000864c82eb571187724a761f88c22cc4e7",
    "0b6f88a3577199526158e61ceea27be811c16df7774dd8519e079564f61fd13b",
    "0ec868e6d15e51d9644f66e1d6471a94589511ca00d29e1014390e6ee4254f5b",
    "2af33e3f866771271ac0c9b3ed2e1142ecd3e74b939cd40d00d937ab84c98591",
    "0b520211f904b5e7d09b5d961c6ace7734568c547dd6858b364ce5e47951f178",
    "0b2d722d0919a1aad8db58f10062a92ea0c56ac4270e822cca228620188a1d40",
    "1f790d4d7f8cf094d980ceb37c2453e957b54a9991ca38bbe0061d1ed6e562d4",
    "0171eb95dfbf7d1eaea97cd385f780150885c16235a2a6a8da92ceb01e504233",
    "0c2d0e3b5fd57549329bf6885da66b9b790b40defd2c8650762305381b168873",
    "1162fb28689c27154e5a8228b4e72b377cbcafa589e283c35d3803054407a18d",
    "2f1459b65dee441b64ad386a91e8310f282c5a92a89e19921623ef8249711bc0",
    "1e6ff3216b688c3d996d74367d5cd4c1bc489d46754eb712c243f70d1b53cfbb",
    "01ca8be73832b8d0681487d27d157802d741a6f36cdc2a0576881f9326478875",
    "1f7735706ffe9fc586f976d5bdf223dc680286080b10cea00b9b5de315f9650e",
    "2522b60f4ea3307640a0c2dce041fba921ac10a3d5f096ef4745ca838285f019",
    "23f0bee001b1029d5255075ddc957f833418cad4f52b6c3f8ce16c235572575b",
    "2bc1ae8b8ddbb81fcaac2d44555ed5685d142633e9df905f66d9401093082d59",
    "0f9406b8296564a37304507b8dba3ed162371273a07b1fc98011fcd6ad72205f",
    "2360a8eb0cc7defa67b72998de90714e17e75b174a52ee4acb126c8cd995f0a8",
    "15871a5cddead976804c803cbaef255eb4815a5e96df8b006dcbbc2767f88948",
    "193a56766998ee9e0a8652dd2f3b1da0362f4f54f72379544f957ccdeefb420f",
    "2a394a43934f86982f9be56ff4fab1703b2e63c8ad334834e4309805e777ae0f",
    "1859954cfeb8695f3e8b635dcb345192892cd11223443ba7b4166e8876c0d142",
    "04e1181763050e58013444dbcb99f1902b11bc25d90bbdca408d3819f4fed32b",
    "0fdb253dee83869d40c335ea64de8c5bb10eb82db08b5e8b1f5e5552bfd05f23",
    "058cbe8a9a5027bdaa4efb623adead6275f08686f1c08984a9d7c5bae9b4f1c0",
    "1382edce9971e186497eadb1aeb1f52b23b4b83bef023ab0d15228b4cceca59a",
    "03464990f045c6ee0819ca51fd11b0be7f61b8eb99f14b77e1e6634601d9e8b5",
    "23f7bfc8720dc296fff33b41f98ff83c6fcab4605db2eb5aaa5bc137aeb70a58",
    "0a59a158e3eec2117e6e94e7f0e9decf18c3ffd5e1531a9219636158bbaf62f2",
    "06ec54c80381c052b58bf23b312ffd3ce2c4eba065420af8f4c23ed0075fd07b",
    "118872dc832e0eb5476b56648e867ec8b09340f7a7bcb1b4962f0ff9ed1f9d01",
    "13d69fa127d834165ad5c7cba7ad59ed52e0b0f0e42d7fea95e1906b520921b1",
    "169a177f63ea681270b1c6877a73d21bde143942fb71dc55fd8a49f19f10c77b",
    "04ef51591c6ead97ef42f287adce40d93abeb032b922f66ffb7e9a5a7450544d",
    "256e175a1dc079390ecd7ca703fb2e3b19ec61805d4f03ced5f45ee6dd0f69ec",
    "30102d28636abd5fe5f2af412ff6004f75cc360d3205dd2da002813d3e2ceeb2",
    "10998e42dfcd3bbf1c0714bc73eb1bf40443a3fa99bef4a31fd31be182fcc792",
    "193edd8e9fcf3d7625fa7d24b598a1d89f3362eaf4d582efecad76f879e36860",
    "18168afd34f2d915d0368ce80b7b3347d1c7a561ce611425f2664d7aa51f0b5d",
    "29383c01ebd3b6ab0c017656ebe658b6a328ec77bc33626e29e2e95b33ea6111",
    "10646d2f2603de39a1f4ae5e7771a64a702db6e86fb76ab600bf573f9010c711",
    "0beb5e07d1b27145f575f1395a55bf132f90c25b40da7b3864d0242dcb1117fb",
    "16d685252078c133dc0d3ecad62b5c8830f95bb2e54b59abdffbf018d96fa336",
    "0a6abd1d833938f33c74154e0404b4b40a555bbbec21ddfafd672dd62047f01a",
    "1a679f5d36eb7b5c8ea12a4c2dedc8feb12dffeec450317270a6f19b34cf1860",
    "0980fb233bd456c23974d50e0ebfde4726a423eada4e8f6ffbc7592e3f1b93d6",
    "161b42232e61b84cbf1810af93a38fc0cece3d5628c9282003ebacb5c312c72b",
    "0ada10a90c7f0520950f7d47a60d5e6a493f09787f1564e5d09203db47de1a0b",
    "1a730d372310ba82320345a29ac4238ed3f07a8a2b4e121bb50ddb9af407f451",
    "2c8120f268ef054f817064c369dda7ea908377feaba5c4dffbda10ef58e8c556",
    "1c7c8824f758753fa57c00789c684217b930e95313bcb73e6e7b8649a4968f70",
    "2cd9ed31f5f8691c8e39e4077a74faa0f400ad8b491eb3f7b47b27fa3fd1cf77",
    "23ff4f9d46813457cf60d92f57618399a5e022ac321ca550854ae23918a22eea",
    "09945a5d147a4f66ceece6405dddd9d0af5a2c5103529407dff1ea58f180426d",
    "188d9c528025d4c2b67660c6b771b90f7c7da6eaa29d3f268a6dd223ec6fc630",
    "3050e37996596b7f81f68311431d8734dba7d926d3633595e0c0d8ddf4f0f47f",
    "15af1169396830a91600ca8102c35c426ceae5461e3f95d89d829518d30afd78",
    "1da6d09885432ea9a06d9f37f873d985dae933e351466b2904284da3320d8acc",
    "2796ea90d269af29f5f8acf33921124e4e4fad3dbe658945e546ee411ddaa9cb",
    "202d7dd1da0f6b4b0325c8b3307742f01e15612ec8e9304a7cb0319e01d32d60",
    "096d6790d05bb759156a952ba263d672a2d7f9c788f4c831a29dace4c0f8be5f",
    "054efa1f65b0fce283808965275d877b438da23ce5b13e1963798cb1447d25a4",
    "1b162f83d917e93edb3308c29802deb9d8aa690113b2e14864ccf6e18e4165f1",
    "21e5241e12564dd6fd9f1cdd2a0de39eedfefc1466cc568ec5ceb745a0506edc",
    "1cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf08",
    "0f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb24100",
    "1671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c2320",
    "0fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870",
    "193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba",
    "102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f8",
    "0fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1",
    "216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d22",
    "1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161",
];
/// circomlib MDS matrix, t = 3 (`M[1]`): `new[i] = sum_j M[i][j] old[j]`.
const M: [[&str; 3]; 3] = [
    [
        "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
        "16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
        "2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
    ],
    [
        "2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
        "2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23",
        "101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa",
    ],
    [
        "143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
        "176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911",
        "19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0",
    ],
];
/// The optimised (neptune) round constants, t = 3 (`poseidon_constants_opt.json` `C[1]`).
const OPT_C: [&str; 81] = [
    "0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e",
    "00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864",
    "08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5",
    "084d520e4e5bb469e1f9075cb7c490efa59565eedae2d00ca8ef88ceea2b0197",
    "2d15d982d99577fa33da56722416fd734b3e667a2f9f15d8eb3e767ae0fd811e",
    "0ed2538844aba161cf1578a43cf0364e91601f6536a5996d0efbe65632c41b6d",
    "2600c27d879fbca186e739e6363c71cf804c877d829b735dcc3e3af02955e60a",
    "28f8bd44a583cbaa475bd15396430e7ccb99a5517440dfd970058558282bf2c5",
    "09cd7d4c380dc5488781aad012e7eaef1ed314d7f697a5572d030c55df153221",
    "11bb6ee1291aabb206120ecaace460d24b6713febe82234951e2bee7d0f855f5",
    "2d74e8fa0637d9853310f3c0e3fae1d06f171580f5b8fd05349cadeecfceb230",
    "2735e4ec9d39bdffac9bef31bacba338b1a09559a511a18be4b4d316ed889033",
    "0f03c1e9e0895db1a5da6312faa78e971106c33f826e08dcf617e24213132dfd",
    "17094cd297bf827caf92920205b719c18741090b8f777811848a7e9ead6778c4",
    "0db8f419c21f92461fc2b3219465798348df90d4178042c81ba7d4b4d559e2b8",
    "243443613f64ffa417427ed5933fcfbc66809db60b9ca1724a22709ceceeece2",
    "22af49fbfd5d7e9fcd256c25c07d3dd8ecbbae6deecd03aa04bb191fada75411",
    "14fbd37fa8ad6e4e0c78a20d93c7230c4677f797b4327323f7f7c097c19420e0",
    "15a9298bbb882534d4b2c9fbc6e4ef4189420c4eb3f3e1ea22faa7e18b5ae625",
    "2f7de75f23ddaaa5221323ebceb2f2ac83eef92e854e75434c2f1d90562232bc",
    "036a4432a868283b78a315e84c4ae5aeca216f2ff9e9b2e623584f7479cd5c27",
    "2180d7786a8cf810e277218ab14a11e5e39f3c962f11e860ae1c5682c797de5c",
    "0a268ef870736eebd0cb55be640d73ee3778990484cc03ce53572377eefff8e4",
    "1eefefe11c0be4664f2999031f15994829e982e8c90e09069df9bae16809a5b2",
    "27e87f033bd1e0a89ca596e8cb77fe3a4b8fb93d9a1129946571a3c3cf244c52",
    "01498a3e6599fe243321f57d6c5435889979c4f9d2a3e184d21451809178ee39",
    "27c0a41f4cb9fe67e9dd4d7ce33707f74d5d6bcc235bef108dea1bbebde507aa",
    "1f75230908b141b46637238b120fc770f4f4ae825d5004c16a7c91fe1dae280f",
    "25f99a9198e923167bba831b15fffd2d7b97b3a089808d4eb1f0a085bee21656",
    "101bc318e9ea5920d0f6acdc2bb526593d3d56ec8ed14c67622974228ba900c6",
    "1a175607067d517397c1334ecb019754ebc0c852a3cf091ec1ccc43207a83c76",
    "0f02f0e6d25f9ea3deb245f3e8c381ee6b2eb380ba4af5c1c4d89770155df37b",
    "151d757acc8237af08d8a6677203ec9692565de456ae789ff358b3163b393bc9",
    "256cd9577cea143049e0a1fe0068dd20084980ee5b757890a79d13a3a624fad4",
    "0513abaff6195ea48833b13da50e0884476682c3fbdd195497b8ae86e1937c61",
    "1d9570dc70a205f36f610251ee6e2e8039246e84e4ac448386d19dbac4e4a655",
    "18f1a5194755b8c5d5d7f1bf8aaa6f56effb012dd784cf5e044eec50b29fc9d4",
    "266b53b615ef73ac866512c091e4a4f2fa4bb0af966ef420d88163238eebbca8",
    "2d63234c9207438aa42b8de27644c02268304dfeb8c89a1a3f4fd6e8344ae0f7",
    "2ab30fbe51ee49bc7b3adde219a6f0b5fbb976205ef8df7e0021daee6f55c693",
    "1aee6d4b3ebe9366dcb9cce48969d4df1dc42abcd528b270068d9207fa6a45c9",
    "1891aeab71e34b895a79452e5864ae1d11f57646c60bb34aa211d123f6095219",
    "24492b5f95c0b0876437e94b4101c69118e16b2657771bd3a7caab01c818aa4b",
    "01752161b3350f7e1b3b2c8663a0d642964628213d66c10ab2fddf71bcfde68f",
    "0ab676935722e2f67cfb84938e614c6c2f445b8d148de54368cfb8f90a00f3a7",
    "0b0f72472b9a2f5f45bc730117ed9ae5683fc2e6e227e3d4fe0da1f7aa348189",
    "16aa6f9273acd5631c201d1a52fc4f8acaf2b2152c3ae6df13a78a513edcd369",
    "2f60b987e63614eb13c324c1d8716eb0bf62d9b155d23281a45c08d52435cd60",
    "18d24ae01dde92fd7606bb7884554e9df1cb89b042f508fd9db76b7cc1b21212",
    "04fc3bf76fe31e2f8d776373130df79d18c3185fdf1593960715d4724cffa586",
    "0d18f6b53fc69546cfdd670b41732bdf6dee9e06b21260c6b5d26270468dbf82",
    "00ba4231a918f13acec11fbafa17c5223f1f70b4cdb045036fa5d7045bd10e24",
    "07b458b2e00cd7c6100985301663e7ec33c826da0635ff1ebedd0dd86120b4c8",
    "1c35c2d96db90f4f6058e76f15a0c8286bba24e2ed40b16cec39e9fd7baa5799",
    "1d12bea3d8c32a5d766568f03dd1ecdb0a4f589abbef96945e0dde688e292050",
    "0d953e20022003270525f9a73526e9889c995bb62fdea94313db405a61300286",
    "29f053ec388795d786a40bec4c875047f06ff0b610b4040a760e33506d2671e1",
    "04188e33735f46b14a4952a98463bc12e264d5f446e0c3f64b9679caaae44fc2",
    "149ec28846d4f438a84f1d0529431bb9e996a408b7e97eb3bf1735cdbe96f68f",
    "0de20fae0af5188bca24b5f63630bad47aeafd98e651922d148cce1c5fdddee8",
    "12d650e8f790b1253ea94350e722ad2f7d836c234b8660edf449fba6984c6709",
    "22ab53aa39f34ad30ea96717ba7446aafdadbc1a8abe28d78340dfc4babb8f6c",
    "26503e8d4849bdf5450dabea7907bc3de0de109871dd776904a129db9149166c",
    "1d5e7a0e2965dffa00f5454f5003c5c8ec34b23d897e7fc4c8064035b0d33850",
    "0ee3d8daa098bee012d96b7ec48448c6bc9a6aefa544615b9cb3c7bbd07104cb",
    "1bf282082a04979955d30754cd4d9056fa9ef7a7175703d91dc232b5f98ead00",
    "07ae1344abfc6c2ce3e951bc316bee49971645f16b693733a0272173ee9ad461",
    "217e3a247827c376ec21b131d511d7dbdc98a36b7a47d97a5c8e89762ee80488",
    "215ffe584b0eb067a003d438e2fbe28babe1e50efc2894117509b616addc30ee",
    "1e770fc8ecbfdc8692dcedc597c4ca0fbec19b84e33da57412a92d1d3ce3ec20",
    "2f6243cda919bf4c9f1e3a8a6d66a05742914fc19338b3c0e50e828f69ff6d1f",
    "246efddc3117ecd39595d0046f44ab303a195d0e9cc89345d3c03ff87a11b693",
    "0053e8d9b3ea5b8ed4fe006f139cbc4e0168b1c89a918dfbe602bc62cec6adf1",
    "1b894a2f45cb96647d910f6a710d38b7eb4f261beefff135aec04c1abe59427b",
    "0aeb1554e266693d8212652479107d5fdc077abf88651f5a42553d54ec242cc0",
    "16a735f6f7209d24e6888680d1781c7f04ba7d71bd4b7d0e11faf9da8d9ca28e",
    "0487b8b7fab5fc8fd7c13b4df0543cd260e4bcbb615b19374ff549dcf073d41b",
    "1e75b9d2c2006307124bea26b0772493cfb5d512068c3ad677fdf51c92388793",
    "05120e3d0e28003c253b46d5ff77d272ae46fa1e239d1c6c961dcb02da3b388f",
    "0da5feb534576492b822e8763240119ac0900a053b171823f890f5fd55d78372",
    "2e211b39a023031a22acc1a1f5f3bb6d8c2666a6379d9d2c40cc8f78b7bd9abe",
];
/// The sparse partial-round matrices, t = 3 (`S[1]`), five a round.
const OPT_S: [&str; 285] = [
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "03f0815ab463f1b76ee25a9b8768b3231a89752f427f4f063ab718e707576b31",
    "15648bf46f60d82954c7e33029b3617357012a3d3b1d34c8e008859f1dbfb317",
    "127e00c2253de07818ca7f2eafdd7564d05ea850cf61f1daa0cfefbf7fbfba85",
    "066365afd18a41ef9382fc0b1d265cb4d3ce470a8cbbb878f7d48051630747bd",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "219d14f823513140dc69a96f7fe7e086f4fa24c84e57dcf2b099715c4404aae7",
    "03a30bfbbf2cb86d4a6a63a8050d91f9f14f4d33696d37ebaefa9ac2302132d5",
    "2121bbcdeaa33a35b0270fb7d5c9f94edad5a84d74b06e3385104b0b41935bcc",
    "196b544fbeb0a792cfbb82c289e579b7cd5580c2e338a389d053ef8b3d10e70e",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2809c3a1547c0cee89c1db270ef479c26973ec73edb4bd4e7d907ea0202f560f",
    "11c34446b083ef92ca157585a02b8b342a4c67175b31f4b5d40d4e96dfc5c8f1",
    "253ea0b33a8bf3b2367c030e3289cbe0f6242ad7709d90b86d9d8026e2e39925",
    "30467dc1930f6afe90c89d4007ad29fc4f5a19c006d1030438c16df85637bd5f",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2f9d4b55495f7e377e20e6f5a3a88af7aa6a536458b38bbe13c8ebfbbba54f44",
    "1d9e9d5c736e3151f11d36d499e7e093d8ee2353be18aad54cfd03ff0feac4b8",
    "124b617b43e598f9ebf622f7823a3de7d1bfedb87e097c315f343de301e54841",
    "198e7cfc66ae45774055cf073bedc945a5f9c5b19cae08d789cc5748ffe199b2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2eac25b3498dfadffd124ab3aad57789eb945ba57443099c5bb6c27ed977fe24",
    "1ee02c175cdfe1871b378305c1bb9c904e8af1d4454ed3550b3c6ab5f4f90126",
    "0616f8c34c607266b29ea8f9d2dfa47ff6fbb1d9745c48609fa98301d0f679d5",
    "181d68b0a188504958b9f19cbbdb972a853e51ed385e4883a43a42832803370b",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2d5397ce863464a25d6b7f5b015d579181d1ce2f24cbabf6059e9327f5ba7004",
    "15bf817491b94d71e8912940cc0b80277713e7d32da2b6591724d8dbd4bc2618",
    "2a7cbd11460b177ab76feab28b69485ac8cc687740bc910994a3827d29c08714",
    "0f7cd5ffa4661730ab56e447fae5cc1763cb462da80a85614c237b290de9d502",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0e0766004b4c4176eb13273508eb6575f768137d86d305be644ce04531008100",
    "0625fa7145813481f6d148be6b9c8bb7b54ee3c1afac00104e1f763000b9924c",
    "007c5472508b459916ee0f5461aad2e0b19cd9c7b184f515b65136318ce2c6a5",
    "0567375470d189b693ac77ab3fb7557231d53073951d43c54685879cb7a89fcb",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1d0406bcbec83f8d5165f56c063e42108ad21f51ea4bfc71601174ba5c7b8bcc",
    "0c02b18eef22332d280a8aa1f86405f3375f06342f8696ee7c73b46c63272cb7",
    "17c1fc174cd9a6ebeaa7add2f801a664823509ad4fd1b15aad053a55ad6da4cf",
    "05f843c23024eb1dab7ebbc86709a021aaa6caf433f7ed258a08638e9584b32d",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "22df2420697ca28b5cc51c53165e002727b45ccd90a55c87589f792f0ad8cb37",
    "2f1438303a7b49d473400aaedf0f48009fd3af804b76be86417588efc4d7302a",
    "2323d5fcf2da8965c6b2b7b4fbf9a24bbaa7f4dccd35d5ca6155c5463093b23b",
    "026c85b9dfbbe48fe83b753a5e7336b9f40f7b961e9c54f94e37700073d4d26e",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "031511000251ec86feb38b5ab4e335f070b271df4c20979528e41d65384c318f",
    "18e588324a9bbaacb42fa69e5d90a0c0e27cd16b941e34a60ff5df9a26c03af1",
    "2642b5d8e16b953b070635775c8d3c9498357d6ad9bef2e7d99f03c10ea1f95f",
    "21fc313ba11c60e8e84ff60db906a0f031189b0b48335c4221f909aef836c133",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2d3562e3d4b42bc6890b698cc6ab89f7311298bcbac6e4e9f2f4d93d06dae151",
    "0a74ef541d360e842e3e0b6ff7e5c7c77934a5f67616f01c189d886dfd2e0808",
    "140564b53e0a812ac3983d6e3b433afa43f434087d9e754967c2c9b1b02caf8a",
    "14709e32d98ae4cd18b400181e71ab9759c436c8e83fa6993adb6f2db6bba9d0",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0734b2366c59e394423f179e1266dd392372db4f2dba651f4a619a4b52bdc010",
    "11fb2d705c94b08d5ad3e3c5fb6629abe963ed92913642c7d02d7e71088fd2d4",
    "27d03abf5c1f290e5d715eba19371050ef6eb7f78fd84be834e4cc3618059484",
    "13ed9e9e6b452df27fb3353cfc2cd63ebe817f212a39c6a8bb9b441ac1395861",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1319c51cf37aaa10246cdaaa04a12e88795de4452604263a7c5b79ab99cbd23c",
    "000bca25588d187b7f9dad839f2c8cb526a4cf444eebbd0e715b6cea019ac3f2",
    "1d837ea0341c5964181226874b923cd01a069b493f02f7a3c01be23cf51d593f",
    "1b41ce9ed3634cbd42c427ce4c5c83774149e2a6dbd25f24012090db7de4e7f9",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0671f0e3b674ae7cddc790ecc4e946f4bca74b98b78a127c7b56bd6673f1ce1f",
    "019fc073797a39b272e40cd30615f55fefeb682c1ac14143071d0449a5426e4e",
    "017bee47d262a497fd1f7c5c6d5a7c70fa4209480bf5d97311c5096619e9fd13",
    "2073cff92d3141b480763539cff2978a4c7944721cc937ba00cc8527274471e3",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "03bd7b3e2c1885877f43182a55a91d48f9c58d152e730fe2c7aa46b1fa663baa",
    "226ebc9a538b5bbaff128edfb9bbf5fa0ceb100719a14c8dfed9ffbbbad9b6b7",
    "0d395f0b08b9fede0373a06e1552c0e634a49572af1d830dc6e394e8a5d3b21a",
    "28242439b524540a30d49b68e19e31ba5284bd3bcf1e0f2f41f77d5331f99ffa",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0370d6fa19eaac142d2de034801ab85e0b457e129e91f929754b48c6154d4df6",
    "09a16f573b3280f390762abf269579eaa37939bc0c753feb0a2b2e0bcbde1659",
    "2228e360fb5b162b496ac443f98127ee3c0021a690b71b268d99981368231d97",
    "07e42c2ca633d2c49fabf83991476d209431e34d8032b6a1b97675f3c567f944",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2ce12d7269663770c3cab85a6215a32eed35fda1d8e9d753a50fe96097724a9f",
    "03d7427704c61e2009eeb9b1b45a0125084bc4daf70973a7ba0b2231815b15de",
    "10f8abf0764185861c1267fcf4b4b33ca096fb4ddc4626732d86921e553e69c6",
    "17ccaf6f26f7267a025d7cb456e3aeb251a1a620aaf6568a5c95644c7c5914cc",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "063bb306b96310051385c3ce00ca820ad0e3651a6e55754d59de6df28cea4d51",
    "1f761ee5553c5e86f2c304a18095ab7403242e0b65e608bc920cf993a4169974",
    "0dc5f00bbfd7c1d9a23c0e666859ba6564bcde8761b45717cd6bdfc09de4e8f2",
    "06de511520e277b7df07c3536381c13eb44cf790a230abc391089760bfc40ef2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2a134348c8660efcf9ef54863e70528a1fd4481b50a1fe21f24a8c06e10cca03",
    "0aeb5023bbb9a64c4bd80089e99edf8ed5f6f1ffb63a7dbba1b33520bcfce37b",
    "141a6d0810366ae225ecb5f0bfdc9995406c5960ab26155836fc51fb7cb933d1",
    "09d2ea05ef54dadbbe776f404dca6626cc0b2539990bc0b8bfe87497f1e2c5b7",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1e56d244a8e41be5d104d5f8ef70891d22d4a5432441bfe8ff1a16e91719cdde",
    "1d4f020c57c4f14aec908b2f99b5c4fd5e09447fa85c2fd68ba4d5c5f50c7b49",
    "0763911a3a92a4f0e09f4e14cd03398d8d82a1e09db80fb0ee1e833764c18fd3",
    "12857275be2fe6b9ba2ec68f9061643f1fc5d9a2c5e47e55684366e54b302946",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2ed11ccd2e2e2376655ffe9a96c4b81adc0a60353c5d83d4d0ebf50d1bbf87c0",
    "03e31de8958e82645b320d5e3e966ef4726d5b1c2cfbb4acd288a21543c6d594",
    "11e880dfefdbd08858ae890046533d58da28a608d7e905366ec2ca4a36e71963",
    "1835b275deaed2d00704a9c3cc21ab7a44a34662978d53c190dc25e969a507b2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "068b75315e25ed4ace5a4a9480e1d82ce5d44f76f1324240419f372ff8d3c3f5",
    "1b7ef7d04aec73d62b052d2ad12b92a4268fccd795c839d698ad3b22823274d1",
    "28c0c848022a90606f6193ff5501b57216b670727f4b8efcc240d30bbaa9f03f",
    "13bda49296cbcc51686a7bfb1c39f3f254370985a16660efd6e5d82d4f068e1b",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2e7987ea8204389d11eb10b34265e378a945729f86c3e0e2fd38490d3a594141",
    "0826d4a2324ad3aa4b2b45c10a190fedef702aeffda3226ce5415fffd03935c8",
    "002dbeee85eaeaa9fa3675ef541c9df7bb964a85435c3b59685f93b434036ded",
    "227ee7a945edaee6919418ecb3279b11e6fa44f5f5c5abfb966a4be599cb86c7",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1d0a6d1a9519877805ac90d696faf2a5ffadc23986de8c698d541471c7244220",
    "2208aaba508ae816da4f333b7854fbbcd10eea1db284ec3e9f4de02b25f6e9d4",
    "28a58901035b2c99e36a7d29b587a215c9e59268e2f8e01a175720971ccf04ec",
    "0112f6d8d42b0a0d123a07865ca1376df317a2a14ffc0191226f38a8adfd6238",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "08c6eb19c016d1833174dda182d266d5c727f97fb4d01f1daf906b6d3c6e2308",
    "1359d2d6c8b5a116d0b38b95f9c642df75b1be9a48c8698ecfea9103f73f1879",
    "10c5052ec67ab9b6a467c1cc1878d91aaa07aacf7725f8a5ed42b699c4af3ca7",
    "0583c4d292d54f3cdb708803e6338fc6afdb188d5d4e9f060193823684c96c75",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2d94a1c55be382151a4054c5b96322e7bcd1fe2b3e076e16ee2c18bfc06f57b4",
    "15e3402fdde8770fb997369579c1b1703ef77c671927ead80dbc64dd2211c3ec",
    "185be98784817f22f7b21e6b867d5a71b5000bef8bb902eb302677e20a727be3",
    "18db4321c721c03666ed8927c89890aa8aad1b00c054547b5ca14cd94de467b6",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2a852b6247f5d61f0c390b3f3d799188528849bcd2cd0aff4eb2134a039b5126",
    "2510aeed51b7f506e65fb9a18ee0124aa5276f6de1cd771b165930204da58f22",
    "0f2074a32eb8260fb5bd3a236f03a47b47b7fb54dcad1d7977d6486513bab5f2",
    "2f4c69297866bd45a8270e19941926cec3531c9e12c4c2c84971404bfa044090",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "154668727d2dbadf05d083a65093c0d0e92df5fd5f3fd75e9b792c562a37473f",
    "1e6ffc5d6a1ff5dc4fd77fc5ab5c8c4e8d3e2e375bcd1194a91e5b0f7b13cadf",
    "2cf1a1d7c44309109d75acbc9395cb8398c8b2d428538571fafa389da29990c6",
    "140fb39a89f26f6d87cf76cd5ce8da47aa5d8a023e24cf016ecf64cf793c9880",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1289d13d58a17b5bf0712b201fb3cddfce2c16dac159990b8298a93a8589f9e8",
    "0f45cf974d2c9edb5781e8d3d207adc8370cf56bc5218749610920fe98b2db2e",
    "11909c81a16518046b79edfd24f5abcc585a81d1b333568b8687a1c9eceb44d4",
    "2990b23c81882f7709f3b891a0e3da4d6917672f2d5a1041fd7bbd6792330d16",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0609551b14716ca3cd5560e0821e7285e0a083ea9a16dc102ecf461e4aef7277",
    "0c8c1abdfab99d03fd93dced2467354b6175de1755f4f93dc0880eaa08d03f77",
    "138bd098c4923b9fbd02f33f8bec6c730db3fed298ec09f78a7a55d08f2e0b10",
    "2e61e4bc021630114673f0f77161ae55dcd0b45ce07d9ae3f21bb5a3190f14c0",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0124860913e3df8f65a9c4060ce3297c626abd1c22401c905ddb408260d8e910",
    "013807f89c394a133ec104804d955cbe125f24c5701d98286c6ac8b7ed052ec8",
    "2e88d1a6938f0788132aa9eeaec08d2f59aa444050c8f4c4e85578abb0fc2fe5",
    "01f3d24f17cfc6050a0cbf64e1f1787e2257be3c3ba607c2e8fcc1f26abf3104",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1fe1cb0e2ae169f83b9d4f133d41fb5b3fe6c76a82a916bfd9b62f82f0f8d0bf",
    "0ef79351229409cd353329221229827e19946f3d8d1c48bf5e3377f9177071f3",
    "18fb2e46fc1b90fe1c4893ef77a9d111507551883127860e89088608373beda9",
    "077afe2579f42ec14c32ef0761e23a3cc0ad6263a68c5cb61916bd57120d1868",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "079769092daa5a752642c04ccf8a6ea54e2ac9836fdd65d248b186f1490b7b99",
    "1d8bf229c19968f0254eb6e09c5c8bfd67eb9734606b676b663c76cf76bab4a5",
    "2a33b7d855e7fe55f93556e49e4b37737664f14236f17256428f29f6ec1bddad",
    "25b0331d7e2b15af4ec161c86e84ba6ab2056077e7aa7536340dc3187ccca8b2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0762098f5fe26598ccbf45e4810211b0ffcf8ccbb92c16e2f4f13f22342474e2",
    "0e234d720d70b2886d0da4c007b1bda42362e144185c70716dece2b6172c2514",
    "1d82bedccd2bc8a06e3742e720b7fec2ea72182f11c0c60d135c811152aa4b60",
    "0480064d4b3eb0ada5e9a3e7d05930b7c3397fd6b94d481314bd1c690a17c979",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "10a892763b3cca9ef7593fbb1140edc8c8e4580568560cf41867f7464fb0c11a",
    "0b5ec64548ea841ac921f9b2553680785978b315667ae4714dde4cd7f4de8b91",
    "10554aca4e348e5949761bd7131dfaebd78010edd030e1a9ce3c65c9db931d46",
    "15be66f38d86b0998b93655462b1f475b9be9de306e150d4ac648fab3db0cff6",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "176ad3600fd3491182d182957ffad01bf6c26e9d4ab0c23caaf308e427d3dbe8",
    "2b6f355b3dbf65f09335001d705ac125e3beb20f4fc11bd3ce82b5cf0af2e6f2",
    "01c85c06a6d5d40d81d7c89edefb32d1a8448c51288fa296b6de9ff788c77451",
    "20e1e876c4746a0cbd9a51d76b2e25f82361c389e43f7d1f51a70aaac2460d79",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "20e46219f684186d2a024b637bc35a29ee3b08ce737701392d987dda9217fa08",
    "2ea7279db9f2aa0f654e987907277c24480766367a8bd90e28be0f2ed6091367",
    "136be2a7f18924c9362096d472bc75ca0969dc077c9171b1641be95091780f74",
    "1ca2033501baa3f73067c4300fb0f51119ed5736fbc8f1f6c924baf0df5a0e9e",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0a82f199c2505277ecaa75e495f34e3525824f7a4a9d9fa1da810832b48a50c7",
    "0ecf10485307b4bae92fefb0d7f7782a9f37a2722e7ed9eb7925a2dea580b7d5",
    "07b642138dfd6a6dd12aa22f08a8296d68615c8478f13af16aebbbb339a3936b",
    "1d9dda43a25593ffd2256d34921fb86ed70e760ba76d61e9cbc3b6dd0f1a2150",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2f1af228520c8b751dc91136c91c6bccd5367eb08213d392958ce2fd3d7d2fce",
    "1fecfe833ad540455c6d6c1ab3de4abae61ada625a1a2b6b18551a45a6cde123",
    "18fc8e608c735b2b3b0d7583460227575657ff8a77abe637bdd3ad28e4a23c88",
    "28f740bc1182e9706ebf03cb3f53aba8a43ce0b618783a5586388a7547faa815",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "047998cc0af5a26b94ad301e4b998d29e960a4851cfd13822bed35b7146966a4",
    "1b5f1525b31db911dda43e415e1b9a3a9725c7b52e880ee130a14a692b777b70",
    "275a83fa5d19b4535f65e965a90eac9bf770ae9bd1d7b1af945fa57ed5c8de6e",
    "2e8789257ed2cbcccb430568e49bc9dc2a563359808c9897ce3e40a6f6a27aa8",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0927f46cfe80feefeb2721a4c09e9d17f60c34500dcd6e41e2925a39c8e2c7c1",
    "1f868ae04832a5dbc37619bfe6ab6a97fd8fb2cfbc1ecf9e0e484bbfe7698101",
    "09d7a11e27d2f53109b73f745b2defed65d94ba80f308fb19ce6d56c9b45eff4",
    "282d857cfe8da3b5104e1c2823fb7c5b9a7b25924fda5995b0c351aa2b879dff",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "20ba8a9fcec815b13f349ff830ae663b27576e135c0744f6987fb0f6ff49c217",
    "11b6afc91e32f1ca4589fba12e657d226d57b471ddd2ab1b66a8ae4dcbfb136e",
    "2e666402ac9cc588316e335c7d93db344788eec2c72ddf3f908141736cebc3be",
    "17522e0e9e64f795a202a110e283faad7057aec5c9ed9a1a74920f2794f18595",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2d2ed17f7a1f3ee9e20b470cad4cc7319e6adb40e2ff24b7878cb9878edbd3b9",
    "1a81efb19d7e1edaa96fa276e89e85d08f75e54a8136f4d73c937da16c7bf9f4",
    "27ff57c1ca847e57210a7b44e52e5630f299c5f451c7a0d515a16bb3bd33e237",
    "1c1a8e22230abcd13c5be96031bfa167840d117b3c6a5a0a11be26a7f5fb1a94",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "02a1c3f15d4927c843627a9cd533e4250d81e7774d2c32b59d5836f9c19a5657",
    "2ddbb7239eb904d81c52499b37cb4be1af0373a10ac112e185acb219899357e4",
    "0dff198393085a754e0d6faec54be81d8edf8bc25edadab48a86fad6da0afb60",
    "10d50c2473146bbc76275fcc589d038dec8db28728789f28b6d5f504bd1645ca",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "061e8328fb5593f92a53dfd40e1022e6231ba45948506282536b08b4476c1538",
    "1b589243847198ded90b644bee31ac58067debf3f07d3c51cfa5a0dd9f6d9784",
    "04b00c0da1f851e59863b053bd4c6087190f0bdcced99d5ce6f67a420a3bd1f7",
    "239941a46c2b93d9126a70163009a7ac27f8a8d42e35018b3bec8cdcb5ddfd67",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "204f26ca7993b03ac2c35377cb0a3712bfc9bc3ec0bfecb4e87ef6814acf2ea2",
    "085aff9c7fdadba039d832d8be165a1e5747cf7308d515e348ef117e926d721c",
    "249042a8dc111f27c4ae9db044c0b0b3f10e57d05e093158efd375df00ea2068",
    "06e799bcdf2b4a74542854f3029803e2f84550665203327b3e0825977413e96b",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "1cb3caed4bffb6aca9f4d2c002921bc3fffed333cae12085c612496183b87996",
    "0b47e9755fae480128a128bfd4faa6a3dd6ea03cab566889dcd99e84d310d51c",
    "0c7e4cea365c2061920a0c9fd2c360a6506293bc024fd1ca3f0bb730da886a4f",
    "21da1f701bac77bcbbaa30d964d6f6f63dbe1b20d9d6988c8dcd7ba4187215df",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "09ae612e8ba1ca1370905fb67899d10db86b47bd19965b6edd1a9486e3c6cc55",
    "262e1e0b56cac47fc150f284491190e6aab75445b0c99373fe1f7a0e3b95cf3d",
    "234bf4a7dce7587c2c87c293e3bb7c9e2a7bfa5f29fd4ddeaa5d3f67491d34bd",
    "2f6cbac694c886b02d0a527cac744fb658d2690e213d7432eee67f6cb69f70c2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "22accb18b7c49b4b7bb8c9fdf78b7aded52aa1842fff818d9a3300876dec3ad9",
    "081e2f0652f898c6d659f22d2c77be302eabd9182a0b3d3cbf623a1df7f8f2fc",
    "12c0a25e70d006eccea3ada75d669b8c534b962890f3ffc016b3186ad675b935",
    "10ef9c23848128cc2fd6fc869df24d7ab56efd349edd56f49f8d4f2381df3259",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "2161cd280772819dd4a81262b71df1bcc2c1d41b9491e0620bda347962b240f0",
    "2cebb0ae5108318eb406590041b5248292533364f799bc41b7f4fdd12cb8d38a",
    "2b2092f86b5979a7fe4f7c22d9561f3bf2852283a656880fb759e08709a0a62f",
    "1566b3402d774b8c08146188425a442450cfc900cf643e7382b2d8507a065fed",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "11a316aa31607f268fb4c56d6c57ba01627c3635fccf8d3d1a163e601d1a0173",
    "0de7ee069c934256b782648b560e595408a5e8434644609152e353d9c2874e44",
    "02d36f4029245704cc84df0297708c5e5845c36ae706c72e67128b8949eab1af",
    "01b8cc326b5ee160f53198c217fb34e899bde46cd82dabdc284d7951d546f858",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "27625da0f73ea07110689fb2187b71694cbf9203fd4ddf8a96ece85407550ebb",
    "1cd8338a3e5b1ad7cdc0da581a6950f6dea349c3edda06cb99ba025b94e4790d",
    "05ea02d65b209f6da763856c94b6438c78a8aed8d3e67e877a10a84072741a56",
    "09f7cb68d4e388f85366cfcf284a895d8b6250ced627e810817743ce03330a55",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "18c6230ddc0f896827b043f5e58dbd1aec13995a202e4ebcdfeb969e9d5c1212",
    "073a6114b997285e1a91c0a0fdccdaa8452e4f07bfd2e1a10578232096db6dcd",
    "2e78746340b2a6d222c6a1fc0838adf5fe013f39b1660ce7a3e7742b2f37be7f",
    "07aa27e7150baddd06303ad8e5e4bf4249b7ea846553def28e675259d3e5c851",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0b66fdec210ea4eabf623d2712cf4d9fa90273ccb4643f680cbc98345715ead8",
    "2fb6a29d9f394a589b633b8a4d6be51c9c0601ce0b140be641acea41c49aa5e3",
    "29025cc66fd041c4fc845e9c1c2cd1288569fb243d049bd675a69dc889b2ce2a",
    "150963f0aca9bcbe4126214ab9c627a6f7ed731cfa695168b85d534b17be3f48",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0ed59780302257663f72c1bfc6656eb7b5bca2e47bec0d5798a08a32a61a8a65",
    "07e19cb8a893369b3d30ae188c767f391c11888a3000debfc8d30c06143cc084",
    "0600c7d2b6946345e5f1eeeafb5eb8ec2b6ecfe528d2c052cd860afb4a3aa272",
    "0596083b6c972bc13022a1f33d6523b4773f2cd0a480e19ea0125119f0385705",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "210b5c36f27a07d97f98b9d8663d85db2e64513099a8e1ef6db21043631e24c4",
    "13bb2764bf1475cfc7bb9f3d563c5cc201c2489874e9159326a8f4930b7883f9",
    "202cf557d625c26080eb082862a76757287872b181e89997219e4b7576e24d30",
    "0e561c3f8bd4f76e76d49e97142d220601fbc5a03d905a4728ea1f95fd8824b2",
    "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
    "0de20097480e7555471785de07bd9809d57dd859bbe827307c33ae9ed7890597",
    "072f2a6287fb984bb810df8c5788eebcfd2825613cb72bb80cde8edd76d2e97d",
    "2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
    "143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
];
/// The MDS matrix of the optimised form (`M[1]`), applied transposed: `new[i] = sum_j M[j][i] old[j]`.
const OPT_M: [[&str; 3]; 3] = [
    [
        "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
        "2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
        "143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
    ],
    [
        "16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
        "2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23",
        "176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911",
    ],
    [
        "2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
        "101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa",
        "19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0",
    ],
];
/// The pre-sparse matrix (`P[1]`), applied transposed.
const OPT_P: [[&str; 3]; 3] = [
    [
        "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
        "1e6f20a11d1e31e43f83dcedddb9a0236203f5f24ae72c925a8a79a66831f51d",
        "1bd8c528472e57bdc722a141f8785694484f426725403ae24084e3027e782467",
    ],
    [
        "16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
        "2d51ba82c8073c6d6bacf1ad5e56655b7143625b0a9e9c3190527a1a5f05079a",
        "1b07d6d51e6f7e97e0ab10fc2e51ea83ce0611f940ff0731b5f927fe8d6a77c9",
    ],
    [
        "2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
        "11e12a40d262ae88e8376f62d19edf43093cdef1ccf34d985a3e53f0bc5765a0",
        "221c170e4d02a2479c6f3e47b5ff55781574f980d89038308a3ef37cce8463bd",
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonnative::tests::{Rng, Sliced, exhaust, gadget};
    use crate::{build, read_statement};

    fn fr_of(x: &BigUint) -> Fr {
        Fr::from_be_bytes_mod_order(&x.to_bytes_be())
    }

    #[test]
    fn reference_matches_published_vector() {
        let s = permute_ref([Fr::ZERO, Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(
            hex(&digest_bytes(s[0])),
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The optimised form (`poseidon_opt.js`) natively, on `Fr`.
    fn permute_opt(mut s: [Fr; 3]) -> [Fr; 3] {
        let c = |i: usize| fr(OPT_C[i]);
        let mat = |m: &[[&str; 3]; 3], s: [Fr; 3]| -> [Fr; 3] {
            std::array::from_fn(|i| (0..T).map(|j| fr(m[j][i]) * s[j]).sum())
        };
        for i in 0..T {
            s[i] += c(i);
        }
        for r in 0..ROUNDS_F / 2 - 1 {
            s = s.map(pow5);
            for i in 0..T {
                s[i] += c((r + 1) * T + i);
            }
            s = mat(&OPT_M, s);
        }
        s = s.map(pow5);
        for i in 0..T {
            s[i] += c((ROUNDS_F / 2) * T + i);
        }
        s = mat(&OPT_P, s);
        for r in 0..ROUNDS_P {
            s[0] = pow5(s[0]) + c((ROUNDS_F / 2 + 1) * T + r);
            let sp = |j: usize| fr(OPT_S[(2 * T - 1) * r + j]);
            let s0 = sp(0) * s[0] + sp(1) * s[1] + sp(2) * s[2];
            for k in 1..T {
                s[k] += s[0] * sp(T + k - 1);
            }
            s[0] = s0;
        }
        for r in 0..ROUNDS_F / 2 - 1 {
            s = s.map(pow5);
            for i in 0..T {
                s[i] += c((ROUNDS_F / 2 + 1) * T + ROUNDS_P + r * T + i);
            }
            s = mat(&OPT_M, s);
        }
        s = s.map(pow5);
        mat(&OPT_M, s)
    }

    #[test]
    fn optimised_form_is_the_permutation() {
        let mut rng = Rng(5);
        let r = bn254_r().p;
        for _ in 0..20 {
            let s: [Fr; 3] = std::array::from_fn(|_| fr_of(&rng.below(&r)));
            assert_eq!(permute_opt(s), permute_ref(s));
        }
    }

    /// The S-box gadget at a small prime, over every input and every hint: accepted means `y = x^5 mod p`, and
    /// every input has an accepted hint.
    #[test]
    fn sbox_sound_and_complete_for_every_hint() {
        for p in [5u64, 7] {
            let m = Modulus::new(BigUint::from(p));
            let (s, outs) = gadget(|nn| {
                let x = nn.hint(3, BigUint::zero);
                let mut pos = Pos {
                    nn,
                    m: m.clone(),
                    ints: vec![],
                    limit: LIMIT,
                    stats: Stats::default(),
                };
                let xi = pos.int(x.clone());
                let y = pos.pow5(xi);
                vec![x.w, pos.ints[y].w.clone()]
            });
            let mut found = [false; 8];
            exhaust(&s, |_, v, l| {
                let (x, y, ok) = (
                    Sliced::word(v, &outs[0], l),
                    Sliced::word(v, &outs[1], l),
                    Sliced::word(v, &outs[2], l),
                );
                if ok == 1 {
                    assert_eq!(y % p, x.pow(5) % p, "p {p}: {x}^5 accepted as {y}");
                    found[x as usize] = true;
                }
            });
            assert!(found.iter().all(|&f| f));
            println!("pow5 mod {p}: all {} input and hint bits enumerated", s.n_inputs());
        }
    }

    /// Materialising a linear form at a small prime, every input and hint: `3 a + 5 b + 2` (mod 7), canonical.
    #[test]
    fn materialise_sound_and_complete_for_every_hint() {
        let p = 7u64;
        let m = Modulus::new(BigUint::from(p));
        let (s, outs) = gadget(|nn| {
            let a = nn.hint(3, BigUint::zero);
            let b = nn.hint(3, BigUint::zero);
            let mut pos = Pos {
                nn,
                m: m.clone(),
                ints: vec![],
                limit: LIMIT,
                stats: Stats::default(),
            };
            let (ia, ib) = (pos.int(a.clone()), pos.int(b.clone()));
            let f = Lf {
                terms: vec![(ia, BigUint::from(3u32)), (ib, BigUint::from(5u32))],
                k: BigUint::from(2u32),
            };
            let x = pos.materialise(&f, true);
            vec![a.w, b.w, pos.ints[x].w.clone()]
        });
        let mut found = [false; 64];
        exhaust(&s, |_, v, l| {
            let g = |k: usize| Sliced::word(v, &outs[k], l);
            if g(3) == 1 {
                assert_eq!(g(2), (3 * g(0) + 5 * g(1) + 2) % p);
                found[(g(0) | g(1) << 3) as usize] = true;
            }
        });
        assert!(found.iter().all(|&f| f));
    }

    fn run_workload<const LEN: usize>(seeds: &[u64]) -> usize {
        let (circuit, srcs, used) = build::<PoseidonSponge<LEN>>();
        circuit.check_wired().unwrap();
        for &seed in seeds {
            let inst = PoseidonSponge::<LEN>::instance(seed);
            let st = read_statement(&circuit.values(&inst.inputs), &srcs);
            assert_eq!(st, inst.statement, "seed {seed}");
            assert_eq!(st[32], 1);
            let bad = PoseidonSponge::<LEN>::invalid_instance(seed).unwrap();
            let st = read_statement(&circuit.values(&bad.inputs), &srcs);
            assert_eq!(st, bad.statement);
            assert_ne!(st, inst.statement);
        }
        // A wrong digest hint (its lowest bit) and a wrong message bit with honest hints both fail.
        let inst = PoseidonSponge::<LEN>::instance(seeds[0]);
        let mut bad = inst.inputs.clone();
        bad[0] = !bad[0];
        assert_eq!(
            read_statement(&circuit.values(&bad), &srcs)[32],
            0,
            "a message bit flipped under the same hints"
        );
        let n = bad.len();
        let mut bad = inst.inputs.clone();
        // A bit of the last hints (the digest's residue and quotient, or the last S-box's) flipped.
        bad[n - 300] = !bad[n - 300];
        assert_eq!(read_statement(&circuit.values(&bad), &srcs)[32], 0);
        used
    }

    /// One permutation (a 62-byte message: two chunks), the whole circuit evaluated.
    #[test]
    fn sponge_one_permutation_matches_reference() {
        let used = run_workload::<62>(&[1, 2, 3]);
        println!("poseidon, 62-byte message (1 permutation): {used} rows");
    }

    /// The row breakdown, from one permutation's circuit, and the 1 KiB workload's totals.
    #[test]
    fn row_breakdown() {
        for limit in [1, 2, 3] {
            let mut c = Ckt::new();
            let before = c.rows();
            let (_, _, st) = circuit(&mut c, None, 124, limit);
            let rows = c.rows() - before;
            println!(
                "limit {limit}: 2 permutations {rows} rows; S-box {} rows each ({} of them); materialisations {} \
                 rows ({}); permutation {:?}",
                st.sbox / st.n_sbox,
                st.n_sbox,
                st.materialise,
                st.n_materialise,
                st.perms
            );
        }
        let mut c = Ckt::new();
        let (_, _, st) = circuit(&mut c, None, 124, LIMIT);
        let perm = st.perms[1];
        println!("rows per S-box: {}", st.sbox / st.n_sbox);
        println!(
            "rows per full round (3 S-boxes, 3 materialisations): {}",
            st.full_rounds / (2 * ROUNDS_F)
        );
        println!("rows per partial round: {}", st.partial_rounds / (2 * ROUNDS_P));
        println!("rows per permutation (second, all inputs hinted): {perm}");
    }

    /// The 1 KiB workload built, closed (2^29 rows) and evaluated for three seeds and an invalid instance (some
    /// 30 GB; run with `--ignored`).
    #[test]
    #[ignore]
    fn full_1k_matches_reference() {
        let used = run_workload::<MESSAGE_BYTES>(&[1, 2, 3]);
        println!("poseidon 1 KiB: {used} rows, evaluated");
    }

    /// The 1 KiB workload counted (about 2^28.4 rows: some 10 GB; run with `--ignored`).
    #[test]
    #[ignore]
    fn count_1k() {
        let mut c = Ckt::new();
        let (_, _, st) = circuit(&mut c, None, MESSAGE_BYTES, LIMIT);
        println!(
            "poseidon 1 KiB: {} rows (2^{:.2}), {} inputs; S-boxes {} x {}; materialisations {} rows; perms {:?}",
            c.rows(),
            (c.rows() as f64).log2(),
            c.n_inputs(),
            st.n_sbox,
            st.sbox / st.n_sbox,
            st.materialise,
            st.perms
        );
    }
}
