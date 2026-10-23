//! Encoded-input ML-DSA-44 verification. SHAKE uses the shared Falcon permutation hook.
//! Finite circuit families expose rejection budgets and reject exhausted executions.
use crate::{Ckt, Instance, PUBLIC_BITS, Wire, Word, Workload, bytes_to_bits};
const Q: u64 = 8_380_417;
fn konst(x: u64, n: usize) -> Word {
    Ckt::constant_word(x.into(), n)
}
fn wide(x: &[Wire], n: usize) -> Word {
    let mut a = x.to_vec();
    a.resize(n, Wire::ZERO);
    a
}
fn lt(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Wire {
    c.sub(a, b).1.not()
}
fn reduce(c: &mut Ckt, mut a: Word) -> Word {
    // 2^23 = 8191 (mod q). Repeated folds reduce any <=46-bit product.
    while a.len() > 24 {
        let hi = a[23..].to_vec();
        let n = (hi.len() + 13).max(24) + 1;
        let shifted = {
            let mut x = vec![Wire::ZERO; 13];
            x.extend(&hi);
            wide(&x, n)
        };
        let h = wide(&hi, n);
        let scaled = c.sub(&shifted, &h).0;
        let low = wide(&a[..23], n);
        a = c.add(&scaled, &low);
        // The proven numeric bound is < 2^(hi_bits+13)+2^23.
        let bound = (((1u128 << hi.len()) - 1) * 8191) + ((1u128 << 23) - 1);
        a.truncate((128 - bound.leading_zeros()) as usize);
    }
    let n = a.len().max(24);
    a = wide(&a, n);
    // A <2^24 and q >2^22: at most two subtractions.
    for _ in 0..2 {
        let (d, ge) = c.sub(&a, &konst(Q, n));
        a = c.mux_word(ge, &d, &a);
    }
    a.truncate(23);
    a
}
fn add(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    let s = c.add(&wide(a, 24), &wide(b, 24));
    reduce(c, s)
}
fn sub(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    let aq = c.add(&wide(a, 24), &konst(Q, 24));
    let s = c.sub(&aq, &wide(b, 24)).0;
    reduce(c, s)
}
fn mul(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    if a.iter().all(|w| w.as_const().is_some()) && !b.iter().all(|w| w.as_const().is_some()) {
        return mul(c, b, a);
    }
    if let Some(coefficient) = b
        .iter()
        .enumerate()
        .try_fold(0u64, |v, (i, w)| w.as_const().map(|bit| v | ((bit as u64) << i)))
    {
        let modulus = crate::falcon::Modq::new(Q);
        let mut linear = crate::falcon::Lin::new(&modulus);
        linear.add(&crate::falcon::MV::word(a), coefficient, 0);
        let output = linear.finish(c, true);
        return reduce(c, output.bits());
    }
    let mut accumulator = crate::falcon::Acc::default();
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            let product = c.and(x, y);
            accumulator.lit(product, i + j, false);
        }
    }
    let acc = accumulator.finish(c, 46);
    reduce(c, acc)
}
fn pow(mut a: u64, mut e: u64) -> u64 {
    let mut r = 1;
    while e > 0 {
        if e & 1 != 0 {
            r = r * a % Q;
        }
        a = a * a % Q;
        e >>= 1;
    }
    r
}
fn zeta(k: usize) -> u64 {
    pow(1753, (k as u8).reverse_bits().into())
}
fn ntt(c: &mut Ckt, mut a: Vec<Word>, inverse: bool) -> Vec<Word> {
    if !inverse {
        let mut k = 0;
        let mut len = 128;
        while len > 0 {
            for start in (0..256).step_by(2 * len) {
                k += 1;
                let z = konst(zeta(k), 23);
                for j in start..start + len {
                    let t = mul(c, &z, &a[j + len]);
                    let x = add(c, &a[j], &t);
                    let y = sub(c, &a[j], &t);
                    a[j] = x;
                    a[j + len] = y;
                }
            }
            len /= 2;
        }
    } else {
        let mut k = 256;
        let mut len = 1;
        while len < 256 {
            for start in (0..256).step_by(2 * len) {
                k -= 1;
                let z = konst(Q - zeta(k), 23);
                for j in start..start + len {
                    let x = add(c, &a[j], &a[j + len]);
                    let y = sub(c, &a[j], &a[j + len]);
                    a[j] = x;
                    a[j + len] = mul(c, &z, &y);
                }
            }
            len *= 2;
        }
        let inv = konst(pow(256, Q - 2), 23);
        a = a.iter().map(|x| mul(c, x, &inv)).collect();
    }
    a
}
/// Stable prefix-count compaction shared with the Falcon frontend.
fn compact(c: &mut Ckt, candidates: Vec<Word>) -> (Vec<Word>, Wire) {
    let reject: Vec<_> = candidates.iter().map(|v| lt(c, v, &konst(Q, 23)).not()).collect();
    crate::falcon::compact(c, &candidates, &reject, 256, 5)
}
fn expand_a(c: &mut Ckt, rho: &[Wire], checks: &mut Word) -> Vec<Vec<Vec<Word>>> {
    (0..4)
        .map(|row| {
            (0..4)
                .map(|col| {
                    let mut input = rho.to_vec();
                    input.extend(konst(col, 8));
                    input.extend(konst(row, 8));
                    let stream = crate::falcon::shake(c, &input, 840, 168);
                    let candidates = stream.as_chunks::<24>().0.iter().map(|w| w[..23].to_vec()).collect();
                    let (a, ok) = compact(c, candidates);
                    checks.push(ok);
                    a
                })
                .collect()
        })
        .collect()
}
fn ball(c: &mut Ckt, seed: &[Wire], checks: &mut Word) -> Vec<Word> {
    let stream = crate::falcon::shake256(c, seed, 136);
    // Store each coefficient as (nonzero,negative). No field multiplications here.
    let mut p = vec![vec![Wire::ZERO; 2]; 256];
    let mut step = konst(0, 6);
    for byte in stream[64..].as_chunks::<8>().0.iter() {
        let active = lt(c, &step, &konst(39, 6));
        let i = c.add(&wide(&step, 8), &konst(217, 8));
        let below = lt(c, &i, byte).not();
        let take = c.and(active, below);
        let mut old = vec![Wire::ZERO; 2];
        let mut sign = Wire::ZERO;
        for k in 0..39 {
            let eq = c.eq(&step, &konst(k, 6));
            let t = c.and(eq, stream[k as usize]);
            sign = c.or(sign, t);
        }
        let mut at_j = Vec::new();
        let mut at_i = Vec::new();
        for k in 0..256 {
            let ej = c.eq(byte, &konst(k, 8));
            let ei = c.eq(&i, &konst(k, 8));
            for (b, out) in old.iter_mut().enumerate() {
                let t = c.and(ej, p[k as usize][b]);
                *out = c.or(*out, t);
            }
            at_j.push(c.and(take, ej));
            at_i.push(c.and(take, ei));
        }
        for k in 0..256 {
            let moved = c.mux_word(at_i[k], &old, &p[k]);
            p[k] = c.mux_word(at_j[k], &[Wire::ONE, sign], &moved);
        }
        let inc = wide(&[take], 6);
        step = c.add(&step, &inc);
    }
    checks.push(c.eq(&step, &konst(39, 6)));
    p.into_iter()
        .map(|v| {
            let signed = c.mux_word(v[1], &konst(Q - 1, 23), &konst(1, 23));
            c.mux_word(v[0], &signed, &konst(0, 23))
        })
        .collect()
}
fn hints(c: &mut Ckt, bytes: &[Wire], checks: &mut Word) -> Vec<Vec<Wire>> {
    let indices: Vec<_> = bytes[..640].as_chunks::<8>().0.iter().collect();
    let ends: Vec<_> = bytes[640..].as_chunks::<8>().0.iter().collect();
    let mut begin = konst(0, 8);
    let mut out = Vec::new();
    for end in ends {
        checks.push(lt(c, end, &begin).not());
        checks.push(lt(c, &konst(80, 8), end).not());
        let mut used = Vec::new();
        for s in 0..80 {
            let ge = lt(c, &konst(s, 8), &begin).not();
            let under = lt(c, &konst(s, 8), end);
            used.push(c.and(ge, under));
        }
        for s in 1..80 {
            let increasing = lt(c, indices[s - 1], indices[s]);
            let ok = c.or(used[s].not(), used[s - 1].not());
            checks.push(c.or(ok, increasing));
        }
        let poly = (0..256)
            .map(|i| {
                let terms: Vec<_> = (0..80)
                    .map(|s| {
                        let eq = c.eq(indices[s], &konst(i, 8));
                        c.and(eq, used[s])
                    })
                    .collect();
                c.any(&terms)
            })
            .collect();
        out.push(poly);
        begin = end.to_vec();
    }
    for (s, index) in indices.iter().enumerate() {
        let unused = lt(c, &konst(s as u64, 8), &begin).not();
        let zero = c.is_zero(*index);
        checks.push(c.or(unused.not(), zero));
    }
    out
}
fn high_bits(c: &mut Ckt, r: &[Wire], hint: Wire) -> Word {
    // Exact Euclidean division of r+gamma2-1 by 2*gamma2; quotient 44 maps to zero.
    let gamma2 = (Q - 1) / 88;
    let numerator = c.add(&wide(r, 24), &konst(gamma2 - 1, 24));
    let mut rem = vec![Wire::ZERO; 24];
    let mut quotient = vec![Wire::ZERO; 24];
    for i in (0..24).rev() {
        let mut shifted = vec![numerator[i]];
        shifted.extend(&rem[..23]);
        let (d, ge) = c.sub(&shifted, &konst(2 * gamma2, 24));
        rem = c.mux_word(ge, &d, &shifted);
        quotient[i] = ge;
    }
    let is44 = c.eq(&quotient, &konst(44, 24));
    let high = c.mux_word(is44, &konst(0, 6), &quotient[..6]);
    // LowBits >0 iff r > high*2gamma2, except high=0 wraparound near q.
    let base = mul(c, &wide(&high, 23), &konst(2 * gamma2, 23));
    let pos0 = lt(c, &base, r);
    let pos = c.and(pos0, is44.not());
    let plus = c.add(&high, &konst(1, 6));
    let wrapplus = c.eq(&plus, &konst(44, 6));
    let plus = c.mux_word(wrapplus, &konst(0, 6), &plus);
    let (minus, _) = c.sub(&high, &konst(1, 6));
    let zero = c.is_zero(&high);
    let minus = c.mux_word(zero, &konst(43, 6), &minus);
    let adjusted = c.mux_word(pos, &plus, &minus);
    c.mux_word(hint, &adjusted, &high)
}
/// Standard byte encodings in the order pk || message || signature. Public digest is
/// exactly L5's BLAKE2s(validity_u64_le || pk || message), followed by validity.
pub fn build(c: &mut Ckt) -> Word {
    let pk = c.inputs(1312 * 8);
    let message = c.inputs(32 * 8);
    let sig = c.inputs(2420 * 8);
    let mut checks = Vec::new();
    let mut z = Vec::new();
    for poly in sig[256..(32 + 2304) * 8].as_chunks::<{ 256 * 18 }>().0.iter() {
        z.push(
            poly.as_chunks::<18>()
                .0
                .iter()
                .map(|raw| {
                    checks.push(lt(c, &konst(78, 18), raw));
                    checks.push(lt(c, raw, &konst(262066, 18)));
                    let x = c.sub(&konst(Q + 131072, 24), &wide(raw, 24)).0;
                    reduce(c, x)
                })
                .collect::<Vec<_>>(),
        );
    }
    let h = hints(c, &sig[(32 + 2304) * 8..], &mut checks);
    eprintln!("mldsa stage decode rows {}", c.rows());
    let a = expand_a(c, &pk[..256], &mut checks);
    eprintln!("mldsa stage ExpandA rows {}", c.rows());
    let tr = crate::falcon::shake256(c, &pk, 64);
    let mut mp = tr;
    mp.extend(konst(0, 16));
    mp.extend(&message);
    let mu = crate::falcon::shake256(c, &mp, 64);
    let challenge = ball(c, &sig[..256], &mut checks);
    let chat = ntt(c, challenge, false);
    let zhat: Vec<_> = z.into_iter().map(|p| ntt(c, p, false)).collect();
    let t1: Vec<Vec<Word>> = pk[256..]
        .as_chunks::<{ 256 * 10 }>()
        .0
        .iter()
        .map(|p| {
            p.as_chunks::<10>()
                .0
                .iter()
                .map(|v| {
                    let mut w = vec![Wire::ZERO; 13];
                    w.extend(v);
                    w
                })
                .collect()
        })
        .collect();
    let that: Vec<_> = t1.into_iter().map(|p| ntt(c, p, false)).collect();
    eprintln!("mldsa stage forward NTT rows {}", c.rows());
    let mut encoded = Vec::new();
    for row in 0..4 {
        let mut az = vec![konst(0, 23); 256];
        for col in 0..4 {
            for i in 0..256 {
                let product = mul(c, &a[row][col][i], &zhat[col][i]);
                az[i] = add(c, &az[i], &product);
            }
        }
        for i in 0..256 {
            let product = mul(c, &chat[i], &that[row][i]);
            az[i] = sub(c, &az[i], &product);
        }
        let w = ntt(c, az, true);
        for i in 0..256 {
            encoded.extend(high_bits(c, &w[i], h[row][i]));
        }
    }
    let mut challenge_input = mu;
    challenge_input.extend(encoded);
    let computed = crate::falcon::shake256(c, &challenge_input, 32);
    checks.push(c.eq(&computed, &sig[..256]));
    let valid = c.all(&checks);
    let mut digest_input = vec![valid];
    digest_input.resize(64, Wire::ZERO);
    digest_input.extend(pk);
    digest_input.extend(message);
    let mut public = crate::blake2s::blake2s(c, &digest_input);
    public.push(valid);
    public.resize(PUBLIC_BITS, Wire::ZERO);
    eprintln!(
        "mldsa stage complete rows {} perms {}",
        c.rows(),
        c.keccak_calls().len()
    );
    public
}
pub struct MlDsa44;
impl Workload for MlDsa44 {
    const NAME: &'static str = "mldsa44";
    fn build(c: &mut Ckt) -> Word {
        build(c)
    }
    fn instance(_: u64) -> Instance {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("vectors/mldsa44-L5.json")).unwrap();
        let hex = |name: &str| {
            let s = fixture[name].as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let mut data = hex("pk");
        data.extend(hex("message"));
        data.extend(hex("signature"));
        let mut statement = [0; 64];
        statement[..32].copy_from_slice(&hex("public_digest"));
        statement[32] = 1;
        Instance {
            inputs: bytes_to_bits(&data),
            statement,
        }
    }
    fn invalid_instance(_: u64) -> Option<Instance> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn eval(f: impl FnOnce(&mut Ckt, &[Wire]) -> Word, words: &[(u64, usize)]) -> u64 {
        let mut c = Ckt::new();
        let inputs = c.inputs(words.iter().map(|x| x.1).sum());
        let mut output = f(&mut c, &inputs);
        output.resize(PUBLIC_BITS, Wire::ZERO);
        let (circuit, sources) = c.finish(&output);
        let bits: Vec<bool> = words
            .iter()
            .flat_map(|&(v, n)| (0..n).map(move |i| v >> i & 1 != 0))
            .collect();
        let values = circuit.values(&bits);
        let statement = crate::read_statement(&values, &sources);
        u64::from_le_bytes(statement[..8].try_into().unwrap())
    }
    #[test]
    fn modular_products_and_usehint_boundaries() {
        for (a, b) in [
            (0, 0),
            (Q - 1, Q - 1),
            (Q - 1, 1753),
            (1234567, 7654321),
            (8191, 1 << 22),
        ] {
            assert_eq!(eval(|c, x| mul(c, &x[..23], &x[23..]), &[(a, 23), (b, 23)]), a * b % Q);
        }
        let gamma2 = (Q - 1) / 88;
        for r in [0, 1, gamma2, gamma2 + 1, 2 * gamma2, Q - gamma2 - 1, Q - gamma2, Q - 1] {
            for hint in [false, true] {
                let quotient = (r + gamma2 - 1) / (2 * gamma2);
                let high = if quotient == 44 { 0 } else { quotient };
                let low = if quotient == 44 {
                    r as i64 - Q as i64
                } else {
                    r as i64 - (high * 2 * gamma2) as i64
                };
                let expected = if !hint {
                    high
                } else if low > 0 {
                    (high + 1) % 44
                } else {
                    (high + 43) % 44
                };
                assert_eq!(
                    eval(|c, x| high_bits(c, x, Wire::constant(hint)), &[(r, 23)]),
                    expected,
                    "r={r},hint={hint}"
                );
            }
        }
    }
}
