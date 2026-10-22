//! Boolean field gadgets for the existing full-adder format.

use circuit_suite::{Ckt, Wire, Word};
use primitives::field::F192;

fn xor(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    c.xor_word(a, b)
}

fn clmul(c: &mut Ckt, a: &[Wire], b: &[Wire], leaf: usize) -> Word {
    let n = a.len();
    assert_eq!(n, b.len());
    if n <= leaf {
        let mut out = vec![Wire::ZERO; 2 * n];
        for i in 0..n {
            for j in 0..n {
                let p = c.and(a[i], b[j]);
                out[i + j] = c.xor(out[i + j], p);
            }
        }
        return out;
    }
    let h = n / 2;
    let low = clmul(c, &a[..h], &b[..h], leaf);
    let high = clmul(c, &a[h..], &b[h..], leaf);
    let aa = xor(c, &a[..h], &a[h..]);
    let bb = xor(c, &b[..h], &b[h..]);
    let middle = clmul(c, &aa, &bb, leaf);
    let mut out = vec![Wire::ZERO; 2 * n];
    for i in 0..n {
        out[i] = c.xor(out[i], low[i]);
        out[i + n] = c.xor(out[i + n], high[i]);
        let cross = c.xor3(middle[i], low[i], high[i]);
        out[i + h] = c.xor(out[i + h], cross);
    }
    out
}

fn base_mul(c: &mut Ckt, a: &[Wire], b: &[Wire], leaf: usize) -> Word {
    let mut product = clmul(c, a, b, leaf);
    for k in (64..128).rev() {
        for shift in [0, 1, 3, 4] {
            product[k - 64 + shift] = c.xor(product[k - 64 + shift], product[k]);
        }
    }
    product[..64].to_vec()
}

#[cfg(test)]
fn linear_naive(c: &mut Ckt, a: &[Wire], f: impl Fn(F192) -> F192) -> Word {
    let mut out = vec![Wire::ZERO; 192];
    for (i, &bit) in a.iter().enumerate() {
        if bit == Wire::ZERO {
            continue;
        }
        let mut limbs = [0u64; 3];
        limbs[i / 64] = 1 << (i % 64);
        let image = f(F192::new(limbs[0], limbs[1], limbs[2]));
        for (j, limb) in [image.c0, image.c1, image.c2].into_iter().enumerate() {
            let mut limb = limb;
            while limb != 0 {
                let k = limb.trailing_zeros() as usize;
                limb &= limb - 1;
                out[64 * j + k] = c.xor(out[64 * j + k], bit);
            }
        }
    }
    out
}

#[cfg(test)]
fn mul_with_leaf(c: &mut Ckt, a: &[Wire], b: &[Wire], leaf: usize) -> Word {
    let aa: Vec<_> = a.chunks(64).collect();
    let bb: Vec<_> = b.chunks(64).collect();
    let diagonal: Vec<_> = (0..3).map(|i| base_mul(c, aa[i], bb[i], leaf)).collect();
    let mut cross = Vec::new();
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        let x = xor(c, aa[i], aa[j]);
        let y = xor(c, bb[i], bb[j]);
        let p = base_mul(c, &x, &y, leaf);
        cross.push(
            (0..64)
                .map(|k| c.xor3(p[k], diagonal[i][k], diagonal[j][k]))
                .collect::<Word>(),
        );
    }
    let mut out = Vec::new();
    for k in 0..64 {
        out.push(c.xor(diagonal[0][k], cross[2][k]));
    }
    for k in 0..64 {
        out.push(c.xor3(cross[0][k], cross[2][k], diagonal[2][k]));
    }
    for k in 0..64 {
        out.push(c.xor3(cross[1][k], diagonal[1][k], diagonal[2][k]));
    }
    out
}

/// Multiply a base-field word by x, modulo x^64 + x^4 + x^3 + x + 1.
fn base_x(c: &mut Ckt, a: &[Wire]) -> Word {
    let mut out = vec![a[63]];
    out.extend_from_slice(&a[..63]);
    for i in [1, 3, 4] {
        out[i] = c.xor(out[i], a[63]);
    }
    out
}

fn base_div_x(c: &mut Ckt, a: &[Wire]) -> Word {
    let mut out = a[1..].to_vec();
    for i in [0, 2, 3] {
        out[i] = c.xor(out[i], a[0]);
    }
    out.push(a[0]);
    out
}

/// Divide by x + 1. The modulus has value one at x = 1, so the
/// top quotient coefficient is the parity of the reduced product.
fn base_div_x_plus_one(c: &mut Ckt, a: &[Wire]) -> Word {
    let top = a.iter().copied().fold(Wire::ZERO, |s, bit| c.xor(s, bit));
    let mut previous = top;
    let mut out = Vec::with_capacity(64);
    for (i, &bit) in a.iter().take(63).enumerate() {
        let mut next = bit;
        if [0, 1, 3, 4].contains(&i) {
            next = c.xor(next, top);
        }
        if i != 0 {
            next = c.xor(next, previous);
        }
        out.push(next);
        previous = next;
    }
    out.push(top);
    out
}

fn base_div_x_times_x_plus_one(c: &mut Ckt, a: &[Wire]) -> Word {
    let shifted = base_div_x(c, a);
    base_div_x_plus_one(c, &shifted)
}

/// Evaluate a quadratic over the base field at x.
fn evaluate_x(c: &mut Ckt, a: &[Wire]) -> Word {
    let high = base_x(c, &a[128..]);
    let middle = xor(c, &high, &a[64..128]);
    let shifted = base_x(c, &middle);
    xor(c, &shifted, &a[..64])
}

/// Interpolate the product at 0, 1, x, x + 1 and infinity, then reduce
/// modulo y^3 + y + 1. All divisions are fixed invertible binary linear maps.
fn mul_five(c: &mut Ckt, a: &[Wire], b: &[Wire], leaf: usize) -> Word {
    assert_eq!(a.len(), 192);
    assert_eq!(b.len(), 192);
    let v0 = base_mul(c, &a[..64], &b[..64], leaf);
    let v4 = base_mul(c, &a[128..], &b[128..], leaf);
    let a1: Word = (0..64).map(|i| c.xor3(a[i], a[64 + i], a[128 + i])).collect();
    let b1: Word = (0..64).map(|i| c.xor3(b[i], b[64 + i], b[128 + i])).collect();
    let v1 = base_mul(c, &a1, &b1, leaf);
    let ax = evaluate_x(c, a);
    let bx = evaluate_x(c, b);
    let vx = base_mul(c, &ax, &bx, leaf);
    // In characteristic two, A(x + 1) = A(x) + a1 + a2.
    let ax1: Word = (0..64).map(|i| c.xor3(ax[i], a[64 + i], a[128 + i])).collect();
    let bx1: Word = (0..64).map(|i| c.xor3(bx[i], b[64 + i], b[128 + i])).collect();
    let vx1 = base_mul(c, &ax1, &bx1, leaf);

    // For product coefficients c_i, r1 = c1 + c2 + c3.
    let r1: Word = (0..64).map(|i| c.xor3(v1[i], v0[i], v4[i])).collect();
    let mut fourth = v4.clone();
    for _ in 0..4 {
        fourth = base_x(c, &fourth);
    }
    let xr1 = base_x(c, &r1);
    let numerator: Word = (0..64)
        .map(|i| {
            let lo = c.xor3(vx1[i], v0[i], fourth[i]);
            let hi = c.xor3(v4[i], xr1[i], r1[i]);
            c.xor(lo, hi)
        })
        .collect();
    // j = c2 + x*c3; c3 = (vx + vx1 + v4 + r1) / (x*(x+1)).
    let j = base_div_x_times_x_plus_one(c, &numerator);
    let numerator: Word = (0..64)
        .map(|i| {
            let lo = c.xor(vx[i], vx1[i]);
            let hi = c.xor(v4[i], r1[i]);
            c.xor(lo, hi)
        })
        .collect();
    let c3 = base_div_x_times_x_plus_one(c, &numerator);
    let xc3 = base_x(c, &c3);
    let out2: Word = (0..64).map(|i| c.xor3(j[i], xc3[i], v4[i])).collect();
    let mut out = xor(c, &v0, &c3);
    out.extend(xor(c, &r1, &out2));
    out.extend(out2);
    out
}

pub(crate) fn mul(c: &mut Ckt, a: &[Wire], b: &[Wire]) -> Word {
    mul_five(c, a, b, 4)
}

/// Share short input XORs between the output bits of a binary linear map.
/// Each window has a fixed-size table; only entries used by an output are built.
fn linear_window(c: &mut Ckt, a: &[Wire], f: impl Fn(F192) -> F192, width: usize) -> Word {
    fn entry(c: &mut Ckt, window: &[Wire], mask: usize, table: &mut [Option<Wire>]) -> Wire {
        if let Some(wire) = table[mask] {
            return wire;
        }
        let index = mask.trailing_zeros() as usize;
        let rest = entry(c, window, mask ^ (1 << index), table);
        let wire = c.xor(window[index], rest);
        table[mask] = Some(wire);
        wire
    }
    let mut out = vec![Wire::ZERO; 192];
    for (group, window) in a.chunks(width).enumerate() {
        let mut masks = [0usize; 192];
        for (bit, &wire) in window.iter().enumerate() {
            if wire == Wire::ZERO {
                continue;
            }
            let index = group * width + bit;
            let mut input = [0u64; 3];
            input[index / 64] = 1 << (index % 64);
            let image = f(F192::new(input[0], input[1], input[2]));
            for (limb, mut word) in [image.c0, image.c1, image.c2].into_iter().enumerate() {
                while word != 0 {
                    let index = word.trailing_zeros() as usize;
                    word &= word - 1;
                    masks[64 * limb + index] |= 1 << bit;
                }
            }
        }
        let mut table = vec![None; 1 << window.len()];
        table[0] = Some(Wire::ZERO);
        for (output, mask) in out.iter_mut().zip(masks) {
            let contribution = entry(c, window, mask, &mut table);
            *output = c.xor(*output, contribution);
        }
    }
    out
}

pub(crate) fn linear(c: &mut Ckt, a: &[Wire], f: impl Fn(F192) -> F192) -> Word {
    linear_window(c, a, f, 6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_suite::{bytes_to_bits, read_statement};

    fn bytes(x: F192) -> Vec<u8> {
        [x.c0, x.c1, x.c2].into_iter().flat_map(u64::to_le_bytes).collect()
    }

    fn check(c: Ckt, mut output: Word, pairs: &[(F192, Option<F192>, F192)]) {
        output.resize(512, Wire::ZERO);
        let (circuit, sources) = c.finish(&output);
        circuit.check_wired().unwrap();
        for &(a, b, expected) in pairs {
            let mut input = bytes_to_bits(&bytes(a));
            if let Some(b) = b {
                input.extend(bytes_to_bits(&bytes(b)));
            }
            let got = read_statement(&circuit.values(&input), &sources);
            assert_eq!(&got[..24], &bytes(expected));
        }
    }

    #[test]
    fn profile_multiplication_cutoffs_and_check_native_values() {
        let mut state = 0x15161718191a1b1cu64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state
        };
        let pairs: Vec<_> = (0..24)
            .map(|_| {
                let a = F192::new(next(), next(), next());
                let b = F192::new(next(), next(), next());
                (a, Some(b), a * b)
            })
            .collect();
        for leaf in [1, 2, 4, 8, 16] {
            let mut c = Ckt::new();
            let a = c.inputs(192);
            let b = c.inputs(192);
            let before = c.rows();
            let output = mul_with_leaf(&mut c, &a, &b, leaf);
            let six_product_rows = c.rows() - before;
            println!(
                "{}",
                serde_json::json!({"kind":"field_multiply_rows","method":"six_product","leaf":leaf,"rows":six_product_rows})
            );
            check(c, output, &pairs);
            let mut c = Ckt::new();
            let a = c.inputs(192);
            let b = c.inputs(192);
            let before = c.rows();
            let output = mul_five(&mut c, &a, &b, leaf);
            assert!(c.rows() - before < six_product_rows);
            println!(
                "{}",
                serde_json::json!({"kind":"field_multiply_rows","method":"five_product","leaf":leaf,"rows":c.rows()-before})
            );
            check(c, output, &pairs);
        }
    }

    #[test]
    fn five_product_matches_native_on_every_binary_basis_pair() {
        let basis: Vec<_> = (0..192)
            .map(|i| {
                let mut x = [0u64; 3];
                x[i / 64] = 1 << (i % 64);
                F192::new(x[0], x[1], x[2])
            })
            .collect();
        let mut pairs: Vec<_> = basis
            .iter()
            .flat_map(|&a| basis.iter().map(move |&b| (a, Some(b), a * b)))
            .collect();
        for a in [F192::ZERO, F192::ONE, F192::new(u64::MAX, u64::MAX, u64::MAX)] {
            for b in basis.iter().copied().chain([a]) {
                pairs.push((a, Some(b), a * b));
                pairs.push((b, Some(a), a * b));
            }
        }
        let mut c = Ckt::new();
        let a = c.inputs(192);
        let b = c.inputs(192);
        let output = mul(&mut c, &a, &b);
        check(c, output, &pairs);
    }

    #[test]
    fn sparse_base_maps_match_native_on_every_binary_basis_vector() {
        for mode in 0..3 {
            let constant = match mode {
                0 => F192::new(2, 0, 0),
                1 => F192::new(2, 0, 0).inv(),
                _ => F192::new(3, 0, 0).inv(),
            };
            let pairs: Vec<_> = (0..64)
                .map(|i| {
                    let x = F192::new(1 << i, 0, 0);
                    (x, None, x * constant)
                })
                .collect();
            let mut c = Ckt::new();
            let a = c.inputs(192);
            let mut output = match mode {
                0 => base_x(&mut c, &a[..64]),
                1 => base_div_x(&mut c, &a[..64]),
                _ => base_div_x_plus_one(&mut c, &a[..64]),
            };
            output.resize(192, Wire::ZERO);
            check(c, output, &pairs);
        }
    }

    #[test]
    fn windowed_linear_maps_match_native_on_a_complete_binary_basis() {
        let constant = F192::new(0x123456789abcdef0, 0x9abcdef012345678, 0x876543210abcdef0);
        for map in [|x: F192| x * x, F192::frobenius as fn(F192) -> F192] {
            let pairs: Vec<_> = (0..192)
                .map(|i| {
                    let mut x = [0u64; 3];
                    x[i / 64] = 1 << (i % 64);
                    let x = F192::new(x[0], x[1], x[2]);
                    (x, None, map(x))
                })
                .collect();
            let mut c = Ckt::new();
            let a = c.inputs(192);
            let output = linear(&mut c, &a, map);
            check(c, output, &pairs);
        }
        let pairs: Vec<_> = (0..192)
            .map(|i| {
                let mut x = [0u64; 3];
                x[i / 64] = 1 << (i % 64);
                let x = F192::new(x[0], x[1], x[2]);
                (x, None, x * constant)
            })
            .collect();
        let mut c = Ckt::new();
        let a = c.inputs(192);
        let before = c.rows();
        let output = linear_naive(&mut c, &a, |x| x * constant);
        println!(
            "{}",
            serde_json::json!({"kind":"constant_multiply_rows","method":"naive","rows":c.rows()-before})
        );
        check(c, output, &pairs);
        for width in [3, 4, 5, 6, 7, 8] {
            let mut c = Ckt::new();
            let a = c.inputs(192);
            let before = c.rows();
            let output = linear_window(&mut c, &a, |x| x * constant, width);
            println!(
                "{}",
                serde_json::json!({"kind":"constant_multiply_rows","window":width,"rows":c.rows()-before})
            );
            check(c, output, &pairs);
        }
    }
}
