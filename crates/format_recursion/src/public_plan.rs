//! Public hash I/O projection for the native arithmetic experiment.
//! Arithmetic is left to the proof; this module only projects bytes and bits.

use crate::{
    hash_batch::Request,
    trace::{Op, S, Trace},
};
use fiat_shamir::merkle::hash_to_scalars;
use primitives::field::F192;

fn bytes(x: F192) -> [u8; 24] {
    let mut out = [0; 24];
    for (part, limb) in out.chunks_mut(8).zip([x.c0, x.c1, x.c2]) {
        part.copy_from_slice(&limb.to_le_bytes());
    }
    out
}
fn from_bytes(input: &[u8]) -> F192 {
    let mut b = [0; 24];
    b[..input.len()].copy_from_slice(input);
    let limbs: Vec<_> = b.as_chunks::<8>().0.iter().map(|s| u64::from_le_bytes(*s)).collect();
    F192::new(limbs[0], limbs[1], limbs[2])
}
fn put(values: &mut [Option<F192>], at: usize, value: F192) -> Option<()> {
    if values[at].is_some_and(|old| old != value) {
        return None;
    }
    values[at] = Some(value);
    Some(())
}
fn slice(x: F192, start: usize, len: usize) -> F192 {
    let limbs = [x.c0, x.c1, x.c2];
    let mut out = [0u64; 3];
    for bit in 0..len {
        out[bit / 64] |= ((limbs[(start + bit) / 64] >> ((start + bit) % 64)) & 1) << (bit % 64);
    }
    F192::new(out[0], out[1], out[2])
}

/// Derive only public byte/bit operations. No field addition or multiplication
/// is checked here; those identities must be proved by the arithmetic backend.
pub fn values(program: &Trace, requests: &[Request]) -> Option<Vec<Option<F192>>> {
    let mut caps = vec![192usize; program.nodes.len()];
    for &(a, b) in &program.checks {
        for (a, b) in [(a, b), (b, a)] {
            if matches!(program.nodes[b.0].op, Op::Constant)
                && program.nodes[b.0].value == F192::ZERO
                && let Op::Slice(source, start, len) = program.nodes[a.0].op
                && start + len == 192
            {
                caps[source.0] = caps[source.0].min(start);
            }
        }
    }
    let mut widths: Vec<usize> = Vec::with_capacity(program.nodes.len());
    for (index, node) in program.nodes.iter().enumerate() {
        let width = match &node.op {
            Op::Constant => {
                let limbs = [node.value.c0, node.value.c1, node.value.c2];
                (0..192)
                    .rev()
                    .find(|&i| (limbs[i / 64] >> (i % 64)) & 1 != 0)
                    .map_or(0, |i| i + 1)
            }
            Op::Input | Op::Frobenius(_) => 192,
            Op::Add(a, b) | Op::Select(_, a, b) => widths[a.0].max(widths[b.0]),
            Op::Mul(a, b) => {
                if widths[a.0] <= 64 && widths[b.0] <= 64 {
                    64
                } else {
                    192
                }
            }
            Op::Slice(_, _, n) => *n,
            Op::Pack(parts) => parts.iter().map(|(_, n)| n).sum(),
            Op::Hash(_) | Op::HashHigh(_) => 128,
        };
        widths.push(width.min(caps[index]));
    }
    let mut known = vec![None; program.nodes.len()];
    let mut request = requests.iter();
    for (i, node) in program.nodes.iter().enumerate() {
        if let Op::Hash(parts) = &node.op {
            let req = request.next()?;
            let [lo, hi] = hash_to_scalars(&req.digest);
            put(&mut known, i, lo)?;
            put(&mut known, i + 1, hi)?;
            let mut offset = 0;
            for &(s, n) in parts {
                if n > 24 || widths[s.0] > n * 8 {
                    return None;
                }
                let raw = req.message.get(offset..offset + n)?;
                let value = from_bytes(raw);
                if bytes(value)[widths[s.0].div_ceil(8)..].iter().any(|&b| b != 0)
                    || slice(value, widths[s.0], 192 - widths[s.0]) != F192::ZERO
                {
                    return None;
                }
                put(&mut known, s.0, value)?;
                offset += n;
            }
            if offset != req.message.len() {
                return None;
            }
        }
    }
    if request.next().is_some() {
        return None;
    }
    for (i, node) in program.nodes.iter().enumerate() {
        if let Op::Select(bit, a, b) = node.op
            && let Some(value) = known[i]
        {
            match known[bit.0] {
                Some(F192::ZERO) => put(&mut known, a.0, value)?,
                Some(F192::ONE) => put(&mut known, b.0, value)?,
                Some(_) => return None,
                None => (),
            }
        }
        let value = match &node.op {
            Op::Constant => Some(node.value),
            Op::Slice(a, start, len) => known[a.0].map(|v| slice(v, *start, *len)),
            Op::Pack(parts) => {
                let mut out = [0u64; 3];
                let mut offset = 0;
                let mut complete = true;
                for &(s, n) in parts {
                    let Some(x) = known[s.0] else {
                        complete = false;
                        break;
                    };
                    let limbs = [x.c0, x.c1, x.c2];
                    for bit in 0..n {
                        out[(offset + bit) / 64] |= ((limbs[bit / 64] >> (bit % 64)) & 1) << ((offset + bit) % 64);
                    }
                    offset += n;
                }
                complete.then(|| F192::new(out[0], out[1], out[2]))
            }
            Op::Select(bit, a, b) => match (known[bit.0], known[a.0], known[b.0]) {
                (Some(F192::ZERO), Some(a), Some(_)) => Some(a),
                (Some(F192::ONE), Some(_), Some(b)) => Some(b),
                (Some(_), Some(_), Some(_)) => return None,
                _ => None,
            },
            Op::Frobenius(a) => known[a.0].map(F192::frobenius),
            _ => None,
        };
        if let Some(value) = value {
            put(&mut known, i, value)?;
        }
    }
    Some(known)
}

/// A discarded scalar input may only feed public projections. Overlapping
/// projections must agree, giving an existentially consistent full input.
pub fn check_projections(program: &Trace, known: &[Option<F192>]) -> Option<()> {
    let mut inputs = vec![(F192::ZERO, F192::ZERO); program.nodes.len()];
    for (i, node) in program.nodes.iter().enumerate() {
        match &node.op {
            Op::Slice(a, start, len) if known[a.0].is_none() => {
                if !matches!(program.nodes[a.0].op, Op::Input) {
                    return None;
                }
                let v = known[i]?;
                let (old, mask) = &mut inputs[a.0];
                let mut old_limbs = [old.c0, old.c1, old.c2];
                let mut mask_limbs = [mask.c0, mask.c1, mask.c2];
                let limbs = [v.c0, v.c1, v.c2];
                for bit in 0..*len {
                    let at = start + bit;
                    let value = (limbs[bit / 64] >> (bit % 64)) & 1;
                    let m = 1u64 << (at % 64);
                    if mask_limbs[at / 64] & m != 0 && (old_limbs[at / 64] >> (at % 64)) & 1 != value {
                        return None;
                    }
                    old_limbs[at / 64] = (old_limbs[at / 64] & !m) | (value << (at % 64));
                    mask_limbs[at / 64] |= m;
                }
                *old = F192::new(old_limbs[0], old_limbs[1], old_limbs[2]);
                *mask = F192::new(mask_limbs[0], mask_limbs[1], mask_limbs[2]);
            }
            Op::Pack(parts) => {
                for &(a, _) in parts {
                    known[a.0]?;
                }
                known[i]?;
            }
            Op::Select(bit, a, b) => {
                known[bit.0]?;
                known[a.0]?;
                known[b.0]?;
                known[i]?;
            }
            Op::Frobenius(_) => (),
            _ => (),
        }
    }
    // Unknown raw inputs feeding arithmetic are retained as genuine witness
    // variables. They must not also have discarded projections.
    for node in &program.nodes {
        let operands = match &node.op {
            Op::Add(a, b) | Op::Mul(a, b) => vec![*a, *b],
            Op::Frobenius(a) => vec![*a],
            _ => vec![],
        };
        for S(a) in operands {
            if inputs[a].1 != F192::ZERO {
                return None;
            }
        }
    }
    for &(a, b) in &program.checks {
        if inputs[a.0].1 != F192::ZERO || inputs[b.0].1 != F192::ZERO {
            return None;
        }
    }
    for a in &program.public {
        if inputs[a.0].1 != F192::ZERO {
            return None;
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{replay, trace};
    use flock::membership::Scalar;
    fn requests(program: &Trace) -> Vec<Request> {
        let witness: Vec<_> = program.nodes.iter().map(|n| n.value).collect();
        replay::requests(program, &witness, &[]).unwrap()
    }
    #[test]
    fn repeated_hash_sources_and_lengths_are_bound() {
        trace::start();
        let x = S::input(F192::new(7, 11, 13));
        trace::hash(&[(x, 24)]);
        trace::hash(&[(x, 24)]);
        let t = trace::take();
        let original = requests(&t);
        assert!(values(&t, &original).is_some());
        let mut bad = original.clone();
        bad[1].message[0] ^= 1;
        assert!(values(&t, &bad).is_none());
        let mut bad = original.clone();
        bad[0].message.pop();
        assert!(values(&t, &bad).is_none());
        let mut bad = original.clone();
        bad.push(original[0].clone());
        assert!(values(&t, &bad).is_none());
        assert!(values(&t, &original[..1]).is_none());
    }
    #[test]
    fn projected_inputs_require_consistent_overlaps_and_isolation() {
        for arithmetic in [false, true] {
            trace::start();
            let x = S::input(F192::new(0x123456, 0, 0));
            let a = x.slice(0, 16);
            let b = x.slice(8, 16);
            trace::hash(&[(a, 2)]);
            trace::hash(&[(b, 2)]);
            if arithmetic {
                x.frobenius();
            }
            let t = trace::take();
            let original = requests(&t);
            let known = values(&t, &original).unwrap();
            assert_eq!(check_projections(&t, &known).is_some(), !arithmetic);
            let mut bad = original.clone();
            bad[1].message[0] ^= 1;
            let known = values(&t, &bad).unwrap();
            assert!(check_projections(&t, &known).is_none());
        }
    }
    #[test]
    fn zero_tails_and_boolean_selection_are_checked() {
        trace::start();
        let x = S::input(F192::new(7, 0, 0));
        x.slice(127, 65).assert_eq(S::u(0));
        trace::hash(&[(x, 16)]);
        let t = trace::take();
        let original = requests(&t);
        assert!(values(&t, &original).is_some());
        let mut bad = original;
        bad[0].message[15] |= 128;
        assert!(values(&t, &bad).is_none());
        trace::start();
        let bit = S::input(F192::ONE).slice(0, 2);
        let selected = S::select(bit, S::u(3), S::u(4));
        trace::hash(&[(bit, 1), (selected, 1)]);
        let t = trace::take();
        let original = requests(&t);
        assert!(values(&t, &original).is_some());
        let mut bad = original.clone();
        bad[0].message[0] = 2;
        assert!(values(&t, &bad).is_none());
        let mut bad = original;
        bad[0].message[1] ^= 1;
        assert!(values(&t, &bad).is_none());
    }
}
