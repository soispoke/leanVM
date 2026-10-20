//! Structured R1CS for the upstream application's full-adder rows, copy wiring,
//! and public anchors. This describes the application, not a proof verifier.
//! The quotient backend eliminates five local auxiliary wires per row exactly.
use flock::{
    membership::Statement,
    quotient::{
        circuit::{Circuit, PUBLIC_ROWS},
        domain::beta,
    },
};
use primitives::{
    field::{F64, F192},
    hash::hash,
};

/// Versioned semantics plus concrete wiring. No backend commitment or PIOP parameters.
pub fn identity(c: &Circuit) -> [u8; 32] {
    let mut b = b"structured-r1cs-v1/gf64/upstream-tower/full-adder-6/copy/public-8x128".to_vec();
    b.extend(beta()[1].0.to_le_bytes());
    b.extend((c.log_rows as u64).to_le_bytes());
    for s in &c.sigma {
        b.extend(s.to_le_bytes());
    }
    hash(&b)
}

/// Six rank-one constraints, A(z) B(z) = C(z), on [x,y,c,v,u,w,t,p,q].
fn row_constraints(z: [F64; 9]) -> [(F64, F64, F64); 6] {
    let [x, y, c, v, u, w, t, p, q] = z;
    let theta = beta()[1];
    [
        (x, theta * x + theta * theta, u),
        (y, theta * y + theta * theta, w),
        (c, c + F64::ONE, t),
        (u, w, p),
        (t, u + w, q),
        (v + u + w + t + theta * (p + q), F64::ONE, F64::ZERO),
    ]
}
fn extend([x, y, c, v]: [F64; 4]) -> [F64; 9] {
    let theta = beta()[1];
    let u = x * (theta * x + theta * theta);
    let w = y * (theta * y + theta * theta);
    let t = c * (c + F64::ONE);
    [x, y, c, v, u, w, t, u * w, t * (u + w)]
}
pub fn check(c: &Circuit, cells: &[F64], s: &Statement) -> Result<(), String> {
    let shift = u32::try_from(c.log_rows).map_err(|_| "row overflow")?;
    let n = 1usize.checked_shl(shift).ok_or("row overflow")?;
    let cell_count = n.checked_mul(4).ok_or("cell overflow")?;
    if n < PUBLIC_ROWS || cells.len() != cell_count || c.sigma.len() != cell_count {
        return Err("shape".into());
    }
    for (r, z) in cells.as_chunks::<4>().0.iter().enumerate() {
        for (a, b, c) in row_constraints(extend(*z)) {
            if a * b != c {
                return Err(format!("R1CS row {r}"));
            }
        }
    }
    let mut seen = vec![false; cells.len()];
    for (i, &next) in c.sigma.iter().enumerate() {
        let j = next as usize;
        if j >= cells.len() || seen[j] {
            return Err("invalid permutation".into());
        }
        seen[j] = true;
        if cells[i] != cells[j] {
            return Err(format!("copy {i}"));
        }
    }
    let halves = s.halves();
    for r in 0..PUBLIC_ROWS {
        let word = r / 64;
        let pair = r % 64;
        for role in 0..2 {
            let bit = 2 * pair + role;
            let value = if word < 4 {
                let h = halves[word];
                ((if bit < 64 { h.c0 } else { h.c1 }) >> (bit % 64)) & 1
            } else {
                u64::from(word == 4 && bit == 0)
            };
            if cells[4 * r + role] != F64(value) {
                return Err(format!("public {word}:{bit}"));
            }
        }
    }
    Ok(())
}
pub fn public_claim(id: &[u8; 32], s: &Statement) -> [F192; 2] {
    let mut b = id.to_vec();
    for x in s.halves() {
        b.extend(x.c0.to_le_bytes());
        b.extend(x.c1.to_le_bytes());
    }
    fiat_shamir::merkle::hash_to_scalars(&hash(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_shapes_and_wiring_are_rejected() {
        use flock::quotient::circuit::{Builder, Src};
        let public = std::array::from_fn(|_| vec![Src::Zero; 128]);
        let mut circuit = Builder::new().finish(9, &public);
        let cells = circuit.cells(&[]);
        let statement = Statement {
            y: [0; 32],
            root: [0; 32],
        };
        assert!(check(&circuit, &cells, &statement).is_ok());
        assert!(check(&circuit, &cells[..cells.len() - 1], &statement).is_err());
        for invalid in [8, usize::BITS as usize - 1, usize::MAX] {
            circuit.log_rows = invalid;
            assert!(check(&circuit, &cells, &statement).is_err());
        }
        circuit.log_rows = 9;
        let saved = circuit.sigma[0];
        circuit.sigma[0] = cells.len() as u32;
        assert!(check(&circuit, &cells, &statement).is_err());
        circuit.sigma[0] = circuit.sigma[1];
        assert!(check(&circuit, &cells, &statement).is_err());
        circuit.sigma[0] = saved;
        let mut wrong_statement = statement;
        wrong_statement.y[0] = 1;
        assert!(check(&circuit, &cells, &wrong_statement).is_err());
    }
    #[test]
    fn elimination_matches_gate() {
        let theta = beta()[1];
        for i in 0..128u64 {
            let z = [F64(i * 123457), F64(i * 8791 + 1), F64(i * 701 + 2), F64(i * 17)];
            let e = extend(z);
            let bit = |v: F64| v * (theta * v + theta * theta);
            let [x, y, c, v] = z;
            let u = bit(x);
            let w = bit(y);
            let t = c * c + c;
            let rs = row_constraints(e);
            assert!(rs[..5].iter().all(|(a, b, c)| *a * *b == *c));
            assert_eq!(rs[5].0, v + u + w + t + theta * (u * w + t * (u + w)));
            for k in 4..9 {
                let mut bad = e;
                bad[k] += F64::ONE;
                assert!(row_constraints(bad).iter().any(|(a, b, c)| *a * *b != *c));
            }
        }
    }
}
