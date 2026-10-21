//! A circuit's description: the bytes that determine it, from which anyone rebuilds the circuit, its wiring
//! table and the 32-byte root the verifier is given ([`decode`], then `quotient::Index::new` and the commitment).
//!
//! The format, version 1:
//!
//! ```text
//! "QCD1" | log_rows: u8 | used: varint | 512 public sources | (used - 512) rows of three sources
//! ```
//!
//! A source of row `r` is one varint: `0` the zero, `1` the one, `2` row `r` itself (an input row reads its own
//! bit), and `k >= 3` row `r - (k - 2)`, so a row reading recent rows costs a byte a slot. A public source is
//! `0`, `1`, or `2 + r` for row `r < used`. The rows past `used` are idle (reading three zeros), and the public rows'
//! layout is the one [`Builder::finish`](crate::Builder::finish) fixes: nothing else is free, so two circuits
//! with one description are one circuit.

use crate::{Circuit, PUBLIC_ROWS, Row, Src, WORD_BITS, public_words};

const MAGIC: &[u8; 4] = b"QCD1";

fn put(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn get(data: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *data.get(*at).ok_or("truncated")?;
        *at += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("varint too long".into())
}

const IDLE: Row = Row {
    x: Src::Zero,
    y: Src::Zero,
    c: Src::Zero,
};

/// The statement's 512 sources, read off the public rows (the inverse of [`public_words`]): bit `j` of byte
/// `i`, at `8 i + j`.
pub fn public_sources(circuit: &Circuit) -> Vec<Src> {
    let rows = circuit.rows();
    let mut out = vec![Src::Zero; 512];
    for word in 0..4 {
        for j in 0..WORD_BITS {
            let row = rows[word * WORD_BITS / 2 + j / 2];
            let half = word % 2;
            let bit = 256 * (word / 2) + 8 * (16 * half + 15 - j / 8) + j % 8;
            out[bit] = if j % 2 == 0 { row.x } else { row.y };
        }
    }
    out
}

/// The description of `circuit`.
pub fn encode(circuit: &Circuit) -> Vec<u8> {
    let public = public_sources(circuit);
    let rows = circuit.rows();
    // A public bit that is a constant reads an idle-looking row of its own, so `used` covers the public sources.
    let last_public = public.iter().filter_map(|s| {
        if let Src::Row(r) = s {
            Some(*r as usize + 1)
        } else {
            None
        }
    });
    let used = rows
        .iter()
        .rposition(|row| *row != IDLE)
        .map(|r| r + 1)
        .into_iter()
        .chain(last_public)
        .fold(PUBLIC_ROWS, usize::max);
    let mut out = MAGIC.to_vec();
    out.push(circuit.log_rows as u8);
    put(&mut out, used as u64);
    for src in &public {
        put(
            &mut out,
            match *src {
                Src::Zero => 0,
                Src::One => 1,
                Src::Row(r) => 2 + r as u64,
            },
        );
    }
    for (r, row) in rows.iter().enumerate().take(used).skip(PUBLIC_ROWS) {
        for src in [row.x, row.y, row.c] {
            put(
                &mut out,
                match src {
                    Src::Zero => 0,
                    Src::One => 1,
                    Src::Row(s) => 2 + (r as u64 - s as u64),
                },
            );
        }
    }
    out
}

/// The circuit a description determines, and its public sources; an error for anything not a description.
pub fn decode(data: &[u8]) -> Result<(Circuit, Vec<Src>), String> {
    if data.get(..4) != Some(MAGIC.as_slice()) {
        return Err("magic".into());
    }
    let log_rows = *data.get(4).ok_or("truncated")? as usize;
    if !(crate::MIN_LOG_ROWS..=32).contains(&log_rows) {
        return Err("log_rows".into());
    }
    let n = 1usize << log_rows;
    let mut at = 5;
    let used = get(data, &mut at)? as usize;
    if !(PUBLIC_ROWS..=n).contains(&used) {
        return Err("used".into());
    }
    let public = (0..2 * 2 * WORD_BITS)
        .map(|_| {
            Ok(match get(data, &mut at)? {
                0 => Src::Zero,
                1 => Src::One,
                k if (k - 2) < used as u64 => Src::Row((k - 2) as u32),
                k => return Err(format!("public source {k} of {used}")),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut rows = Vec::with_capacity(n);
    // The public rows, as `Builder::finish` lays them out.
    let (y, root) = public.split_at(256);
    let words = public_words(y, root);
    for r in 0..PUBLIC_ROWS {
        let (word, pair) = (r / (WORD_BITS / 2), r % (WORD_BITS / 2));
        let bit = |j: usize| match word {
            0..4 => words[word][j],
            4 if j == 0 => Src::One,
            _ => Src::Zero,
        };
        rows.push(Row {
            x: bit(2 * pair),
            y: bit(2 * pair + 1),
            c: Src::Zero,
        });
    }
    for r in PUBLIC_ROWS..used {
        let mut src = || -> Result<Src, String> {
            Ok(match get(data, &mut at)? {
                0 => Src::Zero,
                1 => Src::One,
                k if (k - 2) <= r as u64 => Src::Row((r as u64 - (k - 2)) as u32),
                _ => return Err(format!("source of row {r}")),
            })
        };
        let (x, y, c) = (src()?, src()?, src()?);
        rows.push(Row { x, y, c });
    }
    if at != data.len() {
        return Err("trailing bytes".into());
    }
    rows.resize(n, IDLE);
    Ok((Circuit::from_rows(log_rows, rows), public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blake2s::Blake2sOneKiB, build};

    #[test]
    fn a_description_is_its_circuit() {
        let (blake, public, _) = build::<Blake2sOneKiB>();
        assert_eq!(public_sources(&blake), public);
        for circuit in [flock::quotient::circuit::membership(), blake] {
            let data = encode(&circuit);
            let (again, public) = decode(&data).unwrap();
            assert_eq!(again.rows(), circuit.rows());
            assert_eq!(again.sigma, circuit.sigma);
            assert_eq!(public, public_sources(&circuit));
            assert_eq!(encode(&again), data);
            // Anything else is rejected: a truncated description, trailing bytes, a source ahead of its row.
            assert!(decode(&data[..data.len() - 1]).is_err());
            assert!(decode(&[data.clone(), vec![0]].concat()).is_err());
            let mut forward = data.clone();
            *forward.last_mut().unwrap() = 0x7f;
            assert!(decode(&forward).is_err() || decode(&forward).unwrap().0.rows() != circuit.rows());
        }
    }
}
