//! Boolean full-adder lowering into the native application builder. This keeps
//! each input Boolean and drops outputs only by fixed wiring dependencies.
use crate::native_hash::{Builder, Word};
use circuit_suite::{Circuit, PUBLIC_ROWS, Src};

fn read(outputs: &[[Word; 2]], src: Src, component: usize, one: Word) -> Word {
    match src {
        Src::Zero => Word::ZERO,
        Src::One => {
            if component == 0 {
                one
            } else {
                Word::ZERO
            }
        }
        Src::Row(r) => outputs[r as usize][component],
    }
}
fn xor(b: &mut Builder, x: Word, y: Word) -> Word {
    if x == Word::ZERO {
        y
    } else if y == Word::ZERO {
        x
    } else if x == y {
        Word::ZERO
    } else {
        b.gate(x, b.one(), y)
    }
}
fn mul(b: &mut Builder, x: Word, y: Word) -> Word {
    if x == Word::ZERO || y == Word::ZERO {
        Word::ZERO
    } else if x == b.one() || x == y {
        y
    } else if y == b.one() {
        x
    } else {
        b.gate(x, y, Word::ZERO)
    }
}

/// Inputs must be the circuit's free bits in input-row order. They are checked
/// Boolean here, including when callers provide existing native variables.
pub fn lower(b: &mut Builder, circuit: &Circuit, sources: &[Src], inputs: &[Word]) -> Vec<Word> {
    let one = b.one();
    let mut required = vec![[false; 2]; circuit.rows().len()];
    for &src in sources {
        if let Src::Row(r) = src {
            required[r as usize][0] = true;
        }
    }
    for (r, row) in circuit.rows().iter().enumerate().skip(PUBLIC_ROWS).rev() {
        if required[r].iter().any(|&v| v) {
            for (src, component) in [(row.x, 0), (row.y, 0), (row.c, 1)] {
                if let Src::Row(from) = src {
                    required[from as usize][component] = true;
                }
            }
        }
    }
    let mut outputs = vec![[Word::ZERO; 2]; circuit.rows().len()];
    let mut inputs = inputs.iter();
    for (r, row) in circuit.rows().iter().enumerate().skip(PUBLIC_ROWS) {
        if [row.x, row.y, row.c] == [Src::Row(r as u32), Src::Zero, Src::Zero] {
            let bit = *inputs.next().expect("Boolean input row");
            b.boolean(bit);
            outputs[r] = [bit, Word::ZERO];
        } else if required[r].iter().any(|&v| v) {
            let x = read(&outputs, row.x, 0, one);
            let y = read(&outputs, row.y, 0, one);
            let c = read(&outputs, row.c, 1, one);
            let xy = xor(b, x, y);
            let sum = if required[r][0] { xor(b, xy, c) } else { Word::ZERO };
            let carry = if required[r][1] {
                let first = mul(b, x, y);
                let second = mul(b, c, xy);
                xor(b, first, second)
            } else {
                Word::ZERO
            };
            outputs[r] = [sum, carry];
        }
    }
    assert!(inputs.next().is_none());
    sources.iter().map(|&src| read(&outputs, src, 0, one)).collect()
}
