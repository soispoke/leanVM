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
    lower_with_keccak(b, circuit, sources, inputs, &[])
}

pub fn lower_with_keccak(
    b: &mut Builder,
    circuit: &Circuit,
    sources: &[Src],
    inputs: &[Word],
    calls: &[circuit_suite::KeccakCall],
) -> Vec<Word> {
    lower_with_keccak_observe(b, circuit, sources, inputs, calls, |_, _| {})
}

/// Observe native row boundaries while retaining exactly the ordinary lowering.
pub fn lower_with_keccak_observe(
    b: &mut Builder,
    circuit: &Circuit,
    sources: &[Src],
    inputs: &[Word],
    calls: &[circuit_suite::KeccakCall],
    mut observe: impl FnMut(usize, usize),
) -> Vec<Word> {
    let starts: std::collections::HashMap<_, _> = calls.iter().map(|call| (call.output_start, call)).collect();
    let mut placeholders = vec![false; circuit.rows().len()];
    for call in calls {
        placeholders[call.output_start..call.output_start + 1600].fill(true);
    }

    let one = b.one();
    let mut required = vec![[false; 2]; circuit.rows().len()];
    for &src in sources {
        if let Src::Row(r) = src {
            required[r as usize][0] = true;
        }
    }
    for (r, row) in circuit.rows().iter().enumerate().skip(PUBLIC_ROWS).rev() {
        if let Some(call) = starts.get(&r) {
            for wire in &call.input {
                let (src, component, _) = wire.native_source();
                if let Src::Row(from) = src {
                    required[from as usize][component] = true;
                }
            }
        }
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
        observe(r, b.rows());
        if let Some(call) = starts.get(&r) {
            let bits: Vec<_> = call
                .input
                .iter()
                .map(|&wire| {
                    let (src, component, neg) = wire.native_source();
                    let value = read(&outputs, src, component, one);
                    if neg { xor(b, value, one) } else { value }
                })
                .collect();
            let lanes: [Word; 25] = std::array::from_fn(|i| b.pack(&bits[64 * i..64 * (i + 1)]));
            let result = b.keccak_f(lanes);
            for (i, lane) in result.into_iter().enumerate() {
                for (j, bit) in b.bits(lane, 64).into_iter().enumerate() {
                    outputs[r + 64 * i + j] = [bit, Word::ZERO];
                }
            }
        }
        if placeholders[r] {
            continue;
        }
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
    observe(circuit.rows().len(), b.rows());
    assert!(inputs.next().is_none());
    sources.iter().map(|&src| read(&outputs, src, 0, one)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_permutation_placeholders_are_bound_by_bridge() {
        parallel::init();
        let mut c = circuit_suite::Ckt::new();
        c.enable_native_keccak();
        let input = c.inputs(1600);
        let output = circuit_suite::keccak::keccak_f(&mut c, &input);
        let (circuit, sources, calls) = c.finish_native_keccak(&output[..512]);
        let state: [u64; 25] = std::array::from_fn(|i| i as u64 * 12345);
        let mut b = Builder::default();
        let inputs: Vec<_> = (0..1600).map(|i| b.input(state[i / 64] >> (i % 64) & 1)).collect();
        let bits = lower_with_keccak(&mut b, &circuit, &sources, &inputs, &calls);
        let expected = flock::keccak::reduction::permute(&state);
        for (i, chunk) in bits.chunks(64).enumerate() {
            let word = b.pack(chunk);
            assert_eq!(b.value(word).c0, expected[i]);
            b.expose(word);
        }
        let public = b.public_values();
        let bridge = b.setup_mixed().unwrap();
        let proof = bridge
            .prove_mixed(&b.values, &b.permutations, &b.compressions, &[14; 32])
            .unwrap();
        assert!(bridge.verify(&public, &[14; 32], &proof));
    }
    #[test]
    #[should_panic(expected = "native Keccak calls require")]
    fn ordinary_boolean_finish_cannot_discard_native_checks() {
        let mut c = circuit_suite::Ckt::new();
        c.enable_native_keccak();
        let output = c.keccak_permutation(&vec![circuit_suite::Wire::ZERO; 1600]);
        c.finish(&output[..512]);
    }
}
