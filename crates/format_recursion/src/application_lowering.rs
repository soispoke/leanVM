//! Uniform native lowering for Boolean full-adder circuits.
use crate::{
    private_bridge::PrivateShape,
    private_trace,
    trace::{self, S, Trace, hash},
};
use circuit_suite::{Circuit, Src};
use primitives::field::F192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub untrimmed: PrivateShape,
    pub trimmed: PrivateShape,
    pub trim_outputs: bool,
}

/// Fixed application identity derived from the generator's wiring.
pub fn identity(circuit: &Circuit) -> [u8; 32] {
    let mut bytes = b"native-r1cs-full-adder-application-v1".to_vec();
    bytes.extend((circuit.log_rows as u64).to_le_bytes());
    for source in &circuit.sigma {
        bytes.extend(source.to_le_bytes());
    }
    primitives::hash::hash(&bytes)
}

/// Choose solely from fixed circuit wiring, public output positions and identity.
/// Compile both graphs with synthetic inputs, then compare their actual final
/// padded arithmetic rows and hash slots. Equal shapes keep the original graph.
pub fn select(circuit: &Circuit, sources: &[Src]) -> Option<Selection> {
    let id = identity(circuit);
    let inputs = vec![false; circuit.n_inputs()];
    let shape = |trim| {
        let program = lower(circuit, sources, id, &inputs, trim).trace;
        let lowered = private_trace::lower_with_limits(
            &program,
            &program,
            private_trace::Limits {
                rows: usize::MAX,
                variables: usize::MAX,
                compressions: crate::private_bridge::MAX_BLOCKS,
            },
        )?;
        PrivateShape::plan(
            lowered.circuit.rows.len(),
            lowered.circuit.public.len(),
            lowered.compressions.len(),
        )
    };
    let untrimmed = shape(false)?;
    let trimmed = shape(true)?;
    Some(Selection {
        untrimmed,
        trimmed,
        trim_outputs: trimmed.index.log_rows < untrimmed.index.log_rows || trimmed.block_log < untrimmed.block_log,
    })
}

pub struct Compiled {
    pub trace: Trace,
    pub input_rows: usize,
    pub unused_sums: usize,
    pub unused_carries: usize,
    pub statement_halves: Vec<F192>,
}

/// Lower a fixed output-dependency policy. Explicit policies support compiler
/// research and key-isolation tests; normal callers use `select` once at setup.
pub fn lower(circuit: &Circuit, sources: &[Src], id: [u8; 32], inputs: &[bool], trim_outputs: bool) -> Compiled {
    let mut inputs = inputs.iter();
    trace::start();
    let zero = S::u(0);
    let one = S::u(1);
    // Keep both output bits separately. All derived bits are Boolean by
    // induction from constrained free inputs and the full-adder identities.
    let mut outputs = vec![[zero, zero]; circuit.rows().len()];
    let mut required = vec![[!trim_outputs; 2]; outputs.len()];
    if trim_outputs {
        for &src in sources {
            if let Src::Row(r) = src {
                required[r as usize][0] = true;
            }
        }
        for (r, row) in circuit.rows().iter().enumerate().skip(circuit_suite::PUBLIC_ROWS).rev() {
            if required[r].iter().any(|&needed| needed) {
                for (src, component) in [(row.x, 0), (row.y, 0), (row.c, 1)] {
                    if let Src::Row(from) = src {
                        required[from as usize][component] = true;
                    }
                }
            }
        }
    }
    let input_rows = circuit
        .rows()
        .iter()
        .enumerate()
        .skip(circuit_suite::PUBLIC_ROWS)
        .filter(|(r, row)| [row.x, row.y, row.c] == [Src::Row(*r as u32), Src::Zero, Src::Zero])
        .count();
    let unused_sums = required
        .iter()
        .skip(circuit_suite::PUBLIC_ROWS)
        .filter(|r| !r[0])
        .count();
    let unused_carries = required
        .iter()
        .skip(circuit_suite::PUBLIC_ROWS)
        .filter(|r| !r[1])
        .count();
    let read = |outputs: &[[S; 2]], src: Src, carry: usize| match src {
        Src::Zero => zero,
        Src::One => {
            if carry == 0 {
                one
            } else {
                zero
            }
        }
        Src::Row(r) => outputs[r as usize][carry],
    };
    for (r, row) in circuit.rows().iter().enumerate().skip(circuit_suite::PUBLIC_ROWS) {
        outputs[r] = if [row.x, row.y, row.c] == [Src::Row(r as u32), Src::Zero, Src::Zero] {
            let bit = S::input(F192::new(u64::from(*inputs.next().expect("input row")), 0, 0));
            (bit * bit).assert_eq(bit);
            [bit, zero]
        } else {
            let x = read(&outputs, row.x, 0);
            let y = read(&outputs, row.y, 0);
            let c = read(&outputs, row.c, 1);
            if required[r].iter().any(|&needed| needed) {
                let xy = x + y;
                [
                    if required[r][0] { xy + c } else { zero },
                    if required[r][1] { x * y + c * xy } else { zero },
                ]
            } else {
                [zero, zero]
            }
        };
    }
    assert!(inputs.next().is_none());
    // Public statement halves are big endian bytes interpreted as little
    // endian field limbs by the existing application claim convention.
    let words: Vec<_> = sources
        .chunks(128)
        .map(|bits| {
            let mut parts = Vec::with_capacity(128);
            for byte in (0..16).rev() {
                for bit in 0..8 {
                    parts.push((read(&outputs, bits[8 * byte + bit], 0), 1));
                }
            }
            S::pack(&parts)
        })
        .collect();
    let statement_halves = words.iter().map(|word| word.value()).collect();
    let id = fiat_shamir::merkle::hash_to_scalars(&id).map(S::c);
    let mut parts = vec![(id[0], 16), (id[1], 16)];
    parts.extend(words.iter().map(|&word| (word, 16)));
    let digest = hash(&parts);
    let mut program = trace::take();
    program.public = digest.to_vec();
    Compiled {
        trace: program,
        input_rows,
        unused_sums,
        unused_carries,
        statement_halves,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_suite::{Ckt, Wire};

    fn circuit(unused: usize) -> (Circuit, Vec<Src>) {
        let mut c = Ckt::new();
        let inputs = c.inputs(3);
        for _ in 0..unused {
            c.fa(inputs[0], inputs[1], inputs[2]);
        }
        let mut public = inputs;
        public.resize(circuit_suite::PUBLIC_BITS, Wire::ZERO);
        c.finish(&public)
    }

    #[test]
    fn automatic_selection_is_a_pure_function_of_the_circuit() {
        parallel::init();
        for unused in [0, 4096] {
            let (c, outputs) = circuit(unused);
            let selected = select(&c, &outputs).unwrap();
            assert_eq!(selected.trim_outputs, unused != 0);
            let (again, again_outputs) = circuit(unused);
            assert_eq!(selected, select(&again, &again_outputs).unwrap());
            assert_eq!(identity(&c), identity(&again));
            let zero = lower(&c, &outputs, identity(&c), &[false; 3], selected.trim_outputs);
            let one = lower(&c, &outputs, identity(&c), &[true; 3], selected.trim_outputs);
            assert!(zero.trace.same_program(&one.trace));
            for program in [&zero.trace, &one.trace] {
                let lowered = private_trace::lower(program, program).unwrap();
                let actual = PrivateShape::for_circuit(
                    lowered.circuit.rows.len(),
                    lowered.circuit.public.len(),
                    lowered.compressions.len(),
                )
                .unwrap();
                assert_eq!(
                    actual,
                    if selected.trim_outputs {
                        selected.trimmed
                    } else {
                        selected.untrimmed
                    }
                );
            }
            assert_eq!(selected, select(&c, &outputs).unwrap());
        }
    }

    #[test]
    fn planning_counts_connectors_and_retains_the_proving_cap() {
        let below = PrivateShape::plan(7392, 2, 128).unwrap();
        let above = PrivateShape::plan(7393, 2, 128).unwrap();
        assert_eq!(below.index.log_rows, 13);
        assert_eq!(above.index.log_rows, 14);
        let beyond_cap = PrivateShape::plan(1 << crate::native_arithmetic::MAX_LOG_ROWS, 2, 128).unwrap();
        assert!(beyond_cap.index.log_rows > crate::native_arithmetic::MAX_LOG_ROWS);
        assert!(PrivateShape::for_circuit(1 << crate::native_arithmetic::MAX_LOG_ROWS, 2, 128).is_none());
    }
}
