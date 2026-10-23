use circuit_suite::{Circuit, Src, Workload, read_statement};
use format_recursion::trace::{self, S, Trace, hash};
use primitives::field::F192;
use std::{marker::PhantomData, time::Instant};

/// Compile the workload itself, not a verifier for another application proof.
pub struct Application<W> {
    circuit: Circuit,
    sources: Vec<Src>,
    pub id: [u8; 32],
    trim_outputs: bool,
    workload: PhantomData<W>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_suite::{Ckt, Instance, Wire};
    use format_recursion::{private_recursion::Setup, trace::Op};

    struct Adder;
    impl Workload for Adder {
        const NAME: &'static str = "native-adder-test";
        fn build(c: &mut Ckt) -> Vec<Wire> {
            let bits = c.inputs(3);
            let (sum, carry) = c.fa(bits[0], bits[1], bits[2]);
            // Include a second adder whose carry is unused.
            let (extra, _) = c.fa(sum, bits[0], Wire::ZERO);
            let mut public = vec![sum, carry, extra];
            public.resize(circuit_suite::PUBLIC_BITS, Wire::ZERO);
            public
        }
        fn instance(seed: u64) -> Instance {
            let inputs: Vec<_> = (0..3).map(|i| seed >> i & 1 == 1).collect();
            let count = inputs.iter().filter(|&&b| b).count() as u8;
            let mut statement = [0; 64];
            statement[0] = (count & 1) | ((count >> 1) << 1) | (((count & 1) ^ u8::from(inputs[0])) << 2);
            Instance { inputs, statement }
        }
        fn invalid_instance(_: u64) -> Option<Instance> {
            None
        }
    }

    #[test]
    fn native_adder_compilation_binds_inputs_and_preserves_trimmed_outputs() {
        parallel::init();
        let mut app = Application::<Adder>::new();
        app.trim_outputs = true;
        let canonical = app.create(0);
        let setup = Setup::new(canonical.trace).unwrap();
        for seed in 0..8 {
            app.trim_outputs = false;
            let complete = app.create(seed);
            app.trim_outputs = true;
            let trimmed = app.create(seed);
            assert_eq!(complete.claim, trimmed.claim);
            assert!(trimmed.trace.nodes.len() < complete.trace.nodes.len());
            let words = fiat_shamir::merkle::hash_to_scalars(&trimmed.claim);
            let proof = setup.prove(&trimmed.trace, &words).unwrap();
            assert!(setup.verify(&words, &proof));
            let mut invalid = trimmed.trace;
            let input = invalid.nodes.iter().position(|node| node.op == Op::Input).unwrap();
            assert!(matches!(invalid.nodes[input + 1].op, Op::Mul(..)));
            // Forge both sides of the Boolean acceptance check to bypass its
            // host comparison; the compiled multiplication must still reject.
            invalid.nodes[input].value = F192::new(2, 0, 0);
            invalid.nodes[input + 1].value = F192::new(2, 0, 0);
            assert!(invalid.satisfied());
            let forged = setup.prove(&invalid, &words).unwrap();
            assert!(!setup.verify(&words, &forged));
        }
    }
}

pub struct Created {
    pub trace: Trace,
    pub claim: [u8; 32],
    pub report: serde_json::Value,
}

impl<W: Workload> Application<W> {
    pub fn new() -> Self {
        let (circuit, sources, _) = circuit_suite::build::<W>();
        circuit.check_wired().expect("application wiring");
        let mut identity = b"native-r1cs-full-adder-application-v1".to_vec();
        identity.extend((circuit.log_rows as u64).to_le_bytes());
        for s in &circuit.sigma {
            identity.extend(s.to_le_bytes());
        }
        // Large Boolean applications otherwise exceed the native row cap.
        // Specialize from the fixed circuit, never from private witness values.
        let trim_outputs = circuit.log_rows >= 23;
        Self {
            circuit,
            sources,
            id: primitives::hash::hash(&identity),
            trim_outputs,
            workload: PhantomData,
        }
    }

    pub fn expected_claim(&self, seed: u64) -> [u8; 32] {
        let instance = W::instance(seed);
        let statement = flock::membership::Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        let mut bytes = self.id.to_vec();
        for half in statement.halves() {
            bytes.extend(half.c0.to_le_bytes());
            bytes.extend(half.c1.to_le_bytes());
        }
        primitives::hash::hash(&bytes)
    }

    pub fn create(&self, seed: u64) -> Created {
        let instance = W::instance(seed);
        // The independent reference and Boolean evaluation are outside the native witness timer.
        let values = self.circuit.values(&instance.inputs);
        assert_eq!(read_statement(&values, &self.sources), instance.statement);
        let start = Instant::now();
        let mut inputs = instance.inputs.iter();
        trace::start();
        let zero = S::u(0);
        let one = S::u(1);
        // Keep both output bits separately. All derived bits are Boolean by
        // induction from constrained free inputs and the full-adder identities.
        let mut outputs = vec![[zero, zero]; self.circuit.rows().len()];
        let mut required = vec![[!self.trim_outputs; 2]; outputs.len()];
        if self.trim_outputs {
            for &src in &self.sources {
                if let Src::Row(r) = src {
                    required[r as usize][0] = true;
                }
            }
            for (r, row) in self
                .circuit
                .rows()
                .iter()
                .enumerate()
                .skip(circuit_suite::PUBLIC_ROWS)
                .rev()
            {
                if required[r].iter().any(|&needed| needed) {
                    for (src, component) in [(row.x, 0), (row.y, 0), (row.c, 1)] {
                        if let Src::Row(from) = src {
                            required[from as usize][component] = true;
                        }
                    }
                }
            }
        }
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
        for (r, row) in self.circuit.rows().iter().enumerate().skip(circuit_suite::PUBLIC_ROWS) {
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
        let statement = flock::membership::Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        // Public statement halves are big endian bytes interpreted as little
        // endian field limbs by the existing application claim convention.
        let words: Vec<_> = self
            .sources
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
        for (word, expected) in words.iter().zip(statement.halves()) {
            assert_eq!(word.value(), expected);
        }
        let id = fiat_shamir::merkle::hash_to_scalars(&self.id).map(S::c);
        let mut parts = vec![(id[0], 16), (id[1], 16)];
        parts.extend(words.iter().map(|&word| (word, 16)));
        let digest = hash(&parts);
        let mut program = trace::take();
        program.public = digest.to_vec();
        let trace_nodes = program.nodes.len();
        let native_trace_creation_ms = start.elapsed().as_secs_f64() * 1000.;
        let claim = fiat_shamir::merkle::scalars_to_hash(&digest.map(|s| program.nodes[s.0].value)).unwrap();
        assert_eq!(claim, self.expected_claim(seed));
        Created {
            trace: program,
            claim,
            report: serde_json::json!({
                "kind":"native_application_witness", "workload":W::NAME,
                "native_trace_creation_ms":native_trace_creation_ms,
                "boolean_log_rows":self.circuit.log_rows,
                "trim_unused_outputs":self.trim_outputs,
                "trace_nodes":trace_nodes,
            }),
        }
    }
}
