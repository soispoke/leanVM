use circuit_suite::{Circuit, Src, Workload, read_statement};
use format_recursion::{application_lowering, trace::Trace};
#[cfg(test)]
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
        app.trim_outputs = false;
        let control_setup = Setup::new(app.create(0).trace).unwrap();
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
            assert!(!control_setup.verify(&words, &proof));
            let complete_proof = control_setup.prove(&complete.trace, &words).unwrap();
            assert!(control_setup.verify(&words, &complete_proof));
            assert!(!setup.verify(&words, &complete_proof));
            assert!(setup.prove(&complete.trace, &words).is_none());
            let mut wrong = words;
            wrong[0] += F192::ONE;
            assert!(!setup.verify(&wrong, &proof));
            assert!(complete.trace.same_program(&app.with_trimming(false).create(0).trace));
            app = Application::<Adder>::new().with_trimming(true);
            assert!(trimmed.trace.same_program(&app.create(0).trace));
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
        let id = application_lowering::identity(&circuit);
        let trim_outputs = application_lowering::select(&circuit, &sources)
            .expect("native lowering shape comparison")
            .trim_outputs;
        Self {
            circuit,
            sources,
            id,
            trim_outputs,
            workload: PhantomData,
        }
        .with_trimming(trim_outputs)
    }

    /// Research-only override of the relation default; changes the pinned circuit key.
    pub fn with_trimming(mut self, enabled: bool) -> Self {
        self.trim_outputs = enabled;
        self
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
        primitives::protocol_hash::hash(&bytes)
    }

    pub fn create(&self, seed: u64) -> Created {
        let instance = W::instance(seed);
        // The independent reference and Boolean evaluation are outside the native witness timer.
        let values = self.circuit.values(&instance.inputs);
        assert_eq!(read_statement(&values, &self.sources), instance.statement);
        let start = Instant::now();
        let compiled = application_lowering::lower(
            &self.circuit,
            &self.sources,
            self.id,
            &instance.inputs,
            self.trim_outputs,
        );
        let statement = flock::membership::Statement {
            y: instance.statement[..32].try_into().unwrap(),
            root: instance.statement[32..].try_into().unwrap(),
        };
        assert_eq!(compiled.statement_halves, statement.halves());
        let program = compiled.trace;
        let trace_nodes = program.nodes.len();
        let native_trace_creation_ms = start.elapsed().as_secs_f64() * 1000.;
        let claim = fiat_shamir::merkle::scalars_to_hash(
            &program
                .public
                .iter()
                .map(|s| program.nodes[s.0].value)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
        .unwrap();
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
                "boolean_input_rows":compiled.input_rows,
                "omitted_sums":compiled.unused_sums,
                "omitted_carries":compiled.unused_carries,
                "public_pack_bits":512,
                "range_checks":0,
            }),
        }
    }
}
