from pathlib import Path
p=Path(__file__).resolve().parent/'candidate/crates/format_recursion/src/private_trace.rs'
s=p.read_text()
def replace(a,b):
 global s
 assert s.count(a)==1,(a[:100],s.count(a))
 s=s.replace(a,b,1)
replace('    pub original_public_len: usize,\n}', '    pub original_public_len: usize,\n    schedule: Vec<WitnessStep>,\n}')
insert='''
// A setup-owned straight-line program computes fresh helper values. It does not
// change the circuit or omit constraints; every variable keeps its original ID.
#[derive(Clone, Copy)]
enum PackedWord {
    Fixed(u64),
    Variable(usize),
}
impl PackedWord {
    fn get(self, values: &[F192]) -> u64 {
        match self {
            Self::Fixed(word) => word,
            Self::Variable(at) => values[at].c0,
        }
    }
}
#[derive(Clone, Copy)]
enum ValueStep {
    Constant(F192),
    Add(usize, usize),
    MultiplyAdd(usize, usize, usize),
    Limb(usize, usize),
    Bit(usize, usize),
    CompressionOutput(usize),
}
enum WitnessStep {
    Value(ValueStep),
    Compression {
        cv: [usize; 4],
        message: [usize; 8],
        counter: PackedWord,
        flags: PackedWord,
        retain: bool,
    },
}
struct WitnessSchedule {
    steps: Vec<WitnessStep>,
    public: Vec<usize>,
    variables: usize,
}
pub(crate) struct PreparedWitness {
    pub values: Vec<F192>,
    pub compressions: Vec<Compression>,
    pub public: Vec<F192>,
}
impl WitnessSchedule {
    fn evaluate(&self, witness: &Trace) -> PreparedWitness {
        let mut values = Vec::with_capacity(self.variables);
        values.extend([F192::ZERO, F192::ONE]);
        values.extend(witness.nodes.iter().map(|node| node.value));
        let mut compressions = Vec::new();
        let mut output = [0u32; 8];
        for step in &self.steps {
            match *step {
                WitnessStep::Value(step) => {
                    let value = match step {
                        ValueStep::Constant(value) => value,
                        ValueStep::Add(a, b) => values[a] + values[b],
                        ValueStep::MultiplyAdd(a, b, c) => values[a] * values[b] + values[c],
                        ValueStep::Limb(at, limb) => {
                            let x = values[at];
                            F192::new([x.c0, x.c1, x.c2][limb], 0, 0)
                        }
                        ValueStep::Bit(at, bit) => {
                            let x = values[at];
                            F192::new(([x.c0, x.c1, x.c2][bit / 64] >> (bit % 64)) & 1, 0, 0)
                        }
                        ValueStep::CompressionOutput(word) => F192::new(pack32(output[2 * word], output[2 * word + 1]), 0, 0),
                    };
                    values.push(value);
                }
                WitnessStep::Compression { cv, message, counter, flags, retain } => {
                    let initial = std::array::from_fn(|i| (values[cv[i / 2]].c0 >> (32 * (i % 2))) as u32);
                    let message = std::array::from_fn(|i| (values[message[i / 2]].c0 >> (32 * (i % 2))) as u32);
                    let counter = counter.get(&values);
                    let flags = flags.get(&values);
                    output = blake2s_compress(&initial, &message, counter, flags as u32, (flags >> 32) as u32);
                    if retain {
                        compressions.push((initial, message, counter, flags as u32, (flags >> 32) as u32));
                    }
                }
            }
        }
        assert_eq!(values.len(), self.variables, "setup-owned witness schedule");
        let public = self.public.iter().map(|&at| values[at]).collect();
        PreparedWitness { values, compressions, public }
    }
}

'''
replace('#[derive(Clone, Copy, Debug)]\npub struct Limits',insert+'#[derive(Clone, Copy, Debug)]\npub struct Limits')
replace('struct Compiler {\n    rows:', 'struct Compiler {\n    schedule: Vec<WitnessStep>,\n    rows:')
replace('fn variable(&mut self, value: F192) -> usize {\n        let at', 'fn variable(&mut self, value: F192, step: ValueStep) -> usize {\n        self.schedule.push(WitnessStep::Value(step));\n        let at')
replace('let at = self.variable(value);','let at = self.variable(value, ValueStep::Constant(value));')
replace('self.variable(self.values[a] + self.values[b])','self.variable(self.values[a] + self.values[b], ValueStep::Add(a, b))')
replace('self.variable(self.values[bit] * self.values[coefficient] + self.values[acc])','self.variable(self.values[bit] * self.values[coefficient] + self.values[acc], ValueStep::MultiplyAdd(bit, coefficient, acc))')
replace('self.variable(self.values[lo] + self.values[mid] * self.values[y])','self.variable(self.values[lo] + self.values[mid] * self.values[y], ValueStep::MultiplyAdd(mid, y, lo))')
replace('self.variable(F192::new(native[i], 0, 0))','self.variable(F192::new(native[i], 0, 0), ValueStep::Limb(source + 2, i))')
replace('self.variable(F192::new((native[i] >> bit) & 1, 0, 0))','self.variable(F192::new((native[i] >> bit) & 1, 0, 0), ValueStep::Bit(source + 2, 64 * i + bit))')
replace('self.variable(F192::new((limbs[i / 64] >> (i % 64)) & 1, 0, 0))','self.variable(F192::new((limbs[i / 64] >> (i % 64)) & 1, 0, 0), ValueStep::Bit(source + 2, i))')
replace('self.variable(F192::new((value >> i) & 1, 0, 0))','self.variable(F192::new((value >> i) & 1, 0, 0), ValueStep::Bit(variable, i))')
replace('c.variable(c.values[value] * c.values[value])','c.variable(c.values[value] * c.values[value], ValueStep::MultiplyAdd(value, value, 0))')
replace('''            let outputs: [usize; 4] =
                std::array::from_fn(|i| self.variable(F192::new(pack32(output[2 * i], output[2 * i + 1]), 0, 0)));''','''            self.schedule.push(WitnessStep::Compression {
                cv: std::array::from_fn(|i| words[i]),
                message: std::array::from_fn(|i| words[4 + i]),
                counter: PackedWord::Variable(words[12]),
                flags: PackedWord::Variable(words[13]),
                retain: true,
            });
            let outputs: [usize; 4] = std::array::from_fn(|i| {
                self.variable(F192::new(pack32(output[2 * i], output[2 * i + 1]), 0, 0), ValueStep::CompressionOutput(i))
            });''')
replace('''            let fixed = cv.iter().chain(&words).all(|v| self.constant_variables.contains(v));
            let outputs''','''            let fixed = cv.iter().chain(&words).all(|v| self.constant_variables.contains(v));
            let retain = !fixed || (self.compressions.is_empty() && block + 1 == count);
            if retain {
                self.schedule.push(WitnessStep::Compression {
                    cv,
                    message: words,
                    counter: PackedWord::Fixed(counter),
                    flags: PackedWord::Fixed(u64::from(flag)),
                    retain: true,
                });
            }
            let outputs''')
replace('''                    self.variable(value)
                }
            });''','''                    self.variable(value, ValueStep::CompressionOutput(i))
                }
            });''')
replace('if !fixed || (self.compressions.is_empty() && block + 1 == count) {','if retain {')
replace('''    analysis: Analysis,
}''','''    analysis: Analysis,
    schedule: Option<WitnessSchedule>,
}''')
replace('''        Some(Self { program, analysis })
    }
    pub(crate) fn lower_setup(&self) -> Option<Lowered> {
        lower_analyzed(&self.program, &self.program, &self.analysis)
    }''','''        Some(Self { program, analysis, schedule: None })
    }
    pub(crate) fn lower_setup(&mut self) -> Option<Lowered> {
        let mut lower = lower_analyzed(&self.program, &self.program, &self.analysis)?;
        self.schedule = Some(WitnessSchedule {
            steps: std::mem::take(&mut lower.schedule),
            public: lower.circuit.public.clone(),
            variables: lower.circuit.variables,
        });
        Some(lower)
    }
    pub(crate) fn prepare_witness(&self, witness: &Trace) -> Option<PreparedWitness> {
        if !self.program.same_program(witness) {
            return None;
        }
        Some(self.schedule.as_ref()?.evaluate(witness))
    }''')
replace('''    let mut c = Compiler {
        rows:''','''    let mut c = Compiler {
        schedule: Vec::new(),
        rows:''')
replace('''    Some(Lowered {
        circuit:''','''    Some(Lowered {
        schedule: c.schedule,
        circuit:''')
p.write_text(s)
p=p.with_name('private_recursion.rs');s=p.read_text();assert s.count('let prepared = private_trace::PreparedProgram::new(program)?;')==1
s=s.replace('let prepared = private_trace::PreparedProgram::new(program)?;','let mut prepared = private_trace::PreparedProgram::new(program)?;')
a='''        let lower = tracing::info_span!("Compile witness").in_scope(|| self.program.lower(witness))?;
        let public = self.public_values(outputs)?;
        if lower
            .circuit
            .public
            .iter()
            .map(|&v| lower.values[v])
            .collect::<Vec<_>>()
            != public
        {'''
b='''        let lower = tracing::info_span!("Compile witness").in_scope(|| self.program.prepare_witness(witness))?;
        let public = self.public_values(outputs)?;
        if lower.public != public {'''
assert s.count(a)==1;s=s.replace(a,b,1);p.write_text(s)
