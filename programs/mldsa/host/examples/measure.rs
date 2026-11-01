use leanvm::{Output, Program, Proof, Prover, Rate};
use std::{env, fs, time::Instant};
fn main() {
    let args: Vec<String> = env::args().collect();
    parallel::init_with_threads(std::num::NonZeroUsize::new(12).unwrap()).unwrap();
    let (elf, run) = if args[1] == "mldsa" {
        (mldsa_host::ELF, mldsa_host::batch(1))
    } else {
        (falcon_host::ELF, falcon_host::batch(1))
    };
    let override_elf = env::var("L5_PROFILE_ELF").ok().map(|p| fs::read(p).unwrap());
    let program = Program::from_elf(override_elf.as_deref().unwrap_or(elf)).unwrap();
    let output = Output::new(run.expected);
    match args[2].as_str() {
        "phases" => {
            let markers: std::collections::BTreeMap<u64, u64> = fs::read_to_string(&args[3])
                .unwrap()
                .lines()
                .map(|l| {
                    let v: Vec<_> = l.split_whitespace().collect();
                    (u64::from_str_radix(v[0], 16).unwrap(), v[1].parse().unwrap())
                })
                .collect();
            let mut machine = leanvm::Machine::new(program.rv(), &run.advice);
            let mut counts = std::collections::BTreeMap::<u64, u64>::new();
            let mut phase = 100;
            let mut marker_cycles = 0;
            while !machine.halted() {
                if let Some(p) = markers.get(&machine.pc()) {
                    phase = *p;
                    marker_cycles += 1;
                } else {
                    *counts.entry(phase).or_default() += 1;
                }
                machine.step().unwrap();
            }
            assert_eq!(machine.output().unwrap(), run.expected);
            println!("marker_cycles={marker_cycles}");
            for (phase, count) in counts {
                println!("{phase} {count}");
            }
        }
        "contexts" => {
            let mut machine = leanvm::Machine::new(program.rv(), &run.advice);
            let mut calls = Vec::<u64>::new();
            let mut counts = std::collections::BTreeMap::<Vec<u64>, u64>::new();
            while !machine.halted() {
                let pc = machine.pc();
                let mut context = calls.clone();
                context.push(pc);
                *counts.entry(context).or_default() += 1;
                let step = machine.step().unwrap();
                if calls.last().is_some_and(|call| *call + 4 == step.npc) {
                    calls.pop();
                } else if step.npc != pc + 4 && machine.registers().get(leanvm::Reg::RA) == pc + 4 {
                    calls.push(pc);
                }
            }
            assert_eq!(machine.output().unwrap(), run.expected);
            for (pcs, count) in counts {
                println!(
                    "{} {}",
                    count,
                    pcs.iter().map(|p| format!("{p:x}")).collect::<Vec<_>>().join(",")
                );
            }
        }
        "profile" => {
            let mut machine = leanvm::Machine::new(program.rv(), &run.advice);
            let mut counts = std::collections::BTreeMap::<u64, u64>::new();
            while !machine.halted() {
                *counts.entry(machine.pc()).or_default() += 1;
                machine.step().unwrap();
            }
            assert_eq!(machine.output().unwrap(), run.expected);
            for (pc, count) in counts {
                println!("{pc:x} {count}");
            }
        }
        "cycles" => {
            let exec = program.execute(&run.advice).unwrap();
            assert_eq!(exec.output, run.expected);
            let stats = program.measure(&run.advice).unwrap();
            println!("cycles={}\n{}", stats.cycles(), stats.details());
        }
        "prove" => {
            let log_rate: u8 = env::var("L5_LOG_INV_RATE")
                .ok()
                .and_then(|x| x.parse().ok())
                .unwrap_or(Rate::MIN.log_inv_rate());
            let prover = Prover::new(Rate::new(log_rate).unwrap());
            let start = Instant::now();
            let proven = prover.prove(&program, &run.advice).unwrap();
            let seconds = start.elapsed().as_secs_f64();
            assert_eq!(proven.output, output);
            let bytes = proven.proof.to_bytes();
            fs::write(&args[3], &bytes).unwrap();
            println!(
                "wallet_prove_s={seconds} cycles={} proof_bytes={}",
                proven.stats.cycles(),
                bytes.len()
            );
        }
        "merge" => {
            use leanvm::aggregate::{Leaf, LeafShape, Tree, TreeShape};
            let proof = Proof::from_bytes(&fs::read(&args[3]).unwrap()).unwrap();
            let stats = program.measure(&run.advice).unwrap();
            let shape = TreeShape {
                leaf: LeafShape::measured(&stats, Rate::new(2).unwrap()),
                arity_0: 2,
                arity: 2,
                rate: Rate::MIN,
            };
            let setup = Instant::now();
            let tree = Tree::new(&program, shape).unwrap();
            println!("merge_setup_s={}", setup.elapsed().as_secs_f64());
            let start = Instant::now();
            let merged = tree
                .prove_first(&[Leaf::new(&proof, output), Leaf::new(&proof, output)])
                .unwrap();
            println!(
                "merge_s={} proof_bytes={}",
                start.elapsed().as_secs_f64(),
                merged.to_bytes().len()
            );
            tree.verify(&merged, &[output, output]).unwrap();
        }
        "verify" => {
            let proof = Proof::from_bytes(&fs::read(&args[3]).unwrap()).unwrap();
            let start = Instant::now();
            program.verify(output, &proof).unwrap();
            println!("verify_ms={}", start.elapsed().as_secs_f64() * 1000.);
        }
        _ => panic!("mode"),
    }
}
