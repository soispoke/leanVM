# Track A: prover-only optimization challenge

Candidates make the aggregate prover faster without changing what any verifier checks. The score is aggregate time per application at a fixed batch of eight, for each interface separately (`pcs`, `r1cs`, and `r1cs-vm`, the R1CS path on the VM's BLAKE2s transcript).

## Why soundness cannot regress

Soundness is a property of the verifier. A candidate's code runs only in the timed `challenge aggregate` step. Everything else runs from the frozen baseline build: the hidden workload, the client proofs, and the final check, which recompiles the aggregate program itself and verifies the candidate's proof with the reference `cpu::verify`. The program digest seeds the transcript, so a candidate that changes the guest, the compiler output, the transcript, or any constraint produces a proof the reference rejects. The reference also pins the PCS rate (all supported rates are 128-bit, but they trade proof size for prover time) and checks each application's EVM execution and claim coverage.

So Track A needs no Lean check: the statement does not change. A change to what is proven (the Keccak circuit, the R1CS layout, the in-aggregate verifier) is Track B and needs equivalence evidence and review.

## Rules

`challenge.json` is the contract. Candidates may edit only the listed prover crates' sources; any other path rejects the candidate before it is built. That gate is a fast failure and a statement of intent, not the soundness argument. A run is rejected if the candidate's aggregate fails, the reference rejects any repetition's proof, or a limit is exceeded: peak memory above 1.25 times baseline, a larger proof, or more EVM execution gas.

The score is the median over five repetitions of candidate aggregate wall time plus reference verification time, divided by the fan-in. Client proving is excluded because it is identical on both paths and done by the reference. An improvement counts only if the speedup exceeds both 3% and twice the baseline's relative half-range across its own repetitions. Each scored run draws a fresh workload seed that never enters the candidate's tree or process; the evaluator itself flips one byte of the first proof and requires the reference to reject it.

## Hardware

Timing needs a CPU with carry-less multiplication. The `arch-fv-autoresearch-01` VM currently exposes AVX-512 but not `pclmulqdq`, so binary-field arithmetic falls back to software and runs about 200 times slower; the evaluator records `timing_valid: false` there and never counts an improvement. Correctness gates remain valid on any host. Scored runs need host CPU passthrough on that VM or another approved machine.

## Use

```sh
# Calibrate: the baseline against itself.
python3 experiments/pcs-r1cs/challenge/evaluate.py --baseline BASE --candidate BASE \
  --interface r1cs --out runs/base-r1cs
# Score a candidate commit.
python3 experiments/pcs-r1cs/challenge/evaluate.py --baseline BASE --candidate CAND \
  --interface r1cs --baseline-result runs/base-r1cs/result.json --out runs/cand-r1cs
```

Give every interface the same search budget. Report absolute scores on the same machine; the difference between interfaces after comparable effort is the architectural evidence, not either track's speedup over its own baseline.
