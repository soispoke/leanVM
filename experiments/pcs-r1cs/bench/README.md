# Timing on real hardware

The Arch VM cannot time binary-field proving (its virtual CPU lacks `pclmulqdq`), so timed results come from two reference machines, each doing its real job.

## Phone: client proving (Pixel 7)

An application's device proves its own client proof: witness, PIOP and openings. That run peaked at 3.2 GiB here, so it fits a Pixel 7 (Tensor G2, 8 GB). Aggregation does not, needing 6.5 GiB for one application and 43 GiB for eight, and is timed on the node instead.

```sh
sh experiments/pcs-r1cs/bench/build-android.sh      # static aarch64 binary, prints its path
python3 experiments/pcs-r1cs/bench/pixel7.py --binary <that path> --out runs/pixel7 --reps 5
```

The phone needs USB debugging (or wireless `adb`) and nothing installed: the binary is a static PIE run from `/data/local/tmp`. Runs alternate the Keccak (`pcs`, shared with the Keccak R1CS control) and BLAKE2s (`r1cs-vm`) transcripts with a 60-second cooldown, and record the battery temperature, because phones throttle when hot. `--threads` defaults to 4, matching the X1 and A78 cores. `--local` runs the identical pipeline on the host, which is how it was tested here; the aarch64 binary was also checked under QEMU (field tests, the example tests, and one admitted BLAKE2s client proof).

## Node: aggregation (Mac)

```sh
python3 experiments/pcs-r1cs/run.py --output runs/mac --fan-ins 1,2,4,8 --interfaces pcs,r1cs,r1cs-vm
cargo run --locked --release -p rec_aggregation --example tree -- --interface r1cs-vm --leaves 4 --per-leaf 4
```

`run.py` keeps its guarantees: memguard admission before each job, eight performance workers, a fresh output directory, every requested sample present and consistent, and sources unchanged during measurement. The Keccak R1CS control at eight applications needs about 85 GiB.
