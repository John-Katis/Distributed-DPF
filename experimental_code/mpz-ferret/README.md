# exp-mpz-ferret (experiment, not part of ours)

This experiment checks whether mpz-ot-core's Ferret ([privacy-scaling-explorations/mpz](https://github.com/privacy-scaling-explorations/mpz), rev `2cdf3b7`, 0.1.0-alpha.6) could replace `dpf_common::ot::ferret`. `crates/` and `protocols/` are unchanged.

## Setup

- mpz needs Rust 1.95 (edition 2024) and rand 0.10. The main workspace is pinned to 1.87 and rand 0.8.
- So this crate is its own workspace with its own `rust-toolchain.toml`, and the root `Cargo.toml` excludes it.
- mpz-ot-core is sans-IO. Each step returns a serde message, which `src/lib.rs` bincode-encodes and sends as one `Channel` message, so `CommStats` counts it like our traffic.
- mpz bootstraps from any `RCOTSender`/`RCOTReceiver`. `BaseSender`/`BaseReceiver` hand it random COTs from our `CotPair` (endemic base OT + KOS), so the Δ is ours.

## Running

```
cd experimental_code/mpz-ferret
cargo test --release
cargo run --release --example bench-mpz-ferret -- [--n 20000000] [--modes ours-mal,ours-sh,mpz-b13,mpz-default]
```

Tests:

- `correlation_with_our_delta`: every mpz output satisfies `M = K ⊕ r·Δ` under our Δ, across several refills.
- `tampered_extend_aborts`: a corrupted `SenderExtend` fails mpz's SPCOT consistency check.

## Results (2026-10-28, N = 20,000,000 COTs per phase, one direction, one thread per party, one run)

Modes:

- `mpz-b13` uses our `B13.main` parameters (n = 10,485,760, k = 452,000, t = 1,280) once enough COTs are held, and before that mpz's own `REGULAR_PARAMS`.
- `mpz-default` uses mpz's own parameter selector (n from 256,000 to 32,768,000, t = 2,000).

Phases:

- "first N" counts everything from the base COTs to N outputs.
- "next N" is the steady state.

Columns:

- Bytes are both directions.
- Iterations for ours count main iterations only (the `pre` iteration is extra). For mpz they include its bootstrap iteration.

All outputs were checked.

| mode | base COTs | phase | iterations | bytes (MB) | bits/COT | rounds | time (s) | ns/COT |
|---|---|---|---|---|---|---|---|---|
| ours-mal | 41158 | first N | 2 | 2.05 | 0.8218 | 17 | 1.744 | 87.2 |
| ours-mal | 41158 | next N | 2 | 1.11 | 0.4441 | 9 | 1.614 | 80.7 |
| ours-sh | 41030 | first N | 2 | 2.05 | 0.8187 | 6 | 1.180 | 59.0 |
| ours-sh | 41030 | next N | 2 | 1.11 | 0.4440 | 4 | 1.061 | 53.1 |
| mpz-b13 | 27377 | first N | 4 | 2.77 | 1.1099 | 20 | 2.480 | 124.0 |
| mpz-b13 | 27377 | next N | 2 | 1.11 | 0.4442 | 8 | 1.964 | 98.2 |
| mpz-default | 27377 | first N | 3 | 2.53 | 1.0127 | 16 | 2.120 | 106.0 |
| mpz-default | 27377 | next N | 2 | 1.61 | 0.6425 | 8 | 4.332 | 216.6 |

## Findings

**Communication.** At the same LPN parameters, the steady-state traffic is the same: 1.11 MB per 20M COTs (0.444 bits/COT). So our Ferret sends what an independent implementation sends.

**Speed.** At B13, ours is about 20% faster (81 vs 98 ns/COT, single thread, one run). mpz's `rayon` feature was off.

**Rounds.** mpz takes 4 messages per iteration. Ours takes about 4.5 in malicious mode (9 rounds for 2 iterations) and 2 in semi-honest mode.

**Semi-honest mode.** mpz has none: the SPCOT check always runs. Our semi-honest variants would pay for the check: 128 COTs and 2 messages per iteration.

**Bootstrap.**
- mpz fixes the bootstrap iteration to `REGULAR_PARAMS[0]` (n = 256,000, t = 2,000). Our `pre` parameters cannot be set.
- It needs fewer base COTs (27,377 vs 41,158).
- It climbs a ladder of parameter sizes up to B13, so "first N" costs more: 2.77 vs 2.05 MB and 20 vs 17 rounds.

**Parameters.** The parameter selector can be configured, but mpz requires n/t to be a power of two (B13 qualifies). Its defaults (t = 2,000) are not emp-ot's, and the default selector can make more COTs than were asked for: see `mpz-default`'s "next N" row.

**Abort.** On a failed check, the mpz receiver returns an error and sends nothing. Our code tells the sender with one byte. Wiring mpz in would need that byte added around it.

**Fault injection.** Malicious tests can tamper with the serialized messages, as `tampered_extend_aborts` does. That replaces `FerretSender::fault_next`.

**Toolchain.** Putting mpz in `crates/common` means moving the whole workspace to Rust 1.95 and keeping RNG adapters at the boundary (rand 0.8 vs 0.10).

## Note (2026-10-28, later)

The `ours` rows above were measured on our own OT implementation, before `dpf_common::ot` was moved onto emp-ot and libOTe (commit after `fca36ae`). Rerunning now measures the library-backed code. The harnesses set lsb(Δ) = 1 for the Ferret sender, so the receiver needs no lsb exchange.
