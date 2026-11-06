# exp-prf-bench (experiment, not part of ours)

PRF microbenchmarks for §8b of the paper (Tab. prf-2pc and Tab. prf-local).
`crates/` and `protocols/` are unchanged; the PRF code is taken from them.

## Running

```
cargo test --release -p exp-prf-bench
cargo run --release -p exp-prf-bench --example bench-prf -- local
cargo run --release -p exp-prf-bench --example bench-prf -- 2pc
cargo run --release -p exp-prf-bench --example bench-prf -- ferret
```

`all` runs the three modes in order. `2pc` takes about a minute and `local` a few.

## What each mode measures

- `local` (Tab. prf-local): the latency of one plaintext call, each call on the previous output, median of 7 runs. It covers the AES-128 block, AES–MMO `H_K`, a GGM node (2 calls), and the DGH+21 LPN-PRG with `B` row-wise, column-XOR, and one half. It also gives the throughput on independent inputs (full-domain style).
- `2pc` (Tab. prf-2pc): one call of F_prf on an XOR-shared input, in batches of 1 and of one n = 32 key pair, median of 5 runs. Every output is checked against the clear.
  - All correlations come from Ferret (B13), bootstrapped once and not counted.
  - Columns: `online_kbit` is the input-dependent traffic. `corr_kbit` is the measured preprocessing traffic, and `cots` the COTs consumed, charged at 0.443 bit each in `cot_kbit`.
  - The table's Corr. is `corr_kbit + cot_kbit`.
  - The rows:
    - `aes_mmo_ot_tower`: ours (`dpf_common::aes_tower::OtTower`), the Boyar–Peralta circuit with ANDs from corrected COTs.
    - `aes_mmo_maestro_style`: `src/maestro.rs`, our two-party adaptation of MAESTRO's F_16-tower lookup.
      - Online, per S-box: three F_16 products with the corrected-COT technique, plus one 16-entry one-hot lookup. That is 116 bits and 12 COTs, in 3 rounds per S-box layer (30 per call).
      - Preprocessing, per S-box: the one-hot vector e_r from its 11 monomials, 28 bits and 6 COTs.
    - `aes_mmo_and_triples`: `src/triples.rs`, the Boyar–Peralta circuit (`exp_bp_sbox::boyar_peralta`) with one Beaver triple per AND. Each triple comes from 2 random COTs, one per direction, with no traffic. Per S-box: 136 bits and 68 COTs.
    - `lpn_prg_dgh21`: FssNN's 2PC LPN-PRG (`fssnn::semi_honest::sec_prg`), with its preprocessing.
- `ferret`: the time and traffic of one Ferret COT, refills included.

## Results (2026-11-06, i7-12700K, `2pc`, kbit per call)

| Row | Batch | Online | Corr. (measured + COTs) | Total | bit/out | Rounds |
|---|---|---|---|---|---|---|
| OT tower | 1, 32 | 13.92 | 0 + 1.35 (3,040 COTs) | 15.27 | 119.3 | 40 |
| MAESTRO-style | 1, 32 | 18.56 | 4.48 + 1.28 (2,880 COTs) | 24.32 | 190.0 | 30 |
| AND triples | 1, 32 | 21.76 | 0 + 4.82 (10,880 COTs) | 26.58 | 207.7 | 40 |
| LPN-PRG (FssNN) | 64 | 1.90 | 3.97 + 0.71 (1,598 COTs) | 6.58 | 25.7 | 2 |
| LPN-PRG (FssNN) | 1 | 1.90 | 4.18 + 0.85 (1,919 COTs) | 6.94 | 27.1 | 2 |
