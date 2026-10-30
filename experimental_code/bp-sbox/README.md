# exp-bp-sbox (experiment, not part of ours)

This experiment asks whether the Boyar–Peralta AES S-box ("A depth-16 circuit for the AES S-box": 34 ANDs, AND-depth 4) beats the F4 tower of ht-aes (36 ANDs, depth 4) under the OT tower's ANDs-from-COTs protocol.

`protocols/ht-aes` and `crates/common` are unchanged.

- `CotCircuit` is `OtTower` with the circuit as a parameter. It uses the same F_And with two Cross terms per AND, the same hashing and the same message pattern, and it implements `TowerBackend`, so `mmo_shared` runs on it unchanged.
- `Schedule` decides which bits party 1 corrects. Before each AND layer it corrects a basis of that layer's operands modulo the span of the bits already corrected. The resulting COT count is the rank, which is the minimum this protocol allows for a given circuit.
- `boyar_peralta()` is Figures 5, 7 and 8 of the paper as printed (forward direction, D = U7).
- `tower()` rebuilds the ht-aes tower as a circuit.

The tests check:

- both circuits against the S-box on all 256 inputs,
- the schedules,
- 2PC AES–MMO against the cleartext result.

## Running

```
cargo test --release -p exp-bp-sbox
cargo run --release -p exp-bp-sbox --example bench-bp-sbox -- [--n 32] [--reps 5]
```

## Results (2026-10-30, n = 32, sh-bin with ℓ = 64; both parties in one process, 20 cores)

### Per S-box

| Circuit | ANDs | AND layers: (ANDs, new COTs) | COTs | Bits | Rounds |
|---|---|---|---|---|---|
| F4 tower (ours) | 36 | (9, 8) (3, 4) (6, 2) (18, 4) | 18 | 90 | 4 |
| Boyar–Peralta | 34 | (9, 8) (3, 4) (4, 3) (18, 4) | 19 | 87 | 4 |

The only difference is the inversion's middle. The tower carries a single F4 element e (2 bits) between its second and third AND layers. Boyar–Peralta carries three independent products, M25, M31 and M34.

### AES part of one Gen

The AES part is 66 calls plus Π_KeyExp of K and K'. Timings are the median of 11 runs.

| Backend | ANDs | COTs | Bytes | Rounds | Online |
|---|---|---|---|---|---|
| `OtTower` (ht-aes) | 383,040 | 191,520 | 119,700 | 1,320 | 27.9 ms |
| `CotCircuit`, F4 tower | 383,040 | 191,520 | 119,700 | 1,320 | 28.8 ms |
| `CotCircuit`, Boyar–Peralta | 361,760 | 202,160 | 115,710 | 1,320 | 27.2 ms |

On the tower, `CotCircuit` sends exactly the bytes `OtTower` does. Same-engine runtimes differ by about 5%: Boyar–Peralta hashes 68 cross terms per S-box instead of 72.

### Whole Gen

The F4 tower row is the measured ht-aes sh-bin Gen. The Boyar–Peralta row is that Gen minus AES(`OtTower`) plus AES(Boyar–Peralta).

Ferret B13 yields 10,016,992 COTs per main iteration and direction. One iteration costs 552,976 B and 362 ms.

| S-box | Gen bytes | Gen rounds | LAN | WAN | dir-0 COTs per key | Keys per Ferret iteration | Ferret per key |
|---|---|---|---|---|---|---|---|
| F4 tower | 121,908 | 1,353 | 13.56 s | 135.3 s | 191,584 | 52 | 10.6 kB, 6.9 ms |
| Boyar–Peralta | 117,918 (−3.3%) | 1,353 | 13.56 s | 135.3 s | 202,224 (+5.6%) | 49 | 11.2 kB, 7.3 ms |

Including the amortised Ferret cost, the totals per key are:

- F4 tower: 132.5 kB.
- Boyar–Peralta: 129.1 kB (−2.6%).

Both are latency-bound: at 1,353 rounds, LAN and WAN times are equal to within 1 ms.
