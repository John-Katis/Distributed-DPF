# exp-ot-libs (experiment, not part of ours)

This experiment runs every OT library we could find next to our `dpf_common::ot`, component by component, and compares them. `crates/` and `protocols/` are unchanged.

## Libraries

| Library | Language | Revision | What it has that we also have |
|---|---|---|---|
| emp-ot (+ emp-tool) | C++ | 0.3.0 | Naor–Pinkas, Chou–Orlandi base OT; IKNP COT/OT, semi-honest and malicious (KOS-style); Ferret, semi-honest and malicious |
| libOTe | C++ | `5d419c34` | SimplestOT (CO15), Masny–Rindal base OT; IKNP, KOS, KOS Δ-OT; Silent OT (dual LPN, not Ferret); KKRT, OOS 1-out-of-N |
| mpz-ot-core | Rust | `2cdf3b7` | Chou–Orlandi; KOS COT; Ferret (malicious only) |
| CryProt | Rust | `1e5cb7a` | SimplestOT; IKNP, KOS; Silent OT (dual LPN, not Ferret) |
| swanky | Rust | `cdbf4c0` | Naor–Pinkas, Chou–Orlandi; ALSZ (semi-honest), KOS |

None of them has KK13 1-out-of-N OT. The closest are libOTe's KKRT and OOS, which are different protocols.

## Layout

- `cpp/count_io.h`: an in-memory duplex link between two threads. It counts bytes, messages and rounds with the rule of our `Channel`: a message is stamped with clock + 1, a party's clock is the largest stamp it has received, and writes leave as one message on flush or on the next read.
  - `cpp/emp/bench_emp.cpp` plugs it in as an emp `IOChannel`.
  - `cpp/libote/bench_libote.cpp` drives it through coproto's `BufferingSocket`. Its framing headers are included in the byte count.
- `rust/`: our code, mpz and swanky. swanky gets the same link (`count.rs`) as its `AbstractChannel`. Our code and mpz run on our `Channel`.
- `rust-cryprot/`: CryProt, in its own crate because it pins `aes = "=0.9.1"` while swanky and mpz need `^0.9.3`.
  - It runs over its own QUIC transport on localhost.
  - Bytes come from its metrics layer, and rounds are not counted.
  - Its "COT with chosen Δ" rows report the same bytes as random OT. That can't be right (a chosen Δ costs one block per OT, as swanky shows), so its metrics miss a stream there.
- `fetch.sh` clones the C++ libraries at the pinned revisions into `deps/` (git-ignored) and builds them and both harnesses.
- `run.sh` writes `results/*.csv` with the columns `lib,component,security,n,phase,bytes,rounds,msgs,secs,check`.

The Rust crates are their own workspaces: swanky needs Rust 1.99 and mpz needs 1.95, while the main workspace is pinned to 1.87. The root `Cargo.toml` excludes this directory.

### Build fixes on this machine (Ubuntu 22.04: g++ 11, CMake 3.22)

- **emp-ot:** main is a 1.0 alpha that needs CMake 3.25, so we use the 0.3.0 release.
- **libOTe, partial build:** its NTT and RingLPN parts need `<format>` (GCC 13), so only the OT protocols are built. Its own test suite doesn't compile, so we build the library target only.
- **SPIN (libOTe's encoder, rev `f2010e0`):** it writes `struct alignas(16) __attribute__((may_alias)) block`, which g++ 11 rejects. `fetch.sh` changes the macro to `[[gnu::may_alias]]`, which means the same thing, and SPIN then builds and runs.

## Method

- Both parties run in one process, one thread each.
- Party 0 is the OT sender and holds Δ.
- A phase starts after a round trip that isn't counted.
- Bytes are both directions.
- Rounds are the maximum over the two parties, in the sense of our network model: messages in flight at the same time share a round.
- Time is the slower party's wall time.
- Sizes:
  - n = 2^23 for IKNP/KOS/OT
  - 20,000,000 for Ferret and Silent OT
  - 2^20 for 1-out-of-N with N = 8
- **Every output of every row was checked** against its definition:
  - COT: `M = K ⊕ r·Δ`
  - OT: the receiver gets the chosen message
  - random-choice protocols: the choice bits are balanced
  - 1-out-of-N: the receiver's encoding equals the sender's encoding at its choice, and differs at the next value

In all 86 rows (`results/`), the check passed.

Hardware: i7-12700K (AVX2, VAES, no AVX-512). Results are from one run each, on 2026-10-28.

## Results by component

Below, "B/item" is bytes per output (COT, OT or 1-out-of-N OT), and "ns/item" is time per output. Setup rows are the base OTs.

### Base OT (128 OTs)

| | Protocol | Bytes | Rounds | ms |
|---|---|---|---|---|
| ours | Naor–Pinkas, random OT, P-256 | 4,290 | 2 | 53 |
| emp-ot | Naor–Pinkas, chosen messages | 21,829 | 3 | 17 |
| swanky | Naor–Pinkas, chosen messages | 16,384 | 3 | 14 |
| ours | Masny–Rindal (endemic), P-256 | 16,896 | 2 | 97 |
| libOTe | Masny–Rindal, Curve25519 | 8,344 | 1 | 17 |
| emp-ot / libOTe / mpz / swanky / CryProt | Chou–Orlandi | 12,997 / 4,236 / 8,240 / 8,224 / 4,203 | 3 / 3 / 3 / 3 / – | 8 / 29 / 18 / 7 / 9 |

- Our Naor–Pinkas is the random-OT variant with compressed points: 2 points from the sender and 128 from the receiver, 33 B each, which is 4,290 B.
- Our Masny–Rindal sends two points per OT each way. The sender uses a fresh key-agreement secret per OT and per j (`endemic.rs`), while libOTe's sender uses one point for all 128 OTs. That's why ours is twice the size. It's a one-time cost.

### COT with Δ (IKNP semi-honest, KOS malicious), n = 2^23

| | sh B/item | sh rounds | sh ns/item | mal B/item | mal rounds | mal ns/item |
|---|---|---|---|---|---|---|
| **ours** (`CotSender`/`CotPair`) | 16.000 | 1 | **324** | 16.001 | 4 | **348** |
| emp-ot (IKNP) | 16.000 | 1 | 22 | 16.000 | 1 | 28 |
| libOTe (IKNP/KOS random OT; KOS Δ-OT) | 16.000 | 1 | 42 | 16.001; Δ-OT 21.0 | 3 | 55; Δ-OT 97 |
| mpz (KOS) | – | – | – | 16.004 | 3 | 96 |
| swanky (ALSZ/KOS random OT) | 16.000 | 1 | 76 | 16.000 | 5 | 156 |
| CryProt (random OT) | 16.000 | – | 20 | 16.000 | – | 34 |

- The bytes match exactly: 128 bits per COT plus a constant for the KOS check.
  - Ours: +5,568 B. That's `KOS_EXTRA` = 168 padding COTs and the proof in both directions, since `CotPair` always runs both.
  - emp: +4,160 B. mpz: +36,920 B.
- **Ours is 4–16× slower than every library.** At the same bytes, emp-ot and CryProt take about 20–30 ns per COT, against our 324.
- Malicious rounds: ours takes 4 (coin toss, proof). emp's KOS takes 1, because it derives χ from a hash of the transcript instead of a coin toss.

### Chosen-message 1-out-of-2 OT (IKNP), n = 2^23

| | B/item | Rounds | ns/item |
|---|---|---|---|
| ours (`iknp.rs`, semi-honest) | 48.000 | 2 | 368 |
| emp-ot sh / mal | 48.000 / 48.000 | 2 / 2 | 58 / 64 |

The bytes are identical: 128 bits of columns plus 2 × 128 bits of padded messages.

### Ferret (B13 parameters), 20M COTs per phase

| | Setup B | Setup rounds | Steady B per 20M | Steady rounds | ns/item |
|---|---|---|---|---|---|
| **ours sh** | 945,181 | 6 | 1,110,112 | 4 | 55 |
| emp-ot sh | 951,543 | 5 | 1,105,952 | 1 | 32 |
| **ours mal** | 978,074 | 12 | 1,110,242 | 9 | 80 |
| emp-ot mal | 960,023 | 7 | 1,106,272 | 5 | 35 |
| mpz mal, B13 | 477,408 | 8 | 1,110,388 | 8 | 100 |
| mpz mal, own defaults | 477,408 | 8 | 1,606,308 | 8 | 221 |

The steady state is two main iterations.

- **Communication matches emp-ot, the Ferret authors' code.** The semi-honest difference is exactly 4,160 B = 2 iterations × t·h bits (1,280 · 13 bits each): our receiver sends `b = r ⊕ α ⊕ 1` for every tree level (Fig. 6). emp skips that message because it takes the punctured positions straight from the receiver's random base-COT choice bits. That also saves rounds:
  - semi-honest: 1 round for both iterations in emp, 2 per iteration in ours;
  - malicious: 5 rounds against 9.
- Setup traffic agrees within 1% (same `pre` parameters). mpz's setup is smaller because it bootstraps with its own smaller parameter set (see `../mpz-ferret`).
- Ours is 1.7× (semi-honest) to 2.3× (malicious) slower than emp-ot, and 20% faster than mpz.

### Silent OT (dual LPN, not Ferret), 20M COTs

| | B per 20M | Rounds | ns/item |
|---|---|---|---|
| libOTe sh, SPIN / BlkAcc3x32 (default) / ExConv7x24 | 82,048 | 1 | 245 / 240 / 311 |
| libOTe mal, same codes | 84,184 | 3 | 249 / 261 / 329 |
| CryProt sh / mal | 226,953 / 235,290 | – | 332 / 343 |

- These send 5–13× less than Ferret but are 3–10× slower here, single-threaded.
- libOTe's own timer puts 1.8 s of the sender's 2.1 s in the encoder (`dualEncode`), with the PPRF at 0.3 s, so the encode step dominates.
- SPIN is about the same speed as the default code on this CPU. It has AVX2 but no AVX-512, so SPIN runs its AVX2 kernels.
- They aren't drop-in replacements for Ferret: the paper says Ferret.

### 1-out-of-N, N = 8, 2^20 OTs

| | Protocol | B/item | Rounds | ns/item |
|---|---|---|---|---|
| ours | KK13, chosen messages, l = 2 / 8 bits | 34 / 40 | 2 | 2,256 / 2,374 |
| libOTe | KKRT (sh), random encodings | 64 | 1 | 1,345 |
| libOTe | OOS (mal), random encodings | 64 | 3 | 1,509 |

- Ours: 256 bits of Walsh–Hadamard columns plus N·l message bits, which is the 2λ + N·l of CrypTFlow2 §2.2.2. KKRT's code is 512 bits, and its random encodings send no messages.
- The libOTe times include encoding all 8 values per OT on the sender side, so they're upper bounds.
- There's no library KK13 to compare against byte for byte.

## Findings

1. **Correctness.** Every one of our components gives correct outputs over 8–20M instances, and wherever a library runs the same protocol, our traffic is the same:
   - IKNP COT and chosen OT: identical to the byte;
   - KOS: the same up to the check constant;
   - Ferret: within 0.4% of emp-ot, with the difference fully explained by the derandomisation message.

   Together with the tamper tests (`cheating_sender_is_caught`, `kos_catches_inconsistent_columns`, `bad_points_abort` in `crates/common`, and `../mpz-ferret`), this is strong evidence that the implementations are right. What it can't show is security beyond the consistency checks, such as choice bits leaking through timing.
2. **IKNP/KOS speed.** Ours is the slowest IKNP measured, 15× slower than emp-ot at the same traffic. The protocol is the same, so the cost has to be in the local computation (bit-matrix transpose, PRG). It matters for the protocols that use IKNP without Ferret.
3. **Ferret rounds.** emp-ot shows that the receiver's per-level message isn't needed: the punctured index can be the receiver's random base-COT choices. That would remove 2 rounds per iteration in semi-honest mode, and 4 of 9 rounds per 20M in malicious mode.
4. **Ferret speed.** emp-ot is 1.7–2.3× faster. mpz is slower than ours.
5. **Library-only stack.** Only emp-ot covers both Ferret modes and IKNP/KOS. It has no Masny–Rindal base OT (it uses Chou–Orlandi) and no KK13, and it's C++.

## Note (2026-10-28, later)

The `ours` rows above were measured on our own OT implementation, before `dpf_common::ot` was moved onto emp-ot and libOTe (commit after `fca36ae`). Rerunning now measures the library-backed code. The harnesses set lsb(Δ) = 1 for the Ferret sender, so the receiver needs no lsb exchange.
