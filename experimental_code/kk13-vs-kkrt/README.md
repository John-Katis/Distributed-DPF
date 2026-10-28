# exp-kk13-vs-kkrt (experiment, not part of ours)

This experiment compares the CrypTFlow2 bit triples behind floram-arith's F_AND (XLH+25 App. A) on our KK13 against the same triples on libOTe's KKRT. `protocols/` keeps KK13.

Both sides build the triples the same way, as `dpf_common::bool2pc` does: one 1-out-of-8 OT of 2-bit messages per correlated pair (CrypTFlow2's `_8KKOT`), with the first triple used.

- **KK13 (ours):** `examples/kk13_triples.rs` on `dpf_common::ot::kkot`. Its 256 base OTs are Naor–Pinkas, now from emp-ot.
- **KKRT (libOTe):** `kkrt_triples.cpp`, built by `build.sh` against the libOTe build in `../ot-libs`.
  - KKRT gives random encodings of all 8 values.
  - The sender masks its 8 two-bit messages with the low 2 bits of each encoding and sends 16 bits per OT.

Phases:

1. **setup:** base OTs, plus KKRT's `init` for all OTs.
2. **seq:** 200 single-triple calls one after another. This is how floram-arith calls `triples(1)`, once per AND.
3. **batch:** one batch of 2^20 triples.

Every triple was checked: (a₀ ⊕ a₁) ∧ (b₀ ⊕ b₁) = c₀ ⊕ c₁. Bytes and rounds use our `Channel` rule on both sides (KKRT through `../ot-libs/cpp/count_io.h`, with coproto framing included).

```
cargo run --release -p exp-kk13-vs-kkrt --example kk13-triples -- 200 1048576
./build.sh && ./build/kkrt_triples 200 1048576
```

## Results (2026-10-28, one thread per party, one run)

| | Setup bytes | Setup rounds | Setup ms | Per AND (seq): bytes | rounds | µs | Batch: bytes/triple | rounds | ns/triple |
|---|---|---|---|---|---|---|---|---|---|
| KK13 (ours) | 43,589 | 3 | 19 | 34 | 2 | 55 | 34 (272 bits) | 2 | 2,528 |
| KKRT (libOTe) | 12,460 | 3 | 141 | 82 | 2 | 7.5 | 66 (528 bits) | 2 | 1,375 |

Where the numbers come from:
- **Bytes per triple:**
  - KK13: 256 bits of Walsh–Hadamard columns plus 8 × 2 message bits.
  - KKRT: a 512-bit code plus the same 16 bits.
  - In the seq phase, KKRT also pays coproto's framing on two messages (82 instead of 66).
- **Setup:**
  - KK13: 256 Naor–Pinkas base OTs (emp's chosen-message OTNP).
  - KKRT: libOTe's base OTs plus IKNP for its 512 base keys, and `init` precomputing for all 1,048,776 OTs, which is most of its 141 ms.

## What it means for floram-arith

One Gen with a 16-bit input uses 49 ANDs: 3 per bit in BitDec plus 1 for CCMP. That's 49 single-triple calls. Measured Gen (`bench-floram-arith gen --in-bits 16 --out-bits 64`) for scale:

- 72,484 B and 150 rounds in Gen;
- 87,249 B of setup.

| Per Gen (16-bit input) | KK13 | KKRT | Difference |
|---|---|---|---|
| Triple bytes | 49 × 34 = 1,666 | 49 × 82 = 4,018 | +2,352 B (+3.2% of Gen's 72,484 B) |
| Triple rounds | 98 | 98 | none |
| Triple time | ≈ 2.7 ms | ≈ 0.37 ms | −2.3 ms of the ≈ 6.8 ms Gen compute |
| Setup bytes | 43,589 | 12,460 | −31 KB (one-time) |

- **Rounds:** identical. Both need 2 per triple, so the latency-bound part of Gen doesn't change.
- **Communication:** KKRT costs about twice the bytes per triple. Per Gen that's small, since Gen is dominated by the per-level correction words, but it goes the wrong way.
- **Setup:** smaller with KKRT, but it's paid once.
- **Time:** KKRT is about 7× faster per single call. Our KK13 transposes all 256 columns even for one OT, while KKRT's per-OT work is small after `init`.
- **Paper:** XLH+25 App. A specifies "the bit triplets generated using the protocol in Cryptflow2", i.e. KKOT. Its reference code uses SCI's `kkot.h`. Switching to KKRT would be a deviation from the paper. The cost model (2λ + N·l bits per OT, as in CrypTFlow2 §2.2.2) holds for KK13 only.
