# Distributed DPF protocols

A Cargo workspace of two-party distributed point function (DPF) protocols.
Each protocol is its own crate, and all of them build on one shared library.

```
crates/
  common/            dpf-common: the shared library
protocols/
  floram-cprg/       Floram-CPRG distributed DPF (Doerner–shelat, CCS'17)
  half-tree/         Half-Tree distributed DPF (Guo et al., EC'23), semi-honest,
                     and its actively secure variant with one-bit leakage
                     (Zhang et al., S&P'24)
  floram-arith/      dealer-less DPF with arithmetic input/output
                     (Xing et al., NDSS'25) on the Floram tree
scripts/
  bench_all.sh       runs all benchmarks into results/*.csv
REFERENCES.md        papers and techniques this code implements
```

| Protocol | Security | α input | Payload | Correction words via |
|---|---|---|---|---|
| `floram-cprg` | semi-honest | XOR shares | `F_2^m` | GC MUX per level |
| `half-tree` (`semi_honest`) | semi-honest | XOR shares | `F_2^m` | COT + global offset Δ (no 2PC per level) |
| `half-tree` (`malicious`) | malicious, one-bit leakage | BDOZ-authenticated bits | `GF(2^128)^bm` + SPDZ MACs | as above, plus a batch MAC check |
| `floram-arith` | semi-honest | additive shares mod 2^n (BitDec from bit triples) | `Z_2^ℓ`, ℓ ≤ 64 | COT-based block MUX per level, CCMP + arithmetic MUX for the last word |

## Shared library: `dpf-common`

| Module | Contents |
|---|---|
| `block`   | `Block` (128-bit), bit/byte packing, domain-depth and payload-width helpers |
| `prg`     | two-key Davies–Meyer AES PRG (`left`, `right`, batched `expand_many`) |
| `hash`    | fixed-key AES hashes (with the σ orthomorphism), the keyed CCR hash `H_S` (Half-Tree, half-gates), TMMO tweakable CCR hash, AES-CTR stream |
| `net`     | in-process two-party network (`run_two_party`, `Channel`, `CommStats`) |
| `ot`      | base OTs over secp256r1 (Naor–Pinkas, semi-honest; Masny–Rindal endemic OT, malicious), semi-honest IKNP extension, 128-bit correlated OT (`CotPair`, sender-chosen Δ; in malicious mode endemic base OTs + KOS15 check), Ferret LPN-based COT extension (`CotPair::enable_ferret`), and KK13 1-of-N OT (`kkot`) |
| `gf128`   | GF(2^128) multiplication (`pclmulqdq` with a portable fallback) |
| `coin`    | SHA-256 commitments, coin tossing, `Abort` |
| `mac`     | authenticated sharing: `binary` (BDOZ bits + SPDZ over GF(2^128)), `z2k` (SPDZ2k), `fp` (SPDZ over F_p), all with deferred batch MAC checks |
| `arith`   | Z_2^ℓ helpers and SIRNN's COT-based arithmetic MUX |
| `bool2pc` | F_AND / F_OR on XOR-shared bits from CrypTFlow2 bit triples, COT-based block MUX |
| `bench`   | shared CLI and CSV schema for every `examples/bench*.rs` |
| `gc`      | half-gates garbled circuits over XOR-shared inputs (`GcParty`, `Garbler`, `Evaluator`) |
| `testing` | cleartext point function `point_fn` and `random_beta`, for tests and benchmarks |

## Adding a protocol

1. Create `protocols/<name>/` with a `Cargo.toml` that depends on
   `dpf-common.workspace = true`. The workspace picks up every directory under
   `protocols/` automatically.
2. Put the protocol-specific sources in `protocols/<name>/src/`. For a protocol
   with both security models, use one module per variant:
   ```
   src/lib.rs
   src/semi_honest/   (or semi_honest.rs)
   src/malicious/     (or malicious.rs)
   ```
3. Add `tests/` (compare against `dpf_common::testing::point_fn`) and
   `examples/bench.rs`.
4. Code that more than one protocol needs goes into `crates/common`.

## Commands

```
cargo test --workspace --release                 # everything
cargo test -p floram-cprg --release              # one protocol
cargo run --release -p floram-cprg --example bench -- all --in-bits 16
cargo run --release -p half-tree --example bench-half-tree -- all --variant ht --in-bits 16
cargo run --release -p half-tree --example bench-half-tree -- all --variant mal --in-bits 16
cargo run --release -p floram-arith --example bench-floram-arith -- all --in-bits 16 --out-bits 64
scripts/bench_all.sh --max-in-bits 20         # all four, CSV into results/
```

All benchmarks print the same CSV schema (`dpf_common::bench::HEADER`); the
first two columns are `mode,variant`.
