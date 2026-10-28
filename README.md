# Distributed DPF protocols

A Cargo workspace of distributed point function (DPF) protocols, two-party
except for Duoram's 3P variant with a helper.
Each protocol is its own crate, and all of them build on one shared library.

```
crates/
  common/            dpf-common: the shared library
  ot-sys/            bindings to emp-ot/emp-tool (Naor–Pinkas, IKNP/KOS,
                     Ferret, half-gates), libOTe (Masny–Rindal) and SCI
                     (KK13, CrypTFlow2 triples, SiRNN MUX), used by
                     dpf_common::{ot, gc, bool2pc, arith}
protocols/
  floram-cprg/       Floram-CPRG distributed DPF (Doerner–shelat, CCS'17)
  half-tree/         Half-Tree distributed DPF (Guo et al., EC'23), semi-honest,
                     and its actively secure variant with one-bit leakage
                     (Zhang et al., S&P'24)
  floram-arith/      dealer-less DPF with arithmetic input/output
                     (Xing et al., NDSS'25) on the Floram tree
  fssnn/             FssNN's distributed key generation (Yang et al.,
                     ProvSec'24, Alg. 5) for a Z2 DPF, with the DGH+21
                     LPN-PRG evaluated in 2PC
  duoram/            the DPF part of Duoram (Vadapalli et al., USENIX Sec'23):
                     preprocessing at a random target, online shift; 2P and 3P
  ht-aes/            ours: dealer-free half-tree DPF with shared on-path state,
                     F_PRF = fixed-key AES-MMO in 2PC over the F4 tower;
                     semi-honest (FOLEAGE triples), malicious on the same
                     preprocessing (payload MAC, Π_Verify), and malicious with
                     every share authenticated (A1–A5, bucketed triples)
scripts/
  bench_all.sh       runs all benchmarks into results-gen/ or results-eval/
REFERENCES.md        papers and techniques this code implements
```

| Protocol | Security | α input | Payload | Correction words via |
|---|---|---|---|---|
| `floram-cprg` | semi-honest | XOR shares | `F_2^m` | GC MUX per level |
| `half-tree` (`semi_honest`) | semi-honest | XOR shares | `F_2^m` | COT + global offset Δ (no 2PC per level) |
| `half-tree` (`malicious`) | malicious, one-bit leakage | BDOZ-authenticated bits | `GF(2^128)^bm` + SPDZ MACs | as above, plus a batch MAC check |
| `floram-arith` | semi-honest | additive shares mod 2^n (BitDec from bit triples) | `Z_2^ℓ`, ℓ ≤ 64 | COT-based block MUX per level, CCMP + arithmetic MUX for the last word |
| `fssnn` (`bin`, `arith`) | semi-honest | XOR shares | `F_2^ℓ` (`bin`) or `Z_2^ℓ` (`arith`), ℓ ≤ 256 | both trees' seeds XOR-shared, LPN-PRG (DGH+21) in 2PC per level, COT MUX; correlations from IKNP + KK13 OT |
| `ht-aes` (`sh`) | semi-honest | XOR shares | `F_p` (Goldilocks for ℓ ≤ 64, `2^127 − 1` above) | shared on-path state, AES-MMO in 2PC per level (F4 tower, FOLEAGE triples), COT for α·Δ; at the leaf B2A by daBits and the sign by a daBit and one Beaver triple (the paper's leaf, three rounds) |
| `ht-aes` (`sh-bin`) | semi-honest | XOR shares | `F_2^ℓ`, ℓ ≤ 128 | as `sh`; the leaf opens `W_0 ⊕ W_1 ⊕ β` (no B2A, no sign) |
| `ht-aes` (`mal`) | malicious with abort (the paper's §malicious: key material checked by Π_Verify; selective failure as in Prop. "Selective-failure channel") | XOR shares | `{0,1}^ℓ ⊂ GF(2^128)` + payload MAC | the `sh` Gen on the same FOLEAGE/Ferret preprocessing, plus `F^mac` at the leaf, `δ·β` from ℓ string triples, the payload-MAC word under a persistent δ; Π_Verify on outputs |
| `ht-aes` (`mal-arith`) | malicious with abort, as `mal` | XOR shares | `F_p` + payload MAC in `F_p` (Goldilocks for ℓ ≤ 64, `2^127 − 1` above) | the `sh` Gen on the same preprocessing; at the leaf `F^pay`, `F^mac` and the `sh` leaf on both words, `δ·β` by one more Beaver product; Π_Verify over `F_p` |
| `ht-aes` (`mal-auth`) | malicious with abort, no leakage | authenticated bits | `{0,1}^ℓ ⊂ GF(2^128)` + payload MAC | as `mal` on SPDZ bit MACs ((A1)–(A5)), F4 triples from leaky triples + bucketing on malicious-Ferret aBits; one check of all openings, Π_Verify on outputs |
| `duoram` (`2p`, `3p`) | semi-honest | additive shares mod 2^n (online shift) | `Z_2^ℓ`, ℓ ≤ 64 | Du–Atallah product per level at a random target; triples from helper P2 (`3p`) or IKNP OT (`2p`); one-round online phase |

## Shared library: `dpf-common`

| Module | Contents |
|---|---|
| `block`   | `Block` (128-bit), bit/byte packing, domain-depth and payload-width helpers |
| `prg`     | two-key Davies–Meyer AES PRG (`left`, `right`, batched `expand_many`) |
| `hash`    | fixed-key AES hashes (with the σ orthomorphism), the keyed CCR hash `H_S` (Half-Tree, half-gates), TMMO tweakable CCR hash, AES-CTR stream |
| `net`     | in-process two- and three-party networks (`run_two_party`, `run_three_party`, `Channel`, `Peers`, `CommStats`) |
| `ot`      | base OTs over secp256r1 (Naor–Pinkas, semi-honest; Masny–Rindal endemic OT, malicious), semi-honest IKNP extension, 128-bit correlated OT (`CotPair`, sender-chosen Δ; in malicious mode endemic base OTs + KOS15 check), Ferret LPN-based COT extension (`CotPair::enable_ferret`), and KK13 1-of-N OT (`kkot`) |
| `gf128`   | GF(2^128) multiplication (`pclmulqdq` with a portable fallback) |
| `coin`    | SHA-256 commitments, coin tossing, `Abort` |
| `mac`     | authenticated sharing: `binary` (BDOZ bits + SPDZ over GF(2^128)), `z2k` (SPDZ2k), `fp` (SPDZ over F_p), all with deferred batch MAC checks; `af4`: SPDZ bit MACs for F4 circuits, leaky F4 triples (Π_LaAND over F4) with WRK17 bucketing, the hash-and-commit check of all openings, and the authenticated `TowerBackend` |
| `arith`   | Z_2^ℓ helpers and SIRNN's COT-based arithmetic MUX |
| `bool2pc` | F_AND / F_OR on XOR-shared bits from CrypTFlow2 bit triples, COT-based block MUX |
| `bench`   | shared CLI and CSV schema for every `examples/bench*.rs` |
| `stream`  | batched depth-first tree walk for the streaming tree mode (`TreeMode`) |
| `gc`      | half-gates garbled circuits over XOR-shared inputs (`GcParty`, `Garbler`, `Evaluator`) |
| `f4`      | the field F4 (`h·ω + l` as two bits), scalar and packed |
| `aes_tower` | fixed-key AES–MMO in the clear and in 2PC: S-box in the F4 tower (12 F4 products, depth 4; 1,920 products / 40 rounds per call), F4 products from a pluggable `TowerBackend`, semi-honest `BeaverF4` |
| `foleage` | the FOLEAGE F4-OLE PCG (port of the reference code): ternary random DPF, packed FFT, expansion to OLEs and F4 triples, and the dealer-free seed generation of §5 (chosen 1-of-3 OT from COTs), which the reference code leaves out |
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

The OT libraries (emp-tool, emp-ot, libOTe, EzPC/SCI) are git submodules in
`third_party/`, pinned to fixed revisions; `build.sh` checks the prerequisites
(git, cmake ≥ 3.20, g++ ≥ 11 with OpenMP, python3, OpenSSL headers, rustup),
fetches the submodules, applies `crates/ot-sys/patches/`, builds libOTe and
then the workspace. The first run needs network (libOTe's cmake also clones
four small dependencies of its own).

```
git clone https://github.com/John-Katis/Distributed-DPF.git   # not --recursive: build.sh fetches only what is needed
cd Distributed-DPF
./build.sh            # or ./build.sh --test to also run the test suite
```

- **Patches to emp** (`crates/ot-sys/patches/`, applied by `build.sh`):
  emp-tool's `error()` throws instead of calling `exit(1)`, so a failed check
  becomes an `Abort` the Rust side can report; emp-ot's malicious Ferret calls
  `error()` when the SPCOT consistency check fails, where upstream only prints
  "SPCOT consistency check fails" and carries on. libOTe and SCI are unpatched
  (SCI's socket I/O is replaced by headers in `crates/ot-sys/cpp/sci_override/`).
- **Expected compiler errors:** while building libOTe, its own test files
  (`libOTe_Tests`, e.g. `'macoro' does not name a type`) fail to compile with
  g++ 11. Only the library is needed; `build.sh` builds that target separately
  and checks that the static libraries exist.
- **Tested on** Ubuntu 22.04 (g++ 11.4, cmake 3.22, OpenSSL 3.0.2, Rust 1.87
  from `rust-toolchain.toml`), from a fresh clone with an empty cargo cache.
- `experimental_code/ot-libs` has its own `fetch.sh` and `deps/` (other
  library versions, e.g. libOTe with KKRT); `build.sh` does not cover it.

```
cargo test --workspace --release                 # everything
cargo test -p floram-cprg --release              # one protocol
cargo run --release -p floram-cprg --example bench -- all --in-bits 16 --out-bits 128
cargo run --release -p half-tree --example bench-half-tree -- all --variant ht --in-bits 16 --out-bits 128
cargo run --release -p half-tree --example bench-half-tree -- all --variant mal-ferret --in-bits 16 --out-bits 128
cargo run --release -p floram-arith --example bench-floram-arith -- all --in-bits 16 --out-bits 128
cargo run --release -p fssnn --example bench-fssnn -- all --variant bin --in-bits 16 --out-bits 64
cargo run --release -p fssnn --example bench-fssnn -- all --variant arith --in-bits 16 --out-bits 64
cargo run --release -p duoram --example bench-duoram -- all --variant 2p --in-bits 16 --out-bits 64
cargo run --release -p duoram --example bench-duoram -- all --variant 3p --in-bits 16 --out-bits 128
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant sh --in-bits 16 --out-bits 64
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant sh-bin --in-bits 16 --out-bits 64
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant mal --in-bits 16 --out-bits 64
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant mal-arith --in-bits 16 --out-bits 64
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant mal-auth --in-bits 16 --out-bits 64
scripts/bench_all.sh                          # Gen, n = 8..32, out-bits 64 and 128, one CSV per protocol in results-gen/
scripts/bench_all.sh full                     # full-domain eval, same sweep, into results-eval/
```

All benchmarks print the same CSV schema (`dpf_common::bench::HEADER`); the
first two columns are `mode,variant`. `--out-bits` sets the payload width for
every protocol, with each one's own group: `F_2^m` (any m) for floram-cprg
and half-tree (default 128), `Z_2^ℓ` with ℓ ≤ 128 for floram-arith and duoram
(default 64), and for fssnn `F_2^ℓ` (`bin`) or `Z_2^ℓ` (`arith`) with ℓ ≤ 256
(default 64; `bin` with ℓ = 1 is FssNN's own `Z_2`). floram-arith and duoram
compute and send Z_2^ℓ in 64-bit words for ℓ ≤ 64 and in 128-bit words above,
so ℓ = 64 and ℓ = 128 each pay their own word size. From ℓ = 128 on, every
protocol takes one more PRG call per leaf for the output, because a leaf has
only 127 bits above its control bit. `scripts/bench_all.sh` sweeps every
protocol over ℓ ∈ {64, 128} (`OUT_LIST=…` overrides).

Every row reports the same metrics, for Gen and for evaluation alike:

| column | meaning |
|---|---|
| `comm_p0`, `comm_p1`, `comm_p2` | bytes each party sends (`comm_p2`: Duoram-3P's helper, else 0) |
| `comm_total` | all traffic, their sum |
| `rounds` | one-way latencies, a simultaneous exchange counting once; max over the parties = the protocol's total |
| `comp_ms` | wall time from the start to the end of the operation (Gen: slower party, setup included) |
| `lan_net_ms`, `wan_net_ms` | `rounds·latency + 8·comm_total/bandwidth` |
| `lan_total_ms`, `wan_total_ms` | `comp_ms` + that network time |

The simulated networks are LAN = 1 Gbit/s with 10 ms per round and WAN =
100 Mbit/s with 100 ms per round (`--lan ms,mbps`, `--wan ms,mbps` override
them). Nothing is delayed for real: network time is added analytically from
the counted bytes and rounds. DPF evaluation is local, so `eval` (one point)
and `full` (whole domain) rows have zero communication and rounds. The `gen`
row then breaks Gen down into three phases:

| phase | columns | what |
|---|---|---|
| setup | `setup_ms`, `setup_bytes` | base OTs, keys, Ferret bootstrap; once per session |
| preprocessing | `pre_ms`, `pre_bytes`, `pre_rounds` | the input-independent correlations Gen consumes: random COTs/OTs, bit triples, PRG correlations, Duoram-3P's dealing |
| generation | `gen_ms_p*`, `gen_bytes`, `gen_bytes_per_level`, `gen_rounds` | generation proper, given those correlations |

Where the paper (or its reference code) makes the correlations ahead of Gen,
they are made in the preprocessing phase, before α and β are used. Where Gen
needs a COT or OT on a secret choice bit (the bits of α, a MUX selector),
preprocessing makes it with a random choice and Gen derandomises it with one
bit (one round), as Ferret does:

| protocol | preprocessing |
|---|---|
| floram-cprg | none: as in Obliv-C, Gen runs chosen-input IKNP for the evaluator's labels at each level |
| half-tree (`ht`) | n random COTs per direction (GYW+23 Fig. 11) |
| half-tree (`mal-ferret`) | n + 128·(bm + 1) random F_aBit COTs per direction for α, β and ⟨r⟩ (Ferret; refills only when its buffer runs out) |
| floram-arith | none: as in the reference code, each AND makes its triples (KKOT) and each MUX its COTs (IKNP) when called |
| fssnn | PRG correlations for 2n (+2) calls, 2n bit triples, 3n (+2ℓ+1 for `arith`) Ferret COTs per direction |
| duoram (`2p`) | n AND triples from COTs, n + 2·w random COTs for the Gilboa products |
| duoram (`3p`) | P2's one message to each party (n AND triples, n + 2 product triples) |
| ht-aes (`sh`) | FOLEAGE expansion into (2n + 2)·1,920 F4 triples (local), n bit-times-block triples from Ferret random OTs, n Ferret COTs per direction, 2κ + 1 daBits and one Beaver triple over F_p from COT OLEs (κ = min(⌈log p⌉ + 40, 128)); the FOLEAGE seeds (≥ 3^12 OLEs, ~26 MB) are generated without a dealer in setup |
| ht-aes (`mal`) | as `sh`: FOLEAGE expansion into (2n + 4)·1,920 F4 triples, n + ℓ bit-times-block triples from Ferret random OTs (branch selection, δ·β), n Ferret COTs per direction; FOLEAGE seeds generated in setup |
| ht-aes (`sh-bin`) | as `sh` with n Ferret COTs per direction (the α-bits only) |
| ht-aes (`mal-arith`) | as `mal` with n string triples (branch selection), n Ferret COTs per direction, 4κ + 1 daBits and three Beaver triples over F_p (two signs, δ·β) from COT OLEs |
| ht-aes (`mal-auth`) | (2n + 4)·1,920 + 64·(2n + ℓ) authenticated F4 triples: 4× as many leaky triples from malicious-Ferret aBits, bucketed and checked; COTs for the n + ℓ + 254 input bits |

For Duoram, generation proper is its own preprocessing (the DPF at a random
target) plus the one-round online phase, which the bench also prints as a
`#` line. The synchronisation between preprocessing and generation that keeps
one party's timing from including the other's is counted in no phase.

### Streaming tree mode (`--stream`)

By default every protocol holds its tree as the papers and reference code do:
one whole level at a time, so a party needs a few × 2^n × 16 bytes and the
sweep runs out of memory around n = 27–28. With `--stream` the tree-based
protocols (floram-cprg, half-tree, floram-arith, duoram) keep only the root
and the correction words opened so far. Whenever Gen needs a level's sum, a
batched depth-first walk from the root regenerates that level, XORs it into a
running accumulator and drops it. FssNN's and ht-aes's Gen only follow α's
path, so for those two only the full-domain eval streams.

- Memory is about `batch · n` blocks (default batch 2^16, `--batch-log b`).
- Gen does about 2× the PRG work, because each level re-expands the levels
  above it. Full-domain eval streams in one pass at no extra cost and folds the
  outputs into a checksum instead of returning a 2^n vector.
- The messages, bytes and rounds are identical to the stored mode (each crate's
  `tests/stream.rs` checks this), so only the timing columns differ.
- The variant column reads `<variant>+stream`.
- `--stream-from n` keeps the stored tree below 2^n and streams from 2^n on.
  `scripts/bench_all.sh` uses it so each protocol runs stored for as long as
  it fits in memory: streaming from n = 29 (Floram, HT, Floram-arith), 27
  (HT-mal) and 30 (Duoram); FssNN always runs stored.

The stored code paths are unchanged and remain the default. In code, the
`*_mode` entry points take a `dpf_common::stream::TreeMode`, and keys have an
`eval_full_stream` next to `eval_full`.
