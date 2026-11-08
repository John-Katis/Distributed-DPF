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
  ht-aes/            ours: dealer-free half-tree DPF, local top phase of ν ≥ 1
                     levels, level-independent lower levels (M_ℓ),
                     F_PRF = AES-MMO under public keys in 2PC, every AND
                     of the F4-tower S-box from COTs (the OT tower);
                     semi-honest, and malicious with abort on the same Gen
                     (payload MAC, one product per bottom level, glue
                     residual, Π_Verify, one-bit leakage)
  ggm-lpn/           ours on a full GGM tree with the DGH+21 LPN-PRG: local
                     top phase of ν ≥ 0 levels with two side seed words per
                     level, glue, pre-sampled bottom levels (M_ℓ), all 2PC
                     LPN-PRG calls in one batch; semi-honest, binary payload
scripts/
  bench_all.sh       runs all benchmarks into results-gen/ (Gen),
                     results-single-point/ (eval at single points) or
                     results-eval/ (full-domain eval)
  bench_template.sh  AES half-tree vs LPN-PRG GGM instance of ours at several ν,
                     with Floram and Half-Tree, into results-template/{gen,full}/
  paper_data.py      the paper's plot tables (paper-eval/6-dpf-data.tex) from
                     results-gen/, results-eval/, results-template/; Gen amortized
  estimate_{gen,eval,full}.py  rows `+est` above the last measured input width
REFERENCES.md        papers and techniques this code implements
```

| Protocol | Security | α input | Payload | Correction words via |
|---|---|---|---|---|
| `floram-cprg` | semi-honest | XOR shares | `F_2^m` | GC MUX per level; γ = acc⁰ ⊕ acc¹ ⊕ β in the circuit (Fig. 7 l.15), the accumulator and β as XOR-shared inputs |
| `half-tree` (`semi_honest`) | semi-honest | XOR shares | `F_2^m` | COT + global offset Δ (no 2PC per level) |
| `half-tree` (`malicious`) | malicious, one-bit leakage | BDOZ-authenticated bits | `GF(2^128)^bm` + SPDZ MACs | as above, plus a batch MAC check |
| `floram-arith` | semi-honest | additive shares mod 2^n (BitDec from bit triples) | `Z_2^ℓ`, ℓ ≤ 64 | COT-based block MUX per level, CCMP + arithmetic MUX for the last word |
| `fssnn` (`bin`, `arith`) | semi-honest | XOR shares | `F_2^ℓ` (`bin`) or `Z_2^ℓ` (`arith`), ℓ ≤ 256 | both trees' seeds XOR-shared, LPN-PRG (DGH+21) in 2PC per level, COT MUX; correlations from IKNP + KK13 OT |
| `ht-aes` (`sh`) | semi-honest | XOR shares | `F_p`: Babybear (the paper's) for ℓ ≤ 31, Goldilocks for ℓ ≤ 64, `2^127 − 1` above | public β; per session (`semi_honest::Session`) one public K (`F = H_K`, `F^pay = H_K(· ∥ 0)`) and one shared Δ, which is also the Ferret keys `Γ_b = Δ_b`; per Gen a public W re-randomises the roots `k_b = Δ_b ⊕ W`; 𝓕_COT in Gen: ⟨α_ℓ·Δ⟩ and ⟨Y⟩ = ⟨u_n⟩ ⊕ ⟨t_{n,0}·Δ⟩ (t_{n,0} = lsb(u_n)) from random COTs under `Γ_b = Δ_b`, one bit per COT per direction, one round; top phase: each party expands its own tree to level ν ≥ 1 (`--nu`, default max(1, min(17, n − 1))), `CW_ℓ` from frontier sums, one opening per level; glue: tag sums mod 4, the tag shared locally (no AND), one bit-times-Δ COT, open `M_ν`; lower levels on pre-sampled `u_ℓ`: all 2(n − ν + 1) AES-MMO calls in 2PC in one batch of 40 rounds (every S-box AND from Ferret COTs, the OT tower), concurrent with the top phase, then `CW_ℓ` and `M_ℓ` opened; leaf indexed by tag: `W_CW = W^(0) − W^(1) − (1 − 2σ)β` by daBits, no product; rounds max(ν + 3, 43) |
| `ht-aes` (`sh-bin`) | semi-honest | XOR shares | `F_2^ℓ`, ℓ ≤ 128 | as `sh` with XOR-shared β; the leaf hashes `u_n`, `u_n ⊕ Δ` (no Y: in characteristic 2 the tag order does not matter, so the AES–MMO calls do not wait for 𝓕_COT) and opens `W_0 ⊕ W_1 ⊕ β` (no B2A, no sign); rounds max(ν + 3, 42) |
| `ht-aes` (`mal`) | malicious with abort, one-bit selective-failure leakage (the paper's §malicious, ported to characteristic 2) | XOR shares | `{0,1}^ℓ ⊂ GF(2^128)` + payload MAC | the `sh-bin` Gen in its session (one K, one ⟨Δ⟩, W per Gen, `--nu`) with public β and the paper's additions: (A) a public `K^mac` and the payload-MAC word `W^MAC_CW = h̃_0 ⊕ h̃_1 ⊕ β·δ` under a persistent δ, (B) `(⟨α_ℓ·Δ⟩, ⟨P_ℓ⟩)` from one bit-times-2-block product per bottom level (no zeroing); no glue residual (C), since a swap does not change `y_0 ⊕ y_1` (tested); the Π_Verify mask `(r, δr)` from 128 string triples; Π_Verify on shared outputs (opens only `z = Σχy + r` and σ), then the outputs opened and checked against their MACs (`verify_and_open`); rounds max(ν + 3, 42) |
| `ht-aes` (`mal-arith`) | malicious with abort, as `mal` | XOR shares | Babybear + MAC in `F_{q^4}` (the paper's) for ℓ ≤ 31; payload and MAC in Goldilocks for ℓ ≤ 64, in `2^127 − 1` above | the `sh` Gen in its session (`--nu`) with public β and the paper's additions: (A) public `K^mac_1, …, K^mac_c` (c = 3 for `F_{q^4}`), `F^mac` on `u_n`, `u_n ⊕ Δ` (indexed by server), `W^MAC_CW = 𝓕_mul(1 − 2σ, W̃_0 − W̃_1 − β·δ)` (one Beaver triple, three rounds with the payload word); (B) one product per bottom level; (C) the glue residual ω = (G_0 − G_1) − v² + v'² with ψ_r quadratic, `r` coin-tossed after 256 B2As, two Beaver squares, kept with the key (three rounds on the top phase's lane); default ν = max(1, min(15, n − 1)), since ψ_r runs on all 2^ν frontier nodes; Π_Verify over the MAC field also checks Σχ'ω; rounds max(ν + 6, 44) |
| `ggm-lpn` (`bin`) | semi-honest | XOR shares | `F_2^ℓ`, ℓ ≤ 256 | our template on BGI's GGM tree (node `s ∥ t`, λ = 127) with the DGH+21 LPN-PRG (`fssnn::sec_prg`, correlations from Ferret); every level ℓ has a secret offset `V_ℓ = seed(U_ℓ) ∥ 1` and two side seed words `s^L = D_L ⊕ ¬α_ℓ·U_ℓ`, `s^R = D_R ⊕ α_ℓ·U_ℓ` plus BGI's tag words, so the Keep children differ by `V_ℓ`; α, `U_ℓ`, `α_ℓ·U_ℓ`, `u_{ℓ−1,0}`, `t_{ℓ−1,0}·α_ℓ` and each level's MUX triple from one bit-times-3-block triple per level (one random COT per direction); top phase: each party expands its own tree to level ν ≥ 0 (`--nu`, default min(1, n)), one opening per level; glue: tag sums mod 4, the tag shared locally (no AND), `⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ ¬⟨t_{ν,0}⟩·⟨V_ν⟩`, open `M_ν`; bottom: all 2(n − ν) 2PC LPN-PRG calls on pre-sampled `u_{ℓ−1,0}`, `u_{ℓ−1,0} ⊕ V_{ℓ−1}` in one batch (2 rounds), then the side words with one MUX block (`st^Keep_0`), then `M_ℓ`; leaf `W_CW = Conv(V_n) ⊕ β`; rounds max(ν + 2, 4). The side words below ν follow the research note "Our Framework Applied to FssNN"; those above ν are our extension, with key privacy from a hybrid over the levels (plain PRG; paper, "Instance with an Alternating-Moduli PRF") |
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
| `mac`     | authenticated sharing: `binary` (BDOZ bits + SPDZ over GF(2^128)) with a deferred batch MAC check |
| `arith`   | Z_2^ℓ helpers and SIRNN's COT-based arithmetic MUX |
| `bool2pc` | F_AND / F_OR on XOR-shared bits from CrypTFlow2 bit triples, COT-based block MUX |
| `bench`   | shared CLI and CSV schema for every `examples/bench*.rs` |
| `stream`  | batched depth-first tree walk for the streaming tree mode (`TreeMode`) |
| `gc`      | half-gates garbled circuits over XOR-shared inputs (`GcParty`, `Garbler`, `Evaluator`) |
| `f4`      | the field F4 (`h·ω + l` as two bits) |
| `aes_tower` | AES–MMO in the clear and in 2PC: S-box in the F4 tower with the 7-AND Boyar–Peralta inversion in F16 (34 ANDs, depth 4; 160 S-boxes / 40 rounds per call), every AND from COTs under one offset (`OtTower`: 19 COTs and 87 bits per S-box), public keys (`SharedKey::public`) or XOR-shared keys with Π_KeyExp on shares (`SharedKey`, 40 S-boxes, no extra rounds) |
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

## Paper results: what produces each section

Run from the repository root, one command at a time. Each runner creates
its output folder if it is missing (all of them are git-ignored). The
`bench_*` scripts write one CSV per protocol (and per ν in
`results-template/`), named after the protocol, e.g.
`results-single-point/ht-aes-sh.csv`. Rows ending in `+est` are estimated
(see [Streaming tree mode](#streaming-tree-mode---stream)).

| paper section | command | output |
|---|---|---|
| §6a DPF: Gen (Fig. eval-gen, Gen columns of Tab. eval-comm-rounds) | `scripts/bench_all.sh` | `results-gen/<protocol>.csv` |
| §6a DPF: full-domain Eval (Fig. eval-full, Eval columns of Tab. eval-comm-rounds) | `scripts/bench_all.sh full` | `results-eval/<protocol>.csv` |
| §6a/§6d: evaluation at single points | `scripts/bench_all.sh eval` | `results-single-point/<protocol>.csv` |
| §6b PRF microbenchmarks, Tab. prf-local | `cargo run --release -p exp-prf-bench --example bench-prf -- local` | `results-prf/local.csv` |
| §6b PRF microbenchmarks, Tab. prf-2pc | `cargo run --release -p exp-prf-bench --example bench-prf -- 2pc` | `results-prf/2pc.csv` |
| §6b/§6a: cost of one Ferret COT (the 22.2 ns charged when amortizing) | `cargo run --release -p exp-prf-bench --example bench-prf -- ferret` | `results-prf/ferret.csv` |
| §6c our template (AES vs LPN-PRG), Gen (Fig. eval-template) | `scripts/bench_template.sh` | `results-template/gen/<protocol>[-nuν].csv` |
| §6c our template, full-domain Eval (Fig. eval-template) | `scripts/bench_template.sh full` | `results-template/full/<protocol>[-nuν].csv` |
| plot data of §6a and §6c | `python3 -I scripts/paper_data.py` (after the sweeps above) | rewrites the tables in `paper-eval/6-dpf-data.tex`; prints crossovers and keys per Ferret pool |
| §6d Applications (Tab. eval-apps) | none of its own: extrapolated by hand from the rates above | per joint level from `results-gen/`, per node from `results-prf/local.csv` (checked against `results-single-point/`), per point from `results-eval/` |

Tab. eval-comm-rounds reports the n = 32, ℓ = 64 rows of `results-gen/` and
`results-eval/` at full cost, setup included. The Gen graphs are amortized by
`paper_data.py`.

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
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant mal-arith --in-bits 16 --out-bits 31
cargo run --release -p ht-aes --example bench-ht-aes -- gen --variant sh --in-bits 32 --out-bits 31 --nu 16   # glue level ν ≥ 1 (every variant)
cargo run --release -p ggm-lpn --example bench-ggm-lpn -- all --variant bin --in-bits 16 --out-bits 64 --nu 5   # glue level ν ≥ 0
scripts/bench_template.sh                     # ours with AES (ht-aes sh-bin) and with the LPN-PRG (ggm-lpn), ν ∈ {1, 5, 17}, Floram and Half-Tree (measured to 29, estimated above), Gen n = 8..42, 10 reps, into results-template/gen/
scripts/bench_template.sh full                # full-domain eval, n = 8..32 (ours at ν = 5; measured to 28–29, estimated above), into results-template/full/
scripts/bench_all.sh                          # Gen, n = 12..42 (FssNN and ours measured throughout, the others to 26–29 and estimated above), out-bits 64 and 128, 10 reps, one CSV per protocol in results-gen/
scripts/bench_all.sh eval                     # evaluation at single points, n = 8..42 (FssNN and ours measured throughout, the others to 28–29 and estimated above), into results-single-point/
scripts/bench_all.sh full                     # full-domain eval, n = 8..32 (measured to 27–29, estimated above), into results-eval/
cargo run --release -p exp-prf-bench --example bench-prf -- local   # PRF microbenchmarks (also 2pc, ferret, all), each mode also into results-prf/<mode>.csv
python3 -I scripts/paper_data.py              # rewrite the plot tables of paper-eval/6-dpf-data.tex (Gen amortized, see below); prints crossovers and keys per Ferret pool
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
| `comp_ms` | wall time from the start to the end of the operation, mean over `--reps` (Gen: slower party, setup included) |
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

**Full and amortized cost.** The CSVs, and the tables of the paper, hold the
full cost of one key pair: `comp_ms`, `comm_total`, `rounds` and the totals
include the setup. The paper's Gen graphs (`scripts/paper_data.py`, for
results-gen/ and results-template/) show the cost amortized over the keys of a
session, which is what every further key pair costs:

* the setup is removed from every protocol: `setup_ms` from the computation,
  `setup_bytes` from the traffic, and its rounds (`rounds − pre_rounds −
  gen_rounds`);
* every COT a key pair draws from a Ferret pool (`cots`, without the base COTs
  of Ferret's bootstrap, which FssNN's count includes) is charged at Ferret's
  marginal rate, 0.443 bits (YWLZW20) and 22.2 ns (our Ferret), the price of
  the next Ferret iteration once the pool runs dry. IKNP extension (Floram,
  Half-Tree, Duoram-2P, Xing et al.) runs in preprocessing and stays as
  measured;
* for the protocols on Ferret, the computation is preprocessing plus Gen
  (`pre_ms` + the slower `gen_ms_p*`): `comp_ms` also holds ~59 ms, constant
  in n, outside those timers, at least ~33 ms of it the teardown of the COT
  pool, which a further key does not pay;
* LAN and WAN totals are recomputed from the result with the network model
  above.

Why this is the fair comparison: setup is paid once per session for any
number of keys. The base OTs of IKNP extend to arbitrarily many OTs, and one
Ferret B13 setup (≈ 0.8 s, 3 MB, 16 rounds) leaves 1.0·10⁷ COTs per direction,
enough for about 110 (n = 42) to 1,600 (n = 12) key pairs of ours in
results-gen/, 78 to 5,500 of the two template instances in results-template/
(fewer at larger n and smaller ν), 150 to 510 of FssNN and 34,000 to 37,000
of Zhang et al. (the script prints these ranges, assuming the COTs of a key
pair split evenly between the two directions); after that, every further
COT costs exactly the rate charged above. These protocols exist for
efficiency at scale, and a deployment that generates keys at all generates
many (e.g. the (ct)² DPFs of one PCG seed). Charging one key pair the whole
setup would rank protocols by the size of their one-time setup (3 MB of
Ferret against 22–44 KB of base OTs for Floram and Half-Tree) instead of by
the cost of their keys, by an amount that vanishes after the first keys of a
session. The same rule applies to every protocol; Duoram-3P has no setup.

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
| ht-aes (`sh`) | setup (once per session): ⟨Δ⟩ with `Γ_b = Δ_b` and the public K (one exchange); per Gen the paper's ⟨α⟩, the public W (one exchange), ⟨u_ν⟩, …, ⟨u_n⟩, and n + 2 random Ferret COTs per direction under `Γ_b = Δ_b` for 𝓕_COT (⟨α_ℓ·Δ⟩, ⟨t_{n,0}·Δ⟩ and the glue's product; derandomised in Gen); the OT tower's random Ferret COTs (2(n − ν + 1)·3,040), n − ν bit-times-block triples from Ferret random OTs (Step C), 2κ + 1 daBits over F_p from COT OLEs (κ = ⌈log p⌉ + 40, at most 128) |
| ht-aes (`mal`) | as `sh-bin` (one K, one Δ per session, plus `K^mac`), but 𝓕_COT only for the ν top levels and the glue, n − ν bit-times-2-block triples for (B) instead of Step C's, the OT tower's COTs for 2(n − ν) + 4 calls, 128 bit-times-block triples (the Π_Verify mask `(r, δr)` computed here, one round) |
| ht-aes (`sh-bin`) | as `sh` without the leaf's daBits and without ⟨t_{n,0}·Δ⟩ |
| ht-aes (`mal-arith`) | as `mal` with ⟨t_{n,0}·Δ⟩ and c = ⌈E-degree·κ/128⌉ keys `K^mac_j`, the OT tower's COTs for 2(n − ν) + 2 + 2c calls (c = 3 for `F_{q^4}`), 2(1 + E-degree)κ + 1 + 256 daBits over F and four Beaver triples over the MAC field (the MAC word's sign, the glue residual's two squares, the Π_Verify mask) from COT OLEs |

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

The sweep scripts (`scripts/bench_all.sh`, `scripts/bench_template.sh`) do not use
streaming. Every protocol runs with its stored tree up to the largest input
width that fits in memory and is estimated above it (rows `<variant>+est`,
reps 0). The cut-offs come from peak RSS at ℓ = 128, which doubles per input
bit, kept below ~18 GB of the 27 GB free:

| protocol | Gen measured to | single-point eval measured to | full-domain eval measured to |
|---|---|---|---|
| floram-cprg, half-tree (`ht`), floram-arith | 29 (17.6 GB) | 29 (17.3 GB) | 29 (17.3 GB) |
| half-tree (`mal-ferret`) | 26 (11.3 GB) | 28 | 27 (10.0 GB) |
| duoram (`2p`, `3p`) | 29 (16.5 GB) | 29 | 28 (12.0 GB) |
| fssnn (`bin`, `arith`) | 42 (path to α only) | 42 (path to α only) | 28 (12.0 GB) |
| ht-aes (`sh`, `sh-bin`) | 42 (path to α only) | 42 (path to α only) | 28 (16.0 GB) |
| ht-aes (`mal`, `mal-arith`) | 42 (path to α only) | 42 (path to α only) | 27 (12.0 GB) |
| ggm-lpn (`bench_template.sh`) | 42 (path to α only) | – | 28 (12.0 GB) |

Single-point eval uses keys from the trusted dealer, which builds the whole
tree for the tree-based protocols.

`scripts/estimate_gen.py` doubles the generation time per bit, keeps the setup
and continues preprocessing, bytes, rounds and network time linearly;
`scripts/estimate_eval.py` grows the time of a single-point evaluation
linearly in n (one PRG call per level); `scripts/estimate_full.py` doubles the
time per bit at a constant ns per point. All three replace the `+est` rows of
an earlier run. Streaming would instead measure these widths at about
2× the Gen PRG work of the stored tree the papers describe.

The stored code paths are unchanged and remain the default. In code, the
`*_mode` entry points take a `dpf_common::stream::TreeMode`, and keys have an
`eval_full_stream` next to `eval_full`.
