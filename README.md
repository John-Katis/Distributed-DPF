# Distributed DPF protocols

This repository holds the code of the paper. It contains our dealer-free DPF key generation, a template with a half-tree instance (AES–MMO) and a GGM instance (LPN-PRG), in semi-honest and malicious variants. It also contains every dealer-free baseline we compare against (Floram, Half-Tree, Zhang et al., Xing et al., FssNN and Duoram), all in one Rust workspace on one shared library. The benchmark scripts regenerate every figure and table of the paper's evaluation (§6).

## Contents

1. [Setup](#1-setup)
2. [Reproducing the paper's results](#2-reproducing-the-papers-results)
   - [Step 1: run the benchmarks](#step-1-run-the-benchmarks)
   - [Step 2: build the figure and the tables](#step-2-build-the-figure-and-the-tables)
   - [Measured and extrapolated rows](#measured-and-extrapolated-rows)
   - [Network model and CSV columns](#network-model-and-csv-columns)
3. [Full and amortized cost](#3-full-and-amortized-cost)
4. [Repository structure](#4-repository-structure)
5. [Third-party libraries](#5-third-party-libraries)

## 1. Setup

**Tested on** Ubuntu 22.04 (Linux 6.8) with g++ 11.4, cmake 3.22, OpenSSL 3.0.2 and Rust 1.87, on an Intel Core i7-12700K with 32 GB of RAM. The first build needs network access.

Install the system packages and Rust. `rust-toolchain.toml` pins Rust 1.87.0, and rustup fetches it on the first `cargo` call.

```sh
sudo apt update
sudo apt install -y git cmake g++ make python3 libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Clone the repository and build everything:

```sh
git clone https://github.com/John-Katis/Distributed-DPF.git   # not --recursive: build.sh fetches only what is needed
cd Distributed-DPF
./build.sh            # ./build.sh --test also runs the test suite
```

`build.sh` does the following, and every step can be rerun safely:

1. It checks the prerequisites: git, cmake ≥ 3.20, g++ ≥ 11 with OpenMP, python3, the OpenSSL headers and cargo.
2. It fetches the four C++ libraries as git submodules in `third_party/`, pinned to fixed revisions (see [§5](#5-third-party-libraries)). Of EzPC it checks out only `SCI/src`, without EzPC's own submodules.
3. It applies the two patches in `crates/ot-sys/patches/` to emp-tool and emp-ot.
4. It builds libOTe with only the Masny–Rindal base OT. libOTe's cmake also clones four small dependencies of its own: coproto, macoro, function2 and libdivide.
5. It runs `cargo build --workspace --release`. `crates/ot-sys/build.rs` compiles the emp and SCI code.

While libOTe builds, errors from its own test files (`libOTe_Tests`, e.g. `'macoro' does not name a type`) are expected with g++ 11. Only the library is needed: `build.sh` builds that target separately and checks that its static libraries exist.

A quick check that the build works runs one Gen and Eval of our semi-honest protocol on a domain of 2^16 points:

```sh
cargo run --release -p ht-aes --example bench-ht-aes -- all --variant sh-bin --in-bits 16 --out-bits 64
```

## 2. Reproducing the paper's results

| Paper | Data | Command that writes it |
|---|---|---|
| Fig. eval-gen (Gen, LAN and WAN) and its dotted crossover lines | `results-gen/`, `results-template/gen/ggm-lpn-*-nu2.csv` | `python3 -I scripts/paper_data.py` |
| Tab. eval-comm-rounds (Gen communication and rounds, Eval per point) | as above, and `results-eval/`, `results-template/full/` | `python3 -I scripts/paper_tables.py comm` |
| Tab. eval-apps and the numbers in the text of §6b (when the half-tree instance repays its slower Gen) | as above, and `results-single-point/` | `python3 -I scripts/paper_tables.py apps` |
| §6a, "Methodology": 14.3 ns and 660 ns per node | `results-single-point/` | `python3 -I scripts/paper_tables.py apps` (first line) |
| §6, "Setup": the Ferret session setup (0.8–0.9 s, 3 MB) and the key pairs per COT pool | `setup_ms`, `setup_bytes` in `results-gen/` | `python3 -I scripts/paper_data.py` (last lines) |
| 22.2 ns per Ferret COT (charged in Tab. eval-apps) | `results-prf/ferret.csv` | `cargo run --release -p exp-prf-bench --example bench-prf -- ferret` |

All result directories are git-ignored and created by the scripts. Run every command from the repository root, one at a time, on an otherwise idle machine.

### Step 1: run the benchmarks

```sh
scripts/bench_all.sh            # Gen, n = 12..42           -> results-gen/<protocol>.csv
scripts/bench_all.sh full       # full-domain Eval, n = 8..32 -> results-eval/<protocol>.csv
scripts/bench_all.sh eval       # Eval at single points     -> results-single-point/<protocol>.csv
NU_LIST=2 ONLY="ggm-lpn-bin-nu2 ggm-lpn-arith-nu2" scripts/bench_template.sh gen     # our GGM instance, Gen at ν = 2
ONLY="ggm-lpn-bin-nu5 ggm-lpn-arith-nu5" scripts/bench_template.sh full              # our GGM instance, full-domain Eval
cargo run --release -p exp-prf-bench --example bench-prf -- ferret                    # cost of one Ferret COT
```

- `bench_all.sh` runs every protocol except our GGM instance: Floram, Half-Tree, Zhang et al., Xing et al., FssNN (`bin`, `arith`), Duoram-2P and our four half-tree variants. It writes one CSV per protocol.
- `bench_template.sh` runs our GGM instance (`protocols/ggm-lpn`). The paper uses ν = 2 for its Gen. Its full-domain Eval runs at the script's default ν = 5, since ν changes Eval by only one shift per level.
- Every point of a sweep runs 10 repetitions and reports their mean. Each point is its own process, so a crash (e.g. out of memory) is logged as `# failed:` in the CSV and the sweep moves on to the next protocol.
- `ONLY="name …"` reruns only the named CSVs. This resumes an interrupted sweep.
- The paper reports ℓ = 64 only. The scripts also sweep ℓ = 128. `OUT_LIST=64` in front of each command halves the run time and still gives every number of §6.

### Step 2: build the figure and the tables

```sh
python3 -I scripts/paper_data.py      # plot data of Fig. eval-gen; prints the crossovers and key pairs per Ferret pool
python3 -I scripts/paper_tables.py    # prints Tab. eval-comm-rounds and Tab. eval-apps
```

`paper_data.py` writes the pgfplots tables to `paper-eval/6-dpf-data.tex`, or to the file given as its argument. If the file exists, the script replaces only its `\pgfplotstableread` blocks. A missing CSV only drops its tables, with a warning. The figure plots `\T<Fl,HT,HTm,FA,Dtwo>{A,XA}` for the baselines (`X`: extrapolated) and `\TV<variant>A` for FssNN and ours.

`paper_tables.py` prints both tables as text. The applications are not run but extrapolated from the CSVs, following the "Method" paragraph of §6b. The script's docstring lists every rule: COT charges, interpolation in n, batched WAN rounds, the DCF charge and the Eval rates.

### Measured and extrapolated rows

Every protocol stores its tree as its paper and reference code describe, so the baselines run out of memory around n = 27–29. Each protocol is therefore measured up to the largest input width that keeps peak RSS below about 18 GB at ℓ = 128. Above that width, the scripts write estimated rows (variant `<variant>+est`, reps 0):

| Protocol | Gen measured to | Single-point Eval measured to | Full-domain Eval measured to |
|---|---|---|---|
| floram, half-tree (`ht`), floram-arith | 29 | 29 | 29 |
| half-tree (`mal-ferret`, Zhang et al.) | 26 | 28 | 27 |
| duoram-2p | 29 | 29 | 28 |
| fssnn, ht-aes `sh`/`sh-bin`, ggm-lpn | 42 (path to α only) | 42 | 28 |
| ht-aes `mal`/`mal-arith` | 42 (path to α only) | 42 | 27 |

The estimates come from three scripts, which the sweep scripts call:

- `scripts/estimate_gen.py` doubles the generation time per bit, keeps the setup constant and continues preprocessing, bytes, rounds and network time linearly.
- `scripts/estimate_eval.py` grows a single-point evaluation linearly in n.
- `scripts/estimate_full.py` keeps the time per point constant.

On a machine with less memory, lower the caps in the `run` lines of `scripts/bench_all.sh` and `scripts/bench_template.sh`. Everything above the caps is then estimated.

### Network model and CSV columns

Nothing is delayed for real. Network time is added analytically from the counted bytes and rounds: `rounds · latency + 8 · bytes / bandwidth`.

- The paper uses a LAN with 1 Gbit/s and 0.5 ms per round, and a WAN with 100 Mbit/s and 100 ms per round. Both are set in `scripts/paper_data.py`, and `paper_data.py` and `paper_tables.py` recompute every total from them.
- The `lan_*` columns of the CSVs use the bench default of 10 ms (`--lan ms,mbps`) and are not read.
- A round is one one-way latency. A simultaneous exchange counts once.
- Computation is the wall time of the slower party. All parties run in one process, each on its own thread.

All benchmarks print the same CSV schema (`dpf_common::bench::HEADER`):

| Column | Meaning |
|---|---|
| `mode`, `variant`, `in_bits`, `out_bits`, `reps` | `gen`, `eval` (single points) or `full`; `+est` marks an estimate |
| `comm_p0`, `comm_p1`, `comm_total`, `rounds` | bytes sent per party and in total, and rounds; all include the setup |
| `comp_ms` | wall time of the whole operation, mean over the reps |
| `setup_ms`, `setup_bytes` | once per session: base OTs, keys, Ferret bootstrap |
| `pre_ms`, `pre_bytes`, `pre_rounds` | preprocessing: the input-independent correlations Gen consumes |
| `gen_ms_p0`, `gen_ms_p1`, `gen_bytes`, `gen_rounds` | generation proper, given those correlations |
| `cots` | COTs the key pair consumes |
| `ns_per_eval`, `ns_per_point` | Eval at single points, and full-domain Eval per point |

## 3. Full and amortized cost

The CSVs hold the **full cost** of one key pair: `comp_ms`, `comm_total` and `rounds` include the one-time session setup. Ferret's setup alone takes 0.8–0.9 s, 3 MB and 16 rounds.

The paper's figure and tables report the **cost of a further key pair** in a session, which is preprocessing plus generation. `paper_data.gen_cost` applies the same rules to every protocol:

- It removes the setup: `setup_ms` from the time, `setup_bytes` from the traffic, and the setup rounds (`rounds − pre_rounds − gen_rounds`).
- It does not charge the COTs a key pair draws from the pool of Ferret's setup. One pool of 10⁷ COTs per direction covers at least 110 of our key pairs; `paper_data.py` prints the range per protocol. IKNP extension (Floram, Half-Tree, Duoram-2P, Xing et al.) runs in preprocessing and stays as measured.
- For the protocols on Ferret, the time is `pre_ms + max(gen_ms_p0, gen_ms_p1)`. `comp_ms` also holds about 59 ms per session outside these timers, at least 33 ms of it the teardown of the COT pool, which a further key does not pay.

Tab. eval-apps covers applications with up to millions of keys, which exhaust a pool. It therefore also charges every Ferret COT at Ferret's marginal rate: 0.443 bits (Yang et al., CCS'20) and 22.2 ns (our Ferret, `exp-prf-bench ferret`). It charges every IKNP COT at κ = 128 bits.

This is the fair comparison because the setup is paid once per session, for any number of keys. Charging it to one key pair would rank the protocols by their one-time setup (3 MB of Ferret against 22–44 KB of base OTs for Floram and Half-Tree) instead of by the cost of their keys.

<details>
<summary>What each protocol makes in preprocessing</summary>

Where a protocol's paper or reference code makes the correlations ahead of Gen, the bench makes them in preprocessing, before α and β are used. Gen sometimes needs a COT or OT on a secret choice bit (a bit of α, a MUX selector). Preprocessing then makes it with a random choice, and Gen derandomises it with one bit in one round.

| Protocol | Preprocessing |
|---|---|
| floram-cprg | none: as in Obliv-C, Gen runs chosen-input IKNP for the evaluator's labels at each level |
| half-tree (`ht`) | n random COTs per direction (GYW+23, Fig. 11) |
| half-tree (`mal-ferret`) | n + 128·(bm + 1) random F_aBit COTs per direction for α, β and ⟨r⟩ (Ferret) |
| floram-arith | none: as in the reference code, each AND makes its triples (KK13) and each MUX its COTs (IKNP) when called |
| fssnn | PRG correlations for 2n (+2) calls, 2n bit triples, 3n (+2ℓ+1 for `arith`) Ferret COTs per direction |
| duoram (`2p`) | n AND triples from COTs, n + 2·w random COTs for the Gilboa products |
| ht-aes (`sh`, `sh-bin`) | ⟨α⟩, the public W, the middle AES states of the on-path pairs, ⟨r_ν⟩, …, ⟨r_n⟩, and Ferret COTs under `Γ_b = Δ_b`; the OT tower's random COTs (2(n − ν + 1)·3,040), n − ν + 1 AND triples; for `sh` also 2κ + 1 daBits and one Beaver triple over F_p for the leaf |
| ht-aes (`mal`, `mal-arith`) | as `sh-bin` / `sh`, with the OT tower's COTs for 2(τ − 1) more pairs, the triples of Π_Verify's masks, and for `mal-arith` the daBits and triples of the glue residual over 2^127 − 1 |
| ggm-lpn | one bit-times-3-block triple per level (one random COT per direction), the LPN-PRG correlations of the bottom levels (Ferret) |

Duoram's generation proper is its own preprocessing (the DPF at a random target) plus the one-round online phase.

</details>

## 4. Repository structure

```
build.sh                 fetches and patches the libraries, builds everything (§1)
crates/
  common/                dpf-common: the shared library (PRG, hashes, network, OTs, 2PC AES, MACs, bench CLI)
  ot-sys/                C++ bindings to emp-ot/emp-tool, libOTe and SCI, and the patches to emp
protocols/               one crate per protocol, each with tests/ and examples/bench.rs
  ht-aes/                ours, half-tree instance: semi-honest (sh, sh-bin) and malicious (mal, mal-arith)
  ggm-lpn/               ours, GGM instance with the LPN-PRG: semi-honest (bin, arith)
  floram-cprg/           Floram (Doerner–shelat, CCS'17)
  half-tree/             Half-Tree (Guo et al., EC'23), and its malicious variant (Zhang et al., S&P'24)
  floram-arith/          Xing et al. (NDSS'25)
  fssnn/                 FssNN (Yang et al., ProvSec'24, Alg. 5), with the DGH+21 LPN-PRG in 2PC
  duoram/                the DPF part of Duoram (Vadapalli et al., USENIX Sec'23), 2P and 3P
experimental_code/
  prf-bench/             the Ferret COT rate (and PRF microbenchmarks of an earlier version of the paper)
  bp-sbox/               Boyar–Peralta S-box on the OT tower, a dependency of prf-bench
scripts/                 sweeps (bench_*.sh), estimates above the caps (estimate_*.py), paper data (paper_*.py)
third_party/             the four libraries as pinned git submodules
```

| Crate | Bench example | `--variant` | Security | Payload |
|---|---|---|---|---|
| `ht-aes` | `bench-ht-aes` | `sh-bin`, `sh`, `mal`, `mal-arith` | semi-honest / malicious with abort | F_2^ℓ, or F_p (Goldilocks for ℓ ≤ 64) |
| `ggm-lpn` | `bench-ggm-lpn` | `bin`, `arith` (`--nu`) | semi-honest | F_2^ℓ, or F_p |
| `floram-cprg` | `bench` | – | semi-honest | F_2^ℓ |
| `half-tree` | `bench-half-tree` | `ht`, `mal-ferret` | semi-honest / malicious (one-bit leakage) | F_2^ℓ |
| `floram-arith` | `bench-floram-arith` | – | semi-honest | Z_2^ℓ |
| `fssnn` | `bench-fssnn` | `bin`, `arith` | semi-honest | F_2^ℓ or Z_2^ℓ |
| `duoram` | `bench-duoram` | `2p`, `3p` | semi-honest | Z_2^ℓ |

Every bench takes `gen|eval|full|all --in-bits n --out-bits ℓ --reps R`, e.g. `cargo run --release -p half-tree --example bench-half-tree -- gen --variant ht --in-bits 20 --out-bits 64`. For `ht-aes`, `--nu` sets the glue level; the default is min(17, n − 1), and 15 for `mal-arith`. `cargo test --workspace --release` checks every protocol against the cleartext point function.

## 5. Third-party libraries

All OTs and COTs come from libraries, so their correctness does not rest on our code. The bindings are in `crates/ot-sys`.

| Library (pinned revision) | What we use | Used by |
|---|---|---|
| [emp-ot](https://github.com/emp-toolkit/emp-ot) 0.3.0 | Ferret COT (silent OT), with its SPCOT consistency check in the malicious variants | ours, FssNN, Zhang et al. |
| | IKNP OT extension (with its KOS-style check in malicious mode), Naor–Pinkas base OT | Floram, Half-Tree, Duoram-2P, Xing et al.; the bootstrap of Ferret |
| [emp-tool](https://github.com/emp-toolkit/emp-tool) 0.3.0 | half-gates garbling of AND gates | Floram's garbled circuit per level |
| [libOTe](https://github.com/osu-crypto/libOTe) 5d419c34 | Masny–Rindal base OT | the malicious variants (Zhang et al., ours): base OTs of the KOS-checked IKNP that bootstraps Ferret |
| [SCI / EzPC](https://github.com/mpc-msri/EzPC) f24bf3e | KK13 1-of-N OT, CrypTFlow2 bit triples, SiRNN multiplexer | Xing et al. |

The two patches (`crates/ot-sys/patches/`) make a failed check abort. In emp-tool, `error()` throws instead of calling `exit(1)`, so the Rust side can report an `Abort`. In emp-ot, the malicious Ferret calls `error()` when the SPCOT consistency check fails, where upstream only prints a message and carries on. libOTe and SCI are unpatched. SCI's socket I/O is replaced by the headers in `crates/ot-sys/cpp/sci_override/`, which run it over our in-process channel.

The protocol-specific 2PC parts have no library and are ours, following each protocol's paper:

- the OT tower for 2PC AES–MMO (`dpf_common::aes_tower`);
- Gilboa products, the block MUX and Du–Atallah products;
- the MAC layer of Zhang et al.;
- the LPN-PRG of DGH+21 in 2PC.
