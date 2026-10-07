# half-tree

Distributed generation of Half-Tree DPF keys, with full-domain evaluation as a
by-product, in two security models.

## `semi_honest`: Guo et al., EC'23, §5.2 (Fig. 8, 10, 11)

The parties share a correlated GGM tree whose on-path nodes all differ by a
global offset `Δ = Δ_0 ⊕ Δ_1` (lsb 1), so a level's correction word is
`⊕_j H(X^j_0) ⊕ H(X^j_1) ⊕ ᾱ_i·Δ`. Each party computes its share locally from n
COTs keyed by `Δ_b`. No 2PC runs per level, and each level costs one block per
party.

* Setup: `Session::setup` picks `Δ_b` with `lsb(Δ_b) = b`, runs base OTs for a
  `CotPair`, and tosses one coin for the hash key `S` and the seed of the
  per-run root re-randomiser W (the F_Rand compression of §5.2).
* `Session::gen`: n + 3 flights. These are the COT columns, n−1 levels,
  `(μ, d)`, `(HCW, LCW)` and `CW_{n+1}`.
* `HtKey::eval_point`, `HtKey::eval_full` (about 1.5N hash calls).
* `deal` / `gen_reference`: trusted dealer. `deal` is the bit-exact oracle in the
  tests.

Two choices differ from the paper's presentation:
* COTs come from chosen-choice IKNP (`dpf_common::ot::CotPair`), so the masked
  choice bits `g_b` of Fig. 11 travel inside the extension message.
* `Convert` is PRG-free (the 127 seed bits) for payloads up to 127 bits, as in
  App. F.1. Wider payloads hash each leaf. For a fair comparison with the
  paper's 1.5N cost, benchmark `--out-bits 127`.

## `malicious`: Zhang et al., S&P'24, Fig. 5

* α arrives as BDOZ-authenticated bits (F_aBit = KOS-checked COT) and β as
  SPDZ-authenticated GF(2^128) elements (`dpf_common::mac::binary`).
* Every level is correlated. The leaf word is
  `⊕_j H_1(X^j) ⊕ (β_b ∥ M_b[β])`, and the outputs are SPDZ sharings of `unit(α)`
  (MAC = the leaf) and `β·unit(α)`.
* A random linear combination of all outputs, masked by a random `⟨r⟩`, is
  opened and recorded. `MacParty::check` verifies it together with every other
  opening of the session. A party that tampers with any correction word makes
  the check abort. The adversary learns at most whether it aborted, which is
  one bit.
* W comes from one F_coin call per generation (Fig. 5 step 1).
* `lsb(Δ_b) = b` is enforced by revealing `lsb(K_j)` for λ = 128 sacrificed
  COTs (CWYY23, as ZGY+24 §3.3 prescribes).
* F_aBit / F_COT, both bootstrapped from the maliciously secure Masny–Rindal
  endemic base OT (`dpf_common::ot::endemic`):
  * default: IKNP-style COT with the KOS15 consistency check;
  * `MalSession::setup_with(…, Some(FerretConfig::B13))`: Ferret
    (`dpf_common::ot::ferret`), as in the paper's implementation. Setup bootstraps Ferret
    from KOS COTs and buffers ~10M COTs per direction (≈2 s, ≈1.2 GB for both
    parties in one process); afterwards each COT costs 1 bit instead of 16 bytes.

`run_mal` / `run_mal_gen` run setup, input authentication, generation and the
MAC check. `Fault` injects a deviation for tests.

## Benchmarks

```
cargo run --release -p half-tree --example bench-half-tree -- all --variant ht  --in-bits 20 --out-bits 127
cargo run --release -p half-tree --example bench-half-tree -- all --variant mal --in-bits 20 --out-bits 128
cargo run --release -p half-tree --example bench-half-tree -- all --variant mal-ferret --in-bits 20 --out-bits 128
```

Options and columns follow `dpf_common::bench`. For `mal`, `gen` covers input
authentication, generation and the MAC check, and `cots` includes the KOS
padding.
