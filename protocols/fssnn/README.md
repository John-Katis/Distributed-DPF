# fssnn

A distributed DPF built with the dealer-less key generation of Yang et al.,
"FssNN: Communication-Efficient Secure Neural Network Training via Function
Secret Sharing" (ProvSec'24, full version ePrint 2023/073, §3.3.2–3.3.3,
Alg. 4 and 5). Semi-honest. The authors published no code.

FssNN builds a key-reduced DCF with output group Z2. Here the comparison bit
`v` is dropped and only the tree and the key generation are kept. The result
is a BGI16-style DPF over Z2 (`--out-bits 1`) that can be benchmarked next to
the other protocols. The DCF itself, DDCF/Comp and the NN layers (DReLU, ReLU,
BitXA) are not implemented.

1. **Tree** (Alg. 4 without `v`, `src/tree.rs`; key in `src/semi_honest/key.rs`): a node is `s ∥ t`, with a
   127-bit seed and the state bit in bit 0 (λ = 127, as in the paper).
   `G : {0,1}^127 → {0,1}^256` is the DGH+21 LPN-PRG, and
   `CW^(i) = s_CW ∥ t^L_CW ∥ t^R_CW`.
2. **Early termination** (§3.3.2): only `υ = max(0, n − 6)` levels carry a CW.
   A node at depth υ covers 2^{n−υ} ≤ 64 inputs. The output for low bits `j`
   is bit `j` of its seed, corrected by `t` times bit `j` of the final word
   `Conv(s_0) ⊕ Conv(s_1) ⊕ β·e_{α_low}`. In bits, the key is
   `128 + υ(λ + 2) + 64`.
3. **Distributed Gen** (Alg. 5, `src/semi_honest/gen.rs`): the on-path nodes of *both*
   trees stay XOR-shared. Each level does:
   - F_SecPRG on both shared seeds (step 4);
   - one batched F_MUX^{B,λ} on α_i, for the Lose-side difference (`s_CW`) and
     both Keep children (steps 5, 7);
   - opening of `(s_CW, t^L_CW, t^R_CW)` in one flight;
   - one F_AND per tree for `t^(i−1)·t^Keep_CW`.

   The final word needs an AND tree for the shared one-hot of α's low bits,
   then one opening.
4. **F_SecPRG** (PRG in `src/lpn_prg.rs`, its 2PC in `src/semi_honest/sec_prg.rs`): DGH+21 Construction 3.4 with the Table 3
   parameters (n, m, t) = (128, 512, 256), evaluated gate by gate as in §5.1.
   Lin₂, then Convert(2,3) (open 128 bits), then Lin₃, then Convert(3,2) (open
   512 trits, packed 5 per byte), then Lin₂. That is two rounds and the 1880
   online bits of Table 3 per call.
5. **No dealer** (DGH+21 §5.5):
   - (2,3)-correlations (Protocol 5.2) come from hashed IKNP COTs, i.e. random
     1-of-2 OTs over Z3, plus one keep/discard bit per OT;
   - (3,2)-correlations (Protocol 5.4) come from KK13 1-of-3 OTs of 2-bit
     strings.

   All 2υ calls are preprocessed in one batch at the start of Gen.

| Functionality | Instantiation | Module |
|---|---|---|
| F_SecPRG | DGH+21 LPN-PRG, distributed 2PC with OT-generated correlations | `fssnn::lpn_prg`, `fssnn::semi_honest::sec_prg` |
| F_2PC: MUX | two parallel λ-bit COTs | `dpf_common::bool2pc::mux_block` |
| F_2PC: AND | CrypTFlow2 bit triples (1-of-8 KKOT) | `dpf_common::bool2pc` |
| OT | Naor–Pinkas base OTs, IKNP COT, KK13 1-of-N OT | `dpf_common::ot` |

Notes and deviations:
- **Typos in the papers:** FssNN Alg. 5 step 4 prints the left child twice. In
  DGH+21 Protocol 5.4, `x̃_i + j` should be `x̃_1 + j`, and the receiver must
  unmask `r_c ⊕ z_c`.
- **Root sharing:** ΠShare of the roots is the trivial sharing `(s, 0)`.
- **Leaf conversion:** `Conv(s)` reads the leaf seed's bits 1..=64 directly,
  with no extra PRG call.
- **Discard bits:** they are sent uncompressed (1 bit per OT). DGH+21 suggests
  entropy coding them down to about 1.377 bits per correlation.
- **Cost profile:** Gen communication is dominated by the KK13 1-of-3 OTs
  (256-bit codeword columns each, 512 per PRG call). DGH+21 assumes silent OT
  (PCG) for these correlations, which is not implemented here.
- **Evaluation speed:** point evaluation is LPN-bound, about 1 µs per level
  with POPCNT. It costs 512 popcounts for A·x and 128 parities for one half of
  B·w.

Layout: the PRG (`lpn_prg`) and the tree (`tree`) are shared at the crate
root; everything semi-honest (2PC of the PRG, Gen, key) is in `semi_honest/`,
so a malicious variant can sit next to it, as in `half-tree`.

```
cargo test -p fssnn --release
cargo run --release -p fssnn --example bench-fssnn -- all --in-bits 20 --out-bits 1
```
