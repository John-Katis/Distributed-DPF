# fssnn

A distributed DPF built with the dealer-less key generation of Yang et al.,
"FssNN: Communication-Efficient Secure Neural Network Training via Function
Secret Sharing" (ProvSec'24, full version ePrint 2023/073, §3.3.2–3.3.3,
Alg. 4 and 5). Semi-honest. The authors published no code.

FssNN builds a key-reduced DCF with output group Z2. Here the comparison bit
`v` is dropped and only the tree and the key generation are kept. The result
is a BGI16-style DPF that can be benchmarked next to the other protocols. To
compare at the same output widths, the output is ℓ ≤ 64 bits (`--out-bits ℓ`)
in one of two groups, selected with `--variant`:

- **`bin`**: `{0,1}^ℓ` under XOR. This is FssNN's Z2 with ℓ output bits;
  `--out-bits 1` gives exactly FssNN's construction.
- **`arith`**: the ring Z_2^ℓ, with the BGI16 final word as in
  `floram-arith`. This group is not in FssNN.

The DCF itself, DDCF/Comp and the NN layers (DReLU, ReLU, BitXA) are not
implemented.

1. **Tree** (Alg. 4 without `v`, `src/tree.rs`; key in `src/semi_honest/key.rs`): a node is `s ∥ t`, with a
   127-bit seed and the state bit in bit 0 (λ = 127, as in the paper).
   `G : {0,1}^127 → {0,1}^256` is the DGH+21 LPN-PRG, and
   `CW^(i) = s_CW ∥ t^L_CW ∥ t^R_CW`.
2. **Full tree, no early termination:** all n levels carry a CW and Eval
   expands all 2^n leaves, as in the other protocols. FssNN's early
   termination (§3.3.2, taken from BGI16) would apply to every DPF here, so it
   is left out of all of them. `Conv(s)` is the leaf seed's bits 1..=ℓ.
   - `bin`: a leaf's share is `Conv(s) ⊕ t·CW` with the final word
     `CW = Conv(s_0) ⊕ Conv(s_1) ⊕ β`.
   - `arith`: party b's share is `(−1)^b·(Conv(s) + t·CW)` with
     `CW = (−1)^{t_1}·(β − Conv(s_0) + Conv(s_1))`.

   In bits, the key is `128 + n(λ + 2) + ℓ`.
3. **Distributed Gen** (Alg. 5, `src/semi_honest/gen.rs`): the on-path nodes of *both*
   trees stay XOR-shared. Each level does:
   - F_SecPRG on both shared seeds (step 4);
   - one batched F_MUX^{B,λ} on α_i, for the Lose-side difference (`s_CW`) and
     both Keep children (steps 5, 7);
   - opening of `(s_CW, t^L_CW, t^R_CW)` in one round;
   - one F_AND per tree for `t^(i−1)·t^Keep_CW`.

   The final word ends Gen:
   - `bin`: it is linear in the shares and needs only one ℓ-bit opening.
   - `arith`: the α-leaves of both trees are XOR-shared, so the 2ℓ bits of
     `Conv(s_0)` and `Conv(s_1)` are first converted to additive shares, with
     one F_MUX^{A,ℓ} each (selector the shared bit, W₀ = 0, W₁ = 2^i). Then
     one more F_MUX^{A,ℓ} on the shared `t_1` picks `W` or `−W`, and the
     result is opened. Both are SIRNN's MUX (`dpf_common::arith::mux`), as in
     `floram-arith`, at 2(λ + ℓ) bits per selection. That is
     (2ℓ + 1)·2(λ + ℓ) bits and 4 rounds (two MUX layers, each a COT
     extension and one exchange) on top of the `bin` cost.
   - α is XOR-shared in both variants, as in FssNN; β is XOR-shared (`bin`)
     or additively shared mod 2^ℓ (`arith`).
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

   All 2n calls are preprocessed in one batch at the start of Gen.

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
- **Leaf conversion:** `Conv(s)` reads the leaf seed's bits 1..=ℓ directly,
  with no extra PRG call (ℓ ≤ 64 < λ).
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
cargo run --release -p fssnn --example bench-fssnn -- all --variant bin --in-bits 20 --out-bits 64
cargo run --release -p fssnn --example bench-fssnn -- all --variant arith --in-bits 20 --out-bits 64
```
