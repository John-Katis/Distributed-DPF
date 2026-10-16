# fssnn

A distributed DPF built with the dealer-less key generation of Yang et al.,
"FssNN: Communication-Efficient Secure Neural Network Training via Function
Secret Sharing" (ProvSec'24, full version ePrint 2023/073, §3.3.2–3.3.3,
Alg. 4 and 5). Semi-honest. The authors published no code.

FssNN builds a key-reduced DCF with output group Z2. Here the comparison bit
`v` is dropped and only the tree and the key generation are kept. The result
is a BGI16-style DPF that can be benchmarked next to the other protocols. To
compare at the same output widths, the output is ℓ ≤ 256 bits (`--out-bits ℓ`)
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
   is left out of all of them. `Conv(s)` is the leaf seed's bits 1..=ℓ for
   ℓ ≤ λ = 127. For wider outputs (128, 256) the seed is too short, and
   `Conv(s)` is the first ℓ bits of `G(s)` with the same LPN-PRG, so Eval
   pays one more G per leaf.
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
     `floram-arith` (here `fssnn::word::mux`, for words up to 256 bits),
     at 2ℓ + 2 bits per selection: one masked ℓ-bit word each way, plus
     each party's choice-bit correction for its Ferret COT. That is
     (2ℓ + 1)·(2ℓ + 2) bits and 4 rounds (two MUX layers, each a
     choice-bit correction and one exchange) on top of the `bin` cost. The
     theory is in the section on the `arith` final word below.
   - For ℓ > 127, the leaves first go through two more F_SecPRG calls in 2PC,
     one per tree, batched into one evaluation (2 rounds). Their correlations
     are preprocessed together with the 2n per-level ones. `Conv` is linear in
     G's output, so the XOR shares of `G(s)` give XOR shares of `Conv(s)`.
     This is the cost of an output that needs a PRG on the shared leaf.
   - α is XOR-shared in both variants, as in FssNN; β is XOR-shared (`bin`)
     or additively shared mod 2^ℓ (`arith`).
4. **F_SecPRG** (PRG in `src/lpn_prg.rs`, its 2PC in `src/semi_honest/sec_prg.rs`): DGH+21 Construction 3.4 with the Table 3
   parameters (n, m, t) = (128, 512, 256), evaluated gate by gate as in §5.1.
   Lin₂, then Convert(2,3) (open 128 bits), then Lin₃, then Convert(3,2) (open
   512 trits, packed 5 per byte), then Lin₂. That is two rounds and the 1880
   online bits of Table 3 per call.
5. **No dealer, on silent OT** (DGH+21 §5.5): DGH+21 take the OT
   correlations behind their preprocessing from silent OT (a PCG for OT,
   [BCG+19; YWL+20]). Here setup bootstraps Ferret (YWL+20, semi-honest,
   `FerretConfig::B13` in the bench) on the `CotPair`, and every COT of Gen
   comes from it, the MUXes included. All are random COTs with party 0 as
   sender:
   - (2,3)-correlations (Protocol 5.2): `z_j = H(K ⊕ jΔ) mod 3` is a random
     1-of-2 OT over Z3 with Ferret's random choice bit; party 0 sends one
     keep/discard bit per OT.
   - (3,2)-correlations (Protocol 5.4): two random COTs give a random 1-of-4
     OT of 2-bit strings, `z_{ab} = H(K_1 ⊕ aΔ) ⊕ H(K_2 ⊕ bΔ)`. The receiver
     discards choice 3 (one bit per pair), which leaves a random 1-of-3 OT,
     and party 0 sends `s_j ⊕ z_j` for `j ∈ Z3` (DGH+21's 6 bits).

   All 2n calls are preprocessed in one batch at the start of Gen, in two
   rounds (keep and discard bits cross, then the masked `s_j`). The 2n bit
   triples of F_AND also come from Ferret (FssNN §2.2: "Π_GenMT ... using
   VOLE-style OT generation scheme proposed in Ferret"): one random COT per
   direction and triple, nothing sent.

| Functionality | Instantiation | Module |
|---|---|---|
| F_SecPRG | DGH+21 LPN-PRG, distributed 2PC with correlations from silent OT | `fssnn::lpn_prg`, `fssnn::semi_honest::sec_prg` |
| Silent OT | Ferret COTs (semi-honest), bootstrapped from IKNP | `dpf_common::ot::ferret` |
| F_2PC: MUX | two parallel λ-bit COTs (Ferret) | `dpf_common::bool2pc::mux_block` |
| F_2PC: AND | Beaver bit triples from Ferret random COTs (ABY's R-OT triples; FssNN §2.2 generates its triples with Ferret) | `dpf_common::bool2pc::rot_triples` |
| OT | Naor–Pinkas base OTs, IKNP COT, KK13 1-of-N OT | `dpf_common::ot` |

Notes and deviations:
- **Typos in the papers:** FssNN Alg. 5 step 4 prints the left child twice. In
  DGH+21 Protocol 5.4, `x̃_i + j` should be `x̃_1 + j`, and the receiver must
  unmask `r_c ⊕ z_c`.
- **Root sharing:** ΠShare of the roots is the trivial sharing `(s, 0)`.
- **Leaf conversion:** for ℓ ≤ 127, `Conv(s)` reads the leaf seed's bits
  1..=ℓ directly, with no extra PRG call. Wider outputs take `G(s)`.
- **Discard bits:** they are sent uncompressed (1 bit per OT). DGH+21 suggests
  entropy coding them down to about 1.377 bits per correlation.
- **Cost profile:** with Ferret, Gen proper sends about 34 KB at n = 20
  (the KK13 1-of-3 OTs used before cost about 820 KB), and the one-time
  Ferret bootstrap (about 3 MB, about 1.4 s for one ~10M-COT batch) is in the
  setup columns, as for malicious Half-Tree.
- **Evaluation speed:** point evaluation is LPN-bound, about 1 µs per level
  with POPCNT. It costs 512 popcounts for A·x and 128 parities for one half of
  B·w.

## The `arith` final word without a dealer

FssNN only has the Z2 output. The `arith` variant takes its final word from
BGI16 (Fig. 1) and computes it in 2PC. This section explains why that works
and how it is done.

**BGI16's final word.** Party b's output at a leaf with seed `s_b` and state
bit `t_b` is

    y_b = (−1)^b · (Conv(s_b) + t_b·CW)        (mod 2^ℓ)

- Off the α-path the two trees agree (`s_0 = s_1`, `t_0 = t_1`), so
  `y_0 + y_1 = 0`.
- At α exactly one of `t_0`, `t_1` is 1, and
  `y_0 + y_1 = Conv(s_0) − Conv(s_1) + (t_0 − t_1)·CW`.
  For this to equal β, the CW term must be `W = β − Conv(s_0) + Conv(s_1)`.
  The factor `t_0 − t_1` is +1 if `t_1 = 0` and −1 if `t_1 = 1`, so

      CW = (−1)^{t_1} · (β − Conv(s_0) + Conv(s_1))

  The XOR variant needs no sign, because XOR has no ±.

`Conv` is BGI16's Convert (Fig. 3). For ℓ ≤ λ it takes ℓ bits of the seed.
For ℓ > λ it takes the first ℓ bits of `G(s)`. Here `G` is the tree's
LPN-PRG, so ℓ ≤ 256.

**Why the dealer is not needed.** BGI16's security is a statement about the
distribution of one key `k_b`: it hides α and β. The dealer is only the
simplest way to sample that distribution. Let F_Gen be the functionality that
takes shares of α and β, runs the dealer's Gen and gives `k_b` to `P_b`. If a
semi-honest 2PC securely realizes F_Gen, each party's view can be simulated
from its own key. BGI16's key security then carries over unchanged. FssNN
argues the same way: Thm. 3.2 is in the F_Gen-hybrid model, and Alg. 5 is
the protocol for it.

Here, Gen keeps every value in shares: both trees' nodes (seeds and t bits),
α and β. It opens only the per-level CWs and the final word, and both are part
of the keys. The other messages are OT messages and the masked openings inside
F_SecPRG, and all of these can be simulated. For the same roots, Gen gives
exactly the dealer's key (`deal` is the bit-exact oracle in the tests). From
`P_b`'s view, the final word is masked by `Conv(s_{1−b}^α)`, which is
pseudorandom, in the dealer setting and here alike. The argument covers only
semi-honest parties.

**Computing CW from shares.** After the last level, each party holds XOR
shares of both α-leaves, which give XOR shares of `Conv(s_0)`, `Conv(s_1)`
and `t_1`. Two steps follow:

1. **B2A.** XOR shares cannot simply be added, since `x ⊕ y = x + y − 2xy`
   and the product `xy` needs both parties. A word is a sum of its bits,
   `Conv = Σ_i 2^i·bit_i`, so it is enough to share `2^i·bit_i` additively for
   each XOR-shared bit. That is a MUX with selector `bit_i`, `W0 = 0` and
   `W1 = 2^i`, the public constant held by party 0. The 2ℓ MUXes for both
   words run in one batch. Each party sums its outputs locally, which gives
   additive shares of `Conv(s_0)` and `Conv(s_1)`, and with its share of β an
   additive share of W.
2. **Sign select.** One more MUX with selector `t_1`, `W0 = W` and `W1 = −W`.
   Each party negates its share of W locally to get its share of −W. The
   result is `W + t_1·(−2W) = (−1)^{t_1}·W = CW`, using `(−1)^t = 1 − 2t`. It
   needs W, so it runs after B2A.

Then CW is opened, and both parties store it as `fcw`.

**The MUX** (SIRNN's). The selector `g = g_0 ⊕ g_1` is XOR-shared, and W0, W1
are additively shared with `D = W1 − W0 = D_0 + D_1`. The output is additive
shares of `W0 + g·D`. For each party b,

    (g_0 ⊕ g_1)·D_b = g_b·D_b + g_{1−b}·(1 − 2g_b)·D_b

- The first term is local.
- The second is one COT. `P_b` sends `H(K ⊕ Δ) − H(K) − (1 − 2g_b)·D_b` and
  keeps `−H(K)`. The peer chooses with `g_{1−b}` and gets
  `H(K) + g_{1−b}·(1 − 2g_b)·D_b`.

There is one COT per direction, so each party sends ℓ + 1 bits per selection:
its masked word and its Ferret choice-bit correction. Each MUX layer takes 2
rounds, the correction and then the words. B2A plus the sign select is
therefore 4 rounds over `bin`. In B2A, `D_1 = 0`, so party 1's direction
carries nothing useful. A one-way MUX would save it, but the code keeps
SIRNN's general MUX, as `floram-arith` does.

**Where this is in the code:**
- `src/tree.rs`:
  - `Group::output` is `y_b`. The product `t_b·CW` is a branch on the leaf's
    t bit, and `(−1)^b` is `.signed(party == 1)`.
  - `Group::final_cw` is the dealer's CW.
  - `conv` / `conv_prg` are Convert.
- `src/word.rs`: `mux` is the MUX above. The local term, the masked word `u`
  and the receiver's unmasking `H(M) − g·u` are each one line.
- `src/semi_honest/gen.rs`: `final_cw` runs the steps in order:
  1. the XOR shares of `Conv` (through F_SecPRG for ℓ > 127);
  2. the B2A MUX and the local sums into W;
  3. the sign MUX on `leaves[1].lsb()`;
  4. `open_word`.

Layout: the PRG (`lpn_prg`) and the tree (`tree`) are shared at the crate
root; everything semi-honest (2PC of the PRG, Gen, key) is in `semi_honest/`,
so a malicious variant can sit next to it, as in `half-tree`.

```
cargo test -p fssnn --release
cargo run --release -p fssnn --example bench-fssnn -- all --variant bin --in-bits 20 --out-bits 64
cargo run --release -p fssnn --example bench-fssnn -- all --variant arith --in-bits 20 --out-bits 64
```
