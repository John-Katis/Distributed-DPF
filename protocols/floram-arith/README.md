# floram-arith

The dealer-less DPF of Xing et al., "Distributed Function Secret Sharing and
Applications" (NDSS'25, §IV-A, Alg. 1, 2 and 14), with arithmetic-shared input
and output. It follows the authors' reference implementation,
[xingpz2008/dealerless-FSS_public](https://github.com/xingpz2008/dealerless-FSS_public)
(`keyGenDPF` in `src/legacy/dpf.cpp`, the NDSS version, and
`src/mpc/secure_ops.cpp`). Semi-honest.

1. **BitDec** (Alg. 14): α is additively shared mod 2^n. Starting from the LSB,
   `y[i] = x_b[i] ⊕ q` and `q := OR(AND(x_0[i], x_1[i]), AND(x[i], q))`. That is
   three F_AND calls per bit, as in the reference's `check_bit_overflow`.
2. **Tree** (Alg. 2 lines 3–15): `G(s) = AES_s(0) ∥ AES_s(1)` with the control bit
   in the lsb (`src/tree.rs`). Per level, each party XORs all left and all right
   children.
   - F_MUX^{B,λ} with choice `α_b ⊕ b` picks the off-path sum `σ`.
   - `τ_0` and `τ_1` are local XORs.
   - `(σ, τ_0, τ_1)` is revealed in one flight.
3. **Final correction word** (lines 16–22): `T_b = Σ_j t^j_b` differs between the
   parties by exactly one.
   - CCMP (Alg. 1, one F_AND) gives XOR shares of `g = 1{T_0 < T_1}`, which is
     `t_1` at the α-leaf.
   - F_MUX^{A,ℓ} then selects `W_CW = (−1)^{t_1}(β − Convert(s_0) + Convert(s_1))`
     over Z_2^ℓ.
4. **Eval**: `y_b = (−1)^b (Convert(s_b) + t_b·W_CW) mod 2^ℓ`.

The 2PC building blocks are those of the paper's App. A:

| Functionality | Instantiation | Module |
|---|---|---|
| F_AND | Beaver bit triples from CrypTFlow2's `_8KKOT` generator (1-of-8 KKOT₂), 2 bits online | `dpf_common::bool2pc` |
| F_OR | `1 ⊕ (¬x ∧ ¬y)` | `dpf_common::bool2pc` |
| F_MUX^{B,λ} | two parallel λ-bit COTs | `dpf_common::bool2pc::mux_block` |
| F_MUX^{A,ℓ} | SIRNN's COT MUX, 2(λ+ℓ) bits | `dpf_common::arith::mux` |
| OT | Naor–Pinkas base OTs, IKNP COT, KK13 1-of-N OT | `dpf_common::ot` |

Differences from the reference code:
- **Convert:** it takes the ℓ leaf bits above the control bit (the `s` of
  `s∥t`). The reference includes the control bit. Then
  `lsb(W_CW) = lsb(β) ⊕ τ_0 ⊕ τ_1 ⊕ 1` at the last level, which publishes the
  lsb of β.
- **Batched ANDs:** the reference's batched `and_wrapper` assigns the two
  correlated `_8KKOT` triples (same `a`) to different ANDs, which leaks the
  XOR of their first inputs. Here every AND uses its own triple pair. The
  single-AND calls of the DPF path are unaffected.
- **COTs:** the reference builds each block COT from two 64-bit chosen OTs. Here
  it is one derandomised IKNP COT (λ + λ bits). The functionality is the same.
- **Domain:** N need not be a power of two. Nodes with no leaf below N are
  skipped. They are off-path, so the keys on `[0, N)` are unchanged.
- **Not ported:** the reference's optional random input mask (`masked = true`).
  It belongs to the equality-test gate (Alg. 5), not to the DPF.

The Half-Tree optimisation the paper mentions is not applied; that is what the
`half-tree` crate is for.

```
cargo test -p floram-arith --release
cargo run --release -p floram-arith --example bench-floram-arith -- all --in-bits 20 --out-bits 64
```
