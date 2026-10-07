# floram-arith

The dealer-less DPF of Xing et al., "Distributed Function Secret Sharing and
Applications" (NDSS'25, §IV-A), implemented as the paper describes it: a
Floram-style GGM tree with arithmetic-shared input and output. Semi-honest.

1. **A2B**: α is additively shared mod 2^n. A ripple-carry adder in the
   garbled circuit (n−1 AND gates) produces α's bits as wires, which feed
   Floram's per-level correction-word circuit directly
   (`floram_cprg::cprg::level_circuit`).
2. **Tree**: Floram-CPRG, unchanged (`floram_cprg::cprg::CprgLocal`).
3. **Final correction word**: `T_b = Σ_j t^j_b` differs between the parties by
   exactly one. CCMP (Alg. 1, one AND gate) gives XOR shares of
   `g = 1{T_0 < T_1}`, which equals `t_1` at the α-leaf. The OT-based arithmetic
   MUX (`dpf_common::arith::mux`) then selects
   `W_CW = (−1)^{t_1}(β − Convert(s_0) + Convert(s_1))` over Z_2^ℓ.
4. **Eval**: `y_b = (−1)^b (Convert(s_b) + t_b·W_CW) mod 2^ℓ`.

The Half-Tree optimisation the paper mentions is not applied; that is what the
`half-tree` crate is for.

```
cargo test -p floram-arith --release
cargo run --release -p floram-arith --example bench-floram-arith -- all --in-bits 20 --out-bits 64
```
