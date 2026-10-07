# floram-cprg

A Rust port of the **Floram-CPRG distributed DPF** from Doerner & shelat,
*Scaling ORAM for Secure Computation* (CCS'17, §5, Fig. 6–7). The reference
code is [neucrypt/floram](https://gitlab.com/neucrypt/floram):
`src/oram_fssl/fss_cprg.{c,oc}`. Only the DPF is ported; the ORAM layers are not.

Two semi-honest servers jointly generate a BGI DPF key for a secret-shared
point α ∈ [0, N) and payload β, with no dealer. Each server expands its whole
tree locally. Per level, a small garbled circuit picks the correction word from
the two parties' XOR-accumulated children, so no PRG is evaluated inside 2PC.

## Layout

Files in this crate:

| Module | Floram / Obliv-C counterpart |
|---|---|
| `cprg.rs`  | `CprgLocal` ↔ `fss_cprg_offline_{start,process_round,finalize}`; `gen` ↔ `fss_cprg_traverselevels` + `fss_cprg_getadvice`; `gen_reference` is a plaintext oracle / trusted dealer |
| `key.rs`   | BGI key `(root, {σ_j, τ_{j,L}, τ_{j,R}}, γ)` with `eval_point` / `eval_full` |

Shared code it uses from `dpf-common` (`crates/common`):

| Module | Floram / Obliv-C counterpart |
|---|---|
| `prg.rs`   | `offline_prg`: Davies–Meyer AES with public `keyL` (left child) and `keyR` (right child) |
| `gc.rs`    | Obliv-C Yao: free-XOR + half-gates; shared inputs as in `ocFromShared_impl` (1 OT per bit); reveal as in `yao{Genr,Eval}RevealOblivBits` |
| `ot/`      | Obliv-C OT: Naor–Pinkas base OT over secp256r1 + semi-honest IKNP with 80 base OTs (`OT_KEY_BITS`) |
| `net.rs`   | in-process two-party network (two threads, `mpsc`), counting bytes and flights |

As in Floram, party 0 (Floram's party 1) is the garbler and OT sender, and it
chooses the public PRG keys. Payloads are XOR-shared blocks. The domain size N
need not be a power of two.

Differences from Floram, each fixing a leak of Fig. 7 as printed (a node's lsb
is its t-bit):
- **σ_j is revealed without its lsb**, and a corrected node's lsb is set to its
  t-bit. With the full block, `lsb(σ_j) = τ_{j,ᾱ_j}`, so α_j is public whenever
  `τ_{j,0} ≠ τ_{j,1}` (about half the levels). This costs one AND gate less.
- **The accumulators include every child of an expanded parent**, even a right
  child with no leaf below N (which is then dropped). Otherwise σ_j is publicly
  0 when α's off-path sibling has no leaf below N (e.g. N = 5, α = 4).
- **The payload never contains a leaf's lsb.** For out-bits ≤ 127 the payload
  is the leaf shifted down by one bit (Half-Tree's PRG-free Convert). Wider
  payloads chain `keyL` from the leaf: block k is `left^{k+1}(leaf)`, one AES
  call per block (Floram's `blockmultiple` uses the leaf itself as block 0).
  Otherwise `lsb(γ) = lsb(β) ⊕ 1 ⊕ τ_{m,0} ⊕ τ_{m,1}` is public.

Other differences:
- γ = acc⁰ ⊕ acc¹ ⊕ β is opened directly from XOR shares. Floram's circuit for
  it contains only XOR gates, so the result is the same.
- Base OTs are random OTs, which saves Naor–Pinkas's last flight.
- The code is single-threaded; Floram's OpenMP is not reproduced.

## Usage

```rust
use floram_cprg::{run_gen, Block};
let run = run_gen(1000, 256, /*alpha*/ 42, &[Block(7), Block(9)], /*seed*/ 1);
let [o0, o1] = &run.outs;
let y0 = o0.key.eval_point(42);   // party 0's share
let full0 = o0.key.eval_full();   // party 0's full-domain shares
```

For real use, each party calls `floram_cprg::gen(&mut channel, N, out_bits,
alpha_share, beta_share, seed)` on its own end of a `net::Channel`.

## Tests

```
cargo test -p floram-cprg --release
```

`tests/cleartext.rs` compares every evaluation path with the cleartext function
`f(x) = β if x = α, else 0`. It covers N ∈ {2, 3, 5, 7, 1000, 1024, 4099},
out-bits ∈ {32, 128, 256, 384}, α ∈ {0, N−1, random}, and every α for N = 11.
The paths checked are point eval, full eval, and the output computed during
gen. The 2PC keys are also checked to be bit-identical to the plaintext
reference driver run on the same seeds. `public_key_parts_do_not_leak` checks
the three leaks above stay closed.

## Benchmarks

```
cargo run --release -p floram-cprg --example bench -- gen  --in-bits 20 --out-bits 128
cargo run --release -p floram-cprg --example bench -- eval --in-bits 20 --out-bits 512 --points 100000
cargo run --release -p floram-cprg --example bench -- full --size 100003 --out-bits 300
cargo run --release -p floram-cprg --example bench -- all  --sweep --max-in-bits 22 --out-list 32,128,256,512
```

Output is CSV; the column names are printed as `#` comment lines. `--in-bits n`
sets N = 2^n, `--size N` sets any N, and `--out-bits m` sets the payload width.
