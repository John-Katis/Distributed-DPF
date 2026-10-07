# Distributed DPF protocols

A Cargo workspace of two-party distributed point function (DPF) protocols.
Each protocol is its own crate, and all of them build on one shared library.

```
crates/
  common/            dpf-common: the shared library
protocols/
  floram-cprg/       Floram-CPRG distributed DPF (Doerner–shelat, CCS'17)
```

## Shared library: `dpf-common`

| Module | Contents |
|---|---|
| `block`   | `Block` (128-bit), bit/byte packing, domain-depth and payload-width helpers |
| `prg`     | two-key Davies–Meyer AES PRG (`left`, `right`, batched `expand_many`) |
| `hash`    | fixed-key AES tweakable hash (with the σ orthomorphism), AES-CTR stream |
| `net`     | in-process two-party network (`run_two_party`, `Channel`, `CommStats`) |
| `ot`      | Naor–Pinkas base OT over secp256r1 and semi-honest IKNP extension |
| `gc`      | half-gates garbled circuits over XOR-shared inputs (`GcParty`, `Garbler`, `Evaluator`) |
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

```
cargo test --workspace --release                 # everything
cargo test -p floram-cprg --release              # one protocol
cargo run --release -p floram-cprg --example bench -- all --in-bits 16
```
