# duoram

The DPF part of Vadapalli, Henry, Goldberg, "Duoram: A Bandwidth-Efficient
Distributed ORAM for 2- and 3-Party Computation" (USENIX Security 2023,
extended version ePrint 2022/1747, §4.1, App. C and D). It follows the
authors' code,
[git-crysp.uwaterloo.ca/avadapal/duoram](https://git-crysp.uwaterloo.ca/avadapal/duoram):
`preprocessing/dpfgen.h`, `share-conversion.h`, `p2preprocessing.cpp`, and
`2p-preprocessing/`. Semi-honest.

Duoram generates DPFs **before α and β are known** and adjusts them online.

1. **Preprocessing at a random target r** (`create_dpfs`):
   - P0 and P1 pick XOR shares of r.
   - They build Doerner–shelat's tree with `G_i(s) = AES_k(s ⊕ i) ⊕ i ⊕ s`.
   - Per level, `CW = r_i ? L : R` comes from compute_CW: a Du–Atallah
     product with a bit-times-block AND triple, in two flights. The flag CWs
     `lsb(L) ⊕ r_i ⊕ 1` and `lsb(R) ⊕ r_i` are opened in the second flight.
2. **Deferred final CW** (Pirsona): `Γ_b = (−1)^b Σ lane0(leaves)`. Party 1's
   negation turns the XOR-shared tree into additive shares.
3. **XOR → additive flags** (App. D, `convert_shares`):
   - `pm_b = (−1)^b Σ t_b` gives `pm = ±1`.
   - The second 64-bit lane of the same leaves serves as the extra DPF
     (`Γ'_b`).
   - One Du–Atallah product gives `Γ'·pm`, and one flight opens
     `c = pm + ρ` and `F̄ = Γ'·pm + ρ`.
   - Then `t̃_b = t_b·c + v'_b − t_b·F̄` are additive shares of `e_r`.
4. **xor_to_additive** of r: one Du–Atallah product per bit, batched with
   step 3.
5. **Online**, one flight of two words each way: open `S = α − r mod 2^n` and
   `F = β − Γ`. The output at x is
   `y_b = v_b(x − S) + F·t̃_b(x − S) mod 2^w`.

| Variant | Correlations (AND triples, products) | Module |
|---|---|---|
| `3p` | dealt by the helper P2 in one message per party (Du–Atallah, Duoram §2.2.1) | `duoram::du_atallah::deal` |
| `2p` | AND triples from derandomised IKNP COTs (Duoram App. A), word products as Gilboa products (one COT per bit) | `duoram::du_atallah::Helper::Ot` |

In 3P, P2's only job in the DPF is to deal correlations. In the full ORAM it
also holds DPF copies for READ and UPDATE.

Differences from the reference code, which its README calls "for performance
testing ONLY":
- **Fresh triples with the mask T:** P2's compute_CW triple is
  `γ_0 = bit_1·rand_0` without the mask T of Def. 4. That lets P0 learn
  `bit_1`, and with it P1's target bit. The same triple is also reused for
  every level, and one blind is reused for all bits of `xor_to_additive`.
  Here every product uses a fresh triple with T.
- **Flag conversion mod 2^64:** the reference packs flags into `int8_t` and
  patches overflows (`== ±128 → 0`). Here the conversion runs mod 2^64.
- **PRG key:** the reference passes an uninitialised `AES_KEY` to the PRG.
  Here the key is a fixed public constant.
- **Shift mod 2^n:** the shift S is taken mod 2^n, so N need not be a power of
  two.
- **Not implemented:** the ORAM operations (READ, UPDATE, REFRESHBLINDS), the
  three DPFs per access, and the 2P SPIR read (Spiral + Naor–Pinkas).

```
cargo test -p duoram --release
cargo run --release -p duoram --example bench-duoram -- all --variant 3p --in-bits 20 --out-bits 64
cargo run --release -p duoram --example bench-duoram -- all --variant 2p --in-bits 20 --out-bits 64
```
