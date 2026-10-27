# exp-f4-triples (experiment, not part of ours)

This is an experiment on where the F4 Beaver triples of the ht-aes Gen (the 2PC AES–MMO calls) could come from:

- FOLEAGE with a larger compression factor c, at the largest instance outside the QA-SD attack of ePrint 2025/892 (that bound is 3^(N−1) < 4^(3(c−1))), or
- Ferret random COTs, with no PCG.

`protocols/ht-aes` and `crates/common` are unchanged. This crate copies `dpf_common::foleage` and modifies the copy:

- c is a parameter (`Params::with_c`, `Params::max_log3`).
- Seed generation recomputes each tree level from the CWs instead of holding all trees in memory.
- `Seed::expand` packs ⟨u⟩ in groups of 8 lanes (`P16`) and evaluates the DPFs on all cores.

`ot_triples::rot_f4_triples` is Gilboa's OLE on random COTs, run in both directions:

- It takes 2 COTs per triple and direction.
- Each party sends 2 bits per triple (4 bits per triple in total), all in one round.

## Running

```
cargo run --release -p exp-f4-triples --example bench-f4-triples -- foleage --c 5 [--log3 N] [--in-bits 32] [--variant sh|mal]
cargo run --release -p exp-f4-triples --example bench-f4-triples -- ot [--in-bits 32] [--variant sh|mal]
```

## Results (2026-10-27, n = 32, ℓ = 64; both parties in one process on 20 cores)

Both modes start after the ht-aes setup (base OTs and the Ferret bootstrap), which is not counted. FOLEAGE outputs were checked by a sample of OLEs, and the Ferret triples were all checked.

| Source | Instance | DPFs (ct)² | Seed gen bytes | Rounds | Seed gen | Expand (per instance) | Gens per instance, sh / mal | Triple cost per Gen, sh |
|---|---|---|---|---|---|---|---|---|
| FOLEAGE c = 4 | 3^12 | 11,664 | 25,984,604 | 17 | 0.27 s | 0.05 s | 2 / 2 | 12,992,302 B |
| FOLEAGE c = 5 | 3^16 | 18,225 | 68,630,923 | 25 | 1.0 s | 5.3 s | 169 / 164 | 406,100 B |
| FOLEAGE c = 6 | 3^19 | 26,244 | 129,100,925 | 31 | 118 s | 294 s (15.7 GB peak) | 4,585 / 4,451 | 28,157 B |
| Ferret ROTs | — | — | — | 1 | 0.2 s | — | — | 63,360 B (mal: 65,280 B) |

Gens per instance = ⌊3^N / (2·triples per Gen)⌋. One Gen needs 126,720 triples for sh and 130,560 for mal.

**Total per key (sh-bin):** the triple cost per Gen plus the ht-aes Gen messages, which are 128,872 B whatever the triple source (`results-gen/ht-aes-sh-bin.csv`, setup excluded):

| Source | Per key |
|---|---|
| FOLEAGE c = 4 | ≈ 13.1 MB |
| FOLEAGE c = 5 | ≈ 535 KB |
| FOLEAGE c = 6 | ≈ 157 KB |
| Ferret ROTs | ≈ 192 KB |

Caveats on these totals:

- **Ferret row:** the 1.01 M COTs come out of the bootstrapped pool, so the total above leaves them out. At FssNN's amortised c_F = 0.443 bits per COT they would add about 56 KB, for about 248 KB per key.
- **Seed generation's own COTs:** these are also served from the pool in the FOLEAGE rows.
- **Ferret run with the full Gen:** an earlier run of the full ht-aes Gen with Ferret triples (since reverted from `protocols/`) gave 3,184,144 B including setup and 1,365 rounds. For comparison, FOLEAGE c = 4 gave 29,105,388 B and 1,382 rounds.
