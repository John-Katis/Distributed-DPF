# exp-mal-foleage (experimental)

Maliciously secure F4 Beaver triples from FOLEAGE, for the malicious
`ht-aes` (whose F4 triples currently come from leaky triples + bucketing on
malicious-Ferret aBits, about 1.1 kbit per triple, 19.4 MB of preprocessing
per key at n = 32). Two approaches on one triple PCG, both **dealer-seeded**:
the seeds come from a trusted function, the stand-in for a malicious seed
generation, which is the open part.

## Prior art

* (a) is, up to the encoding of the MACs, the authenticated-triple PCG of
  Boyle et al. (ring-LPN PCGs, CRYPTO'20, ePrint 2022/1035) and of Li, Xing,
  Yao and Yuan (ePrint 2025/169), who cover authenticated Boolean triples
  from QA-SD including the F4 / ternary-DPF case. Both give a maliciously
  secure setup: a malicious DPF key generation with a consistency check
  (`F_c-SUV`), under QA-SD/module-LPN with static leakage (single-entry
  predicates on the noise positions). So the "malicious DPF recursion" of (a)
  is already resolved there; our Γ = √Δ two-lane encoding is a variant of
  their trace-based one. LXYZ25 report 47.5 MB of setup for 3^16
  authenticated Boolean triples (≈ 9 bits per triple), no online cost.
* (b), PCG-VOLE MACs plus a semi-honest-style OLE setup plus sacrifice, did
  not come up in that search. Its security analysis (draft, with what is
  proved and what is assumed) is in `mal_foleage_temp.tex` at the repo root
  (untracked): it needs sampling `a` after the seeds, and a QA-SD leakage
  assumption that also allows pairwise predicates (stronger than static
  leakage).

## The triple PCG (`src/pcg.rs`)

Each party σ has two regular noise vectors `e_σ`, `f_σ` (c = 4, t = 27, as
FOLEAGE), `x_σ = ⟨a, ê_σ⟩`, `y_σ = ⟨a, f̂_σ⟩`, and the triple at coordinate k
is `a = x_0 + x_1`, `b = y_0 + y_1`, `c = ab` (`x_σ y_σ` local, the two cross
terms from `2c²t²` F4-valued DPFs, i.e. two FOLEAGE OLE instances). The MAC
key is `Δ = Δ_0 ⊕ Δ_1 ∈ GF(2^128)` of `MacParty`, so the triples plug into the
authenticated AES tower (`dpf_common::mac::af4`) as they are.

The AES layers are only F2-linear, so every *bit* needs a MAC, i.e. MACs on
`v` and on `v²`. Both come from two MAC lanes `ι(v)Δ` and `ι(v)Γ` with
`Γ = √Δ`: squaring the shares of `ι(v)Γ` gives shares of `ι(v²)Δ` (`src/gf.rs`).

* **Linear MACs** (both approaches): `ι(a)K = ι(x_0)K + ι(x_1)K`, where
  `ι(x_σ)K_σ` is local and `ι(x_σ)K_{1−σ}` is a subfield VOLE on σ's own
  sparse noise: `c·t` GF-valued DPFs per vector and owner, payload
  `ι(v)·K_{1−σ}` at σ's own positions (`4ct = 432` DPFs), FFT'd over
  GF(2^128) and combined with `ι(a_i)`.
* **Product MACs** (approach (a) only): `ι(c)K` from one GF-valued DPF per
  nonzero term of `(e_{0,i} + e_{1,i})(f_{0,j} + f_{1,j})`, payload
  `ι(v_e v_f)·K` (`4c²t² = 46,656` DPFs).

## Approach (a): every MAC from the PCG

`Mode::Full`, `Raw::full_triples`: no interaction after the seeds, MACs and
values consistent by construction.

## Approach (b): linear MACs, aBits for c, sacrifice

`Mode::Linear` + `sacrifice::authenticate_and_sacrifice`:
1. c is authenticated with random aBits `⟨r⟩` (malicious Ferret): open
   `d = c ⊕ r`, `⟨c⟩ = ⟨r⟩ ⊕ d`. A cheater can only shift its share of d,
   i.e. produce `c' = ab + e_c` with `e_c` chosen without honest information.
2. SPDZ sacrifice with bucketing: a coin-tossed permutation into buckets of B;
   the first triple of a bucket is checked against each other one with a
   public `t ∈ F4^*` (open `ρ = ta + f`, `σ = b + g`, then
   `w = tc + h + σf + ρg + ρσ`, must be 0). One wrong triple in a pair always
   fails (t ≠ 0); two wrong ones pass for one t in three. B is the smallest
   with `(B − 1)(log₂ N + log₂ 3) ≥ 40` (B = 4 for 10^4–10^6 triples).
3. One hash-and-commit check of every opening.

Seven rounds per batch.

## Results (`cargo run --release -p exp-mal-foleage --example bench-mal-foleage -- 8 9 10 11`)

Seeds per party as dealt, expansion of one party, (b)'s 2PC on Ferret B13
(bootstrap not counted), one core:

| N | approach | triples out | seed / party | seed bits / triple | expand | expand / triple | online bits / triple | rounds |
|---|---|---|---|---|---|---|---|---|
| 8  | (a) | 6,561   | 17.3 MB | 21,100 | 112 ms  | 17.1 µs | 0    | 0 |
| 8  | (b) | 1,312   | 3.1 MB  | 19,029 | 7 ms    | 1.1 µs  | 69.8 | 7 |
| 9  | (a) | 19,683  | 19.6 MB | 7,952  | 307 ms  | 15.6 µs | 0    | 0 |
| 9  | (b) | 4,920   | 3.1 MB  | 5,108  | 15 ms   | 0.75 µs | 52.5 | 7 |
| 10 | (a) | 59,049  | 22.9 MB | 3,109  | 912 ms  | 15.4 µs | 0    | 0 |
| 10 | (b) | 14,762  | 4.3 MB  | 2,321  | 44 ms   | 0.75 µs | 52.2 | 7 |
| 11 | (a) | 177,147 | 26.3 MB | 1,189  | 2.73 s  | 15.4 µs | 0    | 0 |
| 11 | (b) | 44,286  | 5.4 MB  | 980    | 136 ms  | 0.77 µs | 52.1 | 7 |

(b) consumes B = 4 PCG triples per output triple (5 at N = 8).

**Per malicious `ht-aes` key at n = 32, ℓ = 64** (138,752 triples):

| | preprocessing traffic | local work | seeds |
|---|---|---|---|
| current: leaky triples + bucketing | **19.4 MB** | ~0.4 s | none (Ferret only) |
| (a), N = 11 | 0 | 2.7 s per party | 26 MB per party, i.e. ≥ 1.2 kbit per triple to distribute |
| (b), N = 13 (4 × 138,752 ≤ 3^13) | **0.9 MB** online | ~1.2 s per party | ≈ 2 FOLEAGE instances; ≈ 3 keys per instance |

## What works and what does not

* **Both are correct and authenticated** (tests: every bit's MAC opens; (b)
  aborts when a party shifts its share of c, wherever it lands).
* **(a) is expensive in exactly the way FOLEAGE avoids.** A product MAC needs
  128 bits per position, so FOLEAGE's packing of 243 F4 values into one 512-bit
  leaf is lost: about 3,456 AES blocks per triple and 32 GF(2^128) FFTs, hence
  ~15 µs per triple, 20× (b)'s expansion. Its 46,656 GF-valued DPFs make the
  seeds 5× larger than (b)'s, so it amortises only for very large instances
  (≈ 6 bits per triple of seed at N = 16, at ~10 minutes of expansion per
  party). Worse, its seeds must be *correct*: no check runs after
  expansion, so a malicious seed generation must guarantee every payload
  `ι(v_e v_f)·Δ` and every position: that is the research recursion (a
  maliciously secure distributed DPF for 46,656 points).
* **(b) is the promising one.** About 52 bits per triple online (21× less than
  today), cheap expansion, and its seeds are two FOLEAGE OLE instances plus
  432 VOLE DPFs. More importantly, its check runs *after* expansion, so it
  plausibly breaks the recursion:
  1. The linear-MAC DPFs are a subfield VOLE whose positions are known to
     their owner (an SPCOT with known α, as in Ferret/BCG+19): their
     malicious setup with a consistency check is standard, at the price of a
     few leaked bits of noise positions.
  2. The OT choices of the cross-term DPF generation (trits of the noise
     positions, bits of the noise values) can be bound to the same
     authenticated noise by opening XORs of aBits to zero, so both parts
     use one noise vector.
  3. The cross-term DPFs can then be generated as in FOLEAGE §5 (private
     against a malicious party through malicious OT, correct only up to
     selective failure). Any error is a nonzero error polynomial on a block,
     whose FFT corrupts at least 27 coordinates. Every corrupted triple is
     caught in its bucket, so the abort is (up to 2^-40) the predicate
     "the deviation was triggered", a function of the honest noise trits
     only, not of the triple values used later.
  The assumption left is QA-SD with a little leakage on the noise positions,
  the analogue of the LPN-with-leakage argument of BCG+19. This is a sketch,
  not a proof.
* **Not done yet:** the distributed seed generation for (b) (steps 1–3 above),
  and amortising one instance over several keys in the `ht-aes` bench.
