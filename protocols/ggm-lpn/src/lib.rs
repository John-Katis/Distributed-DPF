//! Our template (local top phase, glue, pre-sampled bottom levels) on a full
//! GGM tree with the LPN-PRG of Dinur et al. (CRYPTO'21, Constr. 3.4), the
//! PRG that FssNN evaluates in 2PC. The `ht-aes` crate is the other instance
//! of the template, on a half-tree with AES–MMO.
//!
//! **Tree.** BGI's tree as in [`fssnn::tree`]: a node is `s ∥ t` (λ = 127 seed
//! bits above the tag bit), `G(s) = st^L ∥ st^R`. A half-tree keeps the two
//! on-path states a fixed Δ apart, so one word per level corrects both
//! children and one shift `M_ℓ` moves them onto pre-sampled states. A GGM
//! tree has no such offset. Here every level ℓ therefore gets a fresh secret
//! offset `V_ℓ = seed(U_ℓ) ∥ 1` and **one seed word per side**:
//!
//! ```text
//! s^L_CW = seed(D_L ⊕ ¬α_ℓ·U_ℓ),   s^R_CW = seed(D_R ⊕ α_ℓ·U_ℓ),
//! t^L_CW = lsb(D_L) ⊕ α_ℓ ⊕ 1,     t^R_CW = lsb(D_R) ⊕ α_ℓ,
//! ```
//!
//! with `D_σ = st^σ_0 ⊕ st^σ_1` the difference of the two on-path nodes'
//! children. The Lose word cancels the Lose children; the Keep word leaves
//! the Keep children at difference `V_ℓ`. A child is `st^σ ⊕ t·(s^σ_CW ∥
//! t^σ_CW) ⊕ M_ℓ`, with `M_ℓ = 0` above the glue level.
//!
//! **Gen** ([`gen`]): the top ν levels are local, as in our half-tree: each
//! party expands its own tree, and `D_σ` is the XOR of the two parties'
//! sums over their levels; `α_ℓ·U_ℓ` is a preprocessed product, so a top
//! level costs one opening. The glue turns level ν into a sharing of
//! `st_{ν,0}` (tag sums mod 4, the tag shared locally, one bit-times-block product with
//! `⟨V_ν⟩`) and opens `M_ν`. Below ν the on-path states `u_{ℓ,0}` and `u_{ℓ,1}
//! = u_{ℓ,0} ⊕ V_ℓ` are pre-sampled, so all 2(n − ν) 2PC PRG calls run in one
//! batch of two rounds; then the side words and `M_ℓ` are opened. The leaf
//! word is `Conv(u_{n,0}) ⊕ Conv(u_{n,1}) ⊕ β`, or, for an arithmetic payload
//! ([`gen::gen_arith`]), the tag-indexed word of the half-tree instance.
//!
//! The pre-sampled bottom with side words and `M_ℓ` is the construction of the
//! research note "Our Framework Applied to FssNN" (FssNN-PS). The side words in
//! the top levels, which remove that note's per-level online multiplexer, are
//! our extension of it. Key privacy, top levels included, follows from plain
//! pseudorandomness of `G` by a hybrid over the levels (paper, "Instance with
//! an Alternating-Moduli PRF"). Semi-honest only: the tests check correctness.
//!
//! * [`key`]: the key and its evaluation.
//! * [`gen`]: the cleartext Gen ([`gen::deal`]) and the 2PC Gen ([`gen::gen`]).

pub mod gen;
pub mod key;

pub use fssnn::Word;
pub use gen::{deal, deal_arith, gen, gen_arith, gen_reference, gen_reference_arith, run_gen, run_gen_arith, DealParams, GenOutput};
pub use key::{ArithKey, BinKey, LevelWord, Tree};

use dpf_common::block::Block;

/// The seed part of a block (tag bit cleared).
#[inline]
pub(crate) fn seed(x: Block) -> Block {
    x.with_lsb(false)
}

/// The glue level used when none is given: ν = 1 (bounded by n). The
/// LPN-PRG's 2PC takes 2 rounds, so each top level adds a round to Gen.
pub const DEFAULT_NU: usize = 1;

/// [`DEFAULT_NU`], at most n.
pub fn default_nu(n: usize) -> usize {
    DEFAULT_NU.min(n)
}

/// 2PC calls of the LPN-PRG in one Gen: two per bottom level, two more at the
/// leaf for ℓ > λ = 127.
pub fn prg_calls(n: usize, nu: usize, bits: usize) -> usize {
    2 * (n - nu) + if bits > fssnn::tree::SEED_BITS { 2 } else { 0 }
}
