//! Our distributed half-tree DPF (the paper's `htDPF.Gen`, §"Fully
//! Distributed DPF"), with `F_PRF` instantiated by AES–MMO in 2PC on the OT
//! tower ([`dpf_common::aes_tower::OtTower`]): every AND of the S-boxes from
//! Ferret COTs.
//!
//! The semi-honest Gen ([`semi_honest::gen`]) is the paper's Figure
//! "DPF.Gen" in a [`semi_honest::Session`]: one public AES key K (`F = H_K`,
//! `F^pay = H_K(· ∥ 0)`) and one secret-shared Δ for all Gens of the session,
//! the roots `k_b = Δ_b ⊕ W` re-randomised per Gen by a public W, and `Δ_b`
//! doubling as party b's Ferret key, so `⟨α_ℓ·Δ⟩` costs a bit per COT; for the
//! top ν ≥ 1 levels each party expands its own tree locally and the words
//! `CW_ℓ` follow from frontier sums; the glue turns the level-ν frontier into
//! a sharing of the on-path state; below ν the on-path states `u_ℓ` are
//! sampled in preprocessing and joined to the tree by one public word `M_ℓ`
//! per level, so all AES–MMO calls in 2PC run in the same 40 rounds,
//! concurrently with the top phase. Evaluation is the half-tree walk `L =
//! H_K(st)`, `R = st ⊕ L`, `st' = child ⊕ t·CW`, followed by `st' ⊕= M_ℓ`
//! for `ℓ ≥ ν` ([`children_masked`]).
//!
//! * [`semi_honest`]: payload in `G = F_p` ([`field`]) with a public β, the
//!   leaf indexed by tag ([`leaf::tag_leaf`]: B2A by daBits, no product).
//! * [`semi_honest::bin`]: the same Gen with a binary payload, no B2A.
//! * [`malicious_arith`]: the paper's §malicious for an arithmetic payload
//!   in F_p: the same Gen in the same session, with (A) the payload-MAC word
//!   under a persistent δ and public keys `K^mac_j` ([`leaf::mal_leaf`]), (B)
//!   one product per bottom level, (C) the glue residual
//!   ([`leaf::glue_residual`]), and Π_Verify on the outputs and residuals.
//! * [`malicious`]: the same for a payload in `{0,1}^ℓ ⊂ GF(2^128)`, without
//!   (C): in characteristic 2 a swap of the servers' states does not change
//!   an output.

pub mod field;
pub mod leaf;
pub mod malicious;
pub mod malicious_arith;
pub mod semi_honest;

use dpf_common::aes_tower::{Mmo, ANDS_PER_CALL};
use dpf_common::block::Block;

/// One half-tree step under `F = f`: the child of `st` in direction `bit`, corrected.
#[inline]
pub fn child(f: &Mmo, st: Block, cw: Block, bit: bool) -> Block {
    let l = f.h(st);
    let c = if bit { st ^ l } else { l };
    c ^ cw.and_bit(st.lsb())
}

/// [`child`] for a whole batch: appends both corrected children of every
/// parent to `out`, interleaved `[L(p0), R(p0), L(p1), …]`.
pub fn children(f: &Mmo, parents: &[Block], cw: Block, out: &mut Vec<Block>) {
    children_masked(f, parents, cw, Block::ZERO, out)
}

/// [`children`] with the level word `m` XORed onto every child (`M_ℓ` of the
/// semi-honest Gen, zero above the glue level).
pub fn children_masked(f: &Mmo, parents: &[Block], cw: Block, m: Block, out: &mut Vec<Block>) {
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    // H(parents) into the upper half, then spread in place: slot i is read
    // before slots 2i, 2i + 1 ≤ k + i are written.
    f.h_many(parents, &mut kids[k..]);
    for (i, &st) in parents.iter().enumerate() {
        let lv = kids[k + i] ^ cw.and_bit(st.lsb());
        kids[2 * i] = lv ^ m;
        kids[2 * i + 1] = st ^ lv ^ m;
    }
}

/// The cleartext walk of the Gen with glue level ν ≥ 1: the n level words and
/// the words `M_ν, …, M_n` for the key `f` (K), roots `st` (`st_0 ⊕ st_1 =
/// Δ`), α and the on-path states `us = [u_ν, …, u_n]` of party 0, and the two
/// leaf states (`u_n`, `u_n ⊕ Δ`).
pub(crate) fn deal_walk_nu(f: &Mmo, roots: [Block; 2], n: usize, nu: usize, alpha: u64, us: &[Block]) -> (Vec<Block>, Vec<Block>, [Block; 2]) {
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert!(n >= 64 || alpha >> n == 0, "α ∈ {{0,1}}^n");
    assert!((1..=n).contains(&nu) && us.len() == n - nu + 1, "1 ≤ ν ≤ n, u_ν, …, u_n");
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let (mut cws, mut ms) = (Vec::with_capacity(n), Vec::with_capacity(us.len()));
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = f.h(st[0]) ^ f.h(st[1]) ^ delta.and_bit(!a);
        st = [child(f, st[0], cw, a), child(f, st[1], cw, a)];
        cws.push(cw);
        if i + 1 >= nu {
            let m = st[0] ^ us[i + 1 - nu];
            ms.push(m);
            st = [st[0] ^ m, st[1] ^ m];
        }
    }
    debug_assert_eq!(st[0] ^ st[1], delta);
    (cws, ms, st)
}

/// The leaf input of the payload hashes: the seed with its control bit cleared.
#[inline]
pub fn leaf_seed(st: Block) -> Block {
    st.with_lsb(false)
}

/// The default glue level: ν = 17, or n − 1 below n = 18 (at least 1). Measured (sh,
/// Babybear, 2026-11-02; `other_tex/nu_scan_temp.tex`): each level moved
/// into the top phase saves ~0.76 ms of 2PC compute and 3.55 kB, while the
/// top phase's local cost doubles per level, so the optimum is a fixed level
/// (16–17 at n = 20 and n = 32), not a fraction of n.
pub const BEST_NU: usize = 17;

/// [`BEST_NU`], at most n − 1 and at least 1 (the paper's `1 ≤ ν < n`; ν = n
/// only for n = 1).
pub fn default_nu(n: usize) -> usize {
    BEST_NU.min(n.saturating_sub(1)).max(1)
}

/// AES–MMO calls in 2PC in one semi-honest Gen of depth n with glue level
/// ν: two per level below ν, two at the leaf.
pub fn sh_calls(n: usize, nu: usize) -> usize {
    2 * (n - nu + 1)
}

/// ANDs of the OT tower in one semi-honest Gen (K is public: no Π_KeyExp).
pub fn sh_ands(n: usize, nu: usize) -> usize {
    sh_calls(n, nu) * ANDS_PER_CALL
}
