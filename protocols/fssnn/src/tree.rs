//! The tree of FssNN's Alg. 4 without the comparison
//! bit `v`, i.e. a BGI16-style DPF with output group Z2. The early termination
//! of §3.3.2 is deliberately not used: every one of the n levels carries a CW
//! and the tree is expanded down to all 2^n leaves, as for the other protocols.
//!
//! A node is one 128-bit block: bit 0 is the state bit `t`, bits 1..128 the
//! λ = 127-bit seed `s` (FssNN's typical λ). `G(s)` is the LPN-PRG on the seed
//! with bit 0 cleared; its 256 output bits are the left child `s^L ∥ t^L` and
//! the right child `s^R ∥ t^R`, so `G : {0,1}^λ → {0,1}^{2(λ+1)}`.
//!
//! The key holds n correction words `CW^(i) = s_CW ∥ t^L_CW ∥ t^R_CW` and a
//! final bit `CW^(n+1)`. The output at a leaf is `Conv(s)` (seed bit 1)
//! corrected by `t · CW^(n+1)`. At α the two leaves have `t_0 ⊕ t_1 = 1`, so
//! `CW^(n+1) = Conv(s_0) ⊕ Conv(s_1) ⊕ β` puts β there; at every other leaf
//! the two nodes are equal and everything cancels.

use crate::lpn_prg::lpn_prg;
use dpf_common::block::Block;

/// Correction word of one level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionWord {
    /// Seed correction, bit 0 clear.
    pub s: Block,
    /// `t^L_CW`, `t^R_CW`.
    pub t: [bool; 2],
}

/// `G` on a node's seed: the uncorrected children.
pub fn expand(node: Block) -> [Block; 2] {
    let y = lpn_prg().eval(node.0 & !1);
    [Block(y[0]), Block(y[1])]
}

/// The child on side `right` of `node`, after its level's correction.
pub fn child(node: Block, cw: &CorrectionWord, right: bool) -> Block {
    let c = Block(lpn_prg().eval_side(node.0 & !1, right as usize));
    if node.lsb() {
        c ^ cw.s ^ Block(cw.t[right as usize] as u128)
    } else {
        c
    }
}

/// The output bit of a leaf's seed.
pub fn conv(node: Block) -> bool {
    (node.0 >> 1) & 1 == 1
}
