//! The tree of FssNN's Alg. 4 without the comparison
//! bit `v`, i.e. a BGI16-style DPF. FssNN's output group is Z2; here it is
//! either `{0,1}^ℓ` under XOR or the ring Z_2^ℓ ([`Group`]). The early termination
//! of §3.3.2 is deliberately not used: every one of the n levels carries a CW
//! and the tree is expanded down to all 2^n leaves, as for the other protocols.
//!
//! A node is one 128-bit block: bit 0 is the state bit `t`, bits 1..128 the
//! λ = 127-bit seed `s` (FssNN's typical λ). `G(s)` is the LPN-PRG on the seed
//! with bit 0 cleared; its 256 output bits are the left child `s^L ∥ t^L` and
//! the right child `s^R ∥ t^R`, so `G : {0,1}^λ → {0,1}^{2(λ+1)}`.
//!
//! The key holds n correction words `CW^(i) = s_CW ∥ t^L_CW ∥ t^R_CW` and a
//! final word `CW^(n+1)`. `Conv(s)` is the ℓ seed bits above the state bit
//! (bits 1..=ℓ; for ℓ = 1 FssNN's single output bit). At α the two leaves have
//! `t_0 ⊕ t_1 = 1`; at every other leaf the two nodes are equal.
//!
//! * [`Group::Xor`]: the share is `Conv(s) ⊕ t·CW^(n+1)` and
//!   `CW^(n+1) = Conv(s_0) ⊕ Conv(s_1) ⊕ β`, FssNN's construction with ℓ bits.
//! * [`Group::Arith`]: the share is `(−1)^b·(Conv(s) + t·CW^(n+1))` and
//!   `CW^(n+1) = (−1)^{t_1}·(β − Conv(s_0) + Conv(s_1))`, as in BGI16 (and
//!   `floram-arith`).

use crate::lpn_prg::lpn_prg;
use dpf_common::arith::{convert, mask, signed};
use dpf_common::block::Block;

/// The output group of the DPF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// `{0,1}^ℓ` under XOR (FssNN's Z2 for ℓ = 1).
    Xor,
    /// The ring Z_2^ℓ.
    Arith,
}

impl Group {
    /// Party `party`'s share at a leaf, with `bits` = ℓ and final word `fcw`.
    #[inline]
    pub fn output(self, party: usize, bits: usize, leaf: Block, fcw: u64) -> u64 {
        let corr = if leaf.lsb() { fcw } else { 0 };
        match self {
            Group::Xor => conv(leaf, bits) ^ corr,
            Group::Arith => signed(party == 1, conv(leaf, bits).wrapping_add(corr) & mask(bits), bits),
        }
    }

    /// The final word from the two α-leaves (cleartext).
    pub fn final_cw(self, bits: usize, leaves: [Block; 2], beta: u64) -> u64 {
        let (c0, c1) = (conv(leaves[0], bits), conv(leaves[1], bits));
        match self {
            Group::Xor => c0 ^ c1 ^ beta,
            Group::Arith => signed(leaves[1].lsb(), beta.wrapping_sub(c0).wrapping_add(c1) & mask(bits), bits),
        }
    }
}

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

/// `Conv`: the ℓ = `bits` output bits of a leaf's seed (bits 1..=ℓ).
pub fn conv(node: Block, bits: usize) -> u64 {
    convert(node, bits)
}
