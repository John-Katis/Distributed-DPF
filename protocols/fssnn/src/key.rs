//! The DPF key and its evaluation: FssNN's Alg. 4 tree without the comparison
//! bit `v`, i.e. a BGI16-style DPF with output group Z2, plus the early
//! termination of §3.3.2.
//!
//! A node is one 128-bit block: bit 0 is the state bit `t`, bits 1..128 the
//! λ = 127-bit seed `s` (FssNN's typical λ). `G(s)` is the LPN-PRG on the seed
//! with bit 0 cleared; its 256 output bits are the left child `s^L ∥ t^L` and
//! the right child `s^R ∥ t^R`, so `G : {0,1}^λ → {0,1}^{2(λ+1)}`.
//!
//! The key holds `υ = max(0, n − 6)` correction words `CW^(i) = s_CW ∥ t^L_CW ∥
//! t^R_CW` and a final 64-bit word. A node at depth υ covers the
//! `2^{n−υ} ≤ 64` inputs sharing its prefix, and the output at the leaf with
//! low bits `j` is bit `j` of `Conv(s)` (seed bits 1..=64) corrected by `t`
//! times bit `j` of the final word. On α's path the two final nodes have
//! `t_0 ⊕ t_1 = 1`, so the final word `Conv(s_0) ⊕ Conv(s_1) ⊕ β·e_{α_low}`
//! puts β at α; off the path the two nodes are equal and everything cancels.

use crate::lpn_prg::lpn_prg;
use dpf_common::block::{depth_for, Block};

/// Leaf outputs packed into one final node (2^6 = 64 ≤ λ).
pub const PACK_BITS: usize = 6;

/// Levels with a correction word for depth `n`.
pub fn levels_for(n: usize) -> usize {
    n.saturating_sub(PACK_BITS)
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

/// The 64 packed output bits of a final node's seed.
pub fn conv(node: Block) -> u64 {
    (node.0 >> 1) as u64
}

#[derive(Clone, Debug)]
pub struct FssKey {
    pub party: usize,
    pub n_size: u64,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub fcw: u64,
}

impl FssKey {
    /// Input bits n.
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// Low input bits resolved inside a final node.
    pub fn leaf_bits(&self) -> usize {
        self.depth() - self.cws.len()
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[CorrectionWord], u64) {
        (&self.cws, self.fcw)
    }

    /// Root (16) + per level 16 + 1 bytes + final word (8). In bits this is
    /// FssNN's `υ(λ + 3) + 2λ` without the `v` bit per level.
    pub fn size_bytes(&self) -> usize {
        16 + 17 * self.cws.len() + 8
    }

    fn output(&self, node: Block, low: usize) -> bool {
        let w = conv(node) ^ if node.lsb() { self.fcw } else { 0 };
        (w >> low) & 1 == 1
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> bool {
        assert!(x < self.n_size);
        let n = self.depth();
        let lb = self.leaf_bits();
        let mut node = self.root;
        for (i, cw) in self.cws.iter().enumerate() {
            node = child(node, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        self.output(node, (x & ((1 << lb) - 1)) as usize)
    }

    /// Shares of `f(0), …, f(N − 1)`.
    pub fn eval_full(&self) -> Vec<bool> {
        let n = self.depth();
        let lb = self.leaf_bits();
        let mut nodes = vec![self.root];
        for (i, cw) in self.cws.iter().enumerate() {
            let keep = self.n_size.div_ceil(1 << (n - 1 - i)) as usize;
            let mut next = Vec::with_capacity(2 * nodes.len());
            for &v in &nodes {
                let [l, r] = expand(v);
                let (cl, cr) = if v.lsb() { (cw.s ^ Block(cw.t[0] as u128), cw.s ^ Block(cw.t[1] as u128)) } else { (Block::ZERO, Block::ZERO) };
                next.push(l ^ cl);
                next.push(r ^ cr);
            }
            next.truncate(keep);
            nodes = next;
        }
        (0..self.n_size).map(|x| self.output(nodes[(x >> lb) as usize], (x & ((1 << lb) - 1)) as usize)).collect()
    }
}
