//! The semi-honest key ([`crate::tree`] for the tree it walks): root, the
//! n level CWs and the final bit, with point and full-domain evaluation.

use crate::tree::{child, conv, expand, CorrectionWord};
use dpf_common::block::{depth_for, Block};

#[derive(Clone, Debug)]
pub struct FssKey {
    pub party: usize,
    pub n_size: u64,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub fcw: bool,
}

impl FssKey {
    /// Input bits n.
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[CorrectionWord], bool) {
        (&self.cws, self.fcw)
    }

    /// Root (16) + per level 16 + 1 bytes + final bit (1 byte). In bits this
    /// is FssNN's `n(λ + 3) + λ + 1` without the `v` bit per level.
    pub fn size_bytes(&self) -> usize {
        16 + 17 * self.cws.len() + 1
    }

    fn output(&self, leaf: Block) -> bool {
        conv(leaf) ^ (leaf.lsb() & self.fcw)
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> bool {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut node = self.root;
        for (i, cw) in self.cws.iter().enumerate() {
            node = child(node, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        self.output(node)
    }

    /// Shares of `f(0), …, f(N − 1)`: expands all 2^n leaves, then drops the
    /// padding positions `x ≥ N`.
    pub fn eval_full(&self) -> Vec<bool> {
        let mut nodes = vec![self.root];
        for cw in &self.cws {
            let mut next = Vec::with_capacity(2 * nodes.len());
            for &v in &nodes {
                let [l, r] = expand(v);
                let (cl, cr) = if v.lsb() { (cw.s ^ Block(cw.t[0] as u128), cw.s ^ Block(cw.t[1] as u128)) } else { (Block::ZERO, Block::ZERO) };
                next.push(l ^ cl);
                next.push(r ^ cr);
            }
            nodes = next;
        }
        nodes[..self.n_size as usize].iter().map(|&v| self.output(v)).collect()
    }
}
