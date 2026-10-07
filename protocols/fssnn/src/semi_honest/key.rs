//! The semi-honest key ([`crate::tree`] for the tree it walks): root, the
//! υ level CWs and the final word, with point and full-domain evaluation.

use crate::tree::{child, conv, expand, CorrectionWord};
use dpf_common::block::{depth_for, Block};

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
