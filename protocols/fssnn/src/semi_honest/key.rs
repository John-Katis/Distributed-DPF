//! The semi-honest key ([`crate::tree`] for the tree it walks): root, the
//! n level CWs and the final word, with point and full-domain evaluation.

use crate::tree::{child, expand, CorrectionWord, Group};
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;

#[derive(Clone, Debug)]
pub struct FssKey {
    pub party: usize,
    pub n_size: u64,
    pub group: Group,
    /// ℓ, the output width.
    pub bits: usize,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub fcw: u64,
}

impl FssKey {
    /// Input bits n.
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[CorrectionWord], u64) {
        (&self.cws, self.fcw)
    }

    /// Root (16) + per level 16 + 1 bytes + final word (ℓ bits). In bits this
    /// is FssNN's `n(λ + 3) + λ + 1` without the `v` bit per level, for ℓ = 1.
    pub fn size_bytes(&self) -> usize {
        16 + 17 * self.cws.len() + self.bits.div_ceil(8)
    }

    fn output(&self, leaf: Block) -> u64 {
        self.group.output(self.party, self.bits, leaf, self.fcw)
    }

    /// This party's share of `f(x)` (XOR or additive, per [`Group`]).
    pub fn eval_point(&self, x: u64) -> u64 {
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
    pub fn eval_full(&self) -> Vec<u64> {
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

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, ys)` with this
    /// party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[u64])) {
        let expand_level = |l: usize, parents: &[Block], out: &mut Vec<Block>| {
            let cw = &self.cws[l - 1];
            for &v in parents {
                let [a, b] = expand(v);
                let (cl, cr) = if v.lsb() { (cw.s ^ Block(cw.t[0] as u128), cw.s ^ Block(cw.t[1] as u128)) } else { (Block::ZERO, Block::ZERO) };
                out.push(a ^ cl);
                out.push(b ^ cr);
            }
        };
        let mut ys = Vec::new();
        walk(self.root, self.cws.len(), batch, expand_level, |x0, leaves| {
            if x0 >= self.n_size {
                return;
            }
            ys.clear();
            ys.extend(leaves[..leaves.len().min((self.n_size - x0) as usize)].iter().map(|&v| self.output(v)));
            visit(x0, &ys);
        });
    }
}
