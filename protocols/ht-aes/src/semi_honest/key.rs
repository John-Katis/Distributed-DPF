//! The semi-honest key: root `Δ_b`, n level words, the payload word in
//! Z_2^ℓ, and its point and full-domain evaluation.

use crate::{child, children, leaf_seed, pay_hash};
use dpf_common::arith::Ring;
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShKey<T: Ring> {
    pub party: usize,
    pub n_size: u64,
    /// ℓ, the output width.
    pub bits: usize,
    /// `st_{0,b} = Δ_b`.
    pub root: Block,
    pub cws: Vec<Block>,
    /// `W_CW = (−1)^{t_{n,0}}·(W_0 − W_1 − β)`.
    pub w_cw: T,
}

impl<T: Ring> ShKey<T> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// Root, n words of 16 bytes, the payload word in ⌈ℓ/8⌉ bytes.
    pub fn size_bytes(&self) -> usize {
        16 + 16 * self.cws.len() + self.bits.div_ceil(8)
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[Block], T) {
        (&self.cws, self.w_cw)
    }

    /// `(−1)^b·(F^pay(s) + t·W_CW)` at a leaf.
    #[inline]
    fn output(&self, leaf: Block, w: Block) -> T {
        let m = T::mask(self.bits);
        let mut y = T::from_block(w).and(m);
        if leaf.lsb() {
            y = y.add(self.w_cw);
        }
        if self.party == 1 {
            y = y.neg();
        }
        y.and(m)
    }

    /// This party's additive share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> T {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root;
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(st, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        self.output(st, pay_hash().h(leaf_seed(st)))
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<T> {
        let mut nodes = vec![self.root];
        for &cw in &self.cws {
            let mut next = Vec::new();
            children(&nodes, cw, &mut next);
            nodes = next;
        }
        nodes.truncate(self.n_size as usize);
        self.outputs(&nodes)
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, ys)` with this
    /// party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[T])) {
        walk(self.root, self.cws.len(), batch, |l, parents, out| children(parents, self.cws[l - 1], out), |x0, leaves| {
            if x0 < self.n_size {
                visit(x0, &self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)]));
            }
        });
    }

    fn outputs(&self, leaves: &[Block]) -> Vec<T> {
        let seeds: Vec<Block> = leaves.iter().map(|&s| leaf_seed(s)).collect();
        let mut w = vec![Block::ZERO; seeds.len()];
        pay_hash().h_many(&seeds, &mut w);
        leaves.iter().zip(&w).map(|(&s, &wv)| self.output(s, wv)).collect()
    }
}
