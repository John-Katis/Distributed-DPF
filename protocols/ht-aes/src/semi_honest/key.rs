//! The semi-honest key: K, root `st_{0,b}`, n level words, the words of the
//! bottom layer ([`Bottom`]), the payload word in F_p, and its point and
//! full-domain evaluation.

use crate::field::Field;
use crate::{expand_level, Bottom};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShKey<T: Field> {
    pub party: usize,
    pub n_size: u64,
    /// `F = H_K`, K public.
    pub prf: Mmo,
    /// `st_{0,b}`, with `st_{0,0} ⊕ st_{0,1} = Δ`.
    pub root: Block,
    pub cws: Vec<Block>,
    /// `M^0_ℓ`, `C_ℓ` and `b^τ_ℓ` for `ν ≤ ℓ ≤ n`.
    pub bottom: Bottom,
    /// `W_CW = (1 − 2t_{n,0})·(W_0 − W_1 − β)`, `W_b` the mask of `X^b_n`.
    pub w_cw: T,
}

impl<T: Field> ShKey<T> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The glue level ν.
    pub fn nu(&self) -> usize {
        self.bottom.nu
    }

    /// K, root, n level words, the bottom layer's words, the payload word.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + 16 * self.cws.len() + self.bottom.size_bytes() + T::BYTES
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[Block], &Bottom, T) {
        (&self.cws, &self.bottom, self.w_cw)
    }

    /// `(−1)^b·(w + t·W_CW)` at a leaf, w the mask read in F_p
    /// ([`Field::from_block`]).
    #[inline]
    fn output(&self, leaf: Block, w: Block) -> T {
        let mut y = T::from_block(w);
        if leaf.lsb() {
            y = y.add(self.w_cw);
        }
        if self.party == 1 {
            y.neg()
        } else {
            y
        }
    }

    /// This party's additive share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> T {
        assert!(x < self.n_size);
        let st = self.bottom.path(&self.prf, self.root, &self.cws, x);
        self.output(st, self.prf.h(self.bottom.hash_input(self.depth(), st)))
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<T> {
        let mut nodes = vec![self.root];
        for (i, &cw) in self.cws.iter().enumerate() {
            let mut next = Vec::new();
            expand_level(&self.prf, &nodes, cw, &self.bottom, i + 1, &mut next);
            nodes = next;
        }
        nodes.truncate(self.n_size as usize);
        let mut ys = Vec::new();
        self.outputs(&nodes, &mut Vec::new(), &mut ys);
        ys
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, ys)` with this
    /// party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[T])) {
        let (mut buf, mut ys) = (Vec::new(), Vec::new());
        walk(
            self.root,
            self.cws.len(),
            batch,
            |l, parents, out| expand_level(&self.prf, parents, self.cws[l - 1], &self.bottom, l, out),
            |x0, leaves| {
                if x0 < self.n_size {
                    self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut ys);
                    visit(x0, &ys);
                }
            },
        );
    }

    /// The outputs at `leaves` into `ys`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, ys: &mut Vec<T>) {
        let k = leaves.len();
        buf.clear();
        let n = self.depth();
        buf.extend(leaves.iter().map(|&s| self.bottom.hash_input(n, s)));
        buf.resize(2 * k, Block::ZERO);
        let (seeds, w) = buf.split_at_mut(k);
        self.prf.h_many(seeds, w);
        ys.clear();
        ys.extend(leaves.iter().zip(&*w).map(|(&s, &wv)| self.output(s, wv)));
    }
}
