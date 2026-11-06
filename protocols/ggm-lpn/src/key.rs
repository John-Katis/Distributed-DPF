//! The key: root, two seed words and two tag words per level, `M_ℓ` for the
//! levels from the glue level on, and the leaf word; point and full-domain
//! evaluation.

use crate::Word;
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;
use fssnn::tree::{conv, expand};

/// The public words of one level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LevelWord {
    /// `s^L_CW`, `s^R_CW`, tag bit clear.
    pub s: [Block; 2],
    /// `t^L_CW`, `t^R_CW`.
    pub t: [bool; 2],
}

impl LevelWord {
    /// The correction of child σ: `s^σ_CW ∥ t^σ_CW`.
    #[inline]
    pub fn side(&self, sigma: usize) -> Block {
        self.s[sigma] ^ Block(self.t[sigma] as u128)
    }

    /// Both children of a node, given `G` of its seed, `g`, its tag `t` and
    /// the level's shift `m`.
    #[inline]
    pub fn children(&self, g: [Block; 2], t: bool, m: Block) -> [Block; 2] {
        [g[0] ^ self.side(0).and_bit(t) ^ m, g[1] ^ self.side(1).and_bit(t) ^ m]
    }
}

#[derive(Clone, Debug)]
pub struct BinKey {
    pub party: usize,
    pub n_size: u64,
    /// ℓ ≤ 256.
    pub bits: usize,
    /// The glue level ν, `0 ≤ ν ≤ n`.
    pub nu: usize,
    pub root: Block,
    /// The n level words.
    pub cws: Vec<LevelWord>,
    /// `M_ℓ` for `ℓ = max(ν, 1), …, n`.
    pub ms: Vec<Block>,
    /// `Conv(u_{n,0}) ⊕ Conv(u_{n,1}) ⊕ β`.
    pub w_cw: Word,
}

impl BinKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// `M_ℓ` for level `level` (1-based), zero above the glue level.
    #[inline]
    pub fn m(&self, level: usize) -> Block {
        let first = self.nu.max(1);
        if level >= first {
            self.ms[level - first]
        } else {
            Block::ZERO
        }
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[LevelWord], &[Block], Word) {
        (&self.cws, &self.ms, self.w_cw)
    }

    /// Root (16), per level two seed words and a byte of tag words (33), 16
    /// per `M_ℓ`, ⌈ℓ/8⌉ for the leaf word.
    pub fn size_bytes(&self) -> usize {
        16 + 33 * self.cws.len() + 16 * self.ms.len() + self.bits.div_ceil(8)
    }

    #[inline]
    fn output(&self, leaf: Block) -> Word {
        let corr = if leaf.lsb() { self.w_cw } else { Word::ZERO };
        conv(leaf, self.bits) ^ corr
    }

    /// This party's XOR share of `f(x)`. Computes `G` of every node on the
    /// path (both children) and keeps the one `x` selects.
    pub fn eval_point(&self, x: u64) -> Word {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut node = self.root;
        for (i, cw) in self.cws.iter().enumerate() {
            let kids = cw.children(expand(node), node.lsb(), self.m(i + 1));
            node = kids[((x >> (n - 1 - i)) & 1) as usize];
        }
        self.output(node)
    }

    fn expand_level(&self, level: usize, parents: &[Block], out: &mut Vec<Block>) {
        let (cw, m) = (&self.cws[level - 1], self.m(level));
        for &v in parents {
            out.extend(cw.children(expand(v), v.lsb(), m));
        }
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<Word> {
        let mut nodes = vec![self.root];
        for l in 1..=self.cws.len() {
            let mut next = Vec::with_capacity(2 * nodes.len());
            self.expand_level(l, &nodes, &mut next);
            nodes = next;
        }
        nodes[..self.n_size as usize].iter().map(|&v| self.output(v)).collect()
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, ys)` with this
    /// party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[Word])) {
        let mut ys = Vec::new();
        walk(self.root, self.cws.len(), batch, |l, p: &[Block], out: &mut Vec<Block>| self.expand_level(l, p, out), |x0, leaves| {
            if x0 >= self.n_size {
                return;
            }
            ys.clear();
            ys.extend(leaves[..leaves.len().min((self.n_size - x0) as usize)].iter().map(|&v| self.output(v)));
            visit(x0, &ys);
        });
    }
}
