//! The keys: root, two seed words and two tag words per level, `M_ℓ` for the
//! levels from the glue level on ([`Tree`]), and the leaf word of a Boolean
//! ([`BinKey`]) or arithmetic ([`ArithKey`]) payload; point and full-domain
//! evaluation.

use crate::Word;
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;
use fssnn::tree::{conv, expand, SEED_BITS};
use ht_aes::field::Field;
use std::ops::Deref;

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

/// The tree part of a key, the same for every payload.
#[derive(Clone, Debug)]
pub struct Tree {
    pub n_size: u64,
    /// The glue level ν, `0 ≤ ν ≤ n`.
    pub nu: usize,
    pub root: Block,
    /// The n level words.
    pub cws: Vec<LevelWord>,
    /// `M_ℓ` for `ℓ = max(ν, 1), …, n`.
    pub ms: Vec<Block>,
}

impl Tree {
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

    /// Root (16), per level two seed words and a byte of tag words (33), 16
    /// per `M_ℓ`.
    fn tree_bytes(&self) -> usize {
        16 + 33 * self.cws.len() + 16 * self.ms.len()
    }

    /// The leaf state of `x`. Computes `G` of every node on the path (both
    /// children) and keeps the one `x` selects.
    fn leaf(&self, x: u64) -> Block {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut node = self.root;
        for (i, cw) in self.cws.iter().enumerate() {
            let kids = cw.children(expand(node), node.lsb(), self.m(i + 1));
            node = kids[((x >> (n - 1 - i)) & 1) as usize];
        }
        node
    }

    fn expand_level(&self, level: usize, parents: &[Block], out: &mut Vec<Block>) {
        let (cw, m) = (&self.cws[level - 1], self.m(level));
        for &v in parents {
            out.extend(cw.children(expand(v), v.lsb(), m));
        }
    }

    /// The leaf states of `0, …, N − 1`, one level at a time.
    fn leaves(&self) -> Vec<Block> {
        let mut nodes = vec![self.root];
        for l in 1..=self.cws.len() {
            let mut next = Vec::with_capacity(2 * nodes.len());
            self.expand_level(l, &nodes, &mut next);
            nodes = next;
        }
        nodes.truncate(self.n_size as usize);
        nodes
    }

    /// A batched walk ([`dpf_common::stream`]): `visit(x0, leaves)` for all x < N.
    fn walk_leaves(&self, batch: usize, mut visit: impl FnMut(u64, &[Block])) {
        walk(self.root, self.cws.len(), batch, |l, p: &[Block], out: &mut Vec<Block>| self.expand_level(l, p, out), |x0, leaves| {
            if x0 < self.n_size {
                visit(x0, &leaves[..leaves.len().min((self.n_size - x0) as usize)]);
            }
        });
    }
}

/// A key with an XOR-shared payload in `{0,1}^ℓ`.
#[derive(Clone, Debug)]
pub struct BinKey {
    pub party: usize,
    /// ℓ ≤ 256.
    pub bits: usize,
    pub tree: Tree,
    /// `Conv(u_{n,0}) ⊕ Conv(u_{n,1}) ⊕ β`.
    pub w_cw: Word,
}

impl Deref for BinKey {
    type Target = Tree;
    fn deref(&self) -> &Tree {
        &self.tree
    }
}

impl BinKey {
    /// The part both parties share.
    pub fn public_part(&self) -> (&[LevelWord], &[Block], Word) {
        (&self.cws, &self.ms, self.w_cw)
    }

    /// The tree, and ⌈ℓ/8⌉ for the leaf word.
    pub fn size_bytes(&self) -> usize {
        self.tree_bytes() + self.bits.div_ceil(8)
    }

    #[inline]
    fn output(&self, leaf: Block) -> Word {
        let corr = if leaf.lsb() { self.w_cw } else { Word::ZERO };
        conv(leaf, self.bits) ^ corr
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> Word {
        self.output(self.leaf(x))
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<Word> {
        self.leaves().iter().map(|&v| self.output(v)).collect()
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: `visit(x0,
    /// ys)` with this party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[Word])) {
        let mut ys = Vec::new();
        self.walk_leaves(batch, |x0, leaves| {
            ys.clear();
            ys.extend(leaves.iter().map(|&v| self.output(v)));
            visit(x0, &ys);
        });
    }
}

/// The block whose low κ bits are the payload mask of a leaf state: its seed
/// bits if they suffice (κ ≤ λ = 127, as `Conv` of the Boolean leaf), else
/// the first output block of `G`. XOR-linear in the state in the first case.
#[inline]
pub(crate) fn seed_mask(st: Block) -> Block {
    Block(st.0 >> 1)
}

/// Whether the mask of [`seed_mask`] has enough bits for F.
pub(crate) fn mask_from_seed<F: Field>() -> bool {
    F::KAPPA <= SEED_BITS
}

/// The payload mask block of a leaf state over F.
#[inline]
pub(crate) fn leaf_mask<F: Field>(st: Block) -> Block {
    if mask_from_seed::<F>() {
        seed_mask(st)
    } else {
        expand(st)[0]
    }
}

/// A key with a public payload in a prime field F and additive output shares.
#[derive(Clone, Debug)]
pub struct ArithKey<F: Field> {
    pub party: usize,
    pub tree: Tree,
    /// `W^(0) − W^(1) − (1 − 2σ)·β`, the masks indexed by tag, `σ = t_{n,0}`.
    pub w_cw: F,
}

impl<F: Field> Deref for ArithKey<F> {
    type Target = Tree;
    fn deref(&self) -> &Tree {
        &self.tree
    }
}

impl<F: Field> ArithKey<F> {
    /// The tree, and one field element for the leaf word.
    pub fn size_bytes(&self) -> usize {
        self.tree_bytes() + F::BYTES
    }

    /// `(−1)^b [w + t·W_CW]` at the leaf state `s ∥ t`.
    #[inline]
    fn output(&self, leaf: Block) -> F {
        let mut y = F::from_block(leaf_mask::<F>(leaf));
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
    pub fn eval_point(&self, x: u64) -> F {
        self.output(self.leaf(x))
    }

    /// Shares of `f(0), …, f(N − 1)`.
    pub fn eval_full(&self) -> Vec<F> {
        self.leaves().iter().map(|&v| self.output(v)).collect()
    }

    /// [`eval_full`](Self::eval_full) without holding the domain.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[F])) {
        let mut ys = Vec::new();
        self.walk_leaves(batch, |x0, leaves| {
            ys.clear();
            ys.extend(leaves.iter().map(|&v| self.output(v)));
            visit(x0, &ys);
        });
    }
}
