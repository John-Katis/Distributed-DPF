//! One party's GGM tree for XLH+25 Alg. 2, expanded the way the authors'
//! reference code does it (`expandDpfPrgLevel` in `src/legacy/dpf.cpp`):
//!
//! * `G(s) = AES_s(0) ∥ AES_s(1)`, i.e. AES-128 keyed by the seed. The left and
//!   right children are the two output blocks, and a child's control bit is
//!   its lsb (the `s∥t` of Alg. 2 line 4 read as one 128-bit block).
//! * Correction (lines 10–13): if the parent's control bit is 1, both children
//!   are XORed with σ and each child's control bit with `τ_side`. σ has lsb 0
//!   and a corrected node's lsb is set to its control bit, which keeps the
//!   paper's `s ∥ t` split: with a full-block σ, `lsb(σ) = τ_{ᾱ_i}` would make
//!   α_i public whenever `τ_0 ≠ τ_1`.
//!
//! The tree is always the full `2^n`-leaf tree: a domain size N that is not a
//! power of two is padded, and every level expands every node.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use dpf_common::arith::{convert, Ring};
use dpf_common::block::{depth_for, expand_in_place, Block};
use dpf_common::stream::{walk, TreeMode};

/// `Convert_ℓ(s)` of a leaf label `s`: the ℓ bits above its control bit for
/// ℓ ≤ 127 ([`convert`]); for ℓ = 128 the seed is too short, and the output is
/// `AES_s(0)`, the first block of `G(s)` (one more PRG call per leaf).
#[inline]
pub fn conv<R: Ring>(s: Block, bits: usize) -> R {
    if bits < 128 {
        convert(s, bits)
    } else {
        let aes = Aes128::new(GenericArray::from_slice(&s.to_bytes()));
        let mut b = GenericArray::from(0u128.to_le_bytes());
        aes.encrypt_block(&mut b);
        R::from_block(Block::from_bytes(b.as_slice()))
    }
}

/// `G(s) = (AES_s(0), AES_s(1))`.
#[inline]
pub fn expand(s: Block) -> [Block; 2] {
    let aes = Aes128::new(GenericArray::from_slice(&s.to_bytes()));
    let mut buf = [GenericArray::from(0u128.to_le_bytes()), GenericArray::from(1u128.to_le_bytes())];
    aes.encrypt_blocks(&mut buf);
    [Block::from_bytes(buf[0].as_slice()), Block::from_bytes(buf[1].as_slice())]
}

/// One level's correction word `CW_i = σ ∥ τ_0 ∥ τ_1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionWord {
    /// Seed correction, lsb 0.
    pub sigma: Block,
    pub tau: [bool; 2],
}

/// One party's tree, advanced one level at a time.
pub struct Tree {
    depth: usize,
    level: usize,
    /// The current level, allocated once for `2^n` nodes. [`expand_level`]
    /// (Self::expand_level) replaces it in place by the uncorrected children,
    /// [`correct`](Self::correct) corrects them in place.
    nodes: Vec<Block>,
    /// Control bits of the last corrected level.
    t: Vec<bool>,
}

impl Tree {
    /// Root seed `s^{0,0}` with control bit `t^{0,0} = b` (Alg. 2 line 2).
    pub fn new(n_size: u64, root: Block, t0: bool) -> Self {
        let depth = depth_for(n_size);
        let mut nodes = Vec::with_capacity(1 << depth);
        nodes.push(root);
        Tree { depth, level: 0, nodes, t: vec![t0] }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Lines 4–5: expands every node and returns `(S^{i,0}, S^{i,1})`, the XOR
    /// of all left and of all right children.
    pub fn expand_level(&mut self) -> (Block, Block) {
        assert!(self.level < self.depth);
        assert_eq!(self.nodes.len(), self.t.len());
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        expand_in_place(&mut self.nodes, |ps, out| {
            for (j, s) in ps.iter().enumerate() {
                let kids = expand(*s);
                l ^= kids[0];
                r ^= kids[1];
                out[2 * j] = kids[0];
                out[2 * j + 1] = kids[1];
            }
        });
        (l, r)
    }

    /// Lines 10–13 with the level's correction word.
    pub fn correct(&mut self, cw: CorrectionWord) {
        assert_eq!(self.nodes.len(), 2 * self.t.len());
        let mut t = Vec::with_capacity(self.nodes.len());
        for (c, x) in self.nodes.iter_mut().enumerate() {
            let tp = self.t[c / 2];
            let tc = x.lsb() ^ (tp & cw.tau[c & 1]);
            t.push(tc);
            *x = (*x ^ cw.sigma.and_bit(tp)).with_lsb(tc);
        }
        self.t = t;
        self.level += 1;
    }

    /// All `2^n` leaves `s^{ℓ_in, i}` and their control bits, after the last
    /// level.
    pub fn leaves(&self) -> (&[Block], &[bool]) {
        assert_eq!(self.level, self.depth);
        (&self.nodes, &self.t)
    }
}

/// The per-level interface that Gen drives. [`Tree`] stores every level (the
/// reference code); [`TreeStream`] regenerates them ([`dpf_common::stream`]).
pub trait ArithTree: Sized {
    fn new(n_size: u64, root: Block, t0: bool, mode: TreeMode) -> Self;
    /// Lines 4–5: `(S^{i,0}, S^{i,1})` of the next level.
    fn expand_level(&mut self) -> (Block, Block);
    /// Lines 10–13 with the level's correction word.
    fn correct(&mut self, cw: CorrectionWord);
    /// Line 16 over all `2^n` leaves: `(Σ Convert_ℓ(s) mod 2^|R|, Σ t)`.
    fn leaf_sums<R: Ring>(&self, bits: usize) -> (R, u64);
    /// The leaf at `x` and its control bit.
    fn leaf(&self, x: u64) -> (Block, bool);
    /// The leaves `x < n` and their control bits, if the tree keeps them.
    fn stored_leaves(&self, n: usize) -> Option<(&[Block], &[bool])>;
}

impl ArithTree for Tree {
    fn new(n_size: u64, root: Block, t0: bool, _: TreeMode) -> Self {
        Tree::new(n_size, root, t0)
    }
    fn expand_level(&mut self) -> (Block, Block) {
        Tree::expand_level(self)
    }
    fn correct(&mut self, cw: CorrectionWord) {
        Tree::correct(self, cw)
    }
    fn leaf_sums<R: Ring>(&self, bits: usize) -> (R, u64) {
        let (seeds, ts) = self.leaves();
        let w = seeds.iter().fold(R::ZERO, |a, s| a.add(conv(*s, bits)));
        (w, ts.iter().filter(|t| **t).count() as u64)
    }
    fn leaf(&self, x: u64) -> (Block, bool) {
        let (s, t) = self.leaves();
        (s[x as usize], t[x as usize])
    }
    fn stored_leaves(&self, n: usize) -> Option<(&[Block], &[bool])> {
        let (s, t) = self.leaves();
        Some((&s[..n], &t[..n]))
    }
}

/// The same tree as [`Tree`], holding only the root and the correction words
/// so far. Every sum is recomputed by a batched walk from the root.
pub struct TreeStream {
    depth: usize,
    batch: usize,
    root: Block,
    t0: bool,
    cws: Vec<CorrectionWord>,
}

impl TreeStream {
    /// A streaming tree over known correction words (for key evaluation).
    pub fn with_cws(n_size: u64, root: Block, t0: bool, cws: Vec<CorrectionWord>, batch: usize) -> Self {
        TreeStream { depth: depth_for(n_size), batch, root, t0, cws }
    }

    /// Corrected children at level `level` (1-based). Below the root a node's
    /// lsb is its control bit; the root's control bit is `t0`.
    fn expand(&self, level: usize, parents: &[Block], out: &mut Vec<Block>) {
        let cw = self.cws[level - 1];
        for p in parents {
            let tp = if level == 1 { self.t0 } else { p.lsb() };
            for (side, x) in expand(*p).into_iter().enumerate() {
                let tc = x.lsb() ^ (tp & cw.tau[side]);
                out.push((x ^ cw.sigma.and_bit(tp)).with_lsb(tc));
            }
        }
    }

    /// Visits the leaves (all `2^n`, padding included) in order and batches.
    /// A leaf's lsb is its control bit.
    pub fn visit_leaves(&self, visit: impl FnMut(u64, &[Block])) {
        assert_eq!(self.cws.len(), self.depth);
        walk(self.root, self.depth, self.batch, |l, p, o| self.expand(l, p, o), visit);
    }
}

impl ArithTree for TreeStream {
    fn new(n_size: u64, root: Block, t0: bool, mode: TreeMode) -> Self {
        TreeStream::with_cws(n_size, root, t0, Vec::new(), mode.batch())
    }

    fn expand_level(&mut self) -> (Block, Block) {
        assert!(self.cws.len() < self.depth);
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        walk(self.root, self.cws.len(), self.batch, |lv, p, o| self.expand(lv, p, o), |_, nodes| {
            for s in nodes {
                let kids = expand(*s);
                l ^= kids[0];
                r ^= kids[1];
            }
        });
        (l, r)
    }

    fn correct(&mut self, cw: CorrectionWord) {
        self.cws.push(cw);
    }

    fn leaf_sums<R: Ring>(&self, bits: usize) -> (R, u64) {
        let (mut w, mut tc) = (R::ZERO, 0u64);
        self.visit_leaves(|_, leaves| {
            for s in leaves {
                w = w.add(conv(*s, bits));
                tc += s.lsb() as u64;
            }
        });
        (w, tc)
    }

    fn leaf(&self, x: u64) -> (Block, bool) {
        let (mut s, mut t) = (self.root, self.t0);
        for (j, cw) in self.cws.iter().enumerate() {
            let side = ((x >> (self.depth - 1 - j)) & 1) as usize;
            let raw = expand(s)[side];
            let tc = raw.lsb() ^ (t & cw.tau[side]);
            s = (raw ^ cw.sigma.and_bit(t)).with_lsb(tc);
            t = tc;
        }
        (s, t)
    }

    fn stored_leaves(&self, _: usize) -> Option<(&[Block], &[bool])> {
        None
    }
}
