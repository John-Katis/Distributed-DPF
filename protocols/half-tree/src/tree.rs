//! One party's share of a Half-Tree (shared pseudorandom correlated GGM tree,
//! GYW+23 §3.2 and Fig. 8), expanded level by level.
//!
//! For a tree of depth `n` with root `X_0`:
//!
//! * levels `1..n−1` are correlated: a parent `X` with t-bit `t = lsb(X)` has
//!   children `H(X) ⊕ t·CW_i` (left) and `H(X) ⊕ X ⊕ t·CW_i` (right). One hash per
//!   parent.
//! * level `n` breaks the correlation: child `σ` is
//!   `H(X ⊕ σ) ⊕ t·(HCW ∥ LCW_σ)`, two hashes per parent.
//!
//! A leaf `X = s ∥ t` yields the payload `Convert(s)`. The tree is always the
//! full `2^n`-leaf tree. A domain size N that is not a power of two is padded
//! (GYW+23 §5): all `2^n` leaves are expanded and enter the sums, and only the
//! outputs for `x < N` are returned.

use dpf_common::block::{depth_for, expand_in_place, Block};
use dpf_common::hash::{convert_hash, CcrHash};
use dpf_common::stream::{walk, TreeMode};

/// Clears the t-bit: `hb(X) ∥ 0`.
#[inline]
pub fn hb(x: Block) -> Block {
    Block(x.0 & !1)
}

/// `Convert` from a leaf to `bm` payload blocks. For payloads of at most 127
/// bits it is the PRG-free conversion of GYW+23 App. F.1 (the 127 seed bits
/// `s = hb(X)` shifted down). Wider payloads hash `s` with a domain-separated
/// fixed-key hash, one call per block. Bits from `out_bits` on are cleared, so
/// the payload is exactly `out_bits` wide and `CW_{n+1}` is opened in
/// `ceil(out_bits/8)` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convert {
    pub out_bits: usize,
    pub bm: usize,
}

impl Convert {
    pub fn new(out_bits: usize) -> Self {
        Convert { out_bits, bm: dpf_common::block::blocks_for_bits(out_bits) }
    }

    /// Mask of payload block `k`.
    #[inline]
    fn mask(&self, k: usize) -> u128 {
        if k + 1 == self.bm { dpf_common::block::last_block_mask(self.out_bits) } else { u128::MAX }
    }

    #[inline]
    fn identity(&self) -> bool {
        self.out_bits <= 127
    }

    /// Payload block `k` for one leaf.
    #[inline]
    pub fn word(&self, leaf: Block, k: usize) -> Block {
        if self.identity() {
            Block((leaf.0 >> 1) & self.mask(0))
        } else {
            Block(convert_hash().h(hb(leaf), k as u64).0 & self.mask(k))
        }
    }

    /// Payload column `k` for all leaves.
    pub fn column(&self, leaves: &[Block], k: usize) -> Vec<Block> {
        let m = self.mask(k);
        if self.identity() {
            leaves.iter().map(|x| Block((x.0 >> 1) & m)).collect()
        } else {
            let mut out = vec![Block::ZERO; leaves.len()];
            let mut s = [Block::ZERO; 1024];
            for (l, o) in leaves.chunks(s.len()).zip(out.chunks_mut(s.len())) {
                for (si, x) in s.iter_mut().zip(l) {
                    *si = hb(*x);
                }
                convert_hash().h_many(&s[..l.len()], k as u64, o);
            }
            if m != u128::MAX {
                out.iter_mut().for_each(|x| x.0 &= m);
            }
            out
        }
    }
}

/// One party's full-domain output: `bm` blocks for each of the `n` points,
/// stored column-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullEval {
    pub n: usize,
    pub bm: usize,
    pub(crate) cols: Vec<Vec<Block>>,
}

impl FullEval {
    pub fn get(&self, x: usize) -> Vec<Block> {
        self.cols.iter().map(|c| c[x]).collect()
    }

    pub fn column(&self, k: usize) -> &[Block] {
        &self.cols[k]
    }
}

/// One party's tree, advanced one level at a time.
pub struct HtLocal {
    h: CcrHash,
    n_size: u64,
    depth: usize,
    conv: Convert,
    /// Levels expanded with the correlated rule: `depth − 1` for the
    /// semi-honest tree, `depth` for the malicious one.
    corr_levels: usize,
    /// Level of `nodes` (0 = root).
    level: usize,
    /// The current level. Allocated once for `2^n` nodes; every level is
    /// expanded into it in place.
    nodes: Vec<Block>,
    /// `H(nodes)`, filled by [`correlated_sum`](HtLocal::correlated_sum).
    scratch: Vec<Block>,
    /// The parents' t-bits while `nodes` holds the raw last-level children.
    parent_t: Vec<bool>,
    leaf_cols: Vec<Vec<Block>>,
    /// The leaves' t-bits, kept by [`finalize`](HtLocal::finalize) when the
    /// identity `Convert` turns `nodes` into the payload column.
    leaf_t: Vec<bool>,
}

fn sum_interleaved(v: &[Block]) -> (Block, Block) {
    let mut l = Block::ZERO;
    let mut r = Block::ZERO;
    for pair in v.chunks(2) {
        l ^= pair[0];
        r ^= pair[1];
    }
    (l, r)
}

impl HtLocal {
    /// The semi-honest tree: correlated levels `1..n−1`, then the last level.
    pub fn start(h: CcrHash, n_size: u64, conv: Convert, root: Block) -> Self {
        let depth = depth_for(n_size);
        Self::with_corr_levels(h, n_size, conv, root, depth - 1)
    }

    /// The malicious tree of ZGY+24 Fig. 5: every level is correlated, and the
    /// caller hashes the leaves itself.
    pub fn start_all_correlated(h: CcrHash, n_size: u64, root: Block) -> Self {
        let depth = depth_for(n_size);
        Self::with_corr_levels(h, n_size, Convert::new(128), root, depth)
    }

    fn with_corr_levels(h: CcrHash, n_size: u64, conv: Convert, root: Block, corr_levels: usize) -> Self {
        let depth = depth_for(n_size);
        let mut nodes = Vec::with_capacity(1 << depth);
        nodes.push(root);
        HtLocal {
            h,
            n_size,
            depth,
            conv,
            corr_levels,
            level: 0,
            nodes,
            scratch: Vec::new(),
            parent_t: Vec::new(),
            leaf_cols: Vec::new(),
            leaf_t: Vec::new(),
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Before a correlated level: hashes every node and returns `⊕_j H(X^j)`.
    pub fn correlated_sum(&mut self) -> Block {
        assert!(self.level < self.corr_levels, "next level is not correlated");
        self.scratch.clear();
        self.scratch.resize(self.nodes.len(), Block::ZERO);
        self.h.h_many(&self.nodes, &mut self.scratch);
        self.scratch.iter().fold(Block::ZERO, |a, b| a ^ *b)
    }

    /// Expands a correlated level with its correction word. Needs
    /// [`correlated_sum`](Self::correlated_sum) first.
    pub fn apply_correlated(&mut self, cw: Block) {
        // In place, from the back: children 2j, 2j+1 only overwrite parents
        // ≥ j, which are already expanded.
        let p = self.nodes.len();
        self.nodes.resize(2 * p, Block::ZERO);
        for j in (0..p).rev() {
            let x = self.nodes[j];
            let l = self.scratch[j] ^ cw.and_bit(x.lsb());
            self.nodes[2 * j] = l;
            self.nodes[2 * j + 1] = l ^ x;
        }
        self.level += 1;
        if self.level == self.depth {
            self.scratch = Vec::new();
        }
    }

    /// The current level's nodes (the leaves once every level is expanded).
    pub fn nodes(&self) -> &[Block] {
        &self.nodes
    }

    /// Before the last level: computes the raw children `H(X ⊕ σ)` and returns
    /// `(⊕_j H(X^j), ⊕_j H(X^j ⊕ 1))` over all parents.
    pub fn last_sums(&mut self) -> (Block, Block) {
        assert_eq!(self.level + 1, self.depth);
        assert_eq!(self.corr_levels + 1, self.depth);
        self.parent_t = self.nodes.iter().map(|x| x.lsb()).collect();
        self.scratch = Vec::new();
        let h = &self.h;
        let mut q0 = [Block::ZERO; 1024];
        let mut q1 = [Block::ZERO; 1024];
        expand_in_place(&mut self.nodes, |ps, out| {
            let k = ps.len();
            h.h_many_tweak(ps, Block::ZERO, &mut q0[..k]);
            h.h_many_tweak(ps, Block(1), &mut q1[..k]);
            for j in 0..k {
                out[2 * j] = q0[j];
                out[2 * j + 1] = q1[j];
            }
        });
        sum_interleaved(&self.nodes)
    }

    /// Applies `(HCW, LCW_0, LCW_1)` to the last level. `hcw`'s lsb is ignored.
    pub fn apply_last(&mut self, hcw: Block, lcw: [bool; 2]) {
        let corr = [Block(hb(hcw).0 | lcw[0] as u128), Block(hb(hcw).0 | lcw[1] as u128)];
        for (c, x) in self.nodes.iter_mut().enumerate() {
            *x ^= corr[c & 1].and_bit(self.parent_t[c / 2]);
        }
        self.parent_t = Vec::new();
        self.level += 1;
    }

    /// After the last level: converts all `2^n` leaves and returns
    /// `⊕_j Convert(leaf_j)` per payload block. With `keep_output` the payload
    /// columns are kept for [`output`](Self::output); otherwise they are
    /// folded chunk by chunk and dropped, and `output` must not be called.
    pub fn finalize(&mut self, keep_output: bool) -> Vec<Block> {
        assert_eq!(self.level, self.depth);
        assert_eq!(self.nodes.len(), 1 << self.depth);
        if !keep_output {
            let mut acc = vec![Block::ZERO; self.conv.bm];
            for leaves in self.nodes.chunks(1024) {
                for (k, a) in acc.iter_mut().enumerate() {
                    *a = self.conv.column(leaves, k).iter().fold(*a, |x, y| x ^ *y);
                }
            }
            return acc;
        }
        if self.conv.identity() {
            // One payload block: shift the leaves in place, keeping the t-bits.
            let n = self.n_size as usize;
            self.leaf_t = self.nodes[..n].iter().map(|x| x.lsb()).collect();
            let m = self.conv.mask(0);
            let mut col = std::mem::take(&mut self.nodes);
            for x in col.iter_mut() {
                *x = Block((x.0 >> 1) & m);
            }
            self.leaf_cols = vec![col];
        } else {
            self.leaf_cols = (0..self.conv.bm).map(|k| self.conv.column(&self.nodes, k)).collect();
        }
        self.leaf_cols.iter().map(|c| c.iter().fold(Block::ZERO, |a, b| a ^ *b)).collect()
    }

    /// Output shares `y(x) = Convert(leaf_x) ⊕ t_x·CW_{n+1}` for `x < N`.
    pub fn output(self, cw_out: &[Block]) -> FullEval {
        let n = self.n_size as usize;
        let t = if self.conv.identity() { self.leaf_t } else { self.nodes[..n].iter().map(|x| x.lsb()).collect() };
        let cols = self
            .leaf_cols
            .into_iter()
            .zip(cw_out)
            .map(|(mut col, g)| {
                col.truncate(n);
                for (y, &tx) in col.iter_mut().zip(&t) {
                    *y ^= g.and_bit(tx);
                }
                col
            })
            .collect();
        FullEval { n: self.n_size as usize, bm: self.conv.bm, cols }
    }
}

/// The per-level interface that Gen drives. [`HtLocal`] stores every level;
/// [`HtStream`] regenerates them ([`dpf_common::stream`]).
pub trait HtTree: Sized {
    /// The semi-honest tree: correlated levels `1..n−1`, then the last level.
    fn start(h: CcrHash, n_size: u64, conv: Convert, root: Block, mode: TreeMode) -> Self;
    /// The malicious tree: every level correlated.
    fn start_all_correlated(h: CcrHash, n_size: u64, root: Block, mode: TreeMode) -> Self;
    fn correlated_sum(&mut self) -> Block;
    fn apply_correlated(&mut self, cw: Block);
    fn last_sums(&mut self) -> (Block, Block);
    fn apply_last(&mut self, hcw: Block, lcw: [bool; 2]);
    /// `⊕_j Convert(leaf_j)`; `keep_output` asks the tree to keep the
    /// payload for [`output`](HtTree::output).
    fn finalize(&mut self, keep_output: bool) -> Vec<Block>;
    /// The full-domain output, if the tree keeps one.
    fn output(self, cw_out: &[Block]) -> Option<FullEval>;
    /// All `2^n` leaves, padding included, in order and in batches.
    fn visit_leaves(&self, visit: impl FnMut(u64, &[Block]));
}

impl HtTree for HtLocal {
    fn start(h: CcrHash, n_size: u64, conv: Convert, root: Block, _: TreeMode) -> Self {
        HtLocal::start(h, n_size, conv, root)
    }
    fn start_all_correlated(h: CcrHash, n_size: u64, root: Block, _: TreeMode) -> Self {
        HtLocal::start_all_correlated(h, n_size, root)
    }
    fn correlated_sum(&mut self) -> Block {
        HtLocal::correlated_sum(self)
    }
    fn apply_correlated(&mut self, cw: Block) {
        HtLocal::apply_correlated(self, cw)
    }
    fn last_sums(&mut self) -> (Block, Block) {
        HtLocal::last_sums(self)
    }
    fn apply_last(&mut self, hcw: Block, lcw: [bool; 2]) {
        HtLocal::apply_last(self, hcw, lcw)
    }
    fn finalize(&mut self, keep_output: bool) -> Vec<Block> {
        HtLocal::finalize(self, keep_output)
    }
    fn output(self, cw_out: &[Block]) -> Option<FullEval> {
        Some(HtLocal::output(self, cw_out))
    }
    fn visit_leaves(&self, mut visit: impl FnMut(u64, &[Block])) {
        assert_eq!(self.level, self.depth);
        visit(0, &self.nodes);
    }
}

/// The same tree as [`HtLocal`], holding only the root and the correction
/// words so far. Every sum is recomputed by a batched walk from the root; there
/// is no full-domain output.
pub struct HtStream {
    h: CcrHash,
    depth: usize,
    conv: Convert,
    corr_levels: usize,
    batch: usize,
    root: Block,
    cws: Vec<Block>,
    /// `(hb(HCW), LCW)` of the last level, once applied.
    last: Option<(Block, [bool; 2])>,
}

impl HtStream {
    /// A streaming tree over known correction words (for key evaluation).
    /// `last = None` is the all-correlated tree of the malicious variant.
    pub fn with_cws(h: CcrHash, n_size: u64, conv: Convert, root: Block, cws: Vec<Block>, last: Option<(Block, [bool; 2])>, batch: usize) -> Self {
        let depth = depth_for(n_size);
        let corr_levels = if last.is_some() { depth - 1 } else { depth };
        assert_eq!(cws.len(), corr_levels);
        HtStream { h, depth, conv, corr_levels, batch, root, cws, last: last.map(|(c, l)| (hb(c), l)) }
    }

    /// Corrected children at level `level` (1-based): `apply_correlated` or
    /// `apply_last` on the parents.
    fn expand(&self, level: usize, parents: &[Block], out: &mut Vec<Block>) {
        let p = parents.len();
        out.resize(2 * p, Block::ZERO);
        if level <= self.corr_levels {
            let cw = self.cws[level - 1];
            let mut hs = vec![Block::ZERO; p];
            self.h.h_many(parents, &mut hs);
            for (j, (x, hx)) in parents.iter().zip(&hs).enumerate() {
                let l = *hx ^ cw.and_bit(x.lsb());
                out[2 * j] = l;
                out[2 * j + 1] = l ^ *x;
            }
        } else {
            let (hcw, lcw) = self.last.expect("last level applied");
            let corr = [Block(hcw.0 | lcw[0] as u128), Block(hcw.0 | lcw[1] as u128)];
            let (mut q0, mut q1) = (vec![Block::ZERO; p], vec![Block::ZERO; p]);
            self.h.h_many_tweak(parents, Block::ZERO, &mut q0);
            self.h.h_many_tweak(parents, Block(1), &mut q1);
            for (j, x) in parents.iter().enumerate() {
                out[2 * j] = q0[j] ^ corr[0].and_bit(x.lsb());
                out[2 * j + 1] = q1[j] ^ corr[1].and_bit(x.lsb());
            }
        }
    }

    /// Visits the corrected nodes of `level`.
    fn walk_level(&self, level: usize, visit: impl FnMut(u64, &[Block])) {
        walk(self.root, level, self.batch, |l, p, o| self.expand(l, p, o), visit);
    }

    /// The level whose nodes are known, i.e. the number of applied levels.
    fn level(&self) -> usize {
        self.cws.len() + self.last.is_some() as usize
    }

    /// Output shares `Convert(leaf_x) ⊕ t_x·CW_{n+1}` for `x < n_size`, in
    /// batches: `visit(x0, cols)` with `cols[k][i]` = block k of point `x0 + i`.
    pub fn outputs(&self, n_size: u64, cw_out: &[Block], mut visit: impl FnMut(u64, &[Vec<Block>])) {
        self.visit_leaves(|x0, leaves| {
            if x0 >= n_size {
                return;
            }
            let leaves = &leaves[..leaves.len().min((n_size - x0) as usize)];
            let cols: Vec<Vec<Block>> = (0..self.conv.bm)
                .map(|k| {
                    let mut col = self.conv.column(leaves, k);
                    for (y, l) in col.iter_mut().zip(leaves) {
                        *y ^= cw_out[k].and_bit(l.lsb());
                    }
                    col
                })
                .collect();
            visit(x0, &cols);
        });
    }
}

impl HtTree for HtStream {
    fn start(h: CcrHash, n_size: u64, conv: Convert, root: Block, mode: TreeMode) -> Self {
        let depth = depth_for(n_size);
        HtStream { h, depth, conv, corr_levels: depth - 1, batch: mode.batch(), root, cws: Vec::new(), last: None }
    }

    fn start_all_correlated(h: CcrHash, n_size: u64, root: Block, mode: TreeMode) -> Self {
        let depth = depth_for(n_size);
        HtStream { h, depth, conv: Convert::new(128), corr_levels: depth, batch: mode.batch(), root, cws: Vec::new(), last: None }
    }

    fn correlated_sum(&mut self) -> Block {
        assert!(self.cws.len() < self.corr_levels, "next level is not correlated");
        let (mut acc, mut hs) = (Block::ZERO, Vec::new());
        self.walk_level(self.cws.len(), |_, nodes| {
            hs.resize(nodes.len(), Block::ZERO);
            self.h.h_many(nodes, &mut hs);
            acc = hs.iter().fold(acc, |a, b| a ^ *b);
        });
        acc
    }

    fn apply_correlated(&mut self, cw: Block) {
        self.cws.push(cw);
    }

    fn last_sums(&mut self) -> (Block, Block) {
        assert_eq!(self.cws.len() + 1, self.depth);
        assert_eq!(self.corr_levels + 1, self.depth);
        let (mut s0, mut s1, mut q) = (Block::ZERO, Block::ZERO, Vec::new());
        self.walk_level(self.cws.len(), |_, nodes| {
            q.resize(nodes.len(), Block::ZERO);
            self.h.h_many_tweak(nodes, Block::ZERO, &mut q);
            s0 = q.iter().fold(s0, |a, b| a ^ *b);
            self.h.h_many_tweak(nodes, Block(1), &mut q);
            s1 = q.iter().fold(s1, |a, b| a ^ *b);
        });
        (s0, s1)
    }

    fn apply_last(&mut self, hcw: Block, lcw: [bool; 2]) {
        self.last = Some((hb(hcw), lcw));
    }

    fn finalize(&mut self, _: bool) -> Vec<Block> {
        let mut acc = vec![Block::ZERO; self.conv.bm];
        self.visit_leaves(|_, leaves| {
            for (k, a) in acc.iter_mut().enumerate() {
                *a = self.conv.column(leaves, k).iter().fold(*a, |x, y| x ^ *y);
            }
        });
        acc
    }

    fn output(self, _: &[Block]) -> Option<FullEval> {
        None
    }

    fn visit_leaves(&self, visit: impl FnMut(u64, &[Block])) {
        assert_eq!(self.level(), self.depth);
        self.walk_level(self.depth, visit);
    }
}
