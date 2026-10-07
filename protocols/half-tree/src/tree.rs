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
//! A leaf `X = s ∥ t` yields the payload `Convert(s)`. Only nodes with a leaf
//! below `N` are kept (as in Floram), which is sound because every node the
//! parties skip is off-path and so has identical shares on both sides. The
//! last level's sums still include every child of a kept parent, so that HCW
//! stays pseudorandom when α's sibling is a skipped node.

use dpf_common::block::{depth_for, Block};
use dpf_common::hash::{convert_hash, CcrHash};

/// Nodes on level `l` (0 = root) of a depth-`depth` tree with `n_size` leaves
/// that have a leaf below `n_size` (Floram's `nextlevelblocks`).
pub fn level_count(n_size: u64, depth: usize, l: usize) -> usize {
    n_size.div_ceil(1u64 << (depth - l)) as usize
}

/// Clears the t-bit: `hb(X) ∥ 0`.
#[inline]
pub fn hb(x: Block) -> Block {
    Block(x.0 & !1)
}

/// `Convert` from a leaf to `bm` payload blocks. For payloads of at most 127
/// bits it is the PRG-free conversion of GYW+23 App. F.1 (the 127 seed bits
/// `s = hb(X)` shifted down). Wider payloads hash `s` with a domain-separated
/// fixed-key hash, one call per block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convert {
    pub out_bits: usize,
    pub bm: usize,
}

impl Convert {
    pub fn new(out_bits: usize) -> Self {
        Convert { out_bits, bm: dpf_common::block::blocks_for_bits(out_bits) }
    }

    #[inline]
    fn identity(&self) -> bool {
        self.out_bits <= 127
    }

    /// Payload block `k` for one leaf.
    #[inline]
    pub fn word(&self, leaf: Block, k: usize) -> Block {
        if self.identity() {
            Block(leaf.0 >> 1)
        } else {
            convert_hash().h(hb(leaf), k as u64)
        }
    }

    /// Payload column `k` for all leaves.
    pub fn column(&self, leaves: &[Block], k: usize) -> Vec<Block> {
        if self.identity() {
            leaves.iter().map(|x| Block(x.0 >> 1)).collect()
        } else {
            let s: Vec<Block> = leaves.iter().map(|x| hb(*x)).collect();
            let mut out = vec![Block::ZERO; leaves.len()];
            convert_hash().h_many(&s, k as u64, &mut out);
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
    nodes: Vec<Block>,
    /// `H(nodes)`, or the raw last-level children, filled by the sum methods.
    scratch: Vec<Block>,
    leaf_cols: Vec<Vec<Block>>,
}

fn sum_interleaved(v: &[Block]) -> (Block, Block) {
    let mut l = Block::ZERO;
    let mut r = Block::ZERO;
    for pair in v.chunks(2) {
        l ^= pair[0];
        if let Some(x) = pair.get(1) {
            r ^= *x;
        }
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
        let mut nodes = Vec::with_capacity(n_size as usize);
        nodes.push(root);
        HtLocal {
            h,
            n_size,
            depth,
            conv,
            corr_levels,
            level: 0,
            nodes,
            scratch: Vec::with_capacity(n_size as usize),
            leaf_cols: Vec::new(),
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
        let next = level_count(self.n_size, self.depth, self.level + 1);
        let mut kids = Vec::with_capacity(next);
        for c in 0..next {
            let p = self.nodes[c / 2];
            let mut x = self.scratch[c / 2] ^ cw.and_bit(p.lsb());
            if c & 1 == 1 {
                x ^= p;
            }
            kids.push(x);
        }
        self.nodes = kids;
        self.level += 1;
    }

    /// The current level's nodes (the leaves once every level is expanded).
    pub fn nodes(&self) -> &[Block] {
        &self.nodes
    }

    /// Before the last level: computes the raw children `H(X ⊕ σ)` and returns
    /// `(⊕_j H(X^j), ⊕_j H(X^j ⊕ 1))` over all parents, then keeps only the
    /// children with a leaf below N. Summing a dropped right child too keeps
    /// HCW pseudorandom when it is α's off-path sibling (else HCW = 0).
    pub fn last_sums(&mut self) -> (Block, Block) {
        assert_eq!(self.level + 1, self.depth);
        assert_eq!(self.corr_levels + 1, self.depth);
        let next = level_count(self.n_size, self.depth, self.depth);
        let p = self.nodes.len();
        let mut q0 = vec![Block::ZERO; p];
        let mut q1 = vec![Block::ZERO; p];
        self.h.h_many_tweak(&self.nodes, Block::ZERO, &mut q0);
        self.h.h_many_tweak(&self.nodes, Block(1), &mut q1);
        self.scratch.clear();
        for j in 0..p {
            self.scratch.push(q0[j]);
            self.scratch.push(q1[j]);
        }
        let sums = sum_interleaved(&self.scratch);
        self.scratch.truncate(next);
        sums
    }

    /// Applies `(HCW, LCW_0, LCW_1)` to the last level. `hcw`'s lsb is ignored.
    pub fn apply_last(&mut self, hcw: Block, lcw: [bool; 2]) {
        let corr = [Block(hb(hcw).0 | lcw[0] as u128), Block(hb(hcw).0 | lcw[1] as u128)];
        for (c, x) in self.scratch.iter_mut().enumerate() {
            *x ^= corr[c & 1].and_bit(self.nodes[c / 2].lsb());
        }
        std::mem::swap(&mut self.nodes, &mut self.scratch);
        self.level += 1;
    }

    /// After the last level: converts every leaf and returns `⊕_j Convert(leaf_j)`
    /// per payload block.
    pub fn finalize(&mut self) -> Vec<Block> {
        assert_eq!(self.level, self.depth);
        assert_eq!(self.nodes.len(), self.n_size as usize);
        self.leaf_cols = (0..self.conv.bm).map(|k| self.conv.column(&self.nodes, k)).collect();
        self.leaf_cols.iter().map(|c| c.iter().fold(Block::ZERO, |a, b| a ^ *b)).collect()
    }

    /// Output shares `y(x) = Convert(leaf_x) ⊕ t_x·CW_{n+1}`.
    pub fn output(self, cw_out: &[Block]) -> FullEval {
        let t: Vec<bool> = self.nodes.iter().map(|x| x.lsb()).collect();
        let cols = self
            .leaf_cols
            .into_iter()
            .zip(cw_out)
            .map(|(mut col, g)| {
                for (y, &tx) in col.iter_mut().zip(&t) {
                    *y ^= g.and_bit(tx);
                }
                col
            })
            .collect();
        FullEval { n: self.n_size as usize, bm: self.conv.bm, cols }
    }
}
