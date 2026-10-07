//! One party's GGM tree for XLH+25 Alg. 2, expanded the way the authors'
//! reference code does it (`expandDpfPrgLevel` in `src/legacy/dpf.cpp`):
//!
//! * `G(s) = AES_s(0) ∥ AES_s(1)`, i.e. AES-128 keyed by the seed. The left and
//!   right children are the two output blocks, and a child's control bit is
//!   its lsb (the `s∥t` of Alg. 2 line 4 read as one 128-bit block).
//! * Correction (lines 10–13): if the parent's control bit is 1, both children
//!   are XORed with σ and each child's control bit with `τ_side`.
//!
//! Only nodes with a leaf below `N` are expanded (as in Floram). The skipped
//! nodes are off-path, so both parties' copies of them are equal and would
//! cancel in every sum the protocol uses.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use dpf_common::block::{depth_for, Block};

/// Nodes on level `l` (0 = root) of a depth-`depth` tree with `n_size` leaves
/// that have a leaf below `n_size`.
pub fn level_count(n_size: u64, depth: usize, l: usize) -> usize {
    n_size.div_ceil(1u64 << (depth - l)) as usize
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
    pub sigma: Block,
    pub tau: [bool; 2],
}

/// One party's tree, advanced one level at a time.
pub struct Tree {
    n_size: u64,
    depth: usize,
    level: usize,
    nodes: Vec<Block>,
    t: Vec<bool>,
    /// Uncorrected children of `nodes`, filled by [`expand_level`](Self::expand_level).
    raw: Vec<Block>,
}

impl Tree {
    /// Root seed `s^{0,0}` with control bit `t^{0,0} = b` (Alg. 2 line 2).
    pub fn new(n_size: u64, root: Block, t0: bool) -> Self {
        let depth = depth_for(n_size);
        Tree { n_size, depth, level: 0, nodes: vec![root], t: vec![t0], raw: Vec::with_capacity(n_size as usize) }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Lines 4–5: expands every node and returns `(S^{i,0}, S^{i,1})`, the XOR
    /// of all left and of all right children.
    pub fn expand_level(&mut self) -> (Block, Block) {
        assert!(self.level < self.depth);
        let next = level_count(self.n_size, self.depth, self.level + 1);
        self.raw.clear();
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        for (j, s) in self.nodes.iter().enumerate() {
            let kids = expand(*s);
            self.raw.push(kids[0]);
            l ^= kids[0];
            if 2 * j + 1 < next {
                self.raw.push(kids[1]);
                r ^= kids[1];
            }
        }
        (l, r)
    }

    /// Lines 10–13 with the level's correction word.
    pub fn correct(&mut self, cw: CorrectionWord) {
        let mut t = Vec::with_capacity(self.raw.len());
        for (c, x) in self.raw.iter_mut().enumerate() {
            let tp = self.t[c / 2];
            t.push(x.lsb() ^ (tp & cw.tau[c & 1]));
            *x ^= cw.sigma.and_bit(tp);
        }
        std::mem::swap(&mut self.nodes, &mut self.raw);
        self.t = t;
        self.level += 1;
    }

    /// The leaves `s^{ℓ_in, i}` and their control bits, after the last level.
    pub fn leaves(&self) -> (&[Block], &[bool]) {
        assert_eq!(self.level, self.depth);
        (&self.nodes, &self.t)
    }
}
