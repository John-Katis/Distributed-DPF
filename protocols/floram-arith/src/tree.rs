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
use dpf_common::block::{depth_for, Block};

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
    nodes: Vec<Block>,
    t: Vec<bool>,
    /// Uncorrected children of `nodes`, filled by [`expand_level`](Self::expand_level).
    raw: Vec<Block>,
}

impl Tree {
    /// Root seed `s^{0,0}` with control bit `t^{0,0} = b` (Alg. 2 line 2).
    pub fn new(n_size: u64, root: Block, t0: bool) -> Self {
        let depth = depth_for(n_size);
        Tree { depth, level: 0, nodes: vec![root], t: vec![t0], raw: Vec::with_capacity(1 << depth) }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Lines 4–5: expands every node and returns `(S^{i,0}, S^{i,1})`, the XOR
    /// of all left and of all right children.
    pub fn expand_level(&mut self) -> (Block, Block) {
        assert!(self.level < self.depth);
        self.raw.clear();
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        for s in &self.nodes {
            let kids = expand(*s);
            self.raw.extend(kids);
            l ^= kids[0];
            r ^= kids[1];
        }
        (l, r)
    }

    /// Lines 10–13 with the level's correction word.
    pub fn correct(&mut self, cw: CorrectionWord) {
        let mut t = Vec::with_capacity(self.raw.len());
        for (c, x) in self.raw.iter_mut().enumerate() {
            let tp = self.t[c / 2];
            let tc = x.lsb() ^ (tp & cw.tau[c & 1]);
            t.push(tc);
            *x = (*x ^ cw.sigma.and_bit(tp)).with_lsb(tc);
        }
        std::mem::swap(&mut self.nodes, &mut self.raw);
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
